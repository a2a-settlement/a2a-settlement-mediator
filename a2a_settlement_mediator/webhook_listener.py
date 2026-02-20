"""Webhook listener for the A2A Settlement Exchange.

Receives escrow.disputed events and triggers the mediation pipeline.
Verifies webhook signatures using HMAC-SHA256 (same scheme as the exchange).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.middleware.base import BaseHTTPMiddleware

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.heartbeat import HeartbeatWorker
from a2a_settlement_mediator.mediator import mediate
from a2a_settlement_mediator.schemas import AuditRecord, WebhookPayload
from a2a_settlement_mediator.settlement_pipeline import (
    get_confirmed_settlement,
    get_merkle_tree,
    get_pending_settlements,
    mark_executed,
    mark_failed,
    settle,
)
from a2a_settlement_mediator.worm_schemas import (
    AgentIdentity,
    AP2Mandate,
    CurrencyPrecision,
    NegotiationTranscript,
    SCHEMA_VERSION,
    SettlementResult,
    export_json_schemas,
)

logger = logging.getLogger(__name__)

MAX_REQUEST_BODY_BYTES = 1 * 1024 * 1024  # 1 MiB hard cap on all request bodies


class _BodySizeLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests whose body exceeds MAX_REQUEST_BODY_BYTES.

    Mitigates Context Bomb attacks at the HTTP layer before any JSON
    parsing or LLM prompt construction occurs.
    """

    async def dispatch(self, request: Request, call_next):
        content_length = request.headers.get("content-length")
        if content_length and int(content_length) > MAX_REQUEST_BODY_BYTES:
            return JSONResponse(
                status_code=413,
                content={"detail": "Request body too large"},
            )
        return await call_next(request)


# Heartbeat recovery worker
_heartbeat = HeartbeatWorker()


@asynccontextmanager
async def _lifespan(_app: FastAPI) -> AsyncIterator[None]:
    _heartbeat.start()
    yield
    _heartbeat.stop()


app = FastAPI(
    title="A2A Settlement Mediator",
    description="AI-powered dispute resolution sidecar for the A2A Settlement Exchange",
    version="0.1.0",
    lifespan=_lifespan,
)

app.add_middleware(_BodySizeLimitMiddleware)


# Thread pool for background mediation (webhook must respond quickly)
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="mediator")

# In-memory audit log (production: persist to database or object store)
_audit_log: list[AuditRecord] = []


# ---------------------------------------------------------------------------
# Signature verification
# ---------------------------------------------------------------------------


def _verify_signature(body: bytes, signature: str | None) -> bool:
    """Verify the webhook HMAC-SHA256 signature."""
    if not settings.webhook_secret:
        # No secret configured — skip verification (development mode)
        logger.warning("Webhook signature verification skipped (no secret configured)")
        return True

    if not signature:
        return False

    expected = hmac.new(
        settings.webhook_secret.encode("utf-8"),
        body,
        hashlib.sha256,
    ).hexdigest()

    expected_sig = f"sha256={expected}"
    return hmac.compare_digest(expected_sig, signature)


# ---------------------------------------------------------------------------
# Background mediation task
# ---------------------------------------------------------------------------


def _run_mediation(escrow_id: str) -> None:
    """Run mediation in a background thread."""
    try:
        audit = mediate(escrow_id)
        _audit_log.append(audit)
    except Exception:
        logger.exception("Background mediation failed for escrow %s", escrow_id)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "a2a-settlement-mediator",
        "version": "0.1.0",
        "auto_resolve_threshold": settings.auto_resolve_threshold,
        "llm_model": settings.llm_model,
    }


@app.post("/webhook")
async def receive_webhook(
    request: Request,
    x_a2ase_signature: str | None = Header(default=None),
    x_a2ase_event: str | None = Header(default=None),
    x_a2ase_delivery: str | None = Header(default=None),
):
    """Receive webhook events from the A2A Settlement Exchange.

    Only processes 'escrow.disputed' events. All others are acknowledged
    but ignored.
    """
    body = await request.body()

    # Verify signature
    if not _verify_signature(body, x_a2ase_signature):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # Parse payload
    try:
        payload = WebhookPayload(**json.loads(body))
    except Exception as exc:
        logger.error("Failed to parse webhook payload: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid payload") from exc

    logger.info(
        "Received webhook: event=%s delivery=%s escrow=%s",
        payload.event,
        x_a2ase_delivery,
        payload.data.get("escrow_id", "unknown"),
    )

    # Only process disputed events
    if payload.event != "escrow.disputed":
        return {"status": "ignored", "event": payload.event}

    escrow_id = payload.data.get("escrow_id")
    if not escrow_id:
        raise HTTPException(status_code=400, detail="Missing escrow_id in webhook data")

    # Submit mediation to background thread (respond to webhook immediately)
    _executor.submit(_run_mediation, escrow_id)

    return {
        "status": "accepted",
        "escrow_id": escrow_id,
        "message": "Mediation initiated",
    }


@app.get("/audits")
def list_audits(limit: int = 20, offset: int = 0):
    """List recent mediation audit records."""
    records = _audit_log[offset : offset + limit]
    return {
        "audits": [r.model_dump(mode="json") for r in records],
        "total": len(_audit_log),
    }


@app.get("/audits/{escrow_id}")
def get_audit(escrow_id: str):
    """Get the audit record for a specific escrow."""
    for record in reversed(_audit_log):
        if record.escrow_id == escrow_id:
            return record.model_dump(mode="json")
    raise HTTPException(status_code=404, detail="Audit record not found")


@app.post("/mediate/{escrow_id}")
def trigger_mediation(escrow_id: str):
    """Manually trigger mediation for a disputed escrow.

    Useful for re-evaluation or testing. Runs synchronously and returns
    the full audit record.
    """
    audit = mediate(escrow_id)
    _audit_log.append(audit)
    return audit.model_dump(mode="json")


# ---------------------------------------------------------------------------
# SEC 17a-4 WORM Settlement Pipeline endpoints
# ---------------------------------------------------------------------------

_settlement_log: list[SettlementResult] = []


class SettlementRequest(BaseModel):
    """Request body for the settlement endpoint."""

    transcript_hash: str
    source_service: str = "crewai"
    session_id: str | None = None
    mandates: list[dict]
    escrow_id: str | None = None
    agent_identities: list[dict] | None = None
    currency_precision: dict | None = None


@app.post("/settle")
def trigger_settlement(req: SettlementRequest):
    """Run the SEC 17a-4 WORM-compliant settlement pipeline.

    Accepts a hashed negotiation transcript and AP2 mandates,
    runs arbitration, timestamping, and Merkle Tree append.
    Returns the full cryptographic proof on success, or the
    failure stage and error on hard-fail.
    """
    transcript = NegotiationTranscript(
        transcript_hash=req.transcript_hash,
        source_service=req.source_service,
        session_id=req.session_id,
    )

    mandates = [AP2Mandate(**m) for m in req.mandates]

    identities = (
        [AgentIdentity(**a) for a in req.agent_identities]
        if req.agent_identities
        else None
    )
    precision = (
        CurrencyPrecision(**req.currency_precision)
        if req.currency_precision
        else None
    )

    result = settle(
        transcript,
        mandates,
        escrow_id=req.escrow_id,
        agent_identities=identities,
        currency_precision=precision,
    )
    _settlement_log.append(result)

    return result.model_dump(mode="json")


@app.get("/settlements")
def list_settlements(limit: int = 20, offset: int = 0):
    """List recent settlement results."""
    records = _settlement_log[offset : offset + limit]
    return {
        "settlements": [r.model_dump(mode="json") for r in records],
        "total": len(_settlement_log),
    }


@app.get("/merkle")
def merkle_status():
    """Return current Merkle Tree state."""
    tree = get_merkle_tree()
    return {
        "tree_size": tree.size,
        "root_hash": tree.root_hash.hex() if tree.size > 0 else None,
    }


# ---------------------------------------------------------------------------
# Gatekeeper recovery endpoints
# ---------------------------------------------------------------------------


@app.get("/settlements/pending")
def list_pending_settlements():
    """Return confirmed settlements whose mandate has not yet been executed.

    The Gatekeeper's recovery loop should poll this endpoint and re-emit
    the AP2 Mandate for each result.
    """
    pending = get_pending_settlements()
    return {
        "pending": [r.model_dump(mode="json") for r in pending],
        "count": len(pending),
    }


class ExecutionAck(BaseModel):
    """Acknowledge that a settlement mandate was executed or failed."""

    settlement_hash: str
    status: str = "executed"
    error: str | None = None


@app.post("/settlements/ack")
def ack_execution(ack: ExecutionAck):
    """Mark a confirmed settlement as executed (or failed).

    Called by the execution engine after the AP2 Mandate has been
    released.  This closes the Gatekeeper's recovery window for the
    given settlement.
    """
    if ack.status == "executed":
        found = mark_executed(ack.settlement_hash)
    elif ack.status == "failed":
        found = mark_failed(ack.settlement_hash, ack.error or "unknown error")
    else:
        raise HTTPException(status_code=400, detail=f"Invalid status: {ack.status!r}")

    if not found:
        raise HTTPException(status_code=404, detail="Settlement not found")

    return {"settlement_hash": ack.settlement_hash, "status": ack.status}


# ---------------------------------------------------------------------------
# Heartbeat status
# ---------------------------------------------------------------------------


@app.get("/heartbeat/status")
def heartbeat_status():
    """Return the current state of the heartbeat recovery worker."""
    return _heartbeat.status()


# ---------------------------------------------------------------------------
# Attestation schema endpoints
# ---------------------------------------------------------------------------


@app.get("/schemas")
def list_schemas():
    """Return versioned JSON Schema definitions for all attestation models.

    External auditors and peer mediators can use these schemas to
    validate settlement proofs without needing the mediator's source code.
    """
    schemas = export_json_schemas()
    return {
        "schema_version": SCHEMA_VERSION,
        "schemas": schemas,
    }
