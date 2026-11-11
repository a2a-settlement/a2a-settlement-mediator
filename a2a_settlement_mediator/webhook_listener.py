"""Webhook listener for the A2A Settlement Exchange.

Receives escrow.disputed events and triggers the mediation pipeline.
Verifies webhook signatures using HMAC-SHA256 (same scheme as the exchange).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from collections.abc import AsyncIterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from starlette.middleware.base import BaseHTTPMiddleware

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.heartbeat import HeartbeatWorker
from a2a_settlement_mediator.mediator import mediate
from a2a_settlement_mediator.patch_assessor import assess_patch
from a2a_settlement_mediator.schemas import AuditRecord, VerifyPatchRequest, WebhookPayload
from a2a_settlement_mediator import storage
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
    from a2a_settlement_mediator.config import assert_public_receipts_tsa
    from a2a_settlement_mediator.receipts.routes import startup_receipts

    assert_public_receipts_tsa(settings.receipts_public, settings.tsa_url)
    storage.initialize_db()
    startup_receipts(settings)
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


def _now() -> float:
    return time.time()


def _verify_patch_signature(
    body: bytes, timestamp: str, signature: str | None
) -> str | None:
    """Return the verified signature hex, or None.

    The signed message is the timestamp header, a literal ``.``, then the raw
    body. Fail closed when unconfigured: ``_verify_signature`` succeeds when
    no webhook secret is set, and payment checks must refuse that path.
    """
    secret = settings.webhook_secret
    if not secret or not signature:
        return None
    message = f"{timestamp}.".encode("ascii") + body
    expected = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(f"sha256={expected}", signature):
        return None
    return expected


# ---------------------------------------------------------------------------
# Background mediation task
# ---------------------------------------------------------------------------


def _exchange_error(escrow_id: str, exc: httpx.HTTPStatusError) -> HTTPException:
    """Translate an exchange HTTP failure into a response the caller can act on.

    Without this the mediator surfaces a bare 500 for every exchange-side
    problem, which hides the difference between "this escrow does not exist"
    and "the exchange rejected our credentials".
    """
    status = exc.response.status_code
    if status == 404:
        return HTTPException(
            status_code=404, detail=f"Escrow {escrow_id!r} not found on the exchange"
        )
    if status in (401, 403):
        return HTTPException(
            status_code=502,
            detail=(
                f"The exchange rejected the mediator's credentials ({status}). "
                "Check A2A_OPERATOR_API_KEY and that its account is active "
                "with operator status."
            ),
        )
    return HTTPException(
        status_code=502, detail=f"Exchange returned {status} for escrow {escrow_id!r}"
    )


def _run_mediation(escrow_id: str) -> None:
    """Run mediation in a background thread."""
    try:
        audit = mediate(escrow_id)
        storage.save_audit_record(escrow_id, audit.model_dump_json())
    except httpx.HTTPStatusError as exc:
        logger.error(
            "Background mediation failed for escrow %s: exchange returned %s for %s",
            escrow_id,
            exc.response.status_code,
            exc.request.url,
        )
    except Exception:
        logger.exception("Background mediation failed for escrow %s", escrow_id)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


_GUIDE_PATH = Path(__file__).parent.parent / "docs" / "bounty-design-guide.md"
_GUIDE_VERSION = "1.1"


def _guide_url() -> str:
    return f"{settings.public_url}/guide"


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "a2a-settlement-mediator",
        "version": "0.1.0",
        "auto_resolve_threshold": settings.auto_resolve_threshold,
        "llm_model": settings.llm_model,
        "guide_url": _guide_url(),
    }


@app.get("/guide")
def bounty_design_guide():
    """Return the bounty design guide for agents posting SettleBridge bounties.

    This endpoint is the primary discovery mechanism for external agents that
    have no prior knowledge of the mediator's verification pipeline.  Any agent
    that hits ``/health`` first will find ``guide_url`` pointing here.

    Returns a JSON object with:
    - ``format``: always ``"text/markdown"``
    - ``version``: guide schema version
    - ``content``: full guide text in Markdown
    - ``source``: canonical GitHub URL for the guide
    """
    if not _GUIDE_PATH.exists():
        raise HTTPException(status_code=404, detail="Bounty design guide not found.")
    content = _GUIDE_PATH.read_text(encoding="utf-8")
    return {
        "format": "text/markdown",
        "version": _GUIDE_VERSION,
        "content": content,
        "public_url": _guide_url(),
        "source": (
            "https://github.com/a2a-settlement/a2a-settlement-mediator"
            "/blob/main/docs/bounty-design-guide.md"
        ),
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
    records, total = storage.list_audit_records(limit, offset)
    return {"audits": records, "total": total}


@app.get("/audits/{escrow_id}")
def get_audit(escrow_id: str):
    """Get the audit record for a specific escrow."""
    record = storage.get_audit_record(escrow_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Audit record not found")
    return record


class MediationRequest(BaseModel):
    """Optional request body for the manual mediation trigger.

    All fields are optional so the endpoint remains backward-compatible
    with callers that send no body.
    """

    mode: str | None = None
    task_type: str | None = None


@app.post("/mediate/{escrow_id}")
def trigger_mediation(escrow_id: str, req: MediationRequest | None = None):
    """Manually trigger mediation for a disputed escrow.

    Accepts an optional JSON body with ``mode`` (``"training"`` or
    ``"production"``) and ``task_type`` to enable structured diagnostic
    output from the LLM.  Callers that send no body continue to work
    as before.

    Runs synchronously and returns the full audit record.
    """
    mode = req.mode if req else None
    task_type = req.task_type if req else None
    try:
        audit = mediate(escrow_id, mode=mode, task_type=task_type)
    except httpx.HTTPStatusError as exc:
        raise _exchange_error(escrow_id, exc) from exc
    storage.save_audit_record(escrow_id, audit.model_dump_json())
    return audit.model_dump(mode="json")


# ---------------------------------------------------------------------------
# SEC 17a-4 WORM Settlement Pipeline endpoints
# ---------------------------------------------------------------------------

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
    result_json = result.model_dump_json()
    settlement_hash = result.settlement_hash if hasattr(result, "settlement_hash") else ""
    if settlement_hash:
        storage.save_settlement_result(settlement_hash, result_json)

    return result.model_dump(mode="json")


@app.get("/settlements")
def list_settlements(limit: int = 20, offset: int = 0):
    """List recent settlement results."""
    records, total = storage.list_settlement_results(limit, offset)
    return {"settlements": records, "total": total}


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
        if found:
            storage.mark_settlement_executed(ack.settlement_hash)
    elif ack.status == "failed":
        found = mark_failed(ack.settlement_hash, ack.error or "unknown error")
        if found:
            storage.mark_settlement_failed(ack.settlement_hash, ack.error or "unknown error")
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


# ---------------------------------------------------------------------------
# Patch assessment
# ---------------------------------------------------------------------------


def _patch_assessment_key(req: VerifyPatchRequest) -> str:
    return f"patch:{req.repo}#{req.pr_number}@{req.head_sha}:{req.spec_hash}"


@app.post("/api/v1/verify-patch")
async def verify_patch(
    request: Request,
    x_a2ase_signature: str | None = Header(default=None),
    x_a2ase_timestamp: str | None = Header(default=None),
):
    """Assess a PR diff against a frozen patch policy.

    Requires ``X-A2ASE-Timestamp`` (unix seconds) and
    ``X-A2ASE-Signature: sha256=<hex>`` over ``{timestamp}.{raw body}``.
    An empty webhook secret refuses the request. A verified signature is
    accepted only once inside its timestamp window.
    """
    if not settings.webhook_secret:
        logger.warning("verify-patch refused because MEDIATOR_WEBHOOK_SECRET is empty")
        raise HTTPException(
            status_code=503,
            detail="verify-patch requires MEDIATOR_WEBHOOK_SECRET",
        )

    if (
        not x_a2ase_timestamp
        or not x_a2ase_timestamp.isascii()
        or not x_a2ase_timestamp.isdigit()
        or len(x_a2ase_timestamp) > 12
        or not x_a2ase_signature
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    now = _now()
    timestamp = int(x_a2ase_timestamp)
    tolerance = settings.signature_tolerance_seconds
    # Values that do not fit in a float are outside any finite window.
    try:
        outside = abs(now - timestamp) > tolerance
    except OverflowError:
        outside = True
    if outside:
        raise HTTPException(
            status_code=401,
            detail="Signature timestamp outside the allowed window",
        )

    body = await request.body()
    signature_hex = _verify_patch_signature(body, x_a2ase_timestamp, x_a2ase_signature)
    if signature_hex is None:
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    # timestamp + tolerance still covers every later `now` that would accept it.
    fresh = storage.remember_patch_signature(
        signature_hex, float(timestamp + tolerance), now
    )
    if not fresh:
        raise HTTPException(status_code=409, detail="Replayed request")

    try:
        req = VerifyPatchRequest.model_validate_json(body)
    except ValidationError as exc:
        logger.error("Invalid verify-patch payload: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid payload") from exc

    assessment = await run_in_threadpool(assess_patch, req)
    raw = assessment.model_dump_json()
    storage.save_patch_assessment(_patch_assessment_key(req), raw)
    return json.loads(raw)


def _mount_receipt_routes() -> None:
    """Attach proof-of-fix routes without importing them during app construction."""
    from a2a_settlement_mediator.receipts.routes import router as receipts_router

    app.include_router(receipts_router)


_mount_receipt_routes()
