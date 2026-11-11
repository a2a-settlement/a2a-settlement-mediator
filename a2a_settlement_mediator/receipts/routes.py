"""HTTP API for proof-of-fix receipts.

``POST /api/v1/receipts`` is backend-only. It reuses the verify-patch
timestamped HMAC: ``X-A2ASE-Timestamp`` and ``X-A2ASE-Signature: sha256=<hex>``
over ``{timestamp}.{raw body}``, with the same replay cache. The other routes
are unauthenticated. Every route returns 404 while
``MEDIATOR_RECEIPTS_ENABLED`` is false.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import ValidationError

from a2a_settlement_mediator.config import MediatorSettings, settings

logger = logging.getLogger(__name__)

router = APIRouter()

_service: Any = None


def set_receipt_service(service: Any) -> None:
    """Install a receipt service. Tests use this to inject a local signer."""
    global _service
    _service = service


def startup_receipts(current: MediatorSettings) -> None:
    """Build the configured service when receipts are enabled.

    An already installed service is kept, so tests can inject one before the
    app starts. Disabling receipts drops the installed service.
    """
    global _service
    if not current.receipts_enabled:
        _service = None
        return
    if _service is not None:
        return
    from a2a_settlement_mediator.receipts.service import ReceiptService

    _service = ReceiptService.from_settings(current)


def _require_service() -> Any:
    if not settings.receipts_enabled or _service is None:
        raise HTTPException(status_code=404, detail="Not Found")
    return _service


def _authorize(body: bytes, timestamp: str | None, signature: str | None) -> None:
    """Timestamped HMAC over ``{timestamp}.{body}``, rejected on replay."""
    from a2a_settlement_mediator import storage, webhook_listener

    if not settings.webhook_secret:
        raise HTTPException(
            status_code=503,
            detail="receipts require MEDIATOR_WEBHOOK_SECRET",
        )
    if (
        not timestamp
        or not timestamp.isascii()
        or not timestamp.isdigit()
        or len(timestamp) > 12
        or not signature
    ):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    now = webhook_listener._now()
    stamp = int(timestamp)
    tolerance = settings.signature_tolerance_seconds
    try:
        outside = abs(now - stamp) > tolerance
    except OverflowError:
        outside = True
    if outside:
        raise HTTPException(
            status_code=401,
            detail="Signature timestamp outside the allowed window",
        )

    signature_hex = webhook_listener._verify_patch_signature(body, timestamp, signature)
    if signature_hex is None:
        raise HTTPException(status_code=401, detail="Invalid webhook signature")
    fresh = storage.remember_patch_signature(signature_hex, float(stamp + tolerance), now)
    if not fresh:
        raise HTTPException(status_code=409, detail="Replayed request")


@router.post("/api/v1/receipts", status_code=201)
async def issue_receipt(
    request: Request,
    x_a2ase_signature: str | None = Header(default=None),
    x_a2ase_timestamp: str | None = Header(default=None),
) -> dict[str, Any]:
    """Sign, timestamp, and store a proof-of-fix draft."""
    service = _require_service()
    body = await request.body()
    _authorize(body, x_a2ase_timestamp, x_a2ase_signature)
    return await run_in_threadpool(_issue_authorized, service, body)


@router.get("/api/v1/receipts/{receipt_id}")
def get_receipt(receipt_id: str) -> dict[str, Any]:
    """Return the stored envelopes, timestamp, Merkle proof, and row hash."""
    service = _require_service()
    document = service.get(receipt_id)
    if document is None:
        raise HTTPException(status_code=404, detail="Receipt not found")
    return document


@router.post("/api/v1/receipts/verify")
async def verify_receipt(request: Request) -> dict[str, Any]:
    """Verify a stored receipt, or the bundle in the request body."""
    service = _require_service()
    body = await request.body()
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="Invalid payload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Invalid payload")
    return await run_in_threadpool(_verify_payload, service, payload)


@router.get("/.well-known/settlebridge-receipt-keys.json")
def receipt_keys() -> dict[str, Any]:
    """JWKS for current and retired receipt signing keys."""
    service = _require_service()
    return service.jwks()


def _issue_authorized(service: Any, body: bytes) -> dict[str, Any]:
    from a2a_settlement_mediator.receipts.predicate import ProofOfFixDraft
    from a2a_settlement_mediator.receipts.service import (
        ReceiptIssueError,
        ReceiptPolicyError,
    )
    from a2a_settlement_mediator.receipts.store import DuplicateReceipt, StoreIntegrityError
    from a2a_settlement_mediator.tsa_client import TSAClientError

    try:
        draft = ProofOfFixDraft.model_validate_json(body)
    except ValidationError as exc:
        logger.error("Invalid receipt payload: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid payload") from exc
    try:
        return service.issue(draft)
    except DuplicateReceipt as exc:
        raise HTTPException(status_code=409, detail=f"duplicate {exc.field}") from exc
    except ReceiptPolicyError as exc:
        logger.warning("receipt policy rejected the draft: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid payload") from exc
    except ValueError as exc:
        logger.info("rejected receipt draft: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid payload") from exc
    except StoreIntegrityError as exc:
        logger.error("receipt store integrity check failed: %s", exc)
        raise HTTPException(
            status_code=503, detail="receipt store failed its integrity check"
        ) from exc
    except (TSAClientError, ReceiptIssueError) as exc:
        logger.warning("receipt timestamp failed: %s", exc)
        raise HTTPException(
            status_code=502, detail="Timestamp authority request failed"
        ) from exc


def _verify_payload(service: Any, payload: dict[str, Any]) -> dict[str, Any]:
    from a2a_settlement_mediator.receipts.service import (
        ReceiptNotFound,
        ReceiptVerifyInputError,
    )

    try:
        return service.verify(
            receipt_id=payload.get("receipt_id"),
            statement_envelope=payload.get("statement_envelope"),
            vsa_envelope=payload.get("vsa_envelope"),
            timestamp_token_b64=payload.get("timestamp_token_b64"),
            merkle_proof=payload.get("merkle_proof"),
            repo=payload.get("repo"),
            commit=payload.get("commit"),
        )
    except ReceiptNotFound as exc:
        raise HTTPException(status_code=404, detail="Receipt not found") from exc
    except ReceiptVerifyInputError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
