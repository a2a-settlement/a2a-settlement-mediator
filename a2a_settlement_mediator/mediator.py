"""Core mediator logic.

Orchestrates the full mediation lifecycle:
1. Collect evidence from the exchange
2. Evaluate via LLM
3. Apply confidence threshold
4. Execute resolution or escalate
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

import httpx
import litellm

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.evidence import collect_evidence
from a2a_settlement_mediator.prompts import SYSTEM_PROMPT, build_evaluation_prompt
from a2a_settlement_mediator.schemas import (
    AuditRecord,
    Resolution,
    Verdict,
    VerdictOutcome,
)

logger = logging.getLogger(__name__)

# Suppress litellm's verbose logging unless explicitly enabled
litellm.suppress_debug_info = True


# ---------------------------------------------------------------------------
# LLM evaluation
# ---------------------------------------------------------------------------


def _call_llm(evidence_json: str) -> tuple[dict, int, int, int]:
    """Send the evidence to the LLM and parse the verdict.

    Returns: (parsed_verdict_dict, prompt_tokens, completion_tokens, latency_ms)
    """
    user_prompt = build_evaluation_prompt(evidence_json)

    t0 = time.monotonic()
    response = litellm.completion(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        temperature=settings.llm_temperature,
        max_tokens=settings.llm_max_tokens,
        timeout=settings.llm_timeout_seconds,
    )
    latency_ms = int((time.monotonic() - t0) * 1000)

    raw_text = response.choices[0].message.content.strip()
    prompt_tokens = response.usage.prompt_tokens if response.usage else 0
    completion_tokens = response.usage.completion_tokens if response.usage else 0

    if settings.audit_log_enabled:
        logger.info("LLM raw response (%dms): %s", latency_ms, raw_text)

    # Strip markdown fences if the LLM wrapped its response
    if raw_text.startswith("```"):
        raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        raw_text = raw_text.strip()

    parsed = json.loads(raw_text)
    return parsed, prompt_tokens, completion_tokens, latency_ms


# ---------------------------------------------------------------------------
# Verdict construction
# ---------------------------------------------------------------------------


def _build_verdict(escrow_id: str, llm_output: dict) -> Verdict:
    """Convert raw LLM output into a typed Verdict with outcome classification."""
    resolution_str = llm_output.get("resolution", "").lower()
    confidence = float(llm_output.get("confidence", 0.0))
    reasoning = llm_output.get("reasoning", "No reasoning provided")
    factors = llm_output.get("factors", [])

    # Clamp confidence to valid range
    confidence = max(0.0, min(1.0, confidence))

    # Determine resolution
    if resolution_str == "release":
        resolution = Resolution.RELEASE
    elif resolution_str == "refund":
        resolution = Resolution.REFUND
    else:
        # Unrecognized resolution → force escalation
        return Verdict(
            escrow_id=escrow_id,
            outcome=VerdictOutcome.ESCALATE,
            resolution=None,
            confidence=0.0,
            reasoning=f"LLM returned unrecognized resolution: {resolution_str!r}",
            factors=factors,
        )

    # Apply confidence threshold
    if confidence >= settings.auto_resolve_threshold:
        outcome = (
            VerdictOutcome.AUTO_RELEASE
            if resolution == Resolution.RELEASE
            else VerdictOutcome.AUTO_REFUND
        )
    else:
        outcome = VerdictOutcome.ESCALATE

    return Verdict(
        escrow_id=escrow_id,
        outcome=outcome,
        resolution=resolution if outcome != VerdictOutcome.ESCALATE else None,
        confidence=confidence,
        reasoning=reasoning,
        factors=factors,
    )


# ---------------------------------------------------------------------------
# Exchange resolution
# ---------------------------------------------------------------------------


def _execute_resolution(escrow_id: str, resolution: Resolution) -> dict:
    """Call POST /exchange/resolve on the exchange as the operator."""
    url = settings.exchange_url.rstrip("/") + "/exchange/resolve"
    headers = {
        "Authorization": f"Bearer {settings.operator_api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "escrow_id": escrow_id,
        "resolution": resolution.value,
    }

    with httpx.Client(timeout=10.0) as client:
        resp = client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()


def _notify_escalation(verdict: Verdict, evidence_json: str) -> None:
    """Send an escalation notice to the configured webhook (e.g., Slack)."""
    if not settings.escalation_webhook_url:
        logger.warning(
            "Dispute %s escalated but no escalation webhook configured", verdict.escrow_id
        )
        return

    payload = {
        "text": (
            f"⚠️ *Dispute Escalated* — Escrow `{verdict.escrow_id}`\n"
            f"Confidence: {verdict.confidence:.0%} "
            f"(threshold: {settings.auto_resolve_threshold:.0%})\n"
            f"LLM suggestion: {verdict.resolution.value if verdict.resolution else 'none'}\n"
            f"Reasoning: {verdict.reasoning}"
        ),
    }
    try:
        with httpx.Client(timeout=5.0) as client:
            client.post(settings.escalation_webhook_url, json=payload)
    except Exception:
        logger.exception("Failed to send escalation notification")


# ---------------------------------------------------------------------------
# Main mediation entry point
# ---------------------------------------------------------------------------


def mediate(escrow_id: str) -> AuditRecord:
    """Run the full mediation pipeline for a disputed escrow.

    Steps:
    1. Collect evidence from the exchange
    2. Serialize and send to LLM for evaluation
    3. Parse verdict and apply confidence threshold
    4. Auto-resolve if confident, escalate otherwise
    5. Return full audit record

    Returns:
        AuditRecord with complete mediation trace.
    """
    logger.info("Starting mediation for escrow %s", escrow_id)

    # 1. Collect evidence
    evidence = collect_evidence(escrow_id)
    evidence_json = evidence.model_dump_json(indent=2)

    # 2. Evaluate via LLM
    exchange_response = None
    error = None
    prompt_tokens = 0
    completion_tokens = 0
    latency_ms = 0

    try:
        llm_output, prompt_tokens, completion_tokens, latency_ms = _call_llm(evidence_json)
        verdict = _build_verdict(escrow_id, llm_output)
    except json.JSONDecodeError as exc:
        logger.error("Failed to parse LLM response as JSON: %s", exc)
        verdict = Verdict(
            escrow_id=escrow_id,
            outcome=VerdictOutcome.ESCALATE,
            confidence=0.0,
            reasoning=f"LLM response was not valid JSON: {exc}",
        )
        error = str(exc)
    except Exception as exc:
        logger.error("LLM evaluation failed: %s", exc)
        verdict = Verdict(
            escrow_id=escrow_id,
            outcome=VerdictOutcome.ESCALATE,
            confidence=0.0,
            reasoning=f"LLM evaluation failed: {exc}",
        )
        error = str(exc)

    # 3. Execute or escalate
    if verdict.outcome in (VerdictOutcome.AUTO_RELEASE, VerdictOutcome.AUTO_REFUND):
        assert verdict.resolution is not None
        try:
            exchange_response = _execute_resolution(escrow_id, verdict.resolution)
            logger.info(
                "Auto-resolved escrow %s → %s (confidence: %.0f%%)",
                escrow_id,
                verdict.resolution.value,
                verdict.confidence * 100,
            )
        except Exception as exc:
            logger.error("Failed to execute resolution on exchange: %s", exc)
            error = str(exc)
            exchange_response = {"error": str(exc)}
    else:
        logger.info(
            "Escalating escrow %s (confidence: %.0f%%, threshold: %.0f%%)",
            escrow_id,
            verdict.confidence * 100,
            settings.auto_resolve_threshold * 100,
        )
        _notify_escalation(verdict, evidence_json)

    # 4. Build audit record
    audit = AuditRecord(
        escrow_id=escrow_id,
        evidence=evidence,
        verdict=verdict,
        llm_model=settings.llm_model,
        llm_prompt_tokens=prompt_tokens,
        llm_completion_tokens=completion_tokens,
        llm_latency_ms=latency_ms,
        exchange_response=exchange_response,
        error=error,
        created_at=datetime.now(timezone.utc),
    )

    if settings.audit_log_enabled:
        logger.info("Audit record: %s", audit.model_dump_json(indent=2))

    return audit
