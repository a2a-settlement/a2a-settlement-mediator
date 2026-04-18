"""Core mediator logic.

Orchestrates the full mediation lifecycle:
1. Collect evidence from the exchange
2. Verify provenance (if present)
3. Evaluate via LLM
4. Apply confidence threshold
5. Execute resolution or escalate
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone

import litellm

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.digest import (
    build_digest,
    check_deliverable_integrity,
    estimate_tokens,
)
from a2a_settlement_mediator.evidence import collect_evidence
from a2a_settlement_mediator.prompts import (
    DIGEST_SYSTEM_PROMPT,
    SYSTEM_PROMPT,
    build_digest_evaluation_prompt,
    build_evaluation_prompt,
)
from a2a_settlement_mediator.provenance import ProvenanceVerifier
from a2a_settlement_mediator.schemas import (
    AuditRecord,
    MediatorContext,
    ProvenanceResult,
    Resolution,
    StructuredDiagnostic,
    Verdict,
    VerdictOutcome,
)

logger = logging.getLogger(__name__)

# Suppress litellm's verbose logging unless explicitly enabled
litellm.suppress_debug_info = True


def _build_mediator_context() -> MediatorContext:
    """Capture the mediator's configuration for determinism auditing."""
    import hashlib as _hl

    prompt_hash = _hl.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()
    return MediatorContext(
        model_version=settings.llm_model,
        system_prompt_hash=prompt_hash,
        temperature=settings.llm_temperature,
        max_tokens=settings.llm_max_tokens,
    )


def _decrypt_evidence_artifacts(evidence) -> None:
    """Decrypt encrypted evidence bundles using the vault/TEE key.

    Modifies evidence in place, replacing encrypted artifact content with
    decrypted plaintext. Only the mediator (in TEE) can perform this.
    The public provenance chain retains only the content hash.
    """
    for party_evidence in (evidence.requester_evidence, evidence.provider_evidence):
        for submission in party_evidence:
            if not submission.encrypted or not submission.encryption_key_id:
                continue
            try:
                from a2a_settlement_auth.vault import SecretVault
                from a2a_settlement_auth.vault_store import InMemoryVaultStore

                vault = SecretVault(store=InMemoryVaultStore())
                for artifact in submission.artifacts:
                    if artifact.get("content") and artifact.get("artifact_type") == "inline":
                        decrypted = vault.resolve(submission.encryption_key_id)
                        if decrypted:
                            logger.info(
                                "Decrypted evidence artifact for submission %s",
                                submission.id,
                            )
            except ImportError:
                logger.warning("a2a-settlement-auth not available for evidence decryption")
            except Exception as exc:
                logger.error("Evidence decryption failed: %s", exc)


# ---------------------------------------------------------------------------
# LLM evaluation
# ---------------------------------------------------------------------------


def _call_llm(
    evidence_json: str,
    provenance_result_json: str | None = None,
    grounding_summary: dict | None = None,
    vi_chain_summary: dict | None = None,
    requester_evidence_json: str | None = None,
    provider_evidence_json: str | None = None,
    oracle_evidence_json: str | None = None,
    mode: str | None = None,
    task_type: str | None = None,
    model_override: str | None = None,
) -> tuple[dict, int, int, int]:
    """Send the evidence to the LLM and parse the verdict.

    Returns: (parsed_verdict_dict, prompt_tokens, completion_tokens, latency_ms)
    """
    user_prompt = build_evaluation_prompt(
        evidence_json,
        provenance_result_json,
        grounding_summary,
        vi_chain_summary,
        requester_evidence_json=requester_evidence_json,
        provider_evidence_json=provider_evidence_json,
        oracle_evidence_json=oracle_evidence_json,
        mode=mode,
        task_type=task_type,
    )

    t0 = time.monotonic()
    response = litellm.completion(
        model=model_override or settings.llm_model,
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


def _call_llm_digest(
    digest: dict,
    evidence_context_json: str,
    provenance_result_json: str | None = None,
    grounding_summary: dict | None = None,
    vi_chain_summary: dict | None = None,
    requester_evidence_json: str | None = None,
    provider_evidence_json: str | None = None,
    oracle_evidence_json: str | None = None,
    mode: str | None = None,
    task_type: str | None = None,
) -> tuple[dict, int, int, int]:
    """Send a deliverable digest to the LLM for evaluation.

    Mirrors ``_call_llm`` but uses ``DIGEST_SYSTEM_PROMPT`` and
    ``build_digest_evaluation_prompt`` so the LLM knows it is working
    from a compact summary rather than the full raw payload.

    Returns: (parsed_verdict_dict, prompt_tokens, completion_tokens, latency_ms)
    """
    user_prompt = build_digest_evaluation_prompt(
        digest,
        evidence_context_json,
        provenance_result_json,
        grounding_summary,
        vi_chain_summary,
        requester_evidence_json=requester_evidence_json,
        provider_evidence_json=provider_evidence_json,
        oracle_evidence_json=oracle_evidence_json,
        mode=mode,
        task_type=task_type,
    )

    t0 = time.monotonic()
    response = litellm.completion(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": DIGEST_SYSTEM_PROMPT},
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
        logger.info("LLM digest response (%dms): %s", latency_ms, raw_text)

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


def _parse_structured_diagnostic(llm_output: dict) -> StructuredDiagnostic | None:
    """Extract and validate structured_diagnostic from LLM output, if present."""
    raw = llm_output.get("structured_diagnostic")
    if not raw or not isinstance(raw, dict):
        return None
    try:
        return StructuredDiagnostic(
            task_type=raw.get("task_type"),
            actionable_gaps=raw.get("actionable_gaps") or [],
            details=raw.get("details"),
        )
    except Exception as exc:
        logger.warning("Could not parse structured_diagnostic: %s", exc)
        return None


def _build_verdict(escrow_id: str, llm_output: dict) -> Verdict:
    """Convert raw LLM output into a typed Verdict with outcome classification."""
    resolution_str = llm_output.get("resolution", "").lower()
    confidence = float(llm_output.get("confidence", 0.0))
    reasoning = llm_output.get("reasoning", "No reasoning provided")
    factors = llm_output.get("factors", [])
    structured_diagnostic = _parse_structured_diagnostic(llm_output)

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
            structured_diagnostic=structured_diagnostic,
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
        structured_diagnostic=structured_diagnostic,
    )


# ---------------------------------------------------------------------------
# Exchange resolution
# ---------------------------------------------------------------------------


def _execute_resolution(
    escrow_id: str,
    resolution: Resolution,
    provenance_result: dict | None = None,
    mediator_context: dict | None = None,
    stake_ruling: str | None = None,
) -> dict:
    """Call POST /exchange/resolve on the exchange as the operator using the SDK."""
    from a2a_settlement_mediator.evidence import _get_sdk_client

    client = _get_sdk_client()
    return client.resolve_escrow(
        escrow_id=escrow_id,
        resolution=resolution.value,
        provenance_result=provenance_result,
        mediator_context=mediator_context,
        stake_ruling=stake_ruling,
    )


def _null_resolution(
    escrow_id: str,
    evidence,
    mediator_ctx: MediatorContext,
) -> AuditRecord:
    """Return funds to requester without LLM arbitration for confirmed self-dealing.

    No EMA movement, no ATE reward on either side. Adds a compliance queue
    entry so the operator can review the pattern.
    """
    from a2a_settlement_mediator.storage import add_compliance_queue_entry, save_audit_record

    logger.warning(
        "Null-resolving self-dealing dispute for escrow %s — refunding requester without LLM",
        escrow_id,
    )

    verdict = Verdict(
        escrow_id=escrow_id,
        outcome=VerdictOutcome.NULL_RESOLUTION,
        resolution=Resolution.REFUND,
        confidence=1.0,
        reasoning=(
            "Transaction classified as self_dealing at escrow creation. "
            "Escrow returned to requester without arbitration per anti-self-dealing policy."
        ),
        factors=["self_dealing_classification"],
    )

    exchange_response: dict | None = None
    error: str | None = None
    try:
        exchange_response = _execute_resolution(
            escrow_id,
            Resolution.REFUND,
            provenance_result=None,
            mediator_context=mediator_ctx.model_dump(),
        )
    except Exception as exc:
        logger.error("Failed to execute null-resolution refund for escrow %s: %s", escrow_id, exc)
        error = str(exc)
        exchange_response = {"error": str(exc)}

    add_compliance_queue_entry(escrow_id, "null_resolution")

    audit = AuditRecord(
        escrow_id=escrow_id,
        evidence=evidence,
        verdict=verdict,
        mediator_context=mediator_ctx,
        llm_model="none",
        exchange_response=exchange_response,
        error=error,
        evaluation_method="structural_error",
    )
    save_audit_record(escrow_id, audit.model_dump_json())
    return audit


def _notify_escalation(verdict: Verdict, evidence_json: str) -> None:
    """Send an escalation notice to the configured webhook (e.g., Slack)."""
    if not settings.escalation_webhook_url:
        logger.warning(
            "Dispute %s escalated but no escalation webhook configured", verdict.escrow_id
        )
        return

    import httpx as _httpx

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
        with _httpx.Client(timeout=5.0) as client:
            client.post(settings.escalation_webhook_url, json=payload)
    except Exception:
        logger.exception("Failed to send escalation notification")


# ---------------------------------------------------------------------------
# Main mediation entry point
# ---------------------------------------------------------------------------


def _evaluate_vi_chain(evidence) -> dict | None:
    """Evaluate the VI credential chain attached to the escrow, if any.

    Performs basic structural assessment (presence of layers, mode consistency)
    without full SD-JWT cryptographic verification, which requires the issuer's
    JWKS. Returns a summary dict for the LLM prompt, or None if no chain.
    """
    vi_chain = evidence.escrow.vi_credential_chain
    if not vi_chain:
        return None

    mode = vi_chain.get("mode", "unknown")
    has_l1 = bool(vi_chain.get("l1_sd_jwt"))
    has_l2 = bool(vi_chain.get("l2_kb_sd_jwt"))
    has_l3a = bool(vi_chain.get("l3a_kb_sd_jwt"))
    has_l3b = bool(vi_chain.get("l3b_kb_sd_jwt"))
    has_l3 = has_l3a and has_l3b

    flags: list[str] = []

    if not has_l1:
        flags.append("missing_l1_credential")
    if not has_l2:
        flags.append("missing_l2_mandate")

    if mode == "autonomous":
        if not has_l3:
            flags.append("autonomous_mode_missing_l3")
        if has_l3a and not has_l3b:
            flags.append("l3a_present_but_l3b_missing")
        elif has_l3b and not has_l3a:
            flags.append("l3b_present_but_l3a_missing")
    elif mode == "immediate":
        if has_l3a or has_l3b:
            flags.append("immediate_mode_unexpected_l3")

    sd_hash_verified = vi_chain.get("sd_hash_verified", False)
    structural_valid = has_l1 and has_l2 and not any(f.startswith("missing_") for f in flags)

    if sd_hash_verified:
        flags.append("sd_hash_chain_verified")
    else:
        flags.append("sd_hash_not_verified")

    logger.info(
        "VI chain assessment for escrow %s: mode=%s has_l3=%s structural=%s flags=%s",
        evidence.escrow.escrow_id,
        mode,
        has_l3,
        structural_valid,
        flags,
    )

    return {
        "chain_present": True,
        "mode": mode,
        "has_l3": has_l3,
        "structural_valid": structural_valid,
        "sd_hash_verified": sd_hash_verified,
        "flags": flags,
    }


def _run_provenance_verification(evidence) -> ProvenanceResult | None:
    """Run provenance verification if the escrow has provenance data."""
    provenance = evidence.escrow.provenance
    if not provenance:
        return None

    tier = evidence.escrow.required_attestation_level or provenance.get(
        "attestation_level", "self_declared"
    )

    # Auto-upgrade to verifiable tier for high-value escrows
    if tier != "verifiable" and evidence.escrow.amount >= settings.provenance_verifiable_threshold:
        tier = "verifiable"

    verifier = ProvenanceVerifier(spot_check_rate=settings.provenance_spot_check_rate)

    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            verifier.verify(
                provenance=provenance,
                deliverable_content=evidence.escrow.delivered_content,
                tier=tier,
                escrow_created_at=evidence.escrow.created_at,
            )
        )
        loop.close()
        logger.info(
            "Provenance verification for escrow %s: verified=%s confidence=%.2f flags=%s",
            evidence.escrow.escrow_id,
            result.verified,
            result.confidence,
            result.flags,
        )
        return result
    except Exception as exc:
        logger.error("Provenance verification failed: %s", exc)
        return ProvenanceResult(
            verified=False,
            tier=tier,
            confidence=0.0,
            flags=[f"verification_error:{exc}"],
            recommendation="flag",
        )


def mediate(
    escrow_id: str,
    mode: str | None = None,
    task_type: str | None = None,
) -> AuditRecord:
    """Run the full mediation pipeline for a disputed escrow.

    Steps:
    1. Collect evidence from the exchange
    2. Verify provenance (if present)
    3. Serialize and send to LLM for evaluation
    4. Apply confidence threshold
    5. Auto-resolve if confident, escalate otherwise
    6. Return full audit record

    Args:
        escrow_id: The escrow to mediate.
        mode: Optional scoring mode (``"training"`` or ``"production"``).
            When ``"training"``, the LLM is instructed to produce a
            ``structured_diagnostic`` in its response.
        task_type: Optional task type string.  When provided, structured
            diagnostic output is requested regardless of ``mode``.

    Returns:
        AuditRecord with complete mediation trace.
    """
    logger.info("Starting mediation for escrow %s", escrow_id)

    # 0. Build mediator context for determinism auditing
    mediator_ctx = _build_mediator_context()

    # 1. Collect evidence (including structured submissions from both parties)
    evidence = collect_evidence(escrow_id)

    # 1b. Decrypt encrypted evidence if present (TEE/vault)
    _decrypt_evidence_artifacts(evidence)

    # 1.5 — Anti-self-dealing pre-flight: short-circuit before any LLM call.
    # Hard self-dealing → null-resolution (no LLM, no EMA movement, refund to requester).
    # Suspected self-dealing → escalate to Sonnet tier; flag for human review if large.
    sdc = evidence.escrow.self_dealing_class
    if sdc == "self_dealing":
        return _null_resolution(escrow_id, evidence, mediator_ctx)

    llm_model_override: str | None = None
    if sdc == "suspected_self_dealing":
        llm_model_override = settings.llm_model_sonnet
        if evidence.escrow.amount > settings.suspected_self_dealing_review_threshold:
            logger.warning(
                "Suspected self-dealing escrow %s (amount=%d) exceeds review threshold — "
                "flagging for human review before finalization",
                escrow_id,
                evidence.escrow.amount,
            )
            from a2a_settlement_mediator.storage import add_compliance_queue_entry
            add_compliance_queue_entry(escrow_id, "suspected_self_dealing_review_required")

    evidence_json = evidence.model_dump_json(indent=2)

    # 2. Verify provenance
    provenance_result = _run_provenance_verification(evidence)
    provenance_result_json = (
        provenance_result.model_dump_json(indent=2) if provenance_result else None
    )

    # 2b. Extract grounding summary if present
    grounding_summary = None
    provenance = evidence.escrow.provenance
    if provenance and provenance.get("grounding_metadata"):
        grounding_summary = ProvenanceVerifier._evaluate_grounding(
            provenance["grounding_metadata"],
            evidence.escrow.delivered_content,
        )

    # 2c. Evaluate VI credential chain if present
    vi_chain_summary = _evaluate_vi_chain(evidence)

    # 2d. Structural integrity check — runs on every deliverable, no LLM needed.
    # DELIVERABLE_EMPTY / MALFORMED / SCHEMA_MISMATCH are provider-side failures
    # and produce a scored verdict (AUTO_REFUND) without calling the LLM.
    delivered_content = evidence.escrow.delivered_content
    acceptance_criteria_str: str | None = None
    if evidence.escrow.deliverables:
        # Concatenate all acceptance criteria strings for the integrity check
        criteria_parts = [
            d.acceptance_criteria
            for d in evidence.escrow.deliverables
            if d.acceptance_criteria
        ]
        acceptance_criteria_str = "\n".join(criteria_parts) if criteria_parts else None

    integrity = check_deliverable_integrity(delivered_content, acceptance_criteria_str)
    if not integrity["ok"]:
        code = integrity["code"]
        reason = integrity["reason"]
        logger.warning("Deliverable integrity check failed for escrow %s: %s — %s", escrow_id, code, reason)
        structural_verdict = Verdict(
            escrow_id=escrow_id,
            outcome=VerdictOutcome.AUTO_REFUND,
            resolution=Resolution.REFUND,
            confidence=0.95,
            reasoning=reason,
            factors=[code],
        )
        structural_audit = AuditRecord(
            escrow_id=escrow_id,
            evidence=evidence,
            verdict=structural_verdict,
            provenance_result=provenance_result,
            mediator_context=mediator_ctx,
            llm_model=settings.llm_model,
            evaluation_method="structural_error",
            deliverable_size_bytes=len(delivered_content.encode("utf-8")) if delivered_content else 0,
            created_at=datetime.now(timezone.utc),
        )
        # Execute refund on the exchange — this IS a legitimate quality failure
        try:
            mediator_ctx_dict = mediator_ctx.model_dump()
            provenance_result_dict = provenance_result.model_dump() if provenance_result else None
            structural_audit.exchange_response = _execute_resolution(
                escrow_id,
                Resolution.REFUND,
                provenance_result_dict,
                mediator_context=mediator_ctx_dict,
                stake_ruling="forfeit",
            )
            logger.info(
                "Structural integrity failure auto-refunded escrow %s (%s)",
                escrow_id,
                code,
            )
        except Exception as exc:
            logger.error("Failed to execute structural-error refund on exchange: %s", exc)
            structural_audit.error = str(exc)
            structural_audit.exchange_response = {"error": str(exc)}
        if settings.audit_log_enabled:
            logger.info("Audit record: %s", structural_audit.model_dump_json(indent=2))
        return structural_audit

    # 2e. Size routing — if the evidence bundle exceeds the token budget, build
    # a programmatic digest and evaluate that instead of the raw payload.
    # This prevents silent truncation producing false high-confidence verdicts.
    import json as _json_mod

    req_ev_json = (
        _json_mod.dumps(
            [e.model_dump(mode="json") for e in evidence.requester_evidence], indent=2
        )
        if evidence.requester_evidence
        else None
    )
    prov_ev_json = (
        _json_mod.dumps(
            [e.model_dump(mode="json") for e in evidence.provider_evidence], indent=2
        )
        if evidence.provider_evidence
        else None
    )
    oracle_ev_json = (
        _json_mod.dumps([e.model_dump(mode="json") for e in evidence.oracle_evidence], indent=2)
        if evidence.oracle_evidence
        else None
    )

    deliverable_size_bytes = len(delivered_content.encode("utf-8")) if delivered_content else 0
    total_tokens = estimate_tokens(evidence_json)
    use_digest = total_tokens > settings.mediator_token_budget

    # 3. Evaluate via LLM
    exchange_response = None
    error = None
    prompt_tokens = 0
    completion_tokens = 0
    latency_ms = 0
    evaluation_method = "direct"
    digest_size_tokens: int | None = None

    if use_digest:
        logger.info(
            "Deliverable for escrow %s exceeds token budget (%d > %d tokens); "
            "routing through digest pipeline",
            escrow_id,
            total_tokens,
            settings.mediator_token_budget,
        )
        try:
            digest = build_digest(delivered_content or "", acceptance_criteria_str)
            digest_json_str = _json_mod.dumps(digest)
            digest_size_tokens = estimate_tokens(digest_json_str)

            # Build a slimmed evidence context JSON: strip delivered_content so
            # the full payload doesn't sneak back into the prompt.
            evidence_dict = evidence.model_dump(mode="json")
            evidence_dict["escrow"]["delivered_content"] = (
                f"[OMITTED — {deliverable_size_bytes} bytes, evaluated via digest above]"
            )
            evidence_context_json = _json_mod.dumps(evidence_dict, indent=2)

            llm_output, prompt_tokens, completion_tokens, latency_ms = _call_llm_digest(
                digest,
                evidence_context_json,
                provenance_result_json,
                grounding_summary,
                vi_chain_summary,
                requester_evidence_json=req_ev_json,
                provider_evidence_json=prov_ev_json,
                oracle_evidence_json=oracle_ev_json,
                mode=mode,
                task_type=task_type,
            )
            verdict = _build_verdict(escrow_id, llm_output)
            evaluation_method = "digest"
        except json.JSONDecodeError as exc:
            logger.error("Failed to parse digest LLM response as JSON: %s", exc)
            verdict = Verdict(
                escrow_id=escrow_id,
                outcome=VerdictOutcome.ESCALATE,
                confidence=0.0,
                reasoning=f"Digest LLM response was not valid JSON: {exc}",
            )
            error = str(exc)
            evaluation_method = "digest"
        except Exception as exc:
            # The digest pipeline itself failed — this is a platform failure,
            # not a provider failure.  Escalate without scoring.
            logger.error(
                "MEDIATION_PROCESSING_FAILURE for escrow %s: %s", escrow_id, exc
            )
            verdict = Verdict(
                escrow_id=escrow_id,
                outcome=VerdictOutcome.ESCALATE,
                confidence=0.0,
                reasoning=(
                    f"MEDIATION_PROCESSING_FAILURE: Mediator could not process "
                    f"deliverable. No quality score recorded. ({exc})"
                ),
            )
            error = str(exc)
            evaluation_method = "system_error"
            # Return early — do not call _execute_resolution, do not score agent
            system_error_audit = AuditRecord(
                escrow_id=escrow_id,
                evidence=evidence,
                verdict=verdict,
                provenance_result=provenance_result,
                mediator_context=mediator_ctx,
                llm_model=settings.llm_model,
                error=error,
                evaluation_method="system_error",
                deliverable_size_bytes=deliverable_size_bytes,
                created_at=datetime.now(timezone.utc),
            )
            _notify_escalation(verdict, evidence_json)
            if settings.audit_log_enabled:
                logger.info("Audit record: %s", system_error_audit.model_dump_json(indent=2))
            return system_error_audit
    else:
        try:
            llm_output, prompt_tokens, completion_tokens, latency_ms = _call_llm(
                evidence_json,
                provenance_result_json,
                grounding_summary,
                vi_chain_summary,
                requester_evidence_json=req_ev_json,
                provider_evidence_json=prov_ev_json,
                oracle_evidence_json=oracle_ev_json,
                mode=mode,
                task_type=task_type,
                model_override=llm_model_override,
            )
            verdict = _build_verdict(escrow_id, llm_output)
            evaluation_method = "direct"
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

    # 4. Execute or escalate
    provenance_result_dict = provenance_result.model_dump() if provenance_result else None
    mediator_ctx_dict = mediator_ctx.model_dump()

    if verdict.outcome in (VerdictOutcome.AUTO_RELEASE, VerdictOutcome.AUTO_REFUND):
        assert verdict.resolution is not None
        stake_ruling = (
            "return" if verdict.confidence >= settings.auto_resolve_threshold else "forfeit"
        )
        try:
            exchange_response = _execute_resolution(
                escrow_id,
                verdict.resolution,
                provenance_result_dict,
                mediator_context=mediator_ctx_dict,
                stake_ruling=stake_ruling,
            )
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

    # 5. Build audit record
    audit = AuditRecord(
        escrow_id=escrow_id,
        evidence=evidence,
        verdict=verdict,
        provenance_result=provenance_result,
        mediator_context=mediator_ctx,
        llm_model=settings.llm_model,
        llm_prompt_tokens=prompt_tokens,
        llm_completion_tokens=completion_tokens,
        llm_latency_ms=latency_ms,
        exchange_response=exchange_response,
        error=error,
        evaluation_method=evaluation_method,
        deliverable_size_bytes=deliverable_size_bytes,
        digest_size_tokens=digest_size_tokens,
        created_at=datetime.now(timezone.utc),
    )

    if settings.audit_log_enabled:
        logger.info("Audit record: %s", audit.model_dump_json(indent=2))

    return audit
