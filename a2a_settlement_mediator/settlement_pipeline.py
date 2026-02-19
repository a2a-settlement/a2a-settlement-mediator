"""SEC 17a-4 WORM-compliant settlement orchestration pipeline.

This is the core engine that wires together:
1. Ingestion of hashed negotiation transcripts + AP2 mandates
2. LLM arbitration via LiteLLM
3. Pre-Dispute Attestation Payload construction
4. RFC 3161 timestamping via a Time Stamp Authority
5. Append to an immutable Merkle Tree with mathematical verification
6. Final cryptographic proof assembly

Hard-fail semantics: if the Merkle append fails verification or the TSA
times out, the entire settlement is rejected.  No partial results escape.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone

import litellm

from a2a_settlement_mediator.arbitration_prompts import (
    ARBITRATION_SYSTEM_PROMPT,
    build_arbitration_prompt,
)
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.merkle import MerkleTree
from a2a_settlement_mediator.tsa_client import (
    RFC3161Client,
    TSAClientError,
    TSATimeoutError,
)
from a2a_settlement_mediator.worm_schemas import (
    AP2Mandate,
    ArbitrationDecision,
    ArbitrationRequest,
    ArbitrationVerdict,
    MerkleAppendResult,
    MerkleLeaf,
    MerkleProof,
    NegotiationTranscript,
    PreDisputeAttestationPayload,
    SettlementProof,
    SettlementResult,
    SettlementStage,
    TimestampToken,
)

logger = logging.getLogger(__name__)

litellm.suppress_debug_info = True

# Module-level Merkle Tree — append-only, survives across pipeline invocations.
# In production this would be backed by persistent storage; the in-memory
# tree satisfies WORM semantics within a single process lifetime.
_merkle_tree = MerkleTree()


def get_merkle_tree() -> MerkleTree:
    """Return the module-level Merkle Tree (useful for inspection/testing)."""
    return _merkle_tree


class SettlementHardFail(Exception):
    """Raised when the pipeline must abort with no partial result."""


# ---------------------------------------------------------------------------
# Stage 1 — LLM arbitration
# ---------------------------------------------------------------------------


def _call_arbitration_llm(request: ArbitrationRequest) -> ArbitrationVerdict:
    """Send the arbitration request to LiteLLM and parse the verdict."""
    mandates_json = json.dumps(
        [m.model_dump(mode="json") for m in request.mandates],
        indent=2,
    )
    user_prompt = build_arbitration_prompt(
        transcript_hash=request.transcript.transcript_hash,
        source_service=request.transcript.source_service,
        session_id=request.transcript.session_id,
        mandates_json=mandates_json,
        escrow_id=request.escrow_id,
    )

    t0 = time.monotonic()
    response = litellm.completion(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": ARBITRATION_SYSTEM_PROMPT},
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
        logger.info("Arbitration LLM response (%dms): %s", latency_ms, raw_text)

    # Strip markdown fences if present
    if raw_text.startswith("```"):
        raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        raw_text = raw_text.strip()

    parsed = json.loads(raw_text)

    decision_str = parsed.get("decision", "").upper()
    if decision_str not in ("APPROVED", "REJECTED"):
        raise ValueError(f"LLM returned unrecognized decision: {decision_str!r}")

    confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0.0))))

    # Low confidence forces REJECTED regardless of LLM output
    if confidence < 0.5:
        decision_str = "REJECTED"

    return ArbitrationVerdict(
        decision=ArbitrationDecision(decision_str),
        confidence=confidence,
        reasoning=parsed.get("reasoning", "No reasoning provided"),
        factors=parsed.get("factors", []),
        mandate_compliance=parsed.get("mandate_compliance", {}),
        llm_model=settings.llm_model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# Stage 2 — Attestation payload construction
# ---------------------------------------------------------------------------


def _build_attestation_payload(
    transcript: NegotiationTranscript,
    mandates: list[AP2Mandate],
    verdict: ArbitrationVerdict,
) -> PreDisputeAttestationPayload:
    """Construct the immutable Pre-Dispute Attestation Payload."""
    payload_hash = PreDisputeAttestationPayload.compute_hash(transcript, mandates, verdict)

    return PreDisputeAttestationPayload(
        transcript=transcript,
        mandates=mandates,
        verdict=verdict,
        payload_hash=payload_hash,
    )


# ---------------------------------------------------------------------------
# Stage 3 — RFC 3161 timestamping
# ---------------------------------------------------------------------------


def _request_timestamp(payload_hash_hex: str) -> TimestampToken:
    """Request an RFC 3161 timestamp for the attestation payload hash.

    Raises SettlementHardFail on timeout or TSA error.
    """
    tsa = RFC3161Client(
        tsa_url=settings.tsa_url,
        timeout_seconds=settings.tsa_timeout_seconds,
    )

    payload_hash_bytes = bytes.fromhex(payload_hash_hex)

    try:
        return tsa.request_timestamp(payload_hash_bytes)
    except TSATimeoutError as exc:
        raise SettlementHardFail(
            f"HARD FAIL: TSA server timed out — settlement cannot proceed. {exc}"
        ) from exc
    except TSAClientError as exc:
        raise SettlementHardFail(
            f"HARD FAIL: TSA request failed — settlement cannot proceed. {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Stage 4 — Merkle Tree append + verification
# ---------------------------------------------------------------------------


def _append_to_merkle_tree(timestamped_payload: bytes) -> MerkleAppendResult:
    """Append the timestamped payload to the Merkle Tree and verify the proof.

    The Merkle append and proof generation happen atomically under a lock.
    After the append, the proof is independently verified against the new
    root hash.  If verification fails, the settlement hard-fails.

    Raises SettlementHardFail if the proof does not verify.
    """
    data_hash = hashlib.sha256(timestamped_payload).hexdigest()

    try:
        leaf_index, leaf_hash, siblings, directions, root_hash = (
            _merkle_tree.append_and_prove(timestamped_payload)
        )
    except Exception as exc:
        raise SettlementHardFail(
            f"HARD FAIL: Merkle Tree append failed — settlement cannot proceed. {exc}"
        ) from exc

    verified = MerkleTree.verify_proof(leaf_hash, siblings, directions, root_hash)

    if not verified:
        raise SettlementHardFail(
            "HARD FAIL: Merkle Tree proof verification failed — "
            "the append was NOT mathematically successful. "
            f"leaf_index={leaf_index} root={root_hash.hex()}"
        )

    logger.info(
        "Merkle append verified: leaf=%d root=%s tree_size=%d",
        leaf_index,
        root_hash.hex(),
        _merkle_tree.size,
    )

    return MerkleAppendResult(
        leaf=MerkleLeaf(
            leaf_index=leaf_index,
            leaf_hash=leaf_hash.hex(),
            data_hash=data_hash,
        ),
        proof=MerkleProof(
            leaf_index=leaf_index,
            leaf_hash=leaf_hash.hex(),
            siblings=[s.hex() for s in siblings],
            directions=directions,
            root_hash=root_hash.hex(),
            tree_size=_merkle_tree.size,
        ),
        root_hash=root_hash.hex(),
        tree_size=_merkle_tree.size,
        verified=True,
    )


# ---------------------------------------------------------------------------
# Stage 5 — Settlement proof assembly
# ---------------------------------------------------------------------------


def _assemble_proof(
    attestation: PreDisputeAttestationPayload,
    timestamp: TimestampToken,
    merkle_result: MerkleAppendResult,
) -> SettlementProof:
    """Assemble the final cryptographic proof tying all components together."""
    binding_input = (
        f"{attestation.payload_hash}:"
        f"{timestamp.message_hash}:"
        f"{merkle_result.root_hash}"
    )
    settlement_hash = hashlib.sha256(binding_input.encode("utf-8")).hexdigest()

    return SettlementProof(
        attestation_payload=attestation,
        timestamp=timestamp,
        merkle_result=merkle_result,
        settlement_hash=settlement_hash,
    )


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------


def settle(
    transcript: NegotiationTranscript,
    mandates: list[AP2Mandate],
    escrow_id: str | None = None,
) -> SettlementResult:
    """Run the full SEC 17a-4 WORM-compliant settlement pipeline.

    Pipeline stages:
        1. ARBITRATION — Call LiteLLM with transcript hash + AP2 mandates
        2. ATTESTATION — If APPROVED, build the Pre-Dispute Attestation Payload
        3. TIMESTAMPING — Request an RFC 3161 timestamp from the TSA
        4. MERKLE_APPEND — Append timestamped payload to the Merkle Tree
        5. MERKLE_VERIFY — Verify the Merkle proof is mathematically correct
        6. COMPLETE — Assemble and return the full cryptographic proof

    Hard-fail semantics:
        - TSA timeout → settlement fails, no proof is returned
        - Merkle append failure → settlement fails, no proof is returned
        - Merkle verification failure → settlement fails, no proof is returned

    Returns:
        SettlementResult with success=True and a full SettlementProof,
        or success=False with error details and the stage where failure occurred.
    """
    started_at = datetime.now(timezone.utc)
    stage = SettlementStage.INGESTION

    logger.info(
        "Settlement pipeline started — transcript_hash=%s mandates=%d escrow=%s",
        transcript.transcript_hash[:16] + "...",
        len(mandates),
        escrow_id or "none",
    )

    request = ArbitrationRequest(
        transcript=transcript,
        mandates=mandates,
        escrow_id=escrow_id,
    )

    # --- Stage 1: Arbitration ---
    stage = SettlementStage.ARBITRATION
    try:
        verdict = _call_arbitration_llm(request)
    except json.JSONDecodeError as exc:
        logger.error("Arbitration LLM returned invalid JSON: %s", exc)
        return SettlementResult(
            success=False,
            error=f"Arbitration LLM returned invalid JSON: {exc}",
            stage_reached=stage,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )
    except Exception as exc:
        logger.error("Arbitration LLM call failed: %s", exc)
        return SettlementResult(
            success=False,
            error=f"Arbitration failed: {exc}",
            stage_reached=stage,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    logger.info(
        "Arbitration verdict: %s (confidence=%.2f)",
        verdict.decision.value,
        verdict.confidence,
    )

    # Gate: only APPROVED proceeds
    if verdict.decision != ArbitrationDecision.APPROVED:
        return SettlementResult(
            success=False,
            error=f"Arbitration REJECTED: {verdict.reasoning}",
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    # --- Stage 2: Build Attestation Payload ---
    stage = SettlementStage.ATTESTATION_BUILD
    try:
        attestation = _build_attestation_payload(transcript, mandates, verdict)
    except Exception as exc:
        logger.error("Attestation payload construction failed: %s", exc)
        return SettlementResult(
            success=False,
            error=f"Attestation construction failed: {exc}",
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    logger.info("Attestation payload built — hash=%s", attestation.payload_hash[:16] + "...")

    # --- Stage 3: RFC 3161 Timestamp ---
    stage = SettlementStage.TIMESTAMPING
    try:
        timestamp = _request_timestamp(attestation.payload_hash)
    except SettlementHardFail as exc:
        logger.error("Settlement hard-fail at timestamping: %s", exc)
        return SettlementResult(
            success=False,
            error=str(exc),
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    logger.info("RFC 3161 timestamp obtained from %s", timestamp.tsa_url)

    # --- Stage 4 + 5: Merkle Tree Append + Verify ---
    stage = SettlementStage.MERKLE_APPEND
    timestamped_payload_json = json.dumps(
        {
            "attestation": attestation.model_dump(mode="json"),
            "timestamp": timestamp.model_dump(mode="json"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    timestamped_payload_bytes = timestamped_payload_json.encode("utf-8")

    try:
        merkle_result = _append_to_merkle_tree(timestamped_payload_bytes)
    except SettlementHardFail as exc:
        logger.error("Settlement hard-fail at Merkle append: %s", exc)
        return SettlementResult(
            success=False,
            error=str(exc),
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    stage = SettlementStage.MERKLE_VERIFY
    # Verification already happened inside _append_to_merkle_tree;
    # if we reach here, the proof is valid.

    # --- Stage 6: Assemble Final Proof ---
    stage = SettlementStage.COMPLETE
    proof = _assemble_proof(attestation, timestamp, merkle_result)

    logger.info(
        "Settlement complete — settlement_hash=%s merkle_root=%s tree_size=%d",
        proof.settlement_hash[:16] + "...",
        merkle_result.root_hash[:16] + "...",
        merkle_result.tree_size,
    )

    return SettlementResult(
        success=True,
        proof=proof,
        stage_reached=stage,
        arbitration_verdict=verdict,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
    )
