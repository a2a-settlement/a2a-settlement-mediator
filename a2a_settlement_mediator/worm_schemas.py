"""Pydantic models for the SEC 17a-4 WORM compliance pipeline.

Covers the full lifecycle: negotiation transcript ingestion, AP2 mandate
evaluation, arbitration decisions, pre-dispute attestation payloads,
RFC 3161 timestamps, Merkle Tree proofs, and final settlement results.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class ArbitrationDecision(str, Enum):
    """Outcome of the LLM arbitration on a negotiation transcript."""

    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class SettlementStage(str, Enum):
    """Tracks how far the pipeline progressed before completion or failure."""

    INGESTION = "ingestion"
    ARBITRATION = "arbitration"
    ATTESTATION_BUILD = "attestation_build"
    TIMESTAMPING = "timestamping"
    MERKLE_APPEND = "merkle_append"
    MERKLE_VERIFY = "merkle_verify"
    COMPLETE = "complete"


# ---------------------------------------------------------------------------
# Input models — ingested from crewai service
# ---------------------------------------------------------------------------


class NegotiationTranscript(BaseModel):
    """Hashed negotiation transcript received from the crewai service."""

    transcript_hash: str = Field(
        ..., description="SHA-256 hex digest of the original negotiation transcript"
    )
    source_service: str = Field(default="crewai", description="Originating service identifier")
    session_id: str | None = Field(default=None, description="CrewAI session identifier")
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AP2Mandate(BaseModel):
    """A proposed AP2 (Agent Protocol Phase 2) mandate for evaluation."""

    mandate_id: str
    description: str
    conditions: list[str] = Field(default_factory=list)
    severity: str = Field(default="standard", description="standard | critical | advisory")
    effective_date: datetime | None = None


# ---------------------------------------------------------------------------
# Arbitration models — LLM evaluation
# ---------------------------------------------------------------------------


class ArbitrationRequest(BaseModel):
    """Bundle submitted to the LLM for arbitration."""

    transcript: NegotiationTranscript
    mandates: list[AP2Mandate]
    escrow_id: str | None = None


class ArbitrationVerdict(BaseModel):
    """Structured LLM decision on whether to approve the settlement."""

    decision: ArbitrationDecision
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    factors: list[str] = Field(default_factory=list)
    mandate_compliance: dict[str, bool] = Field(
        default_factory=dict,
        description="Per-mandate compliance assessment keyed by mandate_id",
    )
    llm_model: str = ""
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_ms: int = 0
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Attestation payload — constructed only when APPROVED
# ---------------------------------------------------------------------------


class PreDisputeAttestationPayload(BaseModel):
    """The immutable attestation record for WORM storage.

    Once constructed, the payload_hash seals the contents. Any mutation
    would invalidate downstream timestamps and Merkle proofs.
    """

    payload_version: str = "1.0"
    transcript: NegotiationTranscript
    mandates: list[AP2Mandate]
    verdict: ArbitrationVerdict
    payload_hash: str = Field(
        ..., description="SHA-256 hex digest of the canonical JSON (excluding this field)"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @staticmethod
    def compute_hash(
        transcript: NegotiationTranscript,
        mandates: list[AP2Mandate],
        verdict: ArbitrationVerdict,
    ) -> str:
        """Compute the deterministic SHA-256 hash over the attestation contents."""
        canonical = {
            "payload_version": "1.0",
            "transcript": transcript.model_dump(mode="json"),
            "mandates": [m.model_dump(mode="json") for m in mandates],
            "verdict": verdict.model_dump(mode="json"),
        }
        import json

        raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# RFC 3161 timestamp
# ---------------------------------------------------------------------------


class TimestampToken(BaseModel):
    """RFC 3161 timestamp token received from a Time Stamp Authority."""

    tsa_url: str
    hash_algorithm: str = "sha256"
    message_hash: str = Field(..., description="Hex-encoded hash that was timestamped")
    timestamp_token_b64: str = Field(
        ..., description="Base64-encoded DER timestamp response from the TSA"
    )
    serial_number: str | None = None
    requested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Merkle Tree proof
# ---------------------------------------------------------------------------


class MerkleLeaf(BaseModel):
    leaf_index: int
    leaf_hash: str = Field(..., description="Hex-encoded SHA-256 leaf hash")
    data_hash: str = Field(..., description="Hex-encoded SHA-256 of the raw data appended")


class MerkleProof(BaseModel):
    """Inclusion proof for a leaf in the Merkle Tree."""

    leaf_index: int
    leaf_hash: str
    siblings: list[str] = Field(
        ..., description="Hex-encoded sibling hashes from leaf to root"
    )
    directions: list[str] = Field(
        ..., description="Direction of each sibling: 'left' or 'right'"
    )
    root_hash: str
    tree_size: int


class MerkleAppendResult(BaseModel):
    """Result of appending a record to the Merkle Tree."""

    leaf: MerkleLeaf
    proof: MerkleProof
    root_hash: str
    tree_size: int
    verified: bool = Field(
        ..., description="Whether the proof was mathematically verified after append"
    )


# ---------------------------------------------------------------------------
# Final settlement output
# ---------------------------------------------------------------------------


class SettlementProof(BaseModel):
    """Complete cryptographic proof bundle for a WORM-compliant settlement."""

    attestation_payload: PreDisputeAttestationPayload
    timestamp: TimestampToken
    merkle_result: MerkleAppendResult
    settlement_hash: str = Field(
        ..., description="SHA-256 tying attestation hash, timestamp, and Merkle root together"
    )
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SettlementResult(BaseModel):
    """Top-level result returned by the settlement pipeline."""

    success: bool
    proof: SettlementProof | None = None
    error: str | None = None
    stage_reached: SettlementStage
    arbitration_verdict: ArbitrationVerdict | None = None
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
