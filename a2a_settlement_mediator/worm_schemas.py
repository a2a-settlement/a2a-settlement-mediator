"""Pydantic models for the SEC 17a-4 WORM compliance pipeline.

Covers the full lifecycle: negotiation transcript ingestion, AP2 mandate
evaluation, arbitration decisions, pre-dispute attestation payloads,
RFC 3161 timestamps, Merkle Tree proofs, and final settlement results.

All payload models carry a ``payload_version`` / ``schema_version`` field
so that external auditors and peer mediators can parse records regardless
of which software version produced them.  Use ``export_json_schemas()``
to emit versioned JSON Schema definitions suitable for publication.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.1"

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

    payload_version: str = SCHEMA_VERSION
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
            "payload_version": SCHEMA_VERSION,
            "transcript": transcript.model_dump(mode="json"),
            "mandates": [m.model_dump(mode="json") for m in mandates],
            "verdict": verdict.model_dump(mode="json"),
        }
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
# Agent identity & currency precision (Merkle leaf hardening)
# ---------------------------------------------------------------------------


class AgentIdentity(BaseModel):
    """Identifies a participating agent in a settlement."""

    agent_id: str = Field(..., min_length=1, description="Unique agent identifier")
    role: str = Field(
        ...,
        min_length=1,
        description="Role in the settlement (e.g. 'buyer', 'seller', 'mediator')",
    )
    protocol_version: str = Field(
        default="2.0", description="A2A protocol version the agent speaks"
    )


class CurrencyPrecision(BaseModel):
    """Financial precision metadata attached to a settlement leaf."""

    currency_code: str = Field(
        ...,
        pattern=r"^[A-Z]{3}$",
        description="ISO 4217 currency code (e.g. 'USD', 'EUR')",
    )
    decimal_places: int = Field(
        ...,
        ge=0,
        le=18,
        description="Number of decimal places (e.g. 2 for USD, 8 for BTC)",
    )


class MerkleLeafPayload(BaseModel):
    """Refined, versioned payload that is serialized and appended to the Merkle Tree.

    Replaces the previous dictionary-based construction, adding version
    tracking, agent identity binding, and currency precision metadata
    for cross-mediator verification and audit compliance.
    """

    leaf_version: str = Field(
        default=SCHEMA_VERSION,
        description="Schema version of this leaf payload",
    )
    agent_identities: list[AgentIdentity] = Field(
        ...,
        min_length=2,
        description="All parties involved in the settlement (minimum two)",
    )
    currency_precision: CurrencyPrecision
    attestation: "PreDisputeAttestationPayload"
    timestamp: TimestampToken
    payload_hash: str = Field(
        ...,
        description="SHA-256 hex digest of the canonical JSON (excluding this field)",
    )

    @staticmethod
    def compute_hash(
        agent_identities: list[AgentIdentity],
        currency_precision: CurrencyPrecision,
        attestation: "PreDisputeAttestationPayload",
        timestamp: TimestampToken,
    ) -> str:
        """Compute the deterministic SHA-256 hash over the leaf payload contents."""
        canonical = {
            "leaf_version": SCHEMA_VERSION,
            "agent_identities": [a.model_dump(mode="json") for a in agent_identities],
            "currency_precision": currency_precision.model_dump(mode="json"),
            "attestation": attestation.model_dump(mode="json"),
            "timestamp": timestamp.model_dump(mode="json"),
        }
        raw = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


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

    schema_version: str = Field(
        default=SCHEMA_VERSION,
        description="Schema version for external auditors to select the correct parser",
    )
    attestation_payload: PreDisputeAttestationPayload
    timestamp: TimestampToken
    merkle_result: MerkleAppendResult
    settlement_hash: str = Field(
        ..., description="SHA-256 tying attestation hash, timestamp, and Merkle root together"
    )
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutionStatus(str, Enum):
    """Tracks whether the settlement mandate has been released to the execution engine."""

    PENDING = "pending"
    EXECUTED = "executed"
    FAILED = "failed"


class SettlementResult(BaseModel):
    """Top-level result returned by the settlement pipeline."""

    success: bool
    proof: SettlementProof | None = None
    error: str | None = None
    stage_reached: SettlementStage
    arbitration_verdict: ArbitrationVerdict | None = None
    execution_status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# JSON Schema export for external auditors
# ---------------------------------------------------------------------------

_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "NegotiationTranscript": NegotiationTranscript,
    "AP2Mandate": AP2Mandate,
    "ArbitrationVerdict": ArbitrationVerdict,
    "PreDisputeAttestationPayload": PreDisputeAttestationPayload,
    "TimestampToken": TimestampToken,
    "AgentIdentity": AgentIdentity,
    "CurrencyPrecision": CurrencyPrecision,
    "MerkleLeafPayload": MerkleLeafPayload,
    "MerkleProof": MerkleProof,
    "MerkleAppendResult": MerkleAppendResult,
    "SettlementProof": SettlementProof,
    "SettlementResult": SettlementResult,
}


def export_json_schemas(output_dir: str | Path | None = None) -> dict[str, dict]:
    """Generate versioned JSON Schema definitions for all attestation models.

    If *output_dir* is provided, each schema is also written to
    ``<output_dir>/<ModelName>.v<version>.schema.json``.

    Returns a dict mapping model name to its JSON Schema dict.
    """
    schemas: dict[str, dict] = {}
    for name, model_cls in _SCHEMA_MODELS.items():
        schema = model_cls.model_json_schema()
        schema["$id"] = f"https://a2a-settlement.org/schemas/{name}/v{SCHEMA_VERSION}"
        schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        schemas[name] = schema

    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        for name, schema in schemas.items():
            path = out / f"{name}.v{SCHEMA_VERSION}.schema.json"
            path.write_text(json.dumps(schema, indent=2) + "\n")

    return schemas
