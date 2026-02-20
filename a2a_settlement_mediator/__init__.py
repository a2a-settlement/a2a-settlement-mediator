"""A2A Settlement Mediator — AI-powered dispute resolution for the A2A Settlement Exchange."""

from a2a_settlement_mediator.config import MediatorSettings, settings
from a2a_settlement_mediator.evidence import collect_evidence
from a2a_settlement_mediator.mediator import mediate
from a2a_settlement_mediator.schemas import (
    AuditRecord,
    EvidenceBundle,
    Resolution,
    Verdict,
    VerdictOutcome,
)
from a2a_settlement_mediator.heartbeat import HeartbeatWorker
from a2a_settlement_mediator.settlement_pipeline import (
    IngestionLimitExceeded,
    get_pending_settlements,
    get_stale_settlements,
    mark_executed,
    mark_failed,
    settle,
)
from a2a_settlement_mediator.worm_schemas import (
    AgentIdentity,
    AP2Mandate,
    ArbitrationDecision,
    ArbitrationVerdict,
    CurrencyPrecision,
    ExecutionStatus,
    MerkleAppendResult,
    MerkleLeafPayload,
    MerkleProof,
    NegotiationTranscript,
    PreDisputeAttestationPayload,
    SettlementProof,
    SettlementResult,
    SettlementStage,
    TimestampToken,
)

__all__ = [
    # Original mediator
    "mediate",
    "collect_evidence",
    "settings",
    "MediatorSettings",
    "AuditRecord",
    "EvidenceBundle",
    "Resolution",
    "Verdict",
    "VerdictOutcome",
    # WORM settlement pipeline
    "settle",
    "IngestionLimitExceeded",
    "get_pending_settlements",
    "get_stale_settlements",
    "mark_executed",
    "mark_failed",
    "HeartbeatWorker",
    "AgentIdentity",
    "AP2Mandate",
    "ArbitrationDecision",
    "ArbitrationVerdict",
    "CurrencyPrecision",
    "ExecutionStatus",
    "MerkleAppendResult",
    "MerkleLeafPayload",
    "MerkleProof",
    "NegotiationTranscript",
    "PreDisputeAttestationPayload",
    "SettlementProof",
    "SettlementResult",
    "SettlementStage",
    "TimestampToken",
]

__version__ = "0.1.0"
