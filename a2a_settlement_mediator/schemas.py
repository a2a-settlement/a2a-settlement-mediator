"""Pydantic models for mediation evidence, verdicts, and audit records."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class Resolution(str, Enum):
    RELEASE = "release"
    REFUND = "refund"


class VerdictOutcome(str, Enum):
    AUTO_RELEASE = "auto_release"
    AUTO_REFUND = "auto_refund"
    ESCALATE = "escalate"


# ---------------------------------------------------------------------------
# Evidence (gathered from exchange before LLM evaluation)
# ---------------------------------------------------------------------------


class Deliverable(BaseModel):
    description: str
    artifact_hash: str | None = None
    acceptance_criteria: str | None = None


class EscrowEvidence(BaseModel):
    """Snapshot of escrow state at time of dispute."""

    escrow_id: str
    requester_id: str
    provider_id: str
    amount: int
    fee_amount: int
    status: str
    dispute_reason: str | None = None
    task_id: str | None = None
    task_type: str | None = None
    deliverables: list[Deliverable] = []
    created_at: datetime | None = None
    expires_at: datetime | None = None


class AccountEvidence(BaseModel):
    """Snapshot of an account's reputation and history."""

    account_id: str
    bot_name: str
    reputation: float
    status: str
    skills: list[str] = []
    total_earned: int = 0
    total_spent: int = 0


class EvidenceBundle(BaseModel):
    """All evidence the mediator collects before evaluating a dispute."""

    escrow: EscrowEvidence
    requester: AccountEvidence
    provider: AccountEvidence
    requester_recent_disputes: int = 0
    provider_recent_disputes: int = 0
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Verdict (LLM output, structured)
# ---------------------------------------------------------------------------


class Verdict(BaseModel):
    """The mediator's decision on a dispute."""

    escrow_id: str
    outcome: VerdictOutcome
    resolution: Resolution | None = None  # None when escalated
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str
    factors: list[str] = []  # Key factors that influenced the decision
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Audit record (persisted for transparency)
# ---------------------------------------------------------------------------


class AuditRecord(BaseModel):
    """Full audit trail for a mediation decision."""

    escrow_id: str
    evidence: EvidenceBundle
    verdict: Verdict
    llm_model: str
    llm_prompt_tokens: int = 0
    llm_completion_tokens: int = 0
    llm_latency_ms: int = 0
    exchange_response: dict | None = None
    error: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Webhook payload (incoming from exchange)
# ---------------------------------------------------------------------------


class WebhookPayload(BaseModel):
    """Incoming webhook event from the exchange."""

    event: str
    timestamp: str
    data: dict
