"""Pydantic models for mediation evidence, verdicts, and audit records."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Literal

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
    NULL_RESOLUTION = "null_resolution"


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
    required_attestation_level: str | None = None
    delivered_content: str | None = None
    provenance: dict | None = None
    vi_credential_chain: dict | None = None
    delivered_at: datetime | None = None
    created_at: datetime | None = None
    expires_at: datetime | None = None
    self_dealing_class: str | None = None


class AccountEvidence(BaseModel):
    """Snapshot of an account's reputation and history."""

    account_id: str
    bot_name: str
    reputation: float
    status: str
    skills: list[str] = []
    total_earned: int = 0
    total_spent: int = 0


class StructuredEvidence(BaseModel):
    """A structured evidence submission from one party or an oracle."""

    id: str
    submitter_id: str
    evidence_type: str
    summary: str
    artifacts: list[dict] = []
    encrypted: bool = False
    content_hash: str = ""
    attestor_id: str | None = None
    attestor_signature: str | None = None
    # "party" = requester/provider self-reported; "oracle" = registered oracle
    source_type: str = "party"
    oracle_id: str | None = None
    submitted_at: datetime | None = None


class EvidenceBundle(BaseModel):
    """All evidence the mediator collects before evaluating a dispute."""

    escrow: EscrowEvidence
    requester: AccountEvidence
    provider: AccountEvidence
    requester_recent_disputes: int = 0
    provider_recent_disputes: int = 0
    requester_evidence: list[StructuredEvidence] = []
    provider_evidence: list[StructuredEvidence] = []
    oracle_evidence: list[StructuredEvidence] = []
    requester_attestation_freshness: dict | None = None
    provider_attestation_freshness: dict | None = None
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Provenance verification result
# ---------------------------------------------------------------------------


class ProvenanceResult(BaseModel):
    """Result of provenance verification by the mediator."""

    verified: bool
    tier: Literal["self_declared", "signed", "verifiable"]
    confidence: float = Field(..., ge=0.0, le=1.0)
    flags: list[str] = []
    recommendation: Literal["approve", "flag", "reject"]


# ---------------------------------------------------------------------------
# Structured diagnostic (training / task-type scoring output)
# ---------------------------------------------------------------------------


class StructuredDiagnostic(BaseModel):
    """Actionable gap analysis produced when mode=training or task_type is provided.

    ``actionable_gaps`` is the primary gradient consumed by the iteration harness:
    an ordered list of specific, correctable deficiencies in the deliverable.

    ``details`` is an optional free-form dict populated by the LLM with
    task-type-appropriate breakdowns (e.g. ``{"missed_entities": [...]}`` for
    data tasks, ``{"omitted_points": [...]}`` for summarisation).  Its keys are
    intentionally unvalidated so the schema can evolve without migrations.
    """

    task_type: str | None = None
    actionable_gaps: list[str] = []
    details: dict | None = None


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
    structured_diagnostic: StructuredDiagnostic | None = None
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Audit record (persisted for transparency)
# ---------------------------------------------------------------------------


class MediatorContext(BaseModel):
    """Snapshot of the mediator's configuration at time of adjudication.

    Ensures the AI's ruling parameters are as auditable as the agents' evidence.
    """

    model_version: str
    system_prompt_hash: str
    temperature: float | None
    max_tokens: int


class AuditRecord(BaseModel):
    """Full audit trail for a mediation decision."""

    escrow_id: str
    evidence: EvidenceBundle
    verdict: Verdict
    provenance_result: ProvenanceResult | None = None
    mediator_context: MediatorContext | None = None
    llm_model: str
    llm_prompt_tokens: int = 0
    llm_completion_tokens: int = 0
    llm_latency_ms: int = 0
    exchange_response: dict | None = None
    error: str | None = None
    # How the deliverable was evaluated. "direct" = full content sent to LLM;
    # "digest" = oversized deliverable was summarised before LLM evaluation;
    # "structural_error" = pre-LLM integrity check failed (provider fault, scored);
    # "system_error" = mediator processing failure (platform fault, not scored).
    evaluation_method: Literal["direct", "digest", "structural_error", "system_error"] = "direct"
    deliverable_size_bytes: int | None = None
    digest_size_tokens: int | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Webhook payload (incoming from exchange)
# ---------------------------------------------------------------------------


class WebhookPayload(BaseModel):
    """Incoming webhook event from the exchange."""

    event: str
    timestamp: str
    data: dict


# ---------------------------------------------------------------------------
# Patch assessment (GitHub bounty diffs)
# ---------------------------------------------------------------------------


class FindingSeverity(str, Enum):
    VIOLATION = "violation"
    REVIEW = "review"


class PolicyRule(str, Enum):
    TEST_FILE_DELETED = "test_file_deleted"
    ASSERTION_CHANGED = "assertion_changed"
    WEAK_ASSERTION_ADDED = "weak_assertion_added"
    TEST_SKIP_ADDED = "test_skip_added"
    SUPPRESSION_ADDED = "suppression_added"
    HARNESS_CHANGED = "harness_changed"
    DEPENDENCY_CHANGED = "dependency_changed"
    PATH_NOT_ALLOWED = "path_not_allowed"
    LITERAL_RETURN_SUSPECT = "literal_return_suspect"
    REVIEWER_CONCERN = "reviewer_concern"
    UNINSPECTABLE_CHANGE = "uninspectable_change"
    REVIEWER_UNAVAILABLE = "reviewer_unavailable"


DEFAULT_RULE_SEVERITY: dict[PolicyRule, FindingSeverity] = {
    PolicyRule.TEST_FILE_DELETED: FindingSeverity.REVIEW,
    PolicyRule.ASSERTION_CHANGED: FindingSeverity.REVIEW,
    PolicyRule.WEAK_ASSERTION_ADDED: FindingSeverity.REVIEW,
    PolicyRule.TEST_SKIP_ADDED: FindingSeverity.REVIEW,
    PolicyRule.SUPPRESSION_ADDED: FindingSeverity.REVIEW,
    PolicyRule.HARNESS_CHANGED: FindingSeverity.VIOLATION,
    PolicyRule.DEPENDENCY_CHANGED: FindingSeverity.VIOLATION,
    PolicyRule.PATH_NOT_ALLOWED: FindingSeverity.VIOLATION,
    PolicyRule.LITERAL_RETURN_SUSPECT: FindingSeverity.REVIEW,
    PolicyRule.REVIEWER_CONCERN: FindingSeverity.REVIEW,
    PolicyRule.UNINSPECTABLE_CHANGE: FindingSeverity.REVIEW,
    PolicyRule.REVIEWER_UNAVAILABLE: FindingSeverity.REVIEW,
}


class PatchPolicy(BaseModel):
    """Restrictions frozen into an AcceptanceSpec before work starts.

    ``rule_severity`` overrides DEFAULT_RULE_SEVERITY per rule. ``allowed_paths``
    are fnmatch globs; empty means every path is allowed.
    ``allowed_dependency_changes`` lists package names that may be added,
    removed, or re-pinned.
    """

    rule_severity: dict[PolicyRule, FindingSeverity] = Field(default_factory=dict)
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_dependency_changes: list[str] = Field(default_factory=list)
    type_ignore_is_suppression: bool = False

    def severity_for(self, rule: PolicyRule) -> FindingSeverity:
        return self.rule_severity.get(rule, DEFAULT_RULE_SEVERITY[rule])


class PolicyFinding(BaseModel):
    rule: PolicyRule
    severity: FindingSeverity
    path: str
    line: int | None = None
    evidence: str = ""
    source: Literal["deterministic", "reviewer"] = "deterministic"


class PatchOutcome(str, Enum):
    ACCEPTABLE = "ACCEPTABLE"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    REJECTED_TOO_LARGE = "REJECTED_TOO_LARGE"


class ReviewerOpinion(BaseModel):
    """Advisory LLM review. Never sufficient for acceptance."""

    status: Literal["completed", "unavailable", "skipped"]
    summary: str = ""
    concerns: list[str] = Field(default_factory=list)
    model: str | None = None


class TraceConsistency(BaseModel):
    """Agent-supplied spans checked for internal consistency only."""

    status: Literal["consistent", "inconsistent", "absent"]
    checks: dict[str, bool] = Field(default_factory=dict)
    basis: Literal["consistency_only"] = "consistency_only"


class VerifyPatchRequest(BaseModel):
    spec_hash: str
    repo: str
    pr_number: int
    head_sha: str
    git_diff: str
    policy: PatchPolicy = Field(default_factory=PatchPolicy)
    bounty_id: str | None = None
    solver_agent_id: str | None = None
    otel_spans: list[dict] | None = None
    enable_reviewer: bool = True


class PatchAssessment(BaseModel):
    outcome: PatchOutcome
    findings: list[PolicyFinding] = Field(default_factory=list)
    reviewer_opinion: ReviewerOpinion
    trace_consistency: TraceConsistency
    diff_sha256: str
    spec_hash: str
    repo: str
    pr_number: int
    head_sha: str
    issued_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
