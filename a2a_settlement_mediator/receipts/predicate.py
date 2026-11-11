"""in-toto Statement v1 for a SettleBridge proof-of-fix receipt.

Canonical JSON matches the WORM pipeline: sorted keys, compact separators,
UTF-8. ``verifier_independent_of_solver`` is emitted only as ``true``, and
only when a third-party solver on another platform passed lineage checks.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    model_serializer,
    model_validator,
)

IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PROOF_OF_FIX_PREDICATE_TYPE = "https://settlebridge.ai/attestations/proof-of-fix/v1"

HOUSE_INDEPENDENCE_STATEMENT = (
    "The fix was produced by a SettleBridge-operated solver. Verifier and "
    "challenger are separate operator identities on the same platform; this "
    "receipt does not claim organizational independence."
)

_NONCE_PATTERN = r"^[0-9a-f]{32}$"
# Must match settlebridge_verifier.interfaces.InconclusiveReason.
INCONCLUSIVE_REASONS = frozenset(
    {
        "no_positive_control",
        "deterministic_violation",
        "controls_failed",
        "unsupported_project",
        "budget_exhausted",
        "infra_error",
        "failure_class_not_exercised",
        "tamper_detected",
    }
)
_REPO_PATTERN = r"^[^/\s]+/[^/\s]+$"


class Verdict(str, Enum):
    """Outcome of an independent proof-of-fix run."""

    VERIFIED = "verified"
    INCOMPLETE_FIX_CONFIRMED = "incomplete_fix_confirmed"
    INCONCLUSIVE = "inconclusive"


class VexStatus(str, Enum):
    """OpenVEX-style status derived from the verdict."""

    FIXED = "fixed"
    AFFECTED = "affected"
    UNDER_INVESTIGATION = "under_investigation"


class SolverKind(str, Enum):
    """Who produced the fix that the verifier examined."""

    THIRD_PARTY = "third_party"
    HOUSE = "house"
    UNKNOWN = "unknown"


_VEX_STATUS_BY_VERDICT: dict[Verdict, VexStatus] = {
    Verdict.VERIFIED: VexStatus.FIXED,
    Verdict.INCOMPLETE_FIX_CONFIRMED: VexStatus.AFFECTED,
    Verdict.INCONCLUSIVE: VexStatus.UNDER_INVESTIGATION,
}


def format_rfc3339(value: datetime) -> str:
    """UTC timestamp with a ``Z`` suffix, matching attestation examples."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    value = value.astimezone(timezone.utc)
    if value.microsecond:
        fraction = f"{value.microsecond:06d}".rstrip("0")
        return value.strftime("%Y-%m-%dT%H:%M:%S.") + fraction + "Z"
    return value.strftime("%Y-%m-%dT%H:%M:%SZ")


def github_subject_name(repo: str) -> str:
    """``git+https://github.com/<owner>/<repo>`` subject name."""
    return f"git+https://github.com/{repo}"


class Vulnerability(BaseModel):
    """Vulnerability the fix claims to close."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    aliases: list[str] = Field(default_factory=list)
    alert_ref: str | None = None


class Vex(BaseModel):
    """VEX status derived from the verdict, plus an optional justification."""

    model_config = ConfigDict(extra="forbid")

    status: VexStatus
    justification: str | None = None


class Reproducibility(BaseModel):
    """Inputs that pin a proof-of-fix run."""

    model_config = ConfigDict(extra="forbid")

    engine_sha: str = Field(min_length=1)
    contractgen_version: str = Field(min_length=1)
    sandbox_image_digest: str = Field(min_length=1)
    prompt_version: str = Field(min_length=1)
    model_ids: list[str]
    seeds: list[int]


class VerifierIdentity(BaseModel):
    """Verifier that issued the receipt."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    operator: str = Field(min_length=1)
    key_id: str = Field(min_length=1)


class Independence(BaseModel):
    """Relationship between the solver that wrote the fix and the verifier.

    ``lineage_checks_passed`` is an issuance input. It is not part of the
    signed predicate. ``verifier_independent_of_solver`` is stored only when
    it is true; serialization omits the key otherwise and never writes false.
    """

    model_config = ConfigDict(extra="forbid")

    solver_kind: SolverKind
    solver_principal_sha256: str = Field(min_length=1)
    same_platform_as_verifier: bool
    statement: str = Field(min_length=1)
    lineage_checks_passed: bool = Field(exclude=True, repr=False)
    verifier_independent_of_solver: Literal[True] | None = None

    @model_validator(mode="before")
    @classmethod
    def _restore_lineage(cls, data: Any) -> Any:
        """A published ``true`` claim already survived lineage checks."""
        if not isinstance(data, dict) or "lineage_checks_passed" in data:
            return data
        restored = dict(data)
        restored["lineage_checks_passed"] = restored.get("verifier_independent_of_solver") is True
        return restored

    @model_validator(mode="after")
    def _enforce_independence(self) -> Independence:
        if self.solver_kind is SolverKind.HOUSE:
            if self.statement != HOUSE_INDEPENDENCE_STATEMENT:
                raise ValueError("house solver must use the conflict statement")
            if self.same_platform_as_verifier is not True:
                raise ValueError("house solver is always on the verifier's platform")
            if self.verifier_independent_of_solver is not None:
                raise ValueError("house solver must not claim verifier independence")
        allowed = (
            self.solver_kind is SolverKind.THIRD_PARTY
            and self.same_platform_as_verifier is False
            and self.lineage_checks_passed is True
        )
        claimed = self.verifier_independent_of_solver is True
        if claimed != allowed:
            raise ValueError(
                "verifier_independent_of_solver is included only when solver_kind "
                "is third_party, same_platform_as_verifier is false, and lineage "
                "checks passed"
            )
        return self

    @model_serializer(mode="wrap")
    def _serialize(self, handler: Any) -> dict[str, Any]:
        data = handler(self)
        if isinstance(data, dict):
            data.pop("lineage_checks_passed", None)
            if data.get("verifier_independent_of_solver") is None:
                data.pop("verifier_independent_of_solver", None)
            elif data.get("verifier_independent_of_solver") is not True:
                raise ValueError(
                    "verifier_independent_of_solver must be true when present, never false"
                )
        return data


class SubjectDigest(BaseModel):
    """Git commit digest for an in-toto subject."""

    model_config = ConfigDict(extra="forbid")

    gitCommit: str = Field(min_length=1)


class Subject(BaseModel):
    """in-toto subject naming the fixed repository at ``fix_commit``."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1)
    digest: SubjectDigest


class ProofOfFixPredicate(BaseModel):
    """Predicate body of a proof-of-fix statement."""

    model_config = ConfigDict(extra="forbid")

    receipt_id: str = Field(min_length=1)
    vulnerability: Vulnerability
    repo: str = Field(pattern=_REPO_PATTERN)
    base_commit: str = Field(min_length=1)
    fix_commit: str = Field(min_length=1)
    pr: int | str | None = None
    verdict: Verdict
    inconclusive_reason: str | None = None
    vex: Vex
    failure_classes_tested: list[str]
    positive_control_on_base: bool
    deterministic_findings_sha256: str = Field(min_length=1)
    frozen_contract_sha256: str = Field(min_length=1)
    challenge_report_sha256: str = Field(min_length=1)
    reproducibility: Reproducibility
    verifier: VerifierIdentity
    independence: Independence
    issued_at: datetime
    nonce: str = Field(pattern=_NONCE_PATTERN)

    @model_validator(mode="after")
    def _enforce_verdict(self) -> ProofOfFixPredicate:
        if self.verdict is Verdict.VERIFIED and self.inconclusive_reason is not None:
            raise ValueError("verified verdict requires inconclusive_reason to be null")
        if self.verdict is Verdict.INCONCLUSIVE and not (self.inconclusive_reason or "").strip():
            raise ValueError("inconclusive verdict requires inconclusive_reason")
        if (
            self.inconclusive_reason is not None
            and self.inconclusive_reason not in INCONCLUSIVE_REASONS
        ):
            raise ValueError("inconclusive_reason is not a known reason")
        expected = _VEX_STATUS_BY_VERDICT[self.verdict]
        if self.vex.status is not expected:
            raise ValueError(
                f"vex status {self.vex.status.value} does not match verdict {self.verdict.value}"
            )
        return self

    @field_serializer("issued_at", when_used="json")
    def _serialize_issued_at(self, value: datetime) -> str:
        return format_rfc3339(value)


class ProofOfFixStatement(BaseModel):
    """in-toto Statement v1 carrying a proof-of-fix predicate."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        serialize_by_alias=True,
    )

    statement_type: Literal["https://in-toto.io/Statement/v1"] = Field(
        alias="_type",
        default=IN_TOTO_STATEMENT_TYPE,
    )
    subject: list[Subject] = Field(min_length=1, max_length=1)
    predicateType: Literal["https://settlebridge.ai/attestations/proof-of-fix/v1"] = (
        PROOF_OF_FIX_PREDICATE_TYPE
    )
    predicate: ProofOfFixPredicate

    @model_validator(mode="after")
    def _subject_matches_fix(self) -> ProofOfFixStatement:
        subject = self.subject[0]
        expected_name = github_subject_name(self.predicate.repo)
        if subject.name != expected_name:
            raise ValueError("subject name must be git+https://github.com/<owner>/<repo>")
        if subject.digest.gitCommit != self.predicate.fix_commit:
            raise ValueError("subject digest gitCommit must equal fix_commit")
        if self.predicateType != PROOF_OF_FIX_PREDICATE_TYPE:
            raise ValueError("predicateType must be the proof-of-fix URI")
        return self


class ProofOfFixDraft(BaseModel):
    """Caller-supplied facts. VEX status, the nonce, and the independence claim are derived."""

    model_config = ConfigDict(extra="forbid")

    receipt_id: str = Field(min_length=1)
    vulnerability: Vulnerability
    repo: str = Field(pattern=_REPO_PATTERN)
    base_commit: str = Field(min_length=1)
    fix_commit: str = Field(min_length=1)
    pr: int | str | None = None
    verdict: Verdict
    inconclusive_reason: str | None = None
    vex_justification: str | None = None
    failure_classes_tested: list[str]
    positive_control_on_base: bool
    deterministic_findings_sha256: str = Field(min_length=1)
    frozen_contract_sha256: str = Field(min_length=1)
    challenge_report_sha256: str = Field(min_length=1)
    reproducibility: Reproducibility
    verifier: VerifierIdentity
    solver_kind: SolverKind
    solver_principal_sha256: str = Field(min_length=1)
    same_platform_as_verifier: bool
    independence_statement: str | None = None
    lineage_checks_passed: bool
    issued_at: datetime | None = None
    nonce: str | None = None


def _independence_from_draft(draft: ProofOfFixDraft) -> Independence:
    """Apply the independence rule. The claim is true or absent, never false."""
    if draft.solver_kind is SolverKind.HOUSE:
        return Independence(
            solver_kind=draft.solver_kind,
            solver_principal_sha256=draft.solver_principal_sha256,
            same_platform_as_verifier=True,
            statement=HOUSE_INDEPENDENCE_STATEMENT,
            lineage_checks_passed=draft.lineage_checks_passed,
            verifier_independent_of_solver=None,
        )
    statement = (draft.independence_statement or "").strip()
    if not statement:
        raise ValueError("third_party solver requires an independence statement")
    claim: Literal[True] | None = None
    if (
        draft.solver_kind is SolverKind.THIRD_PARTY
        and draft.same_platform_as_verifier is False
        and draft.lineage_checks_passed is True
    ):
        claim = True
    return Independence(
        solver_kind=draft.solver_kind,
        solver_principal_sha256=draft.solver_principal_sha256,
        same_platform_as_verifier=draft.same_platform_as_verifier,
        statement=statement,
        lineage_checks_passed=draft.lineage_checks_passed,
        verifier_independent_of_solver=claim,
    )


def build_proof_of_fix_statement(draft: ProofOfFixDraft) -> ProofOfFixStatement:
    """Build a sealed in-toto statement from caller-supplied facts."""
    issued_at = draft.issued_at or datetime.now(timezone.utc)
    if issued_at.tzinfo is None:
        issued_at = issued_at.replace(tzinfo=timezone.utc)
    nonce = draft.nonce if draft.nonce is not None else secrets.token_hex(16)
    predicate = ProofOfFixPredicate(
        receipt_id=draft.receipt_id,
        vulnerability=draft.vulnerability,
        repo=draft.repo,
        base_commit=draft.base_commit,
        fix_commit=draft.fix_commit,
        pr=draft.pr,
        verdict=draft.verdict,
        inconclusive_reason=draft.inconclusive_reason,
        vex=Vex(
            status=_VEX_STATUS_BY_VERDICT[draft.verdict],
            justification=draft.vex_justification,
        ),
        failure_classes_tested=list(draft.failure_classes_tested),
        positive_control_on_base=draft.positive_control_on_base,
        deterministic_findings_sha256=draft.deterministic_findings_sha256,
        frozen_contract_sha256=draft.frozen_contract_sha256,
        challenge_report_sha256=draft.challenge_report_sha256,
        reproducibility=draft.reproducibility,
        verifier=draft.verifier,
        independence=_independence_from_draft(draft),
        issued_at=issued_at,
        nonce=nonce,
    )
    return ProofOfFixStatement(
        subject=[
            Subject(
                name=github_subject_name(draft.repo),
                digest=SubjectDigest(gitCommit=draft.fix_commit),
            )
        ],
        predicate=predicate,
    )


def _omit_unclaimed_independence(data: Any) -> None:
    """Drop a null independence claim so the key is absent, and reject false."""
    if isinstance(data, list):
        for item in data:
            _omit_unclaimed_independence(item)
        return
    if not isinstance(data, dict):
        return
    if "solver_kind" in data:
        data.pop("lineage_checks_passed", None)
        if "verifier_independent_of_solver" in data:
            claim = data["verifier_independent_of_solver"]
            if claim is None:
                data.pop("verifier_independent_of_solver")
            elif claim is not True:
                raise ValueError(
                    "verifier_independent_of_solver must be true when present, never false"
                )
    for value in data.values():
        _omit_unclaimed_independence(value)


def canonical_json_bytes(model: BaseModel) -> bytes:
    """UTF-8 canonical JSON: sorted keys and compact separators, like worm_schemas."""
    payload = model.model_dump(mode="json", by_alias=True)
    _omit_unclaimed_independence(payload)
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return text.encode("utf-8")
