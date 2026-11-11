"""SLSA Verification Summary Attestation for a proof-of-fix statement.

``verificationResult`` is ``PASSED`` only when the proof-of-fix verdict is
``verified``. The policy digest is the SHA-256 of the proof-of-fix predicate's
canonical JSON. ``inputAttestations`` carries the SHA-256 of the whole
proof-of-fix statement.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from a2a_settlement_mediator.receipts.predicate import (
    IN_TOTO_STATEMENT_TYPE,
    ProofOfFixStatement,
    Subject,
    SubjectDigest,
    Verdict,
    canonical_json_bytes,
    format_rfc3339,
)

VSA_PREDICATE_TYPE = "https://slsa.dev/verification_summary/v1"
POLICY_URI = "https://settlebridge.ai/policies/proof-of-fix/v1"


class VerificationResult(str, Enum):
    """SLSA VSA result. Only a verified fix passes."""

    PASSED = "PASSED"
    FAILED = "FAILED"


class VsaVerifier(BaseModel):
    """Verifier identity recorded on the VSA. SLSA asks for ``id`` only."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)


class Sha256Digest(BaseModel):
    """Single SHA-256 digest set entry."""

    model_config = ConfigDict(extra="forbid")

    sha256: str = Field(min_length=64, max_length=64)


class VsaPolicy(BaseModel):
    """Policy that was applied, bound to the proof-of-fix predicate bytes."""

    model_config = ConfigDict(extra="forbid")

    uri: Literal["https://settlebridge.ai/policies/proof-of-fix/v1"] = POLICY_URI
    digest: Sha256Digest


class InputAttestation(BaseModel):
    """An attestation the verifier consumed. Digest is of the statement bytes."""

    model_config = ConfigDict(extra="forbid")

    uri: str = Field(min_length=1)
    digest: Sha256Digest


class VsaPredicate(BaseModel):
    """SLSA verification summary predicate."""

    model_config = ConfigDict(extra="forbid")

    verifier: VsaVerifier
    timeVerified: str = Field(min_length=1)
    resourceUri: str = Field(min_length=1)
    policy: VsaPolicy
    inputAttestations: list[InputAttestation] = Field(min_length=1)
    verificationResult: VerificationResult
    verifiedLevels: list[str]


class VsaStatement(BaseModel):
    """in-toto Statement v1 carrying a SLSA VSA predicate."""

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
    predicateType: Literal["https://slsa.dev/verification_summary/v1"] = VSA_PREDICATE_TYPE
    predicate: VsaPredicate


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build_vsa(
    statement: ProofOfFixStatement,
    *,
    time_verified: datetime | None = None,
) -> VsaStatement:
    """Issue a VSA for the same subject as ``statement``.

    Policy digest covers the proof-of-fix predicate. The input attestation
    digest covers the full proof-of-fix statement. Both are canonical JSON.
    """
    predicate_bytes = canonical_json_bytes(statement.predicate)
    statement_bytes = canonical_json_bytes(statement)
    result = (
        VerificationResult.PASSED
        if statement.predicate.verdict is Verdict.VERIFIED
        else VerificationResult.FAILED
    )
    when = time_verified if time_verified is not None else statement.predicate.issued_at
    subject = statement.subject[0]
    fix_commit = statement.predicate.fix_commit
    return VsaStatement(
        subject=[
            Subject(
                name=subject.name,
                digest=SubjectDigest(gitCommit=subject.digest.gitCommit),
            )
        ],
        predicate=VsaPredicate(
            verifier=VsaVerifier(id=statement.predicate.verifier.id),
            timeVerified=format_rfc3339(when),
            resourceUri=f"{subject.name}@{fix_commit}",
            policy=VsaPolicy(
                digest=Sha256Digest(sha256=_sha256_hex(predicate_bytes)),
            ),
            inputAttestations=[
                InputAttestation(
                    uri=f"urn:settlebridge:receipt:{statement.predicate.receipt_id}",
                    digest=Sha256Digest(sha256=_sha256_hex(statement_bytes)),
                )
            ],
            verificationResult=result,
            verifiedLevels=[],
        ),
    )
