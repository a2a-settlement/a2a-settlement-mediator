"""Proof-of-fix predicate, independence rule, and SLSA VSA."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from a2a_settlement_mediator.receipts import (
    HOUSE_INDEPENDENCE_STATEMENT,
    POLICY_URI,
    PROOF_OF_FIX_PREDICATE_TYPE,
    VSA_PREDICATE_TYPE,
    Independence,
    ProofOfFixDraft,
    ProofOfFixStatement,
    SolverKind,
    Verdict,
    build_proof_of_fix_statement,
    build_vsa,
    canonical_json_bytes,
)

_ISSUED = datetime(2026, 11, 10, 18, 0, tzinfo=timezone.utc)
_NONCE = "0123456789abcdef0123456789abcdef"
_FIX = "b" * 40
_THIRD_PARTY_STATEMENT = "The fix was produced by a third-party solver on a separate platform."


def _draft_kwargs(**overrides):
    data = {
        "receipt_id": "rcpt-1",
        "vulnerability": {
            "id": "GHSA-aaaa-bbbb-cccc",
            "aliases": ["CVE-2026-0001"],
            "alert_ref": "alert-9",
        },
        "repo": "acme/widget",
        "base_commit": "a" * 40,
        "fix_commit": _FIX,
        "pr": 42,
        "verdict": Verdict.VERIFIED,
        "inconclusive_reason": None,
        "vex_justification": None,
        "failure_classes_tested": ["bounds", "authz"],
        "positive_control_on_base": True,
        "deterministic_findings_sha256": "11" * 32,
        "frozen_contract_sha256": "22" * 32,
        "challenge_report_sha256": "33" * 32,
        "reproducibility": {
            "engine_sha": "c" * 40,
            "contractgen_version": "1.2.3",
            "sandbox_image_digest": "sha256:" + "d" * 64,
            "prompt_version": "pof-3",
            "model_ids": ["model-a"],
            "seeds": [1, 2],
        },
        "verifier": {
            "id": "https://settlebridge.ai/verifiers/proof-of-fix",
            "operator": "verifier-ops",
            "key_id": "sb-key-1",
        },
        "solver_kind": SolverKind.THIRD_PARTY,
        "solver_principal_sha256": "44" * 32,
        "same_platform_as_verifier": False,
        "independence_statement": _THIRD_PARTY_STATEMENT,
        "lineage_checks_passed": True,
        "issued_at": _ISSUED,
        "nonce": _NONCE,
    }
    data.update(overrides)
    return data


def _build(**overrides) -> ProofOfFixStatement:
    return build_proof_of_fix_statement(ProofOfFixDraft(**_draft_kwargs(**overrides)))


def test_statement_subject_and_canonical_json():
    statement = _build()
    raw = canonical_json_bytes(statement)
    parsed = json.loads(raw)

    assert parsed["_type"] == "https://in-toto.io/Statement/v1"
    assert parsed["predicateType"] == PROOF_OF_FIX_PREDICATE_TYPE
    assert parsed["subject"] == [
        {"name": "git+https://github.com/acme/widget", "digest": {"gitCommit": _FIX}}
    ]
    assert parsed["predicate"]["issued_at"] == "2026-11-10T18:00:00Z"
    assert parsed["predicate"]["nonce"] == _NONCE
    assert parsed["predicate"]["inconclusive_reason"] is None
    assert raw == json.dumps(parsed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    assert list(parsed) == sorted(parsed)
    again = ProofOfFixStatement.model_validate(parsed)
    assert canonical_json_bytes(again) == raw


def test_canonical_json_escapes_non_ascii_like_worm_schemas():
    statement = _build(failure_classes_tested=["caf\u00e9"])
    raw = canonical_json_bytes(statement)
    assert "caf\u00e9".encode() not in raw
    assert b"\\u00e9" in raw


@pytest.mark.parametrize(
    ("kind", "same_platform", "lineage", "claimed"),
    [
        (SolverKind.HOUSE, True, True, False),
        (SolverKind.HOUSE, False, True, False),
        (SolverKind.HOUSE, True, False, False),
        (SolverKind.HOUSE, False, False, False),
        (SolverKind.THIRD_PARTY, False, True, True),
        (SolverKind.THIRD_PARTY, False, False, False),
        (SolverKind.THIRD_PARTY, True, True, False),
        (SolverKind.THIRD_PARTY, True, False, False),
    ],
)
def test_independence_claim_matrix(kind, same_platform, lineage, claimed):
    statement = _build(
        solver_kind=kind,
        same_platform_as_verifier=same_platform,
        lineage_checks_passed=lineage,
        independence_statement="caller text that house receipts must replace",
    )
    payload = json.loads(canonical_json_bytes(statement))
    independence = payload["predicate"]["independence"]

    assert "lineage_checks_passed" not in independence
    if claimed:
        assert independence["verifier_independent_of_solver"] is True
    else:
        assert "verifier_independent_of_solver" not in independence
    assert independence.get("verifier_independent_of_solver") is not False
    assert b'"verifier_independent_of_solver":false' not in canonical_json_bytes(statement)
    if kind is SolverKind.HOUSE:
        assert independence["statement"] == HOUSE_INDEPENDENCE_STATEMENT
        assert independence["solver_kind"] == "house"
        assert independence["same_platform_as_verifier"] is True
    else:
        assert independence["statement"] == "caller text that house receipts must replace"


def test_false_independence_claim_is_rejected():
    with pytest.raises(ValidationError):
        Independence(
            solver_kind=SolverKind.THIRD_PARTY,
            solver_principal_sha256="ab",
            same_platform_as_verifier=False,
            statement="separate platform",
            lineage_checks_passed=True,
            verifier_independent_of_solver=False,
        )


def test_published_false_claim_does_not_parse():
    statement = _build()
    payload = json.loads(canonical_json_bytes(statement))
    payload["predicate"]["independence"]["verifier_independent_of_solver"] = False
    with pytest.raises(ValidationError):
        ProofOfFixStatement.model_validate(payload)


def test_house_document_cannot_claim_independence():
    statement = _build(solver_kind=SolverKind.HOUSE)
    payload = json.loads(canonical_json_bytes(statement))
    payload["predicate"]["independence"]["verifier_independent_of_solver"] = True
    with pytest.raises(ValidationError):
        ProofOfFixStatement.model_validate(payload)


@pytest.mark.parametrize(
    ("verdict", "status", "reason"),
    [
        (Verdict.VERIFIED, "fixed", None),
        (Verdict.INCOMPLETE_FIX_CONFIRMED, "affected", None),
        (Verdict.INCONCLUSIVE, "under_investigation", "no_positive_control"),
    ],
)
def test_vex_mapping(verdict, status, reason):
    statement = _build(verdict=verdict, inconclusive_reason=reason)
    assert statement.predicate.vex.status.value == status
    parsed = json.loads(canonical_json_bytes(statement))
    assert parsed["predicate"]["vex"]["status"] == status
    assert parsed["predicate"]["verdict"] == verdict.value


def test_verified_rejects_inconclusive_reason():
    with pytest.raises(ValidationError, match="inconclusive_reason"):
        _build(verdict=Verdict.VERIFIED, inconclusive_reason="should be null")


def test_inconclusive_requires_reason():
    with pytest.raises(ValidationError, match="inconclusive_reason"):
        _build(verdict=Verdict.INCONCLUSIVE, inconclusive_reason=None)
    with pytest.raises(ValidationError, match="inconclusive_reason"):
        _build(verdict=Verdict.INCONCLUSIVE, inconclusive_reason="   ")


def test_generated_nonce_is_128_bit_hex(monkeypatch):
    def fake_token_hex(nbytes: int) -> str:
        assert nbytes == 16
        return "ab" * 16

    monkeypatch.setattr(
        "a2a_settlement_mediator.receipts.predicate.secrets.token_hex",
        fake_token_hex,
    )
    statement = _build(nonce=None)
    assert statement.predicate.nonce == "ab" * 16


@pytest.mark.parametrize(
    ("verdict", "result", "reason"),
    [
        (Verdict.VERIFIED, "PASSED", None),
        (Verdict.INCOMPLETE_FIX_CONFIRMED, "FAILED", None),
        (Verdict.INCONCLUSIVE, "FAILED", "no_positive_control"),
    ],
)
def test_vsa_result_mapping_and_policy_digest(verdict, result, reason):
    statement = _build(verdict=verdict, inconclusive_reason=reason)
    vsa = build_vsa(statement)
    predicate_bytes = canonical_json_bytes(statement.predicate)
    statement_bytes = canonical_json_bytes(statement)

    assert vsa.predicate.verificationResult.value == result
    assert vsa.predicate.verifiedLevels == []
    assert vsa.predicateType == VSA_PREDICATE_TYPE
    assert vsa.predicate.policy.uri == POLICY_URI
    assert vsa.predicate.policy.digest.sha256 == hashlib.sha256(predicate_bytes).hexdigest()
    assert (
        vsa.predicate.inputAttestations[0].uri
        == f"urn:settlebridge:receipt:{statement.predicate.receipt_id}"
    )
    assert (
        vsa.predicate.inputAttestations[0].digest.sha256
        == hashlib.sha256(statement_bytes).hexdigest()
    )
    assert vsa.predicate.policy.digest.sha256 != vsa.predicate.inputAttestations[0].digest.sha256
    assert b'"predicateType"' not in predicate_bytes
    assert b'"receipt_id"' in predicate_bytes

    parsed = json.loads(canonical_json_bytes(vsa))
    assert parsed["_type"] == "https://in-toto.io/Statement/v1"
    assert parsed["predicateType"] == VSA_PREDICATE_TYPE
    assert parsed["subject"] == [
        {"name": "git+https://github.com/acme/widget", "digest": {"gitCommit": _FIX}}
    ]
    assert parsed["predicate"]["resourceUri"] == f"git+https://github.com/acme/widget@{_FIX}"
    assert parsed["predicate"]["timeVerified"] == "2026-11-10T18:00:00Z"
    assert parsed["predicate"]["verifier"] == {
        "id": "https://settlebridge.ai/verifiers/proof-of-fix"
    }
    assert parsed["predicate"]["verificationResult"] == result
    assert parsed["predicate"]["verifiedLevels"] == []


def test_unknown_solver_never_claims_independence():
    statement = _build(
        solver_kind=SolverKind.UNKNOWN,
        same_platform_as_verifier=False,
        lineage_checks_passed=True,
        independence_statement="solver identity not established",
    )
    independence = json.loads(canonical_json_bytes(statement))["predicate"]["independence"]
    assert "verifier_independent_of_solver" not in independence


def test_house_independence_rejects_other_platform():
    with pytest.raises(ValidationError):
        Independence(
            solver_kind=SolverKind.HOUSE,
            solver_principal_sha256="ab",
            same_platform_as_verifier=False,
            statement=HOUSE_INDEPENDENCE_STATEMENT,
            lineage_checks_passed=True,
        )


def test_unknown_inconclusive_reason_is_rejected():
    with pytest.raises(ValueError, match="not a known reason"):
        _build(verdict=Verdict.INCONCLUSIVE, inconclusive_reason="coverage gap")
