"""Receipt issuance: DSSE, one RFC 3161 token, Merkle inclusion, and JWKS."""

from __future__ import annotations

import base64
import copy
import json
from datetime import datetime, timezone

import pytest

from a2a_settlement_mediator.config import (
    FREE_TSA_HOSTS,
    ReceiptsConfigError,
    assert_public_receipts_tsa,
    is_free_tsa_url,
)
from a2a_settlement_mediator.receipts.predicate import ProofOfFixDraft, SolverKind, Verdict
from a2a_settlement_mediator.receipts.service import (
    ReceiptIssueError,
    ReceiptService,
    build_granted_timestamp_der,
    combined_envelope_digest,
    granted_timestamp_token,
    message_imprint_sha256,
)
from a2a_settlement_mediator.receipts.signer import LocalSigner
from a2a_settlement_mediator.receipts.store import (
    GENESIS_PREV_HASH,
    DuplicateReceipt,
    ReceiptStore,
    compute_row_hash,
)
from a2a_settlement_mediator.tsa_client import parse_timestamp_response_status
from a2a_settlement_mediator.worm_schemas import TimestampToken

_ISSUED = datetime(2026, 11, 10, 18, 0, tzinfo=timezone.utc)
_NONCE = "0123456789abcdef0123456789abcdef"
_NONCE_2 = "fedcba9876543210fedcba9876543210"
_FIX = "b" * 40
_TSA = "https://tsa.example.com/rfc3161"
_THIRD_PARTY_STATEMENT = "The fix was produced by a third-party solver on a separate platform."


class FakeTSA:
    def __init__(self) -> None:
        self.hashes: list[bytes] = []

    def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
        self.hashes.append(bytes(payload_hash))
        return granted_timestamp_token(payload_hash, _TSA)


class LiarTSA:
    """Reports the right message_hash but stamps a different imprint."""

    def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
        token = granted_timestamp_token(b"\x11" * 32, _TSA)
        return token.model_copy(update={"message_hash": payload_hash.hex()})


def _draft(**overrides) -> ProofOfFixDraft:
    data = {
        "receipt_id": "rcpt-1",
        "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-0001"]},
        "repo": "acme/widget",
        "base_commit": "a" * 40,
        "fix_commit": _FIX,
        "pr": 42,
        "verdict": Verdict.VERIFIED,
        "inconclusive_reason": None,
        "failure_classes_tested": ["bounds"],
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
            "seeds": [1],
        },
        "verifier": {
            "id": "https://settlebridge.ai/verifiers/proof-of-fix",
            "operator": "verifier-ops",
            "key_id": "kid-test",
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
    return ProofOfFixDraft(**data)


def _payload(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))


@pytest.fixture
def tsa() -> FakeTSA:
    return FakeTSA()


@pytest.fixture
def service(tsa: FakeTSA, tmp_path) -> ReceiptService:
    store = ReceiptStore(str(tmp_path / "receipts.db"))
    return ReceiptService(LocalSigner("kid-test"), tsa, store)


def test_issue_timestamps_both_envelopes_once(service: ReceiptService, tsa: FakeTSA):
    document = service.issue(_draft())
    digest = combined_envelope_digest(
        document["statement_envelope"], document["vsa_envelope"]
    )
    assert tsa.hashes == [digest]
    assert document["message_hash"] == digest.hex()
    assert document["prev_hash"] == GENESIS_PREV_HASH
    body = {key: value for key, value in document.items() if key != "row_hash"}
    assert compute_row_hash(body, document["prev_hash"]) == document["row_hash"]
    assert service.verify_chain().ok is True

    checked = service.verify(
        receipt_id=document["receipt_id"], repo="acme/widget", commit=_FIX
    )
    assert checked["valid"] is True
    assert set(checked["checks"]) == {
        "dsse_statement",
        "dsse_vsa",
        "vsa_consistency",
        "tsa_binding",
        "merkle_inclusion",
        "subject",
    }
    assert all(item["ok"] for item in checked["checks"].values())
    assert checked["checks"]["subject"]["skipped"] is False

    skipped = service.verify(receipt_id="rcpt-1")
    assert skipped["valid"] is True
    assert skipped["checks"]["subject"]["skipped"] is True


@pytest.mark.parametrize(
    ("verdict", "reason", "result"),
    [
        (Verdict.VERIFIED, None, "PASSED"),
        (Verdict.INCOMPLETE_FIX_CONFIRMED, None, "FAILED"),
        (Verdict.INCONCLUSIVE, "coverage gap", "FAILED"),
    ],
)
def test_vsa_matches_verdict(service, verdict, reason, result):
    document = service.issue(_draft(verdict=verdict, inconclusive_reason=reason))
    payload = _payload(document["vsa_envelope"])
    statement = _payload(document["statement_envelope"])
    assert payload["predicate"]["verificationResult"] == result
    assert statement["predicate"]["verdict"] == verdict.value
    assert service.verify(receipt_id="rcpt-1")["checks"]["vsa_consistency"]["ok"] is True


def test_house_receipt_omits_independence_claim(service: ReceiptService):
    document = service.issue(
        _draft(
            solver_kind=SolverKind.HOUSE,
            same_platform_as_verifier=False,
            lineage_checks_passed=False,
            independence_statement="caller text that must be replaced",
        )
    )
    payload = _payload(document["statement_envelope"])
    independence = payload["predicate"]["independence"]
    assert "verifier_independent_of_solver" not in independence
    assert independence["solver_kind"] == "house"
    assert independence["same_platform_as_verifier"] is True
    raw = base64.b64decode(document["statement_envelope"]["payload"])
    assert b"verifier_independent_of_solver" not in raw

    claimed = service.issue(
        _draft(receipt_id="rcpt-2", nonce=_NONCE_2, solver_kind=SolverKind.THIRD_PARTY)
    )
    third = _payload(claimed["statement_envelope"])["predicate"]["independence"]
    assert third["verifier_independent_of_solver"] is True


def test_second_receipt_keeps_the_first_merkle_proof(service: ReceiptService):
    first = service.issue(_draft())
    second = service.issue(_draft(receipt_id="rcpt-2", nonce=_NONCE_2))
    assert first["merkle_proof"]["root_hash"] != second["merkle_proof"]["root_hash"]
    assert service.verify(receipt_id="rcpt-1")["checks"]["merkle_inclusion"]["ok"] is True
    assert service.verify(receipt_id="rcpt-2")["checks"]["merkle_inclusion"]["ok"] is True
    assert second["prev_hash"] == first["row_hash"]
    assert service.verify_chain().rows == 2


def test_tampered_payload_and_wrong_kid_fail(service: ReceiptService):
    document = service.issue(_draft())
    tampered = copy.deepcopy(document["statement_envelope"])
    raw = bytearray(base64.b64decode(tampered["payload"]))
    raw[-2] ^= 0x01
    tampered["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    failed = service.verify(
        statement_envelope=tampered,
        vsa_envelope=document["vsa_envelope"],
        timestamp_token_b64=document["timestamp_token_b64"],
        merkle_proof=document["merkle_proof"],
        repo="acme/widget",
        commit=_FIX,
    )
    assert failed["valid"] is False
    assert failed["checks"]["dsse_statement"]["ok"] is False

    wrong_kid = copy.deepcopy(document["statement_envelope"])
    wrong_kid["signatures"][0]["keyid"] = "missing-kid"
    mismatched = service.verify(
        statement_envelope=wrong_kid,
        vsa_envelope=document["vsa_envelope"],
        timestamp_token_b64=document["timestamp_token_b64"],
        merkle_proof=document["merkle_proof"],
    )
    assert mismatched["valid"] is False
    assert "keyid" in mismatched["checks"]["dsse_statement"]["detail"]

    wrong_repo = service.verify(receipt_id="rcpt-1", repo="other/repo", commit=_FIX)
    assert wrong_repo["checks"]["dsse_statement"]["ok"] is True
    assert wrong_repo["checks"]["subject"]["ok"] is False
    assert wrong_repo["valid"] is False


def test_swapped_timestamp_fails_binding(service: ReceiptService):
    document = service.issue(_draft())
    other = granted_timestamp_token(b"\x22" * 32, _TSA)
    checked = service.verify(
        statement_envelope=document["statement_envelope"],
        vsa_envelope=document["vsa_envelope"],
        timestamp_token_b64=other.timestamp_token_b64,
        merkle_proof=document["merkle_proof"],
    )
    assert checked["checks"]["dsse_statement"]["ok"] is True
    assert checked["checks"]["tsa_binding"]["ok"] is False
    assert checked["checks"]["merkle_inclusion"]["ok"] is True
    assert checked["valid"] is False


def test_key_rotation_keeps_old_signatures_verifiable(service: ReceiptService):
    document = service.issue(_draft())
    published = service.rotate_signer(LocalSigner("kid-next"))
    by_kid = {key["kid"]: key for key in published["keys"]}
    assert by_kid["kid-test"]["retired"] is True
    assert by_kid["kid-next"]["retired"] is False
    assert service.verify(receipt_id="rcpt-1")["valid"] is True

    swapped = copy.deepcopy(document["statement_envelope"])
    swapped["signatures"][0]["keyid"] = "kid-next"
    failed = service.verify(
        statement_envelope=swapped,
        vsa_envelope=document["vsa_envelope"],
        timestamp_token_b64=document["timestamp_token_b64"],
        merkle_proof=document["merkle_proof"],
    )
    assert failed["checks"]["dsse_statement"]["ok"] is False

    later = service.issue(_draft(receipt_id="rcpt-2", nonce=_NONCE_2))
    assert later["statement_envelope"]["signatures"][0]["keyid"] == "kid-next"
    assert service.verify(receipt_id="rcpt-2")["valid"] is True


def test_restarted_local_signer_keeps_previous_receipts_verifiable(tmp_path):
    path = str(tmp_path / "receipts.db")
    first_signer = LocalSigner("local-dev")
    first = ReceiptService(first_signer, FakeTSA(), ReceiptStore(path))
    first.issue(_draft())
    second_signer = LocalSigner("local-dev")
    assert first_signer.public_jwk()["x"] != second_signer.public_jwk()["x"]

    second = ReceiptService(second_signer, FakeTSA(), ReceiptStore(path))
    assert second.verify(receipt_id="rcpt-1")["valid"] is True
    later = second.issue(_draft(receipt_id="rcpt-2", nonce=_NONCE_2))
    assert later["statement_envelope"]["signatures"][0]["keyid"] == "local-dev"
    assert second.verify(receipt_id="rcpt-2")["valid"] is True
    keys = second.jwks()["keys"]
    assert [key["kid"] for key in keys].count("local-dev") == 2
    assert sum(not key["retired"] for key in keys) == 1
    assert keys[0]["retired"] is False


def test_duplicate_receipt_id_and_nonce(service: ReceiptService):
    service.issue(_draft())
    with pytest.raises(DuplicateReceipt) as by_id:
        service.issue(_draft(nonce=_NONCE_2))
    assert by_id.value.field == "receipt_id"
    with pytest.raises(DuplicateReceipt) as by_nonce:
        service.issue(_draft(receipt_id="rcpt-2"))
    assert by_nonce.value.field == "nonce"


def test_liar_tsa_is_rejected(tmp_path):
    service = ReceiptService(
        LocalSigner("kid-test"), LiarTSA(), ReceiptStore(str(tmp_path / "receipts.db"))
    )
    with pytest.raises(ReceiptIssueError, match="bind"):
        service.issue(_draft())
    assert service.verify_chain().rows == 0


def test_granted_timestamp_der_exposes_one_imprint():
    digest = b"\x33" * 32
    der = build_granted_timestamp_der(digest)
    assert parse_timestamp_response_status(der) == 0
    assert message_imprint_sha256(der) == digest
    assert der.count(_IMPRINT_PREFIX()) == 1


def _IMPRINT_PREFIX() -> bytes:
    return bytes.fromhex("300d060960864801650304020105000420")


def test_every_denylisted_host_is_refused_for_public_receipts():
    for host in FREE_TSA_HOSTS:
        url = f"https://{host}/tsr"
        assert is_free_tsa_url(url) is True
        with pytest.raises(ReceiptsConfigError, match="free timestamp authority"):
            assert_public_receipts_tsa(True, url)
        assert_public_receipts_tsa(False, url)


@pytest.mark.parametrize(
    ("url", "free"),
    [
        ("HTTP://FREETSA.ORG/TSR", True),
        ("https://www.freetsa.org/tsr", True),
        ("http://tsa.freetsa.org/api", True),
        ("http://user:pass@timestamp.sectigo.com/qualified", True),
        ("https://a.timestamp.apple.com/ts", True),
        ("http://notfreetsa.org/tsr", False),
        ("http://freetsa.org.evil.com/tsr", False),
        ("https://tsa.example.com/rfc3161", False),
    ],
)
def test_free_tsa_host_matching(url, free):
    assert is_free_tsa_url(url) is free
    if free:
        with pytest.raises(ReceiptsConfigError, match="free timestamp authority"):
            assert_public_receipts_tsa(True, url)
    else:
        assert_public_receipts_tsa(True, url)
