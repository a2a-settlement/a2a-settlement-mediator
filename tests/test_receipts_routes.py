"""HTTP API for proof-of-fix receipts. The TSA and signer never touch the network."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator import storage
from a2a_settlement_mediator.config import ReceiptsConfigError, settings
from a2a_settlement_mediator.receipts.routes import set_receipt_service
from a2a_settlement_mediator.receipts.service import ReceiptService, granted_timestamp_token
from a2a_settlement_mediator.receipts.signer import LocalSigner
from a2a_settlement_mediator.receipts.store import ReceiptStore
from a2a_settlement_mediator.webhook_listener import app
from a2a_settlement_mediator.worm_schemas import TimestampToken

_SECRET = "test-secret"
_NOW = 1_700_000_000
_TIMESTAMP = str(_NOW)
_FIX = "b" * 40
_NONCE = "0123456789abcdef0123456789abcdef"
_NONCE_2 = "fedcba9876543210fedcba9876543210"
_TSA = "https://tsa.example.com/rfc3161"
_ISSUE = "/api/v1/receipts"
_KEYS = "/.well-known/settlebridge-receipt-keys.json"


class FakeTSA:
    def __init__(self) -> None:
        self.hashes: list[bytes] = []

    def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
        self.hashes.append(bytes(payload_hash))
        return granted_timestamp_token(payload_hash, _TSA)


def _draft(**overrides) -> dict:
    data = {
        "receipt_id": "rcpt-1",
        "vulnerability": {"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2026-0001"]},
        "repo": "acme/widget",
        "base_commit": "a" * 40,
        "fix_commit": _FIX,
        "pr": 42,
        "verdict": "verified",
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
        "solver_kind": "third_party",
        "solver_principal_sha256": "44" * 32,
        "same_platform_as_verifier": False,
        "independence_statement": "The fix was produced by a third-party solver.",
        "lineage_checks_passed": True,
        "issued_at": "2026-11-10T18:00:00Z",
        "nonce": _NONCE,
    }
    data.update(overrides)
    return data


def _body(**overrides) -> bytes:
    return json.dumps(_draft(**overrides)).encode("utf-8")


def _sign(body: bytes, timestamp: str = _TIMESTAMP, secret: str = _SECRET) -> str:
    message = f"{timestamp}.".encode("ascii") + body
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _post(
    client: TestClient,
    body: bytes,
    timestamp: str = _TIMESTAMP,
    signature: str | None = None,
):
    headers = {"Content-Type": "application/json", "X-A2ASE-Timestamp": timestamp}
    if signature is not None:
        headers["X-A2ASE-Signature"] = signature
    else:
        headers["X-A2ASE-Signature"] = _sign(body, timestamp)
    return client.post(_ISSUE, content=body, headers=headers)


def _payload(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))


@pytest.fixture
def api(tmp_path, monkeypatch):
    database = tmp_path / "mediator.db"
    monkeypatch.setattr(storage, "DB_PATH", str(database))
    monkeypatch.setattr(settings, "receipts_enabled", True)
    monkeypatch.setattr(settings, "receipts_public", False)
    monkeypatch.setattr(settings, "webhook_secret", _SECRET)
    monkeypatch.setattr(settings, "signature_tolerance_seconds", 300)
    monkeypatch.setattr(settings, "tsa_url", _TSA)
    monkeypatch.setattr(
        "a2a_settlement_mediator.webhook_listener._now",
        lambda: float(_NOW),
    )
    tsa = FakeTSA()
    service = ReceiptService(LocalSigner("kid-test"), tsa, ReceiptStore(str(database)))
    set_receipt_service(service)
    try:
        with TestClient(app) as client:
            yield client, service, tsa
    finally:
        set_receipt_service(None)


def test_disabled_routes_are_404(api, monkeypatch):
    client, _service, _tsa = api
    monkeypatch.setattr(settings, "receipts_enabled", False)
    assert client.post(_ISSUE, content=_body()).status_code == 404
    assert client.get(f"{_ISSUE}/rcpt-1").status_code == 404
    assert client.post(f"{_ISSUE}/verify", content=b"{}").status_code == 404
    assert client.get(_KEYS).status_code == 404


def test_missing_secret_is_503(api, monkeypatch):
    client, _service, _tsa = api
    monkeypatch.setattr(settings, "webhook_secret", "")
    response = _post(client, _body())
    assert response.status_code == 503
    assert response.json()["detail"] == "receipts require MEDIATOR_WEBHOOK_SECRET"


def test_bad_signature_and_window_are_401(api):
    client, _service, _tsa = api
    body = _body()
    refused = _post(client, body, signature="sha256=deadbeef")
    assert refused.status_code == 401

    missing = client.post(_ISSUE, content=body)
    assert missing.status_code == 401

    stale = _post(client, body, timestamp="1")
    assert stale.status_code == 401
    assert "window" in stale.json()["detail"]


def test_replay_is_409(api):
    client, _service, _tsa = api
    body = _body()
    signature = _sign(body)
    assert _post(client, body, signature=signature).status_code == 201
    replay = _post(client, body, signature=signature)
    assert replay.status_code == 409
    assert replay.json()["detail"] == "Replayed request"


def test_duplicate_receipt_id_and_nonce_are_409(api):
    client, _service, _tsa = api
    assert _post(client, _body()).status_code == 201

    same_id = _body(nonce=_NONCE_2)
    by_id = _post(client, same_id, timestamp="1700000001")
    assert by_id.status_code == 409
    assert by_id.json()["detail"] == "duplicate receipt_id"

    same_nonce = _body(receipt_id="rcpt-2")
    by_nonce = _post(client, same_nonce, timestamp="1700000002")
    assert by_nonce.status_code == 409
    assert by_nonce.json()["detail"] == "duplicate nonce"


def test_invalid_payload_is_400(api):
    client, _service, _tsa = api
    raw = b"not-json"
    assert _post(client, raw).status_code == 400
    missing = json.dumps({"receipt_id": "rcpt-1"}).encode("utf-8")
    assert _post(client, missing, timestamp="1700000001").status_code == 400


def test_round_trip_issue_get_verify(api):
    client, _service, tsa = api
    created = _post(client, _body())
    assert created.status_code == 201
    document = created.json()
    assert len(tsa.hashes) == 1
    assert document["statement_envelope"]["signatures"][0]["keyid"] == "kid-test"

    fetched = client.get(f"{_ISSUE}/rcpt-1")
    assert fetched.status_code == 200
    assert fetched.json() == document

    verified = client.post(
        f"{_ISSUE}/verify",
        json={"receipt_id": "rcpt-1", "repo": "acme/widget", "commit": _FIX},
    )
    assert verified.status_code == 200
    body = verified.json()
    assert body["valid"] is True
    assert all(check["ok"] for check in body["checks"].values())

    submitted = client.post(f"{_ISSUE}/verify", json=document)
    assert submitted.status_code == 200
    assert submitted.json()["valid"] is True

    vsa = _payload(document["vsa_envelope"])
    assert vsa["predicate"]["verificationResult"] == "PASSED"
    assert client.get(f"{_ISSUE}/missing").status_code == 404
    assert client.post(f"{_ISSUE}/verify", json={}).status_code == 400


def test_tampered_payload_and_wrong_kid_fail_verification(api):
    client, _service, _tsa = api
    document = _post(client, _body()).json()

    tampered = json.loads(json.dumps(document))
    raw = bytearray(base64.b64decode(tampered["statement_envelope"]["payload"]))
    raw[-2] ^= 0x01
    tampered["statement_envelope"]["payload"] = base64.b64encode(bytes(raw)).decode("ascii")
    failed = client.post(f"{_ISSUE}/verify", json=tampered)
    assert failed.status_code == 200
    assert failed.json()["valid"] is False
    assert failed.json()["checks"]["dsse_statement"]["ok"] is False

    wrong_kid = json.loads(json.dumps(document))
    wrong_kid["statement_envelope"]["signatures"][0]["keyid"] = "missing-kid"
    mismatched = client.post(f"{_ISSUE}/verify", json=wrong_kid)
    assert mismatched.status_code == 200
    assert mismatched.json()["valid"] is False
    assert mismatched.json()["checks"]["dsse_statement"]["ok"] is False

    wrong_repo = client.post(
        f"{_ISSUE}/verify",
        json={"receipt_id": "rcpt-1", "repo": "other/repo", "commit": _FIX},
    )
    assert wrong_repo.json()["checks"]["subject"]["ok"] is False
    assert wrong_repo.json()["checks"]["dsse_statement"]["ok"] is True
    assert wrong_repo.json()["valid"] is False


def test_key_rotation_lists_retired_keys(api):
    client, service, _tsa = api
    _post(client, _body())
    service.rotate_signer(LocalSigner("kid-next"))
    listed = client.get(_KEYS)
    assert listed.status_code == 200
    keys = {key["kid"]: key for key in listed.json()["keys"]}
    assert keys["kid-test"]["retired"] is True
    assert keys["kid-test"]["kty"] == "EC"
    assert keys["kid-test"]["alg"] == "ES256"
    assert keys["kid-next"]["retired"] is False
    assert client.post(f"{_ISSUE}/verify", json={"receipt_id": "rcpt-1"}).json()["valid"] is True

    later = _post(client, _body(receipt_id="rcpt-2", nonce=_NONCE_2), timestamp="1700000001")
    assert later.status_code == 201
    assert later.json()["statement_envelope"]["signatures"][0]["keyid"] == "kid-next"
    assert client.post(f"{_ISSUE}/verify", json={"receipt_id": "rcpt-2"}).json()["valid"] is True


def test_house_receipt_has_no_independence_boolean(api):
    client, _service, _tsa = api
    response = _post(
        client,
        _body(
            solver_kind="house",
            same_platform_as_verifier=False,
            lineage_checks_passed=False,
            independence_statement="ignored for house solvers",
        ),
    )
    assert response.status_code == 201
    payload = _payload(response.json()["statement_envelope"])
    independence = payload["predicate"]["independence"]
    assert "verifier_independent_of_solver" not in independence
    assert independence["solver_kind"] == "house"
    raw = base64.b64decode(response.json()["statement_envelope"]["payload"])
    assert b"verifier_independent_of_solver" not in raw
    vsa = _payload(response.json()["vsa_envelope"])
    assert vsa["predicate"]["verificationResult"] == "PASSED"


def test_inconclusive_vsa_is_failed(api):
    client, _service, _tsa = api
    response = _post(
        client,
        _body(verdict="inconclusive", inconclusive_reason="coverage gap"),
    )
    assert response.status_code == 201
    vsa = _payload(response.json()["vsa_envelope"])
    assert vsa["predicate"]["verificationResult"] == "FAILED"
    assert client.post(f"{_ISSUE}/verify", json={"receipt_id": "rcpt-1"}).json()["valid"] is True


def _startup_error(exc: BaseException) -> str:
    grouped = getattr(exc, "exceptions", None)
    if grouped:
        return " ".join(_startup_error(item) for item in grouped)
    return str(exc)


def test_startup_refuses_public_freetsa(monkeypatch):
    monkeypatch.setattr(settings, "receipts_public", True)
    monkeypatch.setattr(settings, "receipts_enabled", False)
    monkeypatch.setattr(settings, "tsa_url", "http://freetsa.org/tsr")
    with pytest.raises(BaseException) as caught:
        with TestClient(app):
            pass
    text = _startup_error(caught.value)
    assert "free timestamp authority" in text
    assert "freetsa.org" in text
    is_config_error = isinstance(caught.value, ReceiptsConfigError)
    assert is_config_error or "ReceiptsConfigError" in repr(caught.value)


def test_startup_allows_public_commercial_tsa(monkeypatch):
    monkeypatch.setattr(settings, "receipts_public", True)
    monkeypatch.setattr(settings, "receipts_enabled", False)
    monkeypatch.setattr(settings, "tsa_url", "https://tsa.example.com/rfc3161")
    with TestClient(app) as client:
        assert client.get(f"{_ISSUE}/rcpt-1").status_code == 404
        assert client.get("/health").status_code == 200
