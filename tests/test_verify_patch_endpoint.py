"""HTTP tests for POST /api/v1/verify-patch.

Signature checks fail closed. The auditor is stubbed and litellm is never called.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator import storage
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.schemas import (
    FindingSeverity,
    PolicyFinding,
    PolicyRule,
)
from a2a_settlement_mediator.webhook_listener import app

_SECRET = "test-secret"
_PATH = "/api/v1/verify-patch"


@pytest.fixture
def audit(monkeypatch):
    state = {"findings": []}

    def _audit(_diff, _policy):
        return list(state["findings"])

    monkeypatch.setattr("a2a_settlement_mediator.patch_assessor.audit_diff", _audit)
    return state


@pytest.fixture
def client(tmp_path, monkeypatch, audit):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "mediator.db"))
    storage.initialize_db()
    monkeypatch.setattr(settings, "webhook_secret", _SECRET)

    def _boom(**_kwargs):
        raise AssertionError("litellm.completion must not be called")

    monkeypatch.setattr(
        "a2a_settlement_mediator.patch_assessor.litellm.completion",
        _boom,
    )
    return TestClient(app)


def _sign(body: bytes, secret: str = _SECRET) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _body(**overrides) -> bytes:
    payload = {
        "spec_hash": "spec-1",
        "repo": "acme/widget",
        "pr_number": 12,
        "head_sha": "abc123",
        "git_diff": "diff --git a/a.py b/a.py\n+a\n",
        "enable_reviewer": False,
    }
    payload.update(overrides)
    return json.dumps(payload).encode("utf-8")


def _post(client: TestClient, body: bytes, signature: str | None):
    headers = {"Content-Type": "application/json"}
    if signature is not None:
        headers["X-A2ASE-Signature"] = signature
    return client.post(_PATH, content=body, headers=headers)


def _key() -> str:
    return "patch:acme/widget#12@abc123:spec-1"


def test_missing_secret_is_503(client, monkeypatch):
    monkeypatch.setattr(settings, "webhook_secret", "")
    body = _body()
    resp = _post(client, body, _sign(body))
    assert resp.status_code == 503
    assert resp.json()["detail"] == "verify-patch requires MEDIATOR_WEBHOOK_SECRET"


def test_bad_signature_is_401(client):
    body = _body()
    resp = _post(client, body, "sha256=deadbeef")
    assert resp.status_code == 401

    missing = _post(client, body, None)
    assert missing.status_code == 401

    shifted = bytearray(body)
    shifted[-1] ^= 0x01
    resp = _post(client, body, _sign(bytes(shifted)))
    assert resp.status_code == 401


def test_good_signature_returns_outcome(client):
    body = _body()
    resp = _post(client, body, _sign(body))
    assert resp.status_code == 200
    data = resp.json()
    diff = json.loads(body)["git_diff"]
    assert data["outcome"] == "ACCEPTABLE"
    assert data["diff_sha256"] == hashlib.sha256(diff.encode("utf-8")).hexdigest()
    assert data["reviewer_opinion"]["status"] == "skipped"
    assert data["trace_consistency"]["status"] == "absent"
    assert data["repo"] == "acme/widget"
    assert data["pr_number"] == 12


def test_violation_flows_through_without_reviewer(client, audit):
    audit["findings"] = [
        PolicyFinding(
            rule=PolicyRule.DEPENDENCY_CHANGED,
            severity=FindingSeverity.VIOLATION,
            path="requirements.txt",
            evidence="added package",
            source="deterministic",
        )
    ]
    body = _body(enable_reviewer=True)
    resp = _post(client, body, _sign(body))
    assert resp.status_code == 200
    data = resp.json()
    assert data["outcome"] == "POLICY_VIOLATION"
    assert data["reviewer_opinion"]["status"] == "skipped"
    assert data["findings"][0]["source"] == "deterministic"


def test_invalid_body_is_400(client):
    raw = b"not-json"
    resp = _post(client, raw, _sign(raw))
    assert resp.status_code == 400

    missing = json.dumps({"repo": "acme/widget"}).encode("utf-8")
    resp = _post(client, missing, _sign(missing))
    assert resp.status_code == 400


def test_repeated_request_overwrites(client):
    first_body = _body(git_diff="diff --git a/a.py b/a.py\n+first\n")
    second_body = _body(git_diff="diff --git a/a.py b/a.py\n+second\n")
    # Identical replay, then a second body that maps to the same storage key.
    again = _post(client, first_body, _sign(first_body))
    first = _post(client, first_body, _sign(first_body))
    second = _post(client, second_body, _sign(second_body))
    assert again.status_code == 200
    assert first.status_code == 200
    assert second.status_code == 200

    with sqlite3.connect(storage.DB_PATH) as conn:
        count = conn.execute("SELECT COUNT(*) FROM patch_assessments").fetchone()[0]
    stored = storage.get_patch_assessment(_key())
    assert count == 1
    assert stored is not None
    assert stored["diff_sha256"] == second.json()["diff_sha256"]
    assert stored["diff_sha256"] != first.json()["diff_sha256"]
    assert stored["issued_at"] == second.json()["issued_at"]
