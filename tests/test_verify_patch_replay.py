"""Replay protection for POST /api/v1/verify-patch.

A signed request is accepted once, and only inside the timestamp window.
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
from a2a_settlement_mediator.webhook_listener import app

_SECRET = "test-secret"
_PATH = "/api/v1/verify-patch"
_NOW = 1_700_000_000
_TIMESTAMP = str(_NOW)
_WINDOW = "Signature timestamp outside the allowed window"
_INVALID = "Invalid webhook signature"


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
    monkeypatch.setattr(settings, "signature_tolerance_seconds", 300)
    monkeypatch.setattr(
        "a2a_settlement_mediator.webhook_listener._now",
        lambda: float(_NOW),
    )

    def _boom(**_kwargs):
        raise AssertionError("litellm.completion must not be called")

    monkeypatch.setattr(
        "a2a_settlement_mediator.patch_assessor.litellm.completion",
        _boom,
    )
    return TestClient(app)


def _sign(body: bytes, secret: str = _SECRET, timestamp: str = _TIMESTAMP) -> str:
    message = f"{timestamp}.".encode("ascii") + body
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
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


def _post(
    client: TestClient,
    body: bytes,
    signature: str | None,
    timestamp: str | None = _TIMESTAMP,
):
    headers = {"Content-Type": "application/json"}
    if signature is not None:
        headers["X-A2ASE-Signature"] = signature
    if timestamp is not None:
        headers["X-A2ASE-Timestamp"] = timestamp
    return client.post(_PATH, content=body, headers=headers)


def _cached() -> dict[str, float]:
    with sqlite3.connect(storage.DB_PATH) as conn:
        rows = conn.execute(
            "SELECT signature, expires_at FROM verify_patch_signatures"
        ).fetchall()
    return {row[0]: row[1] for row in rows}


def test_valid_fresh_request_passes(client):
    body = _body()
    timestamp = str(_NOW - 40)
    resp = _post(client, body, _sign(body, timestamp=timestamp), timestamp=timestamp)
    assert resp.status_code == 200
    assert resp.json()["outcome"] == "ACCEPTABLE"

    cached = _cached()
    signature_hex = _sign(body, timestamp=timestamp).removeprefix("sha256=")
    assert cached == {signature_hex: (_NOW - 40) + 300}


def test_missing_timestamp_is_401(client):
    body = _body()
    resp = _post(client, body, _sign(body), timestamp=None)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID


def test_missing_signature_is_401(client):
    body = _body()
    resp = _post(client, body, None)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID


@pytest.mark.parametrize("timestamp", ["12ab", "1700000000.0", "-5", ""])
def test_nondigit_timestamp_is_401(client, timestamp):
    body = _body()
    resp = _post(client, body, "sha256=" + ("ab" * 32), timestamp=timestamp)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID


def test_non_ascii_digit_timestamp_is_401(client):
    # U+00B2 is a latin-1 digit. ``str.isdigit`` accepts it; the header must not.
    body = _body()
    resp = client.post(
        _PATH,
        content=body,
        headers={
            "Content-Type": "application/json",
            "X-A2ASE-Signature": "sha256=" + ("ab" * 32),
            "X-A2ASE-Timestamp": "²".encode("latin-1"),
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID


@pytest.mark.parametrize("offset", [301, -301])
def test_timestamp_outside_window_is_401(client, offset):
    body = _body()
    timestamp = str(_NOW + offset)
    resp = _post(client, body, _sign(body, timestamp=timestamp), timestamp=timestamp)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _WINDOW


def test_outside_window_is_checked_before_hmac(client):
    body = _body()
    timestamp = str(_NOW + 301)
    resp = _post(client, body, "sha256=" + ("cd" * 32), timestamp=timestamp)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _WINDOW


@pytest.mark.parametrize("digits", [13, 400, 5000])
def test_oversized_timestamp_is_401(client, digits):
    body = _body()
    resp = _post(client, body, "sha256=" + ("ef" * 32), timestamp="9" * digits)
    assert resp.status_code == 401


def test_far_future_timestamp_is_outside_window(client):
    body = _body()
    resp = _post(client, body, "sha256=" + ("ef" * 32), timestamp="9" * 12)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _WINDOW


def test_body_only_signature_is_rejected(client):
    body = _body()
    digest = hmac.new(_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    resp = _post(client, body, f"sha256={digest}")
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID


def test_signature_over_different_timestamp_is_401(client):
    body = _body()
    resp = _post(
        client,
        body,
        _sign(body, timestamp=str(_NOW)),
        timestamp=str(_NOW + 1),
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID


def test_exact_replay_is_409(client):
    body = _body()
    signature = _sign(body)
    first = _post(client, body, signature)
    second = _post(client, body, signature)
    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json()["detail"] == "Replayed request"
    assert len(_cached()) == 1


def test_invalid_body_is_cached_before_validation(client):
    raw = b"not-json"
    signature = _sign(raw)
    first = _post(client, raw, signature)
    second = _post(client, raw, signature)
    assert first.status_code == 400
    assert second.status_code == 409
    assert second.json()["detail"] == "Replayed request"


def test_rejected_timestamp_is_not_cached(client, monkeypatch):
    body = _body()
    timestamp = str(_NOW + 301)
    signature = _sign(body, timestamp=timestamp)
    early = _post(client, body, signature, timestamp=timestamp)
    assert early.status_code == 401
    assert early.json()["detail"] == _WINDOW
    assert _cached() == {}

    monkeypatch.setattr(
        "a2a_settlement_mediator.webhook_listener._now",
        lambda: float(_NOW + 301),
    )
    later = _post(client, body, signature, timestamp=timestamp)
    assert later.status_code == 200


def test_expired_cache_entry_is_purged(client):
    now = float(_NOW)
    expired = "11" * 32
    still_valid = "22" * 32
    assert storage.remember_patch_signature(expired, now - 1, now - 10) is True
    assert storage.remember_patch_signature(still_valid, now + 1000, now - 10) is True

    # The conflicting insert still commits the delete of expired rows.
    assert storage.remember_patch_signature(still_valid, now + 1000, now) is False
    assert set(_cached()) == {still_valid}

    # Once its own row is gone, the same signature can be recorded again.
    assert storage.remember_patch_signature(expired, now + 50, now) is True
    assert set(_cached()) == {still_valid, expired}

    route_expired = "33" * 32
    assert storage.remember_patch_signature(route_expired, now - 1, now - 1) is True
    body = _body(git_diff="diff --git a/a.py b/a.py\n+purge\n")
    timestamp = str(_NOW - 15)
    resp = _post(client, body, _sign(body, timestamp=timestamp), timestamp=timestamp)
    assert resp.status_code == 200

    cached = _cached()
    # The route's clock is the frozen one: this row is already expired there,
    # and still_valid is not (a wall-clock `now` would have deleted it).
    assert route_expired not in cached
    assert still_valid in cached
    assert expired in cached
    fresh = _sign(body, timestamp=timestamp).removeprefix("sha256=")
    assert cached[fresh] == (_NOW - 15) + 300


def test_tolerance_comes_from_settings(client, monkeypatch):
    monkeypatch.setattr(settings, "signature_tolerance_seconds", 10)
    body = _body(git_diff="diff --git a/a.py b/a.py\n+tol\n")
    now = _NOW
    for offset in (-10, 10):
        timestamp = str(now + offset)
        resp = _post(client, body, _sign(body, timestamp=timestamp), timestamp=timestamp)
        assert resp.status_code == 200, timestamp

    for offset in (-11, 11):
        timestamp = str(now + offset)
        resp = _post(client, body, _sign(body, timestamp=timestamp), timestamp=timestamp)
        assert resp.status_code == 401
        assert resp.json()["detail"] == _WINDOW
