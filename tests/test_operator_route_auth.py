"""Authentication on the operator routes and the fail-closed webhook.

Every operator route requires ``X-A2ASE-Signature: v2=<hex>`` over
``v2\\n{timestamp}\\n{nonce}\\n{METHOD}\\n{target}\\n{body}``. A signature is
bound to one method and one target, accepted once, and only inside the
timestamp window. With no secret the routes refuse unless the development
opt-out is on.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator import storage, webhook_listener
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.webhook_listener import app, operator_signature_message

_SECRET = "test-secret"
_NOW = 1_700_000_000
_TIMESTAMP = str(_NOW)
_NONCE = "nonce-0123456789abcdef"
_INVALID = "Invalid operator signature"
_WINDOW = "Signature timestamp outside the allowed window"
_UNCONFIGURED = "operator routes require MEDIATOR_WEBHOOK_SECRET"

_SETTLE_BODY = json.dumps(
    {"transcript_hash": "ab" * 32, "mandates": [], "escrow_id": "esc-1"}
).encode()
_ACK_BODY = json.dumps({"settlement_hash": "missing", "status": "executed"}).encode()

# (method, target, body, status once authentication has passed)
_ROUTES = [
    ("GET", "/audits", None, 200),
    ("GET", "/audits/esc-1", None, 200),
    ("POST", "/mediate/esc-1", b'{"mode":"training"}', 200),
    ("POST", "/settle", _SETTLE_BODY, 200),
    ("GET", "/settlements", None, 200),
    ("GET", "/merkle", None, 200),
    ("GET", "/settlements/pending", None, 200),
    # The handler answers 404 for an unknown settlement hash: authentication passed.
    ("POST", "/settlements/ack", _ACK_BODY, 404),
    ("GET", "/heartbeat/status", None, 200),
]
_IDS = [f"{method} {target}" for method, target, _body, _ok in _ROUTES]
_route = pytest.mark.parametrize("method,target,body,ok_status", _ROUTES, ids=_IDS)

# Routes that are intentionally reachable without an operator signature.
_PUBLIC = {
    ("GET", "/health"),
    ("GET", "/guide"),
    ("GET", "/schemas"),
    # Receipt lookups are public by design and 404 unless receipts are enabled.
    ("GET", "/api/v1/receipts/{receipt_id}"),
    ("POST", "/api/v1/receipts/verify"),
    ("GET", "/.well-known/settlebridge-receipt-keys.json"),
}
# Routes that verify their own HMAC inside the handler.
_OWN_HMAC = {
    ("POST", "/webhook"),
    ("POST", "/api/v1/verify-patch"),
    ("POST", "/api/v1/receipts"),
}


@pytest.fixture
def handlers(monkeypatch):
    """Stub the work behind the routes and record whether it ran."""
    mediate = MagicMock(
        return_value=MagicMock(
            model_dump=lambda mode: {"escrow_id": "esc-1"},
            model_dump_json=lambda: '{"escrow_id": "esc-1"}',
        )
    )
    settle = MagicMock(
        return_value=MagicMock(
            model_dump=lambda mode: {"stage": "confirmed"},
            model_dump_json=lambda: '{"stage": "confirmed"}',
            settlement_hash="",
        )
    )
    monkeypatch.setattr(webhook_listener, "mediate", mediate)
    monkeypatch.setattr(webhook_listener, "settle", settle)
    return {"mediate": mediate, "settle": settle}


@pytest.fixture
def client(tmp_path, monkeypatch, handlers):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "mediator.db"))
    storage.initialize_db()
    storage.save_audit_record("esc-1", '{"escrow_id": "esc-1"}')
    # Audit rows are unique per escrow and second; the routes under test would
    # otherwise collide with the row above.
    monkeypatch.setattr(storage, "save_audit_record", MagicMock())
    monkeypatch.setattr(settings, "webhook_secret", _SECRET)
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    monkeypatch.setattr(settings, "signature_tolerance_seconds", 300)
    monkeypatch.setattr(webhook_listener, "_now", lambda: float(_NOW))
    return TestClient(app)


def _sign(
    method: str,
    target: str,
    body: bytes | None,
    *,
    secret: str = _SECRET,
    timestamp: str = _TIMESTAMP,
    nonce: str = _NONCE,
) -> dict[str, str]:
    message = operator_signature_message(
        timestamp, nonce, method, target.encode(), body or b""
    )
    digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
    return {
        "X-A2ASE-Timestamp": timestamp,
        "X-A2ASE-Nonce": nonce,
        "X-A2ASE-Signature": f"v2={digest}",
    }


def _send(client: TestClient, method: str, target: str, body: bytes | None, headers=None):
    headers = dict(headers or {})
    if body is not None:
        headers["Content-Type"] = "application/json"
    # Bytes, so a test can put non-ASCII octets in a header value.
    raw = [(k.encode("ascii"), v.encode("utf-8")) for k, v in headers.items()]
    return client.request(method, target, content=body, headers=raw)


def _assert_untouched(handlers) -> None:
    handlers["mediate"].assert_not_called()
    handlers["settle"].assert_not_called()


def _other(method: str) -> str:
    return "POST" if method == "GET" else "GET"


# ---------------------------------------------------------------------------
# Wire format
# ---------------------------------------------------------------------------


def test_signed_message_layout():
    message = operator_signature_message(
        "1700000000", "n" * 16, "post", b"/mediate/esc-1?x=1", b'{"a":1}'
    )
    assert message == (
        b"v2\n1700000000\n" + b"n" * 16 + b"\nPOST\n/mediate/esc-1?x=1\n" + b'{"a":1}'
    )


@pytest.mark.parametrize(
    "method,target,body,expected",
    [
        (
            "POST",
            b"/mediate/esc-1",
            b'{"mode":"training","task_type":"recon"}',
            "3b161354e7bf99a50429f28cde82f37f5b831300888654a6b74b26b5dfbb6cef",
        ),
        (
            "GET",
            b"/audits/esc-1",
            b"",
            "a9b40202f1b088408993b4ad610ff1adbf632d23a71be068f72a58f982f4b250",
        ),
    ],
)
def test_known_answer_vectors(method, target, body, expected):
    """The SettleBridge backend asserts the same values in its own tests."""
    message = operator_signature_message(
        "1700000000", "0123456789abcdefghij", method, target, body
    )
    assert hmac.new(b"topsecret", message, hashlib.sha256).hexdigest() == expected


def test_every_route_is_public_self_verifying_or_operator_authenticated(client, monkeypatch):
    """A new route must be classified here, so it cannot ship open by accident.

    Routes are taken from the generated OpenAPI document, so included routers
    are covered. Anything not listed as public or self-verifying must reject
    an unsigned request with the operator-signature error.
    """
    monkeypatch.setattr(settings, "receipts_enabled", True)
    protected = set()
    for path, operations in app.openapi()["paths"].items():
        for method in operations:
            key = (method.upper(), path)
            if key in _PUBLIC | _OWN_HMAC:
                continue
            resp = client.request(key[0], path.replace("{escrow_id}", "esc-1"))
            assert resp.status_code == 401, f"{key} has no authentication"
            assert resp.json() == {"detail": _INVALID}, key
            protected.add(key)
    assert protected == {
        ("GET", "/audits"),
        ("GET", "/audits/{escrow_id}"),
        ("POST", "/mediate/{escrow_id}"),
        ("POST", "/settle"),
        ("GET", "/settlements"),
        ("GET", "/merkle"),
        ("GET", "/settlements/pending"),
        ("POST", "/settlements/ack"),
        ("GET", "/heartbeat/status"),
    }
    listed = {(m.upper(), p) for p, ops in app.openapi()["paths"].items() for m in ops}
    assert _PUBLIC | _OWN_HMAC <= listed


# ---------------------------------------------------------------------------
# Per-route acceptance and rejection
# ---------------------------------------------------------------------------


@_route
def test_good_signature_is_accepted(client, method, target, body, ok_status):
    resp = _send(client, method, target, body, _sign(method, target, body))
    assert resp.status_code == ok_status, resp.text
    if ok_status == 404:
        assert resp.json()["detail"] == "Settlement not found"


@_route
def test_missing_signature_is_rejected(client, handlers, method, target, body, ok_status):
    resp = _send(client, method, target, body)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


@_route
@pytest.mark.parametrize("missing", ["X-A2ASE-Timestamp", "X-A2ASE-Nonce", "X-A2ASE-Signature"])
def test_each_header_is_required(client, handlers, method, target, body, ok_status, missing):
    headers = _sign(method, target, body)
    del headers[missing]
    resp = _send(client, method, target, body, headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


@_route
def test_bad_signature_is_rejected(client, handlers, method, target, body, ok_status):
    headers = _sign(method, target, body)
    headers["X-A2ASE-Signature"] = "v2=" + "0" * 64
    resp = _send(client, method, target, body, headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


@_route
def test_wrong_secret_is_rejected(client, handlers, method, target, body, ok_status):
    resp = _send(client, method, target, body, _sign(method, target, body, secret="other"))
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


@_route
@pytest.mark.parametrize("offset", [-301, 301])
def test_stale_timestamp_is_rejected(client, handlers, method, target, body, ok_status, offset):
    timestamp = str(_NOW + offset)
    resp = _send(client, method, target, body, _sign(method, target, body, timestamp=timestamp))
    assert resp.status_code == 401
    assert resp.json()["detail"] == _WINDOW
    _assert_untouched(handlers)


@_route
@pytest.mark.parametrize("offset", [-300, 300])
def test_timestamp_at_the_window_edge_is_accepted(
    client, method, target, body, ok_status, offset
):
    timestamp = str(_NOW + offset)
    resp = _send(client, method, target, body, _sign(method, target, body, timestamp=timestamp))
    assert resp.status_code == ok_status, resp.text


@_route
def test_replayed_signature_is_rejected(client, handlers, method, target, body, ok_status):
    headers = _sign(method, target, body)
    first = _send(client, method, target, body, headers)
    assert first.status_code == ok_status, first.text
    for mock in handlers.values():
        mock.reset_mock()

    second = _send(client, method, target, body, headers)
    assert second.status_code == 409
    assert second.json()["detail"] == "Replayed request"
    _assert_untouched(handlers)


@_route
def test_same_request_with_a_new_nonce_is_accepted(client, method, target, body, ok_status):
    first = _send(client, method, target, body, _sign(method, target, body))
    second = _send(
        client, method, target, body, _sign(method, target, body, nonce="another-nonce-0123456789")
    )
    assert first.status_code == ok_status
    assert second.status_code == ok_status


@_route
def test_signature_for_another_path_is_rejected(
    client, handlers, method, target, body, ok_status
):
    for other_method, other_target, _body, _ok in _ROUTES:
        if other_target == target:
            continue
        # Same method on purpose: only the path differs from what was signed.
        headers = _sign(method, other_target, body)
        resp = _send(client, method, target, body, headers)
        assert resp.status_code == 401, other_target
        assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


@_route
def test_signature_for_another_method_is_rejected(
    client, handlers, method, target, body, ok_status
):
    resp = _send(client, method, target, body, _sign(_other(method), target, body))
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


@_route
def test_verify_patch_style_signature_is_rejected(
    client, handlers, method, target, body, ok_status
):
    """The ``{timestamp}.{body}`` form does not bind a path, so it is not accepted here."""
    message = f"{_TIMESTAMP}.".encode() + (body or b"")
    digest = hmac.new(_SECRET.encode(), message, hashlib.sha256).hexdigest()
    for value in (f"sha256={digest}", f"v2={digest}"):
        headers = {
            "X-A2ASE-Timestamp": _TIMESTAMP,
            "X-A2ASE-Nonce": _NONCE,
            "X-A2ASE-Signature": value,
        }
        resp = _send(client, method, target, body, headers)
        assert resp.status_code == 401
        assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


@_route
def test_no_secret_refuses(client, handlers, monkeypatch, method, target, body, ok_status):
    monkeypatch.setattr(settings, "webhook_secret", "")
    # Signed with the empty key, which is what an attacker would try.
    for headers in (None, _sign(method, target, body, secret="")):
        resp = _send(client, method, target, body, headers)
        assert resp.status_code == 503
        assert resp.json()["detail"] == _UNCONFIGURED
    _assert_untouched(handlers)


@_route
def test_opt_out_allows_unsigned_requests_without_a_secret(
    client, monkeypatch, method, target, body, ok_status
):
    monkeypatch.setattr(settings, "webhook_secret", "")
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    resp = _send(client, method, target, body)
    assert resp.status_code == ok_status, resp.text


@_route
def test_opt_out_is_ignored_when_a_secret_is_set(
    client, handlers, monkeypatch, method, target, body, ok_status
):
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    resp = _send(client, method, target, body)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID
    _assert_untouched(handlers)


# ---------------------------------------------------------------------------
# Binding details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("target", ["/mediate/esc-1", "/settle", "/settlements/ack"])
@pytest.mark.parametrize("body", [b"{not json", b"[]", b'{"unexpected": true}', b""])
def test_authentication_runs_before_body_validation(client, handlers, target, body):
    """An unsigned caller learns nothing about the expected payload."""
    resp = _send(client, "POST", target, body)
    assert resp.status_code == 401
    assert resp.json() == {"detail": _INVALID}
    _assert_untouched(handlers)


def test_signed_request_with_an_invalid_body_gets_a_validation_error(client, handlers):
    body = b'{"unexpected": true}'
    resp = _send(client, "POST", "/settle", body, _sign("POST", "/settle", body))
    assert resp.status_code == 422
    _assert_untouched(handlers)


def test_signature_does_not_carry_to_another_escrow(client, handlers):
    headers = _sign("POST", "/mediate/esc-1", b"{}")
    resp = _send(client, "POST", "/mediate/esc-2", b"{}", headers)
    assert resp.status_code == 401
    _assert_untouched(handlers)


def test_body_is_bound(client, handlers):
    headers = _sign("POST", "/mediate/esc-1", b'{"mode":"training"}')
    resp = _send(client, "POST", "/mediate/esc-1", b'{"mode":"production"}', headers)
    assert resp.status_code == 401
    _assert_untouched(handlers)


def test_query_string_is_bound(client):
    headers = _sign("GET", "/audits", None)
    assert _send(client, "GET", "/audits?limit=1000", None, headers).status_code == 401

    signed = _sign("GET", "/audits?limit=5&offset=0", None)
    assert _send(client, "GET", "/audits?limit=5&offset=0", None, signed).status_code == 200


def test_percent_encoded_path_is_signed_as_sent(client, handlers):
    target = "/mediate/esc%201"
    resp = _send(client, "POST", target, b"{}", _sign("POST", target, b"{}"))
    assert resp.status_code == 200
    assert handlers["mediate"].call_args.args[0] == "esc 1"
    handlers["mediate"].reset_mock()

    # A signature over the decoded form does not verify.
    decoded = _sign("POST", "/mediate/esc 1", b"{}", nonce="decoded-nonce-0123456789")
    assert _send(client, "POST", target, b"{}", decoded).status_code == 401
    _assert_untouched(handlers)


@pytest.mark.parametrize(
    "nonce",
    ["short", "n" * 129, "has space 0123456789", "new\tline-0123456789ab", "ünïcödé-0123456789ab"],
)
def test_malformed_nonce_is_rejected(client, nonce):
    headers = _sign("GET", "/merkle", None)
    headers["X-A2ASE-Nonce"] = nonce
    resp = _send(client, "GET", "/merkle", None, headers)
    assert resp.status_code == 401
    assert resp.json()["detail"] == _INVALID


@pytest.mark.parametrize("timestamp", ["", "abc", "-1700000000", "1700000000.0", "9" * 13, "١٢٣"])
def test_malformed_timestamp_is_rejected(client, timestamp):
    headers = _sign("GET", "/merkle", None)
    headers["X-A2ASE-Timestamp"] = timestamp
    resp = _send(client, "GET", "/merkle", None, headers)
    assert resp.status_code == 401


def test_non_ascii_signature_is_rejected_not_an_error(client):
    headers = _sign("GET", "/merkle", None)
    headers["X-A2ASE-Signature"] = "v2=é"
    resp = _send(client, "GET", "/merkle", None, headers)
    assert resp.status_code == 401


def test_rejected_signature_is_not_remembered(client):
    """A failed attempt must not burn the nonce for the legitimate caller."""
    bad = _sign("GET", "/merkle", None)
    bad["X-A2ASE-Signature"] = "v2=" + "0" * 64
    assert _send(client, "GET", "/merkle", None, bad).status_code == 401
    assert _send(client, "GET", "/merkle", None, _sign("GET", "/merkle", None)).status_code == 200


# ---------------------------------------------------------------------------
# Routes that stay public
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/health", "/guide", "/schemas"])
def test_public_routes_need_no_signature(client, monkeypatch, path):
    assert client.get(path).status_code == 200
    monkeypatch.setattr(settings, "webhook_secret", "")
    assert client.get(path).status_code == 200


# ---------------------------------------------------------------------------
# /webhook fails closed
# ---------------------------------------------------------------------------


def _webhook_body() -> bytes:
    return json.dumps(
        {
            "event": "escrow.released",
            "timestamp": "2026-01-01T00:00:00+00:00",
            "data": {"escrow_id": "esc-1"},
        }
    ).encode()


def _webhook_sig(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def _post_webhook(client: TestClient, body: bytes, signature: str | None = None):
    headers = {"Content-Type": "application/json"}
    if signature is not None:
        headers["X-A2ASE-Signature"] = signature
    return client.post("/webhook", content=body, headers=headers)


def test_webhook_refuses_without_a_secret(client, monkeypatch):
    monkeypatch.setattr(settings, "webhook_secret", "")
    submitted = MagicMock()
    monkeypatch.setattr(webhook_listener._executor, "submit", submitted)
    disputed = _webhook_body().replace(b"escrow.released", b"escrow.disputed")
    for signature in (None, _webhook_sig(disputed, "")):
        resp = _post_webhook(client, disputed, signature)
        assert resp.status_code == 503
        assert resp.json()["detail"] == "webhook requires MEDIATOR_WEBHOOK_SECRET"
    submitted.assert_not_called()


def test_webhook_opt_out_accepts_unsigned_without_a_secret(client, monkeypatch):
    monkeypatch.setattr(settings, "webhook_secret", "")
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    resp = _post_webhook(client, _webhook_body())
    assert resp.status_code == 200
    assert resp.json()["status"] == "ignored"


def test_webhook_opt_out_is_ignored_when_a_secret_is_set(client, monkeypatch):
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    body = _webhook_body()
    assert _post_webhook(client, body).status_code == 401
    assert _post_webhook(client, body, "sha256=bad").status_code == 401
    assert _post_webhook(client, body, _webhook_sig(body, _SECRET)).status_code == 200


def test_verify_signature_helper_fails_closed(monkeypatch):
    monkeypatch.setattr(settings, "webhook_secret", "")
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    assert webhook_listener._verify_signature(b"{}", None) is False
    assert webhook_listener._verify_signature(b"{}", _webhook_sig(b"{}", "")) is False


# ---------------------------------------------------------------------------
# Startup warning
# ---------------------------------------------------------------------------


def test_opt_out_defaults_to_off():
    from a2a_settlement_mediator.config import MediatorSettings

    if not os.getenv("MEDIATOR_INSECURE_ALLOW_UNAUTHENTICATED"):
        assert MediatorSettings.allow_unauthenticated is False


def test_startup_warns_loudly_when_the_opt_out_is_active(monkeypatch, caplog):
    monkeypatch.setattr(settings, "webhook_secret", "")
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    with caplog.at_level(logging.WARNING, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    [record] = caplog.records
    assert record.levelno == logging.WARNING
    text = record.getMessage()
    assert text.startswith("INSECURE")
    assert "MEDIATOR_INSECURE_ALLOW_UNAUTHENTICATED" in text
    assert "UNAUTHENTICATED" in text


def test_startup_warns_when_no_secret_and_no_opt_out(monkeypatch, caplog):
    monkeypatch.setattr(settings, "webhook_secret", "")
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    with caplog.at_level(logging.WARNING, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    [record] = caplog.records
    assert "503" in record.getMessage()


def test_startup_says_the_opt_out_is_ignored_with_a_secret(monkeypatch, caplog):
    monkeypatch.setattr(settings, "webhook_secret", _SECRET)
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    with caplog.at_level(logging.WARNING, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    [record] = caplog.records
    assert "ignored" in record.getMessage()
    assert _SECRET not in record.getMessage()


def test_startup_is_quiet_when_configured(monkeypatch, caplog):
    monkeypatch.setattr(settings, "webhook_secret", _SECRET)
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    with caplog.at_level(logging.WARNING, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    assert caplog.records == []


def test_lifespan_logs_the_posture(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "mediator.db"))
    monkeypatch.setattr(webhook_listener._heartbeat, "start", lambda: None)
    monkeypatch.setattr(webhook_listener._heartbeat, "stop", lambda: None)
    called = MagicMock()
    monkeypatch.setattr(webhook_listener, "_log_auth_posture", called)
    with TestClient(app):
        pass
    called.assert_called_once_with()
