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
from a2a_settlement_mediator.receipts import routes as receipt_routes
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
# Routes that verify their own HMAC inside the handler, and the purpose whose
# secret keys it. Every other authenticated route is an operator route.
_OWN_HMAC = {
    ("POST", "/webhook"): "webhook",
    ("POST", "/api/v1/verify-patch"): "verify-patch",
    ("POST", "/api/v1/receipts"): "receipts",
}

# One distinct secret per purpose, for the tests that separate them.
_PURPOSE_ATTR = {
    "webhook": "webhook_secret",
    "operator": "operator_secret",
    "verify-patch": "verify_patch_secret",
    "receipts": "receipts_secret",
}
_SPLIT = {purpose: f"{purpose}-only-secret" for purpose in _PURPOSE_ATTR}
_SPLIT_PURPOSES = ["operator", "verify-patch", "receipts"]


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
            proof=None,
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
    _configure(monkeypatch, webhook=_SECRET)
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    monkeypatch.setattr(settings, "signature_tolerance_seconds", 300)
    monkeypatch.setattr(webhook_listener, "_now", lambda: float(_NOW))
    return TestClient(app)


def _configure(monkeypatch, *, transition: bool = False, **secrets: str) -> None:
    """Set the four secrets by purpose name; a purpose left out is unset."""
    for purpose, attr in _PURPOSE_ATTR.items():
        monkeypatch.setattr(settings, attr, secrets.get(purpose.replace("-", "_"), ""))
    monkeypatch.setattr(settings, "secret_transition_accept_fallback", transition)


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


_calls = iter(range(10**6))


def _call_as(client: TestClient, key: tuple[str, str], purpose: str, secret: str | None):
    """Send a request to ``key`` signed with ``secret`` in its purpose's scheme.

    ``secret=None`` sends it unsigned. The body is not a valid payload for the
    self-verifying routes, so "authenticated" shows as any status other than
    401 or 503. Each call differs, so none is refused as a replay.
    """
    method, path = key
    target = path.replace("{escrow_id}", "esc-1")
    unique = next(_calls)
    if purpose == "operator":
        headers = None
        if secret is not None:
            headers = _sign(method, target, None, secret=secret, nonce=f"nonce-{unique:016d}")
        return _send(client, method, target, None, headers)
    body = json.dumps({"event": "escrow.released", "n": unique}).encode()
    headers = {}
    if secret is not None and purpose == "webhook":
        headers["X-A2ASE-Signature"] = _webhook_sig(body, secret)
    elif secret is not None:
        message = f"{_TIMESTAMP}.".encode() + body
        digest = hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
        headers["X-A2ASE-Timestamp"] = _TIMESTAMP
        headers["X-A2ASE-Signature"] = f"sha256={digest}"
    return _send(client, method, target, body, headers)


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
            if key in _PUBLIC or key in _OWN_HMAC:
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
    assert _PUBLIC | set(_OWN_HMAC) <= listed

    # With one secret per purpose, each authenticated route accepts its own
    # purpose's secret and refuses the other three.
    _configure(monkeypatch, **{p.replace("-", "_"): s for p, s in _SPLIT.items()})
    monkeypatch.setattr(receipt_routes, "_service", MagicMock())
    purposes = {key: "operator" for key in protected} | _OWN_HMAC
    for key, purpose in purposes.items():
        for holder, secret in _SPLIT.items():
            status = _call_as(client, key, purpose, secret).status_code
            if holder == purpose:
                assert status not in (401, 503), f"{key} refused its own secret"
            else:
                assert status == 401, f"{key} accepted the {holder} secret"


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
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    with caplog.at_level(logging.WARNING, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    [record] = [r for r in caplog.records if r.getMessage().startswith("INSECURE")]
    assert record.levelno == logging.WARNING
    text = record.getMessage()
    assert "MEDIATOR_INSECURE_ALLOW_UNAUTHENTICATED" in text
    assert "UNAUTHENTICATED" in text
    assert "/webhook" in text and "operator routes" in text
    # The opt-out never covers these two; they are reported as refusing.
    [refusing] = [r for r in caplog.records if "503" in r.getMessage()]
    assert "/api/v1/verify-patch" in refusing.getMessage()
    assert "POST /api/v1/receipts" in refusing.getMessage()
    assert "/webhook" not in refusing.getMessage()


def test_startup_warns_when_no_secret_and_no_opt_out(monkeypatch, caplog):
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    with caplog.at_level(logging.WARNING, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    [record] = caplog.records
    text = record.getMessage()
    assert "503" in text
    for what in ("/webhook", "operator routes", "/api/v1/verify-patch", "/api/v1/receipts"):
        assert what in text


def test_startup_says_the_opt_out_is_ignored_with_a_secret(monkeypatch, caplog):
    _configure(monkeypatch, webhook=_SECRET)
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    with caplog.at_level(logging.WARNING, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    [record] = [r for r in caplog.records if "ignored" in r.getMessage()]
    assert "MEDIATOR_INSECURE_ALLOW_UNAUTHENTICATED" in record.getMessage()
    assert not any(r.getMessage().startswith("INSECURE") for r in caplog.records)
    assert all(_SECRET not in r.getMessage() for r in caplog.records)


def test_startup_is_quiet_when_every_purpose_has_its_own_secret(monkeypatch, caplog):
    _configure(monkeypatch, **{p.replace("-", "_"): s for p, s in _SPLIT.items()})
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


# ---------------------------------------------------------------------------
# Per-purpose secrets
# ---------------------------------------------------------------------------

_PURPOSE_KEY = {
    "webhook": ("POST", "/webhook"),
    "operator": ("GET", "/merkle"),
    "verify-patch": ("POST", "/api/v1/verify-patch"),
    "receipts": ("POST", "/api/v1/receipts"),
}
_UNCONFIGURED_DETAIL = {
    "webhook": "webhook requires MEDIATOR_WEBHOOK_SECRET",
    "operator": _UNCONFIGURED,
    "verify-patch": "verify-patch requires MEDIATOR_WEBHOOK_SECRET",
    "receipts": "receipts require MEDIATOR_WEBHOOK_SECRET",
}
_split_purpose = pytest.mark.parametrize("purpose", _SPLIT_PURPOSES)


@pytest.fixture
def split(client, monkeypatch):
    """The client, with receipts mounted so POST /api/v1/receipts reaches its check."""
    monkeypatch.setattr(settings, "receipts_enabled", True)
    monkeypatch.setattr(receipt_routes, "_service", MagicMock())
    return client


def _status(client, purpose: str, secret: str | None) -> int:
    return _call_as(client, _PURPOSE_KEY[purpose], purpose, secret).status_code


def _accepted(client, purpose: str, secret: str | None) -> bool:
    status = _status(client, purpose, secret)
    assert status != 503, f"{purpose} is unconfigured"
    return status != 401


def _kw(**by_purpose: str) -> dict[str, str]:
    return {purpose.replace("-", "_"): secret for purpose, secret in by_purpose.items()}


def test_new_settings_default_to_unset():
    from a2a_settlement_mediator.config import MediatorSettings

    for attr, env in (
        ("operator_secret", "MEDIATOR_OPERATOR_SECRET"),
        ("verify_patch_secret", "MEDIATOR_VERIFY_PATCH_SECRET"),
        ("receipts_secret", "MEDIATOR_RECEIPTS_SECRET"),
    ):
        if not os.getenv(env):
            assert getattr(MediatorSettings, attr) == ""
    if not os.getenv("MEDIATOR_SECRET_TRANSITION_ACCEPT_FALLBACK"):
        assert MediatorSettings.secret_transition_accept_fallback is False


@pytest.mark.parametrize("purpose", list(_PURPOSE_KEY))
def test_only_the_webhook_secret_set_keys_every_purpose(split, purpose):
    """A deployment that sets nothing new behaves as before."""
    assert _accepted(split, purpose, _SECRET)
    assert not _accepted(split, purpose, "other")
    assert not _accepted(split, purpose, "")


@_split_purpose
def test_own_secret_replaces_the_webhook_secret(split, monkeypatch, purpose):
    _configure(monkeypatch, webhook=_SECRET, **_kw(**{purpose: _SPLIT[purpose]}))
    assert _accepted(split, purpose, _SPLIT[purpose])
    assert not _accepted(split, purpose, _SECRET)
    # The purposes without their own secret still use the webhook secret,
    # and none of them accepts this purpose's secret.
    for other in _PURPOSE_KEY:
        if other != purpose:
            assert _accepted(split, other, _SECRET), other
            assert not _accepted(split, other, _SPLIT[purpose]), other


@_split_purpose
def test_own_secret_works_without_a_webhook_secret(split, monkeypatch, purpose):
    _configure(monkeypatch, **_kw(**{purpose: _SPLIT[purpose]}))
    assert _accepted(split, purpose, _SPLIT[purpose])
    assert not _accepted(split, purpose, "")
    # Everything else has no secret at all and stays closed.
    for other in _PURPOSE_KEY:
        if other != purpose:
            for secret in (None, "", _SPLIT[purpose]):
                resp = _call_as(split, _PURPOSE_KEY[other], other, secret)
                assert resp.status_code == 503, other
                assert resp.json()["detail"] == _UNCONFIGURED_DETAIL[other]


@pytest.mark.parametrize("purpose", list(_PURPOSE_KEY))
@pytest.mark.parametrize("transition", [False, True])
def test_no_secret_at_all_refuses(split, monkeypatch, purpose, transition):
    _configure(monkeypatch, transition=transition)
    for secret in (None, ""):
        resp = _call_as(split, _PURPOSE_KEY[purpose], purpose, secret)
        assert resp.status_code == 503
        assert resp.json()["detail"] == _UNCONFIGURED_DETAIL[purpose]


def test_webhook_never_accepts_a_purpose_secret(split, monkeypatch):
    _configure(monkeypatch, transition=True, **_kw(**_SPLIT))
    assert _accepted(split, "webhook", _SPLIT["webhook"])
    for purpose in _SPLIT_PURPOSES:
        assert not _accepted(split, "webhook", _SPLIT[purpose])


@_split_purpose
def test_transition_accepts_the_own_and_the_webhook_secret(split, monkeypatch, purpose):
    _configure(monkeypatch, transition=True, **_kw(**_SPLIT))
    assert _accepted(split, purpose, _SPLIT[purpose])
    assert _accepted(split, purpose, _SPLIT["webhook"])
    for other in _SPLIT_PURPOSES:
        if other != purpose:
            assert not _accepted(split, purpose, _SPLIT[other]), other
    assert not _accepted(split, purpose, "")


@_split_purpose
def test_transition_is_off_unless_asked_for(split, monkeypatch, purpose):
    _configure(monkeypatch, **_kw(**_SPLIT))
    assert not _accepted(split, purpose, _SPLIT["webhook"])


@_split_purpose
def test_transition_never_accepts_an_empty_key(split, monkeypatch, purpose):
    _configure(monkeypatch, transition=True, **_kw(**{purpose: _SPLIT[purpose]}))
    assert _accepted(split, purpose, _SPLIT[purpose])
    assert not _accepted(split, purpose, "")
    assert _status(split, purpose, None) == 401


@_split_purpose
def test_transition_does_nothing_for_a_purpose_without_its_own_secret(
    split, monkeypatch, purpose
):
    others = {p: s for p, s in _SPLIT.items() if p != purpose}
    _configure(monkeypatch, transition=True, **_kw(**others))
    assert _accepted(split, purpose, _SPLIT["webhook"])
    for other in _SPLIT_PURPOSES:
        if other != purpose:
            assert not _accepted(split, purpose, _SPLIT[other])


def test_replay_is_refused_whichever_secret_signed(split, monkeypatch):
    _configure(monkeypatch, transition=True, **_kw(**_SPLIT))
    for secret in (_SPLIT["operator"], _SPLIT["webhook"]):
        headers = _sign("GET", "/merkle", None, secret=secret)
        assert _send(split, "GET", "/merkle", None, headers).status_code == 200
        assert _send(split, "GET", "/merkle", None, headers).status_code == 409


def test_verify_patch_signature_is_not_valid_for_receipts(split, monkeypatch):
    """Both use ``{timestamp}.{body}``; separate secrets keep them apart."""
    _configure(monkeypatch, **_kw(**_SPLIT))
    assert not _accepted(split, "receipts", _SPLIT["verify-patch"])
    assert not _accepted(split, "verify-patch", _SPLIT["receipts"])


def test_opt_out_is_ignored_for_a_purpose_with_its_own_secret(split, monkeypatch):
    """No webhook secret, opt-out on: /webhook is open, the keyed operator routes are not."""
    _configure(monkeypatch, operator=_SPLIT["operator"])
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    assert _status(split, "operator", None) == 401
    assert _accepted(split, "operator", _SPLIT["operator"])
    assert _accepted(split, "webhook", None)


def test_opt_out_never_covers_verify_patch_or_receipts(split, monkeypatch):
    _configure(monkeypatch)
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    assert _accepted(split, "webhook", None)
    assert _status(split, "operator", None) == 200
    for purpose in ("verify-patch", "receipts"):
        for secret in (None, ""):
            assert _status(split, purpose, secret) == 503


def test_opt_out_is_ignored_when_only_the_webhook_secret_is_set(split, monkeypatch):
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    for purpose in _PURPOSE_KEY:
        assert _status(split, purpose, None) == 401, purpose


# ---------------------------------------------------------------------------
# Startup posture for per-purpose secrets
# ---------------------------------------------------------------------------


def _posture(caplog) -> tuple[str, list[str]]:
    with caplog.at_level(logging.INFO, logger=webhook_listener.logger.name):
        webhook_listener._log_auth_posture()
    [info] = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    return info, warnings


def test_posture_names_each_purpose_and_no_values(monkeypatch, caplog):
    _configure(monkeypatch, webhook=_SPLIT["webhook"], operator=_SPLIT["operator"])
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    info, warnings = _posture(caplog)
    assert info == (
        "Request signing secrets: webhook: MEDIATOR_WEBHOOK_SECRET; "
        "operator: MEDIATOR_OPERATOR_SECRET (own secret); "
        "verify-patch: shares MEDIATOR_WEBHOOK_SECRET; "
        "receipts: shares MEDIATOR_WEBHOOK_SECRET"
    )
    # Some purposes are separated, so the all-shared warning does not fire.
    assert warnings == []
    for secret in _SPLIT.values():
        assert secret not in caplog.text


def test_posture_warns_when_every_purpose_shares_one_secret(monkeypatch, caplog):
    _configure(monkeypatch, webhook=_SECRET)
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    info, warnings = _posture(caplog)
    assert info.count("shares MEDIATOR_WEBHOOK_SECRET") == 3
    [warning] = warnings
    assert warning.startswith("One secret (MEDIATOR_WEBHOOK_SECRET)")
    for name in (
        "MEDIATOR_OPERATOR_SECRET",
        "MEDIATOR_VERIFY_PATCH_SECRET",
        "MEDIATOR_RECEIPTS_SECRET",
    ):
        assert name in warning
    assert _SECRET not in caplog.text


def test_posture_counts_a_copied_value_as_shared(monkeypatch, caplog):
    """Setting every purpose secret to the webhook secret's value separates nothing."""
    _configure(monkeypatch, **_kw(**dict.fromkeys(_PURPOSE_ATTR, _SECRET)))
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    info, warnings = _posture(caplog)
    assert info.count("(same value as MEDIATOR_WEBHOOK_SECRET)") == 3
    assert [w for w in warnings if w.startswith("One secret")]
    assert _SECRET not in caplog.text


def test_posture_reports_two_purposes_with_the_same_own_value(monkeypatch, caplog):
    secrets = dict(_SPLIT, receipts=_SPLIT["operator"])
    _configure(monkeypatch, **_kw(**secrets))
    info, _warnings = _posture(caplog)
    assert "receipts: MEDIATOR_RECEIPTS_SECRET (same value as MEDIATOR_OPERATOR_SECRET)" in info


def test_posture_warns_while_the_transition_is_on(monkeypatch, caplog):
    _configure(monkeypatch, transition=True, webhook=_SPLIT["webhook"], operator=_SPLIT["operator"])
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    info, warnings = _posture(caplog)
    assert (
        "operator: MEDIATOR_OPERATOR_SECRET (transition: MEDIATOR_WEBHOOK_SECRET also accepted)"
        in info
    )
    [warning] = warnings
    assert warning.startswith("MEDIATOR_SECRET_TRANSITION_ACCEPT_FALLBACK is on")
    assert "MEDIATOR_OPERATOR_SECRET" in warning
    assert "MEDIATOR_RECEIPTS_SECRET" not in warning


def test_posture_says_when_the_transition_has_no_effect(monkeypatch, caplog):
    _configure(monkeypatch, transition=True, **_kw(**dict(_SPLIT, webhook="")))
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    _info, warnings = _posture(caplog)
    assert any("has no effect" in w for w in warnings)


def test_posture_reports_unset_purposes(monkeypatch, caplog):
    _configure(monkeypatch, operator=_SPLIT["operator"])
    monkeypatch.setattr(settings, "allow_unauthenticated", False)
    info, warnings = _posture(caplog)
    assert "webhook: not set" in info
    assert "verify-patch: not set" in info
    [warning] = warnings
    assert "503" in warning
    assert "operator routes" not in warning


def test_posture_opt_out_names_only_the_open_purposes(monkeypatch, caplog):
    _configure(monkeypatch, operator=_SPLIT["operator"])
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    _info, warnings = _posture(caplog)
    [insecure] = [w for w in warnings if w.startswith("INSECURE")]
    assert "no secret is set for /webhook." in insecure
