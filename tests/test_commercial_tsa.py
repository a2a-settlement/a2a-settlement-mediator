"""Commercial TSA presets, failover, enterprise auth, and the operator probe."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from a2a_settlement_mediator.config import (
    COMMERCIAL_TSA_PRESETS,
    ReceiptsConfigError,
    assert_public_receipts_tsa,
    resolve_tsa_url,
    settings,
)
from a2a_settlement_mediator.receipts.service import build_granted_timestamp_der
from a2a_settlement_mediator.tsa_client import (
    RFC3161Client,
    TSAClientError,
    TSATimeoutError,
)
from a2a_settlement_mediator.tsa_probe import main, probe_digest
from a2a_settlement_mediator.worm_schemas import TimestampToken

_WHEN = datetime(2026, 11, 15, 16, 0, tzinfo=timezone.utc)
_TSA_ENV = (
    "MEDIATOR_TSA_URL",
    "MEDIATOR_TSA_FALLBACK_URL",
    "MEDIATOR_TSA_BEARER_TOKEN",
    "MEDIATOR_TSA_CLIENT_CERT",
    "MEDIATOR_TSA_CLIENT_KEY",
    "MEDIATOR_TSA_CA_BUNDLE",
    "MEDIATOR_TSA_TIMEOUT",
)
# Repo root, so child processes import this checkout wherever it lives.
_WORKTREE = str(Path(__file__).resolve().parent.parent)
_TOKEN = "super-secret-token"


@pytest.fixture(autouse=True)
def _clear_tsa_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _TSA_ENV:
        monkeypatch.delenv(name, raising=False)


def test_resolve_tsa_url_presets_and_passthrough():
    assert COMMERCIAL_TSA_PRESETS == {
        "digicert": "http://timestamp.digicert.com",
        "sectigo": "http://timestamp.sectigo.com",
    }
    assert resolve_tsa_url("digicert") == "http://timestamp.digicert.com"
    assert resolve_tsa_url("  DIGICERT\n") == "http://timestamp.digicert.com"
    assert resolve_tsa_url("Sectigo") == "http://timestamp.sectigo.com"
    full = "https://tsa.internal.example/rfc3161"
    assert resolve_tsa_url(f"  {full}  ") == full
    assert resolve_tsa_url("https://timestamp.digicert.com/sha256") == (
        "https://timestamp.digicert.com/sha256"
    )
    assert resolve_tsa_url("   ") == ""


def test_public_receipts_reject_free_primary_and_free_fallback():
    assert_public_receipts_tsa(True, "digicert")
    assert_public_receipts_tsa(True, "https://tsa.example.com/rfc3161", "digicert")
    assert_public_receipts_tsa(True, "https://tsa.example.com/rfc3161", "   ")
    assert_public_receipts_tsa(False, "sectigo", "http://freetsa.org/tsr")

    with pytest.raises(ReceiptsConfigError, match="MEDIATOR_TSA_URL") as primary:
        assert_public_receipts_tsa(True, "http://freetsa.org/tsr")
    assert "free timestamp authority freetsa.org" in str(primary.value)
    assert "FALLBACK" not in str(primary.value)

    with pytest.raises(ReceiptsConfigError, match="timestamp.sectigo.com") as preset:
        assert_public_receipts_tsa(True, "sectigo")
    assert "MEDIATOR_TSA_URL" in str(preset.value)

    with pytest.raises(ReceiptsConfigError, match="MEDIATOR_TSA_FALLBACK_URL") as fallback:
        assert_public_receipts_tsa(True, "digicert", "http://freetsa.org/tsr")
    text = str(fallback.value)
    assert "free timestamp authority freetsa.org" in text
    assert "MEDIATOR_TSA_URL" not in text

    with pytest.raises(ReceiptsConfigError, match="MEDIATOR_TSA_URL") as both:
        assert_public_receipts_tsa(True, "http://freetsa.org/tsr", "sectigo")
    assert "FALLBACK" not in str(both.value)


def test_settings_snapshot_reads_commercial_tsa_env():
    configured = _settings_snapshot(
        {
            "MEDIATOR_TSA_URL": "DigiCert",
            "MEDIATOR_TSA_FALLBACK_URL": "sectigo",
            "MEDIATOR_TSA_BEARER_TOKEN": "bearer-secret",
            "MEDIATOR_TSA_CLIENT_CERT": "/tmp/cert.pem",
            "MEDIATOR_TSA_CLIENT_KEY": "/tmp/key.pem",
            "MEDIATOR_TSA_CA_BUNDLE": "/tmp/ca.pem",
        }
    )
    assert configured == {
        "tsa_url": "http://timestamp.digicert.com",
        "tsa_fallback_url": "http://timestamp.sectigo.com",
        "tsa_bearer_token": "bearer-secret",
        "tsa_client_cert": "/tmp/cert.pem",
        "tsa_client_key": "/tmp/key.pem",
        "tsa_ca_bundle": "/tmp/ca.pem",
    }
    defaults = _settings_snapshot({"MEDIATOR_TSA_FALLBACK_URL": "   "})
    assert defaults["tsa_url"] == "http://freetsa.org/tsr"
    assert defaults["tsa_fallback_url"] == ""
    assert defaults["tsa_bearer_token"] == ""
    assert defaults["tsa_client_cert"] == ""
    assert defaults["tsa_client_key"] == ""
    assert defaults["tsa_ca_bundle"] == ""
    assert hasattr(settings, "tsa_fallback_url")
    assert hasattr(settings, "tsa_bearer_token")
    assert hasattr(settings, "tsa_client_cert")
    assert hasattr(settings, "tsa_client_key")
    assert hasattr(settings, "tsa_ca_bundle")


def test_client_sends_bearer_and_tls_material_without_logging_token(monkeypatch, caplog):
    caplog.set_level("DEBUG", logger="a2a_settlement_mediator.tsa_client")
    digest = probe_digest()
    harness = _Harness(
        lambda request: _assert_request(request, "http://primary.example/tsa", digest, _TOKEN)
        or httpx.Response(200, content=build_granted_timestamp_der(digest))
    )
    harness.install(monkeypatch)

    client = RFC3161Client(
        "http://primary.example/tsa",
        timeout_seconds=3.5,
        bearer_token=_TOKEN,
        client_cert="/no/such/cert.pem",
        client_key="/no/such/key.pem",
        ca_bundle="/no/such/ca.pem",
    )
    token = client.request_timestamp(digest)

    assert token.tsa_url == "http://primary.example/tsa"
    assert token.message_hash == digest.hex()
    assert base64.b64decode(token.timestamp_token_b64)
    assert harness.client_kwargs == [
        {
            "timeout": 3.5,
            "verify": "/no/such/ca.pem",
            "cert": ("/no/such/cert.pem", "/no/such/key.pem"),
        }
    ]
    assert _TOKEN not in caplog.text


def test_single_pem_cert_and_default_verify(monkeypatch):
    digest = b"\x11" * 32
    harness = _Harness(
        lambda request: httpx.Response(200, content=build_granted_timestamp_der(digest))
    )
    harness.install(monkeypatch)
    client = RFC3161Client(
        "digicert",
        client_cert="/no/such/only.pem",
    )
    token = client.request_timestamp(digest)
    assert client.tsa_url == "http://timestamp.digicert.com"
    assert token.tsa_url == "http://timestamp.digicert.com"
    assert harness.client_kwargs == [
        {"timeout": 10.0, "verify": True, "cert": "/no/such/only.pem"}
    ]
    assert "authorization" not in {k.lower() for k in harness.requests[0].headers}


def test_client_key_without_cert_is_rejected():
    with pytest.raises(ValueError, match="client certificate"):
        RFC3161Client("https://tsa.example.com/rfc3161", client_key="/no/such/key.pem")


def test_fallback_records_the_url_that_issued_the_token(monkeypatch, caplog):
    caplog.set_level("WARNING", logger="a2a_settlement_mediator.tsa_client")
    digest = b"\x22" * 32
    primary = "http://primary.example/tsa"
    fallback = "http://backup.example/tsa"

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == primary:
            return httpx.Response(503, text=f"down {_TOKEN}")
        assert request.headers["Authorization"] == f"Bearer {_TOKEN}"
        assert digest in request.content
        return httpx.Response(200, content=build_granted_timestamp_der(digest))

    harness = _Harness(handler)
    harness.install(monkeypatch)
    client = RFC3161Client(
        primary,
        timeout_seconds=2.0,
        fallback_url="  " + fallback + "  ",
        bearer_token=_TOKEN,
    )
    token = client.request_timestamp(digest)

    assert [str(request.url) for request in harness.requests] == [primary, fallback]
    assert token.tsa_url == fallback
    assert token.message_hash == digest.hex()
    assert "retrying fallback" in caplog.text
    assert _TOKEN not in caplog.text
    assert _TOKEN not in "".join(str(kwargs) for kwargs in harness.client_kwargs)


def test_timeout_and_rejection_use_fallback(monkeypatch):
    digest = b"\x33" * 32
    primary = "http://primary.example/tsa"
    fallback = "http://backup.example/tsa"
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if str(request.url) == primary:
            raise httpx.ReadTimeout("timed out")
        return httpx.Response(200, content=build_granted_timestamp_der(digest))

    harness = _Harness(handler)
    harness.install(monkeypatch)
    client = RFC3161Client(primary, fallback_url=fallback, timeout_seconds=1.0)
    token = client.request_timestamp(digest)
    assert token.tsa_url == fallback

    def reject(request: httpx.Request) -> httpx.Response:
        if str(request.url) == primary:
            body = b"\x30\x05\x30\x03\x02\x01\x02"  # status = rejection
            return httpx.Response(200, content=body)
        return httpx.Response(200, content=build_granted_timestamp_der(digest))

    second = _Harness(reject)
    second.install(monkeypatch)
    again = RFC3161Client(primary, fallback_url=fallback)
    assert again.request_timestamp(digest).tsa_url == fallback


def test_errors_without_fallback_do_not_open_a_second_client(monkeypatch):
    harness = _Harness(lambda request: (_ for _ in ()).throw(httpx.ReadTimeout("timed out")))
    harness.install(monkeypatch)
    client = RFC3161Client("http://primary.example/tsa", timeout_seconds=1.0)
    with pytest.raises(TSATimeoutError, match="timed out"):
        client.request_timestamp(b"\x44" * 32)
    assert len(harness.client_kwargs) == 1

    def both_fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(f"down {request.url.host}")

    failing = _Harness(both_fail)
    failing.install(monkeypatch)
    covered = RFC3161Client(
        "http://primary.example/tsa",
        fallback_url="http://backup.example/tsa",
    )
    with pytest.raises(TSAClientError, match="backup.example"):
        covered.request_timestamp(b"\x44" * 32)


def test_short_hash_does_not_contact_the_fallback(monkeypatch):
    def boom(**kwargs):
        raise AssertionError(f"httpx.Client should not be called: {kwargs}")

    monkeypatch.setattr("a2a_settlement_mediator.tsa_client.httpx.Client", boom)
    client = RFC3161Client(
        "http://primary.example/tsa",
        fallback_url="http://backup.example/tsa",
    )
    with pytest.raises(ValueError, match="32-byte"):
        client.request_timestamp(b"short")


def test_http_error_body_redacts_the_bearer_token(monkeypatch, caplog):
    caplog.set_level("DEBUG", logger="a2a_settlement_mediator.tsa_client")
    harness = _Harness(
        lambda request: httpx.Response(500, text=f"denied {_TOKEN}")
    )
    harness.install(monkeypatch)
    client = RFC3161Client("http://primary.example/tsa", bearer_token=_TOKEN)
    with pytest.raises(TSAClientError, match="redacted") as caught:
        client.request_timestamp(b"\x55" * 32)
    assert _TOKEN not in str(caught.value)
    assert _TOKEN not in caplog.text
    assert harness.requests[0].headers["Authorization"] == f"Bearer {_TOKEN}"


def test_probe_ok_line_and_json_for_commercial_preset(capsys):
    digest = probe_digest()
    seen: list[bytes] = []

    def factory(*args, **kwargs):
        assert args[0] == "http://timestamp.digicert.com"
        assert kwargs["fallback_url"] == "https://tsa.backup.example/rfc3161"
        assert kwargs["bearer_token"] == ""

        class _Client:
            def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
                seen.append(payload_hash)
                return _token(digest, "http://timestamp.digicert.com")

        return _Client()

    code = main(
        ["--tsa-url", "digicert", "--fallback-url", "https://tsa.backup.example/rfc3161"],
        client_factory=factory,
    )
    captured = capsys.readouterr()
    assert code == 0
    assert seen == [digest]
    assert captured.err == ""
    assert captured.out == (
        "OK tsa_url=http://timestamp.digicert.com "
        "gen_time=2026-11-15T16:00:00+00:00 serial=42\n"
    )

    code = main(
        ["--tsa-url", "https://tsa.example.com/rfc3161", "--json"],
        client_factory=lambda *_a, **_k: _Static(_token(digest, "https://tsa.example.com/rfc3161")),
    )
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["ok"] is True
    assert payload["tsa_url"] == "https://tsa.example.com/rfc3161"
    assert payload["serial"] == "42"
    assert payload["message_hash"] == digest.hex()
    assert payload["gen_time"] == "2026-11-15T16:00:00+00:00"


def test_probe_require_commercial_rejects_free_tsa_before_calling_client(capsys):
    def factory(*_args, **_kwargs):
        raise AssertionError("client must not be built for a free TSA")

    code = main(["--tsa-url", "http://freetsa.org/tsr"], client_factory=factory)
    err = capsys.readouterr().err
    assert code == 2
    assert "free timestamp authority freetsa.org" in err
    assert err.startswith("error: ")

    code = main(
        ["--tsa-url", "digicert", "--fallback-url", "sectigo", "--json"],
        client_factory=factory,
    )
    payload = json.loads(capsys.readouterr().err)
    assert code == 2
    assert payload["ok"] is False
    assert "MEDIATOR_TSA_FALLBACK_URL" in payload["error"]
    assert "timestamp.sectigo.com" in payload["error"]


def test_probe_can_skip_the_commercial_check(capsys):
    digest = probe_digest()
    code = main(
        ["--tsa-url", "http://freetsa.org/tsr", "--no-require-commercial"],
        client_factory=lambda *_a, **_k: _Static(_token(digest, "http://freetsa.org/tsr")),
    )
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith("OK tsa_url=http://freetsa.org/tsr ")


def test_probe_rejects_empty_or_non_echoing_tokens(capsys):
    digest = probe_digest()
    empty = _token(digest, "https://tsa.example.com/rfc3161")
    empty = empty.model_copy(update={"timestamp_token_b64": ""})
    code = main(
        ["--tsa-url", "https://tsa.example.com/rfc3161"],
        client_factory=lambda *_a, **_k: _Static(empty),
    )
    assert code == 1
    assert "empty DER TimestampToken" in capsys.readouterr().err

    other = _token(b"\x99" * 32, "https://tsa.example.com/rfc3161")
    code = main(
        ["--tsa-url", "https://tsa.example.com/rfc3161", "--json"],
        client_factory=lambda *_a, **_k: _Static(other),
    )
    payload = json.loads(capsys.readouterr().err)
    assert code == 1
    assert payload["ok"] is False
    assert "SHA-256" in payload["error"]

    echoed_field_only = _token(digest, "https://tsa.example.com/rfc3161").model_copy(
        update={"timestamp_token_b64": base64.b64encode(b"\x30\x03\x02\x01\x00").decode()}
    )
    code = main(
        ["--tsa-url", "https://tsa.example.com/rfc3161"],
        client_factory=lambda *_a, **_k: _Static(echoed_field_only),
    )
    assert code == 1
    assert "echo the SHA-256 probe digest" in capsys.readouterr().err


def test_probe_reports_tsa_failure_and_passes_enterprise_env(monkeypatch, capsys):
    monkeypatch.setenv("MEDIATOR_TSA_URL", "digicert")
    monkeypatch.setenv("MEDIATOR_TSA_BEARER_TOKEN", _TOKEN)
    monkeypatch.setenv("MEDIATOR_TSA_CLIENT_CERT", "/cert.pem")
    monkeypatch.setenv("MEDIATOR_TSA_CLIENT_KEY", "/key.pem")
    monkeypatch.setenv("MEDIATOR_TSA_CA_BUNDLE", "/ca.pem")
    monkeypatch.setenv("MEDIATOR_TSA_TIMEOUT", "4.5")
    seen: dict = {}

    def factory(*args, **kwargs):
        seen["args"] = args
        seen["kwargs"] = kwargs
        raise TSATimeoutError(f"TSA server timed out holding {_TOKEN}")

    code = main([], client_factory=factory)
    err = capsys.readouterr().err
    assert code == 1
    assert seen["args"] == ("http://timestamp.digicert.com", 4.5)
    assert seen["kwargs"]["bearer_token"] == _TOKEN
    assert seen["kwargs"]["client_cert"] == "/cert.pem"
    assert seen["kwargs"]["client_key"] == "/key.pem"
    assert seen["kwargs"]["ca_bundle"] == "/ca.pem"
    assert seen["kwargs"]["fallback_url"] == ""
    assert "timed out" in err
    assert _TOKEN not in err
    assert "[redacted]" in err


def test_probe_mocked_round_trip_uses_fallback_issuer(monkeypatch, capsys):
    digest = probe_digest()
    primary = "http://primary.example/tsa"
    fallback = "http://backup.example/tsa"

    def handler(request: httpx.Request) -> httpx.Response:
        if str(request.url) == primary:
            raise httpx.ConnectError("primary down")
        assert digest in request.content
        assert request.headers["Content-Type"] == "application/timestamp-query"
        return httpx.Response(200, content=build_granted_timestamp_der(digest))

    _Harness(handler).install(monkeypatch)
    code = main(["--tsa-url", primary, "--fallback-url", fallback])
    out = capsys.readouterr().out
    assert code == 0
    assert out.startswith(f"OK tsa_url={fallback} ")
    assert "serial=" in out
    assert "gen_time=" in out


def test_probe_usage_and_bad_timeout(monkeypatch, capsys):
    code = main(["--not-a-flag"])
    assert code == 2
    assert "unrecognized arguments" in capsys.readouterr().err

    monkeypatch.setenv("MEDIATOR_TSA_TIMEOUT", "nope")
    code = main(["--tsa-url", "digicert"])
    assert code == 2
    assert "MEDIATOR_TSA_TIMEOUT" in capsys.readouterr().err


def test_module_entrypoint_refuses_freetsa_without_network():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "a2a_settlement_mediator.tsa_probe",
            "--tsa-url",
            "http://freetsa.org/tsr",
        ],
        cwd=_WORKTREE,
        env=_child_env(),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 2
    assert "free timestamp authority" in result.stderr
    assert result.stdout == ""


class _Harness:
    def __init__(self, handler) -> None:
        self.transport = httpx.MockTransport(handler)
        self.client_kwargs: list[dict] = []
        self.requests: list[httpx.Request] = []
        self._real = httpx.Client
        self._handler = handler

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        transport = httpx.MockTransport(self._record)
        real = self._real

        def factory(**kwargs):
            self.client_kwargs.append(dict(kwargs))
            kwargs["transport"] = transport
            return real(**kwargs)

        monkeypatch.setattr("a2a_settlement_mediator.tsa_client.httpx.Client", factory)

    def _record(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self._handler(request)


class _Static:
    def __init__(self, token: TimestampToken) -> None:
        self._token = token

    def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
        if payload_hash != probe_digest():
            raise AssertionError("probe did not stamp the deterministic digest")
        return self._token


def _token(digest: bytes, url: str) -> TimestampToken:
    der = build_granted_timestamp_der(digest)
    return TimestampToken(
        tsa_url=url,
        hash_algorithm="sha256",
        message_hash=digest.hex(),
        timestamp_token_b64=base64.b64encode(der).decode("ascii"),
        serial_number="42",
        requested_at=_WHEN,
    )


def _assert_request(
    request: httpx.Request, url: str, digest: bytes, token: str
) -> None:
    assert str(request.url) == url
    assert request.headers["Authorization"] == f"Bearer {token}"
    assert request.headers["Content-Type"] == "application/timestamp-query"
    assert digest in request.content


def _child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Child env with TSA settings cleared and this worktree importable.

    Keeps the parent ``PYTHONPATH`` so a runner that already exposes
    dependencies still can. TSA variables come only from ``extra``.
    """
    env = os.environ.copy()
    for name in _TSA_ENV:
        env.pop(name, None)
    parts = [_WORKTREE]
    for part in env.get("PYTHONPATH", "").split(os.pathsep):
        if part and part not in parts:
            parts.append(part)
    env["PYTHONPATH"] = os.pathsep.join(parts)
    if extra:
        env.update(extra)
    return env


def _settings_snapshot(extra: dict[str, str]) -> dict[str, str]:
    env = _child_env(extra)
    script = (
        "import json\n"
        "from a2a_settlement_mediator.config import settings\n"
        "print(json.dumps({\n"
        "  'tsa_url': settings.tsa_url,\n"
        "  'tsa_fallback_url': settings.tsa_fallback_url,\n"
        "  'tsa_bearer_token': settings.tsa_bearer_token,\n"
        "  'tsa_client_cert': settings.tsa_client_cert,\n"
        "  'tsa_client_key': settings.tsa_client_key,\n"
        "  'tsa_ca_bundle': settings.tsa_ca_bundle,\n"
        "}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=_WORKTREE,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)
