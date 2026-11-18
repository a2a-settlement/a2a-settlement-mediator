"""Unit tests for the outbound fetch guard."""

from __future__ import annotations

import asyncio
import logging
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from a2a_settlement_mediator import outbound
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.outbound import (
    OutboundFetchError,
    OutboundRequestBlocked,
    OutboundResponseTooLarge,
    guarded_fetch,
    is_public_address,
)

PUBLIC_IP = "93.184.216.34"


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def public_dns(monkeypatch):
    """Every name resolves to one public address; no DNS query is made."""
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (PUBLIC_IP, port))
        ],
    )


@pytest.fixture
def transport(monkeypatch):
    """Install a mock transport; returns a function that sets its handler."""
    state = {"handler": lambda request: httpx.Response(200, content=b"ok"), "sent": []}

    def handle(request: httpx.Request) -> httpx.Response:
        state["sent"].append(request)
        return state["handler"](request)

    mock = httpx.MockTransport(handle)
    real_client = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["transport"] = mock
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    return state


@pytest.mark.parametrize(
    "address",
    [
        "93.184.216.34",
        "8.8.8.8",
        "1.1.1.1",
        "172.15.255.255",
        "172.32.0.1",
        "100.63.255.255",
        "100.128.0.1",
        "2606:4700:4700::1111",
        "2a00:1450:4001:81b::200e",
        "::ffff:8.8.8.8",
    ],
)
def test_public_addresses(address):
    assert is_public_address(address) is True


@pytest.mark.parametrize(
    "address",
    [
        "127.0.0.1",
        "127.255.255.254",
        "0.0.0.0",
        "0.1.2.3",
        "10.0.0.1",
        "172.16.0.1",
        "172.31.255.255",
        "192.168.0.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.255",
        "192.0.0.8",
        "192.0.2.1",
        "198.18.0.1",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "224.0.0.1",
        "239.255.255.250",
        "240.0.0.1",
        "255.255.255.255",
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "::ffff:169.254.169.254",
        "::127.0.0.1",
        "64:ff9b::a00:1",
        "2001::1",
        "2001:db8::1",
        "2002:a00:1::1",
        "fc00::1",
        "fd00::1",
        "fe80::1",
        "fe80::1%eth0",
        "fec0::1",
        "ff02::1",
        "not-an-address",
        "",
    ],
)
def test_non_public_addresses(address):
    assert is_public_address(address) is False


def test_private_addresses_are_refused_by_default():
    assert settings.allow_private_fetch_addresses is False
    assert outbound.private_addresses_allowed() is False


@pytest.mark.parametrize(
    "url",
    [
        "ftp://example.test/file",
        "file:///etc/hostname",
        "gopher://example.test/",
        "example.test/no-scheme",
        "http:///no-host",
        "",
    ],
)
def test_only_http_urls_with_a_host(public_dns, transport, url):
    with pytest.raises(OutboundRequestBlocked):
        _run(guarded_fetch("GET", url))
    assert transport["sent"] == []


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT"])
def test_only_read_methods(public_dns, transport, method):
    with pytest.raises(OutboundRequestBlocked):
        _run(guarded_fetch(method, "https://example.test/"))
    assert transport["sent"] == []


def test_https_keeps_the_host_name_for_tls(public_dns, transport):
    _run(guarded_fetch("GET", "https://example.test/path"))

    request = transport["sent"][0]
    assert request.url.host == PUBLIC_IP
    assert request.url.scheme == "https"
    assert request.headers["host"] == "example.test"
    assert request.extensions["sni_hostname"] == "example.test"


def test_body_over_the_cap_is_refused(public_dns, transport):
    transport["handler"] = lambda request: httpx.Response(200, content=b"x" * 2048)

    with pytest.raises(OutboundResponseTooLarge):
        _run(guarded_fetch("GET", "https://example.test/", max_bytes=1024))


def test_body_at_the_cap_is_returned(public_dns, transport):
    transport["handler"] = lambda request: httpx.Response(200, content=b"x" * 1024)

    response = _run(guarded_fetch("GET", "https://example.test/", max_bytes=1024))

    assert response.status_code == 200
    assert response.content == b"x" * 1024


def test_body_is_not_read_when_not_requested(public_dns, transport):
    transport["handler"] = lambda request: httpx.Response(200, content=b"x" * 4096)

    response = _run(guarded_fetch("GET", "https://example.test/", read_body=False, max_bytes=8))

    assert response.status_code == 200
    assert response.content == b""


def test_overall_deadline(public_dns, monkeypatch):
    async def never(*args, **kwargs):
        await asyncio.sleep(30)

    monkeypatch.setattr(outbound, "_send_pinned", never)

    with pytest.raises(OutboundFetchError):
        _run(guarded_fetch("GET", "https://example.test/", timeout=0.05, total_timeout=0.1))


def test_redirect_hop_limit(public_dns, transport):
    transport["handler"] = lambda request: httpx.Response(
        302, headers={"Location": "https://example.test/next"}
    )

    with pytest.raises(OutboundRequestBlocked):
        _run(guarded_fetch("GET", "https://example.test/"))
    assert len(transport["sent"]) == outbound.MAX_REDIRECTS + 1


def test_relative_redirect_stays_on_the_named_host(public_dns, transport):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/old":
            return httpx.Response(307, headers={"Location": "/new?x=1"})
        return httpx.Response(200, content=b"moved")

    transport["handler"] = handler

    response = _run(guarded_fetch("GET", "https://example.test/old"))

    assert response.content == b"moved"
    assert response.url == "https://example.test/new?x=1"
    assert [r.headers["host"] for r in transport["sent"]] == ["example.test", "example.test"]


class _Hello(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits += 1  # type: ignore[attr-defined]
        self.send_response(200)
        self.send_header("Content-Length", "5")
        self.end_headers()
        self.wfile.write(b"hello")

    def log_message(self, *args):
        pass


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Hello)
    server.hits = 0  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_loopback_is_refused_without_the_development_switch(local_server, monkeypatch, caplog):
    monkeypatch.setattr(settings, "allow_private_fetch_addresses", False)
    url = f"http://127.0.0.1:{local_server.server_address[1]}/"

    with caplog.at_level(logging.WARNING, logger=outbound.logger.name):
        with pytest.raises(OutboundRequestBlocked):
            _run(guarded_fetch("GET", url))

    assert local_server.hits == 0
    assert "Blocked outbound request" in caplog.text


def test_development_switch_permits_loopback_and_warns(local_server, monkeypatch, caplog):
    monkeypatch.setattr(settings, "allow_private_fetch_addresses", True)
    url = f"http://127.0.0.1:{local_server.server_address[1]}/"

    with caplog.at_level(logging.WARNING, logger=outbound.logger.name):
        response = _run(guarded_fetch("GET", url))

    assert response.status_code == 200
    assert response.content == b"hello"
    assert local_server.hits == 1
    assert "INSECURE" in caplog.text
    assert "MEDIATOR_INSECURE_ALLOW_PRIVATE_FETCH_ADDRESSES" in caplog.text


def test_development_switch_still_refuses_other_schemes_and_methods(monkeypatch, transport):
    monkeypatch.setattr(settings, "allow_private_fetch_addresses", True)

    with pytest.raises(OutboundRequestBlocked):
        _run(guarded_fetch("GET", "file:///etc/hostname"))
    with pytest.raises(OutboundRequestBlocked):
        _run(guarded_fetch("DELETE", "http://127.0.0.1/"))
    assert transport["sent"] == []


def test_startup_warning_only_when_the_switch_is_on(monkeypatch, caplog):
    with caplog.at_level(logging.WARNING, logger=outbound.logger.name):
        monkeypatch.setattr(settings, "allow_private_fetch_addresses", False)
        outbound.warn_if_private_addresses_allowed()
        assert caplog.text == ""
        monkeypatch.setattr(settings, "allow_private_fetch_addresses", True)
        outbound.warn_if_private_addresses_allowed()
        assert "INSECURE" in caplog.text


# ---------------------------------------------------------------------------
# TLS: the certificate is checked against the URL's host name, not the address
# ---------------------------------------------------------------------------


def _self_signed(tmp_path, name: str):
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(str(cert_path), str(key_path))
    client_ctx = ssl.create_default_context(cafile=str(cert_path))
    return server_ctx, client_ctx


@pytest.fixture
def tls_server(tmp_path, monkeypatch):
    """HTTPS on 127.0.0.1 with a certificate for ``tls.example.test`` only."""
    server_ctx, client_ctx = _self_signed(tmp_path, "tls.example.test")
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Hello)
    server.hits = 0  # type: ignore[attr-defined]
    server.socket = server_ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    real_client = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["verify"] = client_ctx
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    monkeypatch.setattr(settings, "allow_private_fetch_addresses", True)
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *args, **kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
        ],
    )
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_certificate_is_verified_against_the_host_name(tls_server):
    port = tls_server.server_address[1]

    response = _run(guarded_fetch("GET", f"https://tls.example.test:{port}/"))

    assert response.status_code == 200
    assert response.content == b"hello"


def test_certificate_for_another_name_is_rejected(tls_server):
    port = tls_server.server_address[1]

    with pytest.raises(httpx.ConnectError):
        _run(guarded_fetch("GET", f"https://other.example.test:{port}/"))
    assert tls_server.hits == 0
