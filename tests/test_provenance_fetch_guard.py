"""Provenance fetches must stay on the public internet.

Source-reference URIs are written by the provider of an escrow. These tests
drive ``ProvenanceVerifier`` with such URIs and check which requests leave the
process. Name resolution is replaced and HTTP goes either to a recording mock
transport or to a stub server on 127.0.0.1; nothing reaches a real host.
"""

from __future__ import annotations

import asyncio
import hashlib
import socket
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from a2a_settlement_mediator.provenance import ProvenanceVerifier

NOW = datetime.now(timezone.utc)
PUBLIC_IP = "93.184.216.34"
OTHER_PUBLIC_IP = "151.101.1.69"


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _provenance(uri: str, *, level: str = "verifiable", **ref) -> dict:
    return {
        "source_type": "api",
        "source_refs": [
            {"uri": uri, "timestamp": (NOW - timedelta(minutes=5)).isoformat(), **ref}
        ],
        "attestation_level": level,
        "signature": "sig",
    }


def _verify(uri: str, **ref):
    return _run(ProvenanceVerifier().verify_verifiable(_provenance(uri, **ref), "content"))


@pytest.fixture
def dns(monkeypatch):
    """Replace name resolution. Unknown names fail; IP literals resolve locally."""
    table: dict[str, list[str]] = {}
    lookups: list[str] = []
    real_getaddrinfo = socket.getaddrinfo

    def fake_getaddrinfo(host, port, *args, **kwargs):
        if isinstance(host, bytes):
            host = host.decode()
        lookups.append(host)
        if host in table:
            answer = table[host]
            addresses = answer.pop(0) if answer and isinstance(answer[0], list) else answer
            result = []
            for address in addresses:
                family = socket.AF_INET6 if ":" in address else socket.AF_INET
                sockaddr = (address, port, 0, 0) if ":" in address else (address, port)
                result.append((family, socket.SOCK_STREAM, 6, "", sockaddr))
            return result
        # Numeric forms only (dotted, decimal, hex, IPv6): never a DNS query.
        return real_getaddrinfo(
            host, port, type=socket.SOCK_STREAM, flags=socket.AI_NUMERICHOST
        )

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    return _Dns(table, lookups)


class _Dns:
    def __init__(self, table, lookups):
        self.table = table
        self.lookups = lookups

    def set(self, host: str, *addresses: str) -> None:
        self.table[host] = list(addresses)

    def set_sequence(self, host: str, *answers: list[str]) -> None:
        """Successive lookups of ``host`` return successive answers."""
        self.table[host] = [list(a) for a in answers]


@pytest.fixture
def wire(monkeypatch, dns):
    """Record every request the HTTP client would send, and answer it from a script."""
    sent: list[httpx.Request] = []
    script: dict[str, httpx.Response] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        named_host = request.headers.get("host", request.url.host).split(":")[0]
        for key in (f"{named_host}{request.url.path}", named_host):
            if key in script:
                return script[key]
        return httpx.Response(200, content=b"{}")

    transport = httpx.MockTransport(handler)
    real_client = httpx.AsyncClient

    def client(*args, **kwargs):
        kwargs["transport"] = transport
        return real_client(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", client)
    return _Wire(sent, script, dns)


class _Wire:
    def __init__(self, sent, script, dns):
        self.sent = sent
        self.script = script
        self.dns = dns

    def answer(self, key: str, response: httpx.Response) -> None:
        self.script[key] = response

    def connected_hosts(self) -> list[str]:
        return [request.url.host for request in self.sent]


class _Recorder(BaseHTTPRequestHandler):
    def _record(self):
        self.server.seen.append((self.command, self.path))  # type: ignore[attr-defined]
        body = b"internal-only"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_DELETE = do_PUT = do_PATCH = _record

    def log_message(self, *args):
        pass


@pytest.fixture
def internal_service():
    """A real HTTP listener on 127.0.0.1 standing in for a loopback-only service."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    server.seen = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


# ---------------------------------------------------------------------------
# Requests that must never be sent
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "host_form",
    [
        "127.0.0.1",
        "2130706433",  # decimal
        "0x7f000001",  # hex
        "0x7f.0.0.1",  # dotted hex
        "017700000001",  # octal
        "127.1",  # short form
        "loopback.example.test",  # a name whose A record is 127.0.0.1
    ],
)
def test_loopback_service_is_not_contacted(internal_service, dns, host_form):
    dns.set("loopback.example.test", "127.0.0.1")
    port = internal_service.server_address[1]

    result = _verify(f"http://{host_form}:{port}/admin/config")

    assert internal_service.seen == []
    assert result.verified is False
    assert result.recommendation == "reject"


@pytest.mark.parametrize("method", ["POST", "DELETE", "PUT", "PATCH"])
def test_party_chosen_method_is_not_sent(wire, method):
    wire.dns.set("source.example.test", PUBLIC_IP)

    result = _verify("https://source.example.test/data", method=method)

    assert wire.sent == []
    assert result.verified is False


def test_spot_check_does_not_contact_loopback(internal_service, dns):
    port = internal_service.server_address[1]
    provenance = _provenance(f"http://127.0.0.1:{port}/", level="signed")

    result = _run(ProvenanceVerifier(spot_check_rate=1.0).verify_signed(provenance, "content"))

    assert internal_service.seen == []
    assert result.verified is False


@pytest.mark.parametrize(
    "uri",
    [
        "http://127.0.0.1/",
        "http://127.0.0.1:6379/",
        "http://127.8.9.10/",
        "http://0.0.0.0:8000/",
        "http://0/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://172.16.4.4:8080/",
        "http://172.31.255.254/",
        "http://192.168.1.1/",
        "http://100.64.0.1/",
        "http://100.127.255.254/",
        "http://198.18.0.1/",
        "http://192.0.2.10/",
        "http://224.0.0.251/",
        "http://240.0.0.1/",
        "http://255.255.255.255/",
        "http://[::1]/",
        "http://[::1]:2019/config/",
        "http://[::]/",
        "http://[::ffff:127.0.0.1]/",
        "http://[::ffff:7f00:1]/",
        "http://[::ffff:10.0.0.5]/",
        "http://[::ffff:169.254.169.254]/",
        "http://[::127.0.0.1]/",
        "http://[64:ff9b::7f00:1]/",
        "http://[2002:7f00:1::1]/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
        "http://[fd12:3456:789a::1]/",
        "http://[ff02::1]/",
        "http://[2001:db8::1]/",
        "https://127.0.0.1/",
        "https://[::1]:8443/",
    ],
)
def test_non_public_address_literals_are_not_requested(wire, uri):
    result = _verify(uri)

    assert wire.sent == []
    assert result.verified is False
    assert result.recommendation == "reject"


@pytest.mark.parametrize(
    "addresses",
    [
        ["127.0.0.1"],
        ["10.1.2.3"],
        ["169.254.169.254"],
        ["::1"],
        ["fd00::5"],
        ["::ffff:192.168.0.10"],
        # One public answer does not excuse a private one.
        [PUBLIC_IP, "10.1.2.3"],
        ["10.1.2.3", PUBLIC_IP],
        [PUBLIC_IP, "::1"],
    ],
)
def test_names_resolving_to_non_public_addresses_are_not_requested(wire, addresses):
    wire.dns.set("source.example.test", *addresses)

    result = _verify("https://source.example.test/data")

    assert wire.sent == []
    assert result.verified is False


def test_unresolvable_name_is_unreachable(wire):
    result = _verify("https://nxdomain.example.test/data")

    assert wire.sent == []
    assert result.verified is False
    assert any(f.startswith("endpoint_unreachable") for f in result.flags)


def test_connection_goes_to_the_address_that_was_validated(wire):
    """A second, different DNS answer must not be used for the connection."""
    wire.dns.set_sequence("rebind.example.test", [PUBLIC_IP], ["127.0.0.1"], ["127.0.0.1"])

    result = _verify("http://rebind.example.test:8080/data")

    assert wire.connected_hosts() == [PUBLIC_IP]
    assert wire.dns.lookups.count("rebind.example.test") == 1
    request = wire.sent[0]
    assert request.url.port == 8080
    assert request.headers["host"] == "rebind.example.test:8080"
    assert result.verified is True


# ---------------------------------------------------------------------------
# Redirects
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "location",
    [
        "http://127.0.0.1:2019/config/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://inside.example.test/",
        "//127.0.0.1/",
        "file:///etc/hostname",
        "gopher://127.0.0.1:6379/_INFO",
    ],
)
def test_redirect_to_a_non_public_target_is_refused(wire, location):
    wire.dns.set("source.example.test", PUBLIC_IP)
    wire.dns.set("inside.example.test", "10.0.0.7")
    wire.answer("source.example.test", httpx.Response(302, headers={"Location": location}))

    result = _verify("https://source.example.test/data")

    assert wire.connected_hosts() == [PUBLIC_IP]
    assert result.verified is False
    assert result.recommendation == "reject"


def test_redirect_between_public_hosts_is_followed_and_hashed(wire):
    body = b'{"rows": 3}'
    wire.dns.set("source.example.test", PUBLIC_IP)
    wire.dns.set("cdn.example.test", OTHER_PUBLIC_IP)
    wire.answer(
        "source.example.test",
        httpx.Response(301, headers={"Location": "https://cdn.example.test/v2/data"}),
    )
    wire.answer("cdn.example.test/v2/data", httpx.Response(200, content=body))

    result = _verify(
        "https://source.example.test/data",
        content_hash="sha256:" + hashlib.sha256(body).hexdigest(),
    )

    assert wire.connected_hosts() == [PUBLIC_IP, OTHER_PUBLIC_IP]
    assert result.verified is True
    assert result.flags == []


def test_redirect_loop_stops_after_a_few_hops(wire):
    wire.dns.set("source.example.test", PUBLIC_IP)
    wire.answer(
        "source.example.test",
        httpx.Response(302, headers={"Location": "https://source.example.test/again"}),
    )

    result = _verify("https://source.example.test/data")

    assert 1 <= len(wire.sent) <= 5
    assert result.verified is False


# ---------------------------------------------------------------------------
# Legitimate public sources keep working
# ---------------------------------------------------------------------------


def test_public_source_with_matching_hash_is_verified(wire):
    body = b'{"temperature": 21}'
    wire.dns.set("api.example.test", PUBLIC_IP)
    wire.answer("api.example.test", httpx.Response(200, content=body))

    result = _verify(
        "https://api.example.test/forecast?city=Oslo",
        content_hash="sha256:" + hashlib.sha256(body).hexdigest(),
    )

    assert result.verified is True
    assert result.confidence == 0.95
    assert result.recommendation == "approve"
    assert result.flags == []
    request = wire.sent[0]
    assert request.method == "GET"
    assert request.headers["host"] == "api.example.test"
    assert request.url.path == "/forecast"
    assert request.url.query == b"city=Oslo"


def test_public_source_with_wrong_hash_is_rejected(wire):
    wire.dns.set("api.example.test", PUBLIC_IP)
    wire.answer("api.example.test", httpx.Response(200, content=b"something else"))

    result = _verify("https://api.example.test/forecast", content_hash="sha256:" + "0" * 64)

    assert result.verified is False
    assert any(f.startswith("hash_mismatch") for f in result.flags)


def test_public_source_without_hash_is_verified(wire):
    wire.dns.set("api.example.test", PUBLIC_IP, "2606:2800:220:1:248:1893:25c8:1946")

    result = _verify("http://api.example.test:8443/forecast")

    assert result.verified is True
    assert result.recommendation == "approve"


@pytest.mark.parametrize("status", [401, 403])
def test_login_protected_public_source_is_not_verified(wire, status):
    wire.dns.set("api.example.test", PUBLIC_IP)
    wire.answer("api.example.test", httpx.Response(status, content=b"{}"))

    result = _verify("https://api.example.test/private")

    assert result.verified is False
    assert result.recommendation == "flag"
    assert any(f.startswith("endpoint_auth_required") for f in result.flags)
    assert "tier_mismatch:auth_gated_source_use_signed_tier" in result.flags


def test_public_source_error_status_is_reported(wire):
    wire.dns.set("api.example.test", PUBLIC_IP)
    wire.answer("api.example.test", httpx.Response(404, content=b"{}"))

    result = _verify("https://api.example.test/missing")

    assert result.verified is False
    assert any(f.endswith("status=404") for f in result.flags)


def test_head_method_is_still_honoured(wire):
    wire.dns.set("api.example.test", PUBLIC_IP)

    result = _verify("https://api.example.test/forecast", method="head")

    assert [request.method for request in wire.sent] == ["HEAD"]
    assert result.verified is True


def test_spot_check_of_a_public_source_sends_head(wire):
    wire.dns.set("api.example.test", PUBLIC_IP)
    provenance = _provenance("https://api.example.test/forecast", level="signed")

    result = _run(ProvenanceVerifier(spot_check_rate=1.0).verify_signed(provenance, "content"))

    assert [request.method for request in wire.sent] == ["HEAD"]
    assert wire.connected_hosts() == [PUBLIC_IP]
    assert result.verified is True
