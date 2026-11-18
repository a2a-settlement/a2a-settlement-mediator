"""Guarded outbound HTTP for URLs the mediator did not choose itself.

Provenance source references are written by a party to the escrow, so the
mediator must not fetch them the way it fetches its own configured endpoints.
``guarded_fetch`` is the single entry point for such requests:

- only ``http`` and ``https`` URLs, and only ``GET`` or ``HEAD``;
- the host is resolved once, every resolved address must be publicly routable,
  and the connection is made to an address that passed that check (the name is
  not resolved a second time);
- redirects are not followed by the HTTP client. Each ``Location`` is put
  through the same checks, up to ``MAX_REDIRECTS`` hops;
- connect/read timeouts, an overall deadline, and a cap on the body size.

URLs that come only from operator configuration (the exchange, the TSA, the
LLM provider, the escalation webhook, the execution callback) do not go
through this module.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass

import httpx

from a2a_settlement_mediator.config import settings

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = ("http", "https")
ALLOWED_METHODS = ("GET", "HEAD")
MAX_REDIRECTS = 3
MAX_RESPONSE_BYTES = 5 * 1024 * 1024
# Addresses tried, in resolver order, when a connection cannot be established.
MAX_CONNECT_ADDRESSES = 4

_REDIRECT_STATUSES = (301, 302, 303, 307, 308)

# Everything that is not ordinary, publicly routable unicast space.
_BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(net)
    for net in (
        "0.0.0.0/8",  # "this network", unspecified
        "10.0.0.0/8",  # private
        "100.64.0.0/10",  # carrier-grade NAT
        "127.0.0.0/8",  # loopback
        "169.254.0.0/16",  # link-local, cloud metadata
        "172.16.0.0/12",  # private
        "192.0.0.0/24",  # IETF protocol assignments
        "192.0.2.0/24",  # documentation
        "192.88.99.0/24",  # 6to4 relay anycast (deprecated)
        "192.168.0.0/16",  # private
        "198.18.0.0/15",  # benchmarking
        "198.51.100.0/24",  # documentation
        "203.0.113.0/24",  # documentation
        "224.0.0.0/4",  # multicast
        "240.0.0.0/4",  # reserved, broadcast
        "::/8",  # unspecified, loopback, IPv4-compatible, reserved
        "64:ff9b::/96",  # NAT64 (embeds an IPv4 address)
        "64:ff9b:1::/48",  # local-use NAT64
        "100::/64",  # discard-only
        "2001::/23",  # IETF protocol assignments, Teredo
        "2001:db8::/32",  # documentation
        "2002::/16",  # 6to4 (embeds an IPv4 address)
        "fc00::/7",  # unique local
        "fe80::/10",  # link-local
        "fec0::/10",  # site-local (deprecated)
        "ff00::/8",  # multicast
    )
)


class OutboundFetchError(Exception):
    """A guarded fetch could not be completed."""


class OutboundRequestBlocked(OutboundFetchError):
    """The URL, method, resolved address or a redirect target is not allowed."""


class OutboundResponseTooLarge(OutboundFetchError):
    """The response body exceeded the size cap."""


@dataclass(frozen=True)
class GuardedResponse:
    status_code: int
    # Empty when the body was not requested.
    content: bytes
    # The URL that produced this response, after any redirects.
    url: str


def is_public_address(address: str) -> bool:
    """True when ``address`` is an IP literal in publicly routable unicast space."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    if any(ip.version == net.version and ip in net for net in _BLOCKED_NETWORKS):
        return False
    return not (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def private_addresses_allowed() -> bool:
    return bool(settings.allow_private_fetch_addresses)


def warn_if_private_addresses_allowed() -> None:
    if private_addresses_allowed():
        logger.warning(
            "INSECURE: MEDIATOR_INSECURE_ALLOW_PRIVATE_FETCH_ADDRESSES is on. Provenance "
            "URLs supplied by escrow parties may make this mediator send requests to "
            "loopback, private and link-local addresses. Local development only."
        )


warn_if_private_addresses_allowed()


async def _resolve(host: str, port: int) -> list[str]:
    """Resolve ``host`` once and return its distinct addresses in resolver order."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise OutboundFetchError(f"could not resolve host: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        address = str(info[4][0])
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise OutboundFetchError("host resolved to no addresses")
    return addresses


async def _validated_addresses(url: httpx.URL) -> list[str]:
    """Check scheme and host, resolve, and return the addresses safe to connect to."""
    if url.scheme not in ALLOWED_SCHEMES:
        raise OutboundRequestBlocked(f"scheme {url.scheme!r} is not allowed")
    host = url.host
    if not host:
        raise OutboundRequestBlocked("URL has no host")
    port = url.port or (443 if url.scheme == "https" else 80)

    addresses = await _resolve(host, port)
    refused = [a for a in addresses if not is_public_address(a)]
    if refused:
        if not private_addresses_allowed():
            raise OutboundRequestBlocked("host resolves to a non-public address")
        logger.warning(
            "INSECURE: fetching %s although it resolves to a non-public address, "
            "because MEDIATOR_INSECURE_ALLOW_PRIVATE_FETCH_ADDRESSES is on",
            str(url)[:200],
        )
    return addresses[:MAX_CONNECT_ADDRESSES]


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True


async def _send_pinned(
    client: httpx.AsyncClient,
    method: str,
    url: httpx.URL,
    address: str,
    *,
    read_body: bool,
    max_bytes: int,
) -> tuple[int, bytes, str | None]:
    """Send one request to ``address`` while presenting ``url``'s host name.

    The URL's host is replaced by the already-validated address, so the HTTP
    client has no name left to resolve. The original name still goes in the
    ``Host`` header and, for HTTPS, in SNI and certificate verification.
    """
    extensions: dict[str, object] = {}
    if url.scheme == "https" and not _is_ip_literal(url.host):
        extensions["sni_hostname"] = url.host
    async with client.stream(
        method,
        url.copy_with(host=address),
        headers={"Host": url.netloc.decode("ascii")},
        extensions=extensions,
    ) as response:
        body = b""
        if read_body and method != "HEAD" and response.status_code not in _REDIRECT_STATUSES:
            chunks: list[bytes] = []
            received = 0
            async for chunk in response.aiter_bytes():
                received += len(chunk)
                if received > max_bytes:
                    raise OutboundResponseTooLarge(
                        f"response body is larger than {max_bytes} bytes"
                    )
                chunks.append(chunk)
            body = b"".join(chunks)
        return response.status_code, body, response.headers.get("location")


async def _fetch(
    method: str, url: str, *, timeout: float, read_body: bool, max_bytes: int
) -> GuardedResponse:
    if method not in ALLOWED_METHODS:
        raise OutboundRequestBlocked(f"method {method[:16]!r} is not allowed")
    try:
        current = httpx.URL(url)
    except (httpx.InvalidURL, TypeError, ValueError) as exc:
        raise OutboundRequestBlocked(f"URL could not be parsed: {exc}") from exc

    # follow_redirects stays off: every hop is validated here before it is requested.
    # trust_env stays off: a proxy from HTTP(S)_PROXY would do its own name
    # resolution and connect on the mediator's behalf.
    async with httpx.AsyncClient(
        timeout=timeout, follow_redirects=False, trust_env=False
    ) as client:
        for _hop in range(MAX_REDIRECTS + 1):
            addresses = await _validated_addresses(current)
            for index, address in enumerate(addresses):
                try:
                    status, body, location = await _send_pinned(
                        client, method, current, address, read_body=read_body, max_bytes=max_bytes
                    )
                    break
                except (httpx.ConnectError, httpx.ConnectTimeout):
                    if index == len(addresses) - 1:
                        raise
            if status not in _REDIRECT_STATUSES or not location:
                return GuardedResponse(status_code=status, content=body, url=str(current))
            try:
                current = current.join(location)
            except (httpx.InvalidURL, TypeError, ValueError) as exc:
                raise OutboundRequestBlocked(f"redirect target could not be parsed: {exc}") from exc
    raise OutboundRequestBlocked(f"more than {MAX_REDIRECTS} redirects")


async def guarded_fetch(
    method: str,
    url: str,
    *,
    timeout: float = 10.0,
    total_timeout: float | None = None,
    read_body: bool = True,
    max_bytes: int = MAX_RESPONSE_BYTES,
) -> GuardedResponse:
    """Fetch a URL that a party to an escrow (not the operator) supplied.

    Raises ``OutboundRequestBlocked`` when the URL, method, a resolved address
    or a redirect target is refused, ``OutboundResponseTooLarge`` when the body
    exceeds ``max_bytes``, ``OutboundFetchError`` when the host does not
    resolve or the overall deadline passes, and ``httpx.HTTPError`` for
    transport failures.
    """
    deadline = total_timeout if total_timeout is not None else timeout * 3
    try:
        return await asyncio.wait_for(
            _fetch(
                method.upper(), url, timeout=timeout, read_body=read_body, max_bytes=max_bytes
            ),
            deadline,
        )
    except OutboundRequestBlocked as exc:
        logger.warning("Blocked outbound request to %s: %s", str(url)[:200], exc)
        raise
    except asyncio.TimeoutError as exc:
        raise OutboundFetchError(f"request did not finish within {deadline}s") from exc
