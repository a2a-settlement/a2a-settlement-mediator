"""RFC 3161 Time Stamp Authority client.

Constructs DER-encoded TimeStampReq messages, sends them to a TSA over
HTTP, and parses the TimeStampResp to extract the signed timestamp token.

The DER encoding is implemented inline (no external ASN.1 library) to keep
the dependency footprint minimal — important for a WORM compliance system
where every dependency must be auditable.
"""

from __future__ import annotations

import base64
import logging
import os
import time
from datetime import datetime, timezone

import httpx

from a2a_settlement_mediator.config import resolve_tsa_url
from a2a_settlement_mediator.worm_schemas import TimestampToken

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Minimal DER encoder (only the types needed for RFC 3161 TimeStampReq)
# ---------------------------------------------------------------------------

# ASN.1 tag bytes
_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_NULL = 0x05
_TAG_OID = 0x06
_TAG_SEQUENCE = 0x30
_TAG_BOOLEAN = 0x01

# SHA-256 AlgorithmIdentifier OID: 2.16.840.1.101.3.4.2.1
_SHA256_OID_BYTES = bytes([0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01])


def _der_length(length: int) -> bytes:
    """Encode a length in DER format."""
    if length < 0x80:
        return bytes([length])
    elif length < 0x100:
        return bytes([0x81, length])
    elif length < 0x10000:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
    else:
        return bytes(
            [0x83, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]
        )


def _der_tlv(tag: int, value: bytes) -> bytes:
    """Build a DER TLV (Tag-Length-Value) triple."""
    return bytes([tag]) + _der_length(len(value)) + value


def _der_sequence(*items: bytes) -> bytes:
    return _der_tlv(_TAG_SEQUENCE, b"".join(items))


def _der_integer_raw(value: int) -> bytes:
    """Encode a non-negative integer in DER."""
    if value == 0:
        return _der_tlv(_TAG_INTEGER, b"\x00")
    hex_str = format(value, "x")
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    data = bytes.fromhex(hex_str)
    if data[0] & 0x80:
        data = b"\x00" + data
    return _der_tlv(_TAG_INTEGER, data)


def _der_boolean(value: bool) -> bytes:
    return _der_tlv(_TAG_BOOLEAN, b"\xff" if value else b"\x00")


def _der_octet_string(data: bytes) -> bytes:
    return _der_tlv(_TAG_OCTET_STRING, data)


def _der_oid(oid_bytes: bytes) -> bytes:
    return _der_tlv(_TAG_OID, oid_bytes)


def _der_null() -> bytes:
    return _der_tlv(_TAG_NULL, b"")


def build_timestamp_request(data_hash: bytes, nonce: int | None = None) -> bytes:
    """Build a DER-encoded RFC 3161 TimeStampReq.

    Structure::

        TimeStampReq ::= SEQUENCE {
            version          INTEGER  { v1(1) },
            messageImprint   MessageImprint,
            nonce            INTEGER           OPTIONAL,
            certReq          BOOLEAN           DEFAULT FALSE
        }

        MessageImprint ::= SEQUENCE {
            hashAlgorithm    AlgorithmIdentifier,
            hashedMessage    OCTET STRING
        }
    """
    algorithm_id = _der_sequence(_der_oid(_SHA256_OID_BYTES), _der_null())
    message_imprint = _der_sequence(algorithm_id, _der_octet_string(data_hash))

    fields: list[bytes] = [
        _der_integer_raw(1),  # version v1
        message_imprint,
    ]

    if nonce is not None:
        fields.append(_der_integer_raw(nonce))

    fields.append(_der_boolean(True))  # certReq = TRUE

    return _der_sequence(*fields)


def parse_timestamp_response_status(resp_der: bytes) -> int:
    """Extract the PKIStatus integer from a DER-encoded TimeStampResp.

    TimeStampResp ::= SEQUENCE {
        status          PKIStatusInfo,
        timeStampToken  ContentInfo OPTIONAL
    }
    PKIStatusInfo ::= SEQUENCE {
        status        PKIStatus,    -- INTEGER
        ...
    }

    Returns the status integer:
        0 = granted
        1 = grantedWithMods
        2 = rejection
        3 = waiting
        4 = revocationWarning
        5 = revocationNotification
    """
    if len(resp_der) < 5:
        raise ValueError("TimeStampResp too short to contain a valid status")

    # Outer SEQUENCE
    if resp_der[0] != _TAG_SEQUENCE:
        raise ValueError("TimeStampResp does not start with SEQUENCE tag")

    offset = 1
    outer_len, offset = _parse_der_length(resp_der, offset)  # noqa: F841

    # PKIStatusInfo SEQUENCE
    if resp_der[offset] != _TAG_SEQUENCE:
        raise ValueError("PKIStatusInfo does not start with SEQUENCE tag")

    offset += 1
    status_info_len, offset = _parse_der_length(resp_der, offset)  # noqa: F841

    # PKIStatus INTEGER
    if resp_der[offset] != _TAG_INTEGER:
        raise ValueError("PKIStatus is not an INTEGER")

    offset += 1
    int_len, offset = _parse_der_length(resp_der, offset)
    status_bytes = resp_der[offset : offset + int_len]

    status = int.from_bytes(status_bytes, byteorder="big", signed=False)
    return status


def _parse_der_length(data: bytes, offset: int) -> tuple[int, int]:
    """Parse a DER length field starting at *offset*.

    Returns (length_value, new_offset).
    """
    first = data[offset]
    if first < 0x80:
        return first, offset + 1
    num_bytes = first & 0x7F
    length = int.from_bytes(data[offset + 1 : offset + 1 + num_bytes], "big")
    return length, offset + 1 + num_bytes


# ---------------------------------------------------------------------------
# TSA HTTP client
# ---------------------------------------------------------------------------


class TSAClientError(Exception):
    """Raised when the TSA request fails in a non-recoverable way."""


class TSATimeoutError(TSAClientError):
    """Raised when the TSA server does not respond within the timeout."""


class RFC3161Client:
    """HTTP client for requesting RFC 3161 timestamps from a TSA.

    Optional keyword arguments add a fallback URL, a bearer token, and mTLS
    material. Omitting them preserves the previous URL-and-timeout behavior.
    The bearer token is never written to logs or exception text.
    """

    CONTENT_TYPE_REQUEST = "application/timestamp-query"
    CONTENT_TYPE_RESPONSE = "application/timestamp-reply"

    def __init__(
        self,
        tsa_url: str,
        timeout_seconds: float = 10.0,
        *,
        fallback_url: str = "",
        bearer_token: str = "",
        client_cert: str = "",
        client_key: str = "",
        ca_bundle: str = "",
    ) -> None:
        self.tsa_url = resolve_tsa_url(tsa_url)
        self.timeout_seconds = timeout_seconds
        self.fallback_url = resolve_tsa_url(fallback_url) if fallback_url.strip() else ""
        self.bearer_token = bearer_token.strip()
        self.client_cert = client_cert.strip()
        self.client_key = client_key.strip()
        self.ca_bundle = ca_bundle.strip()
        if self.client_key and not self.client_cert:
            raise ValueError(
                "TSA client key requires a client certificate "
                "(MEDIATOR_TSA_CLIENT_CERT / client_cert)"
            )

    def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
        """Request an RFC 3161 timestamp for a SHA-256 hash.

        Args:
            payload_hash: 32-byte SHA-256 digest to be timestamped.

        Returns:
            TimestampToken with the TSA's signed response. ``tsa_url`` is the
            authority that actually issued the token (primary or fallback).

        Raises:
            TSATimeoutError: If the TSA does not respond in time.
            TSAClientError: If the TSA rejects the request or returns an error.
        """
        if len(payload_hash) != 32:
            raise ValueError(f"Expected 32-byte SHA-256 hash, got {len(payload_hash)} bytes")

        try:
            return self._request_from(self.tsa_url, payload_hash)
        except TSAClientError as exc:
            if not self.fallback_url:
                raise
            logger.warning(
                "Primary TSA %s failed (%s); retrying fallback TSA %s",
                self.tsa_url,
                self._scrub(str(exc)),
                self.fallback_url,
            )
            return self._request_from(self.fallback_url, payload_hash)

    def _request_from(self, tsa_url: str, payload_hash: bytes) -> TimestampToken:
        nonce = int.from_bytes(os.urandom(16), "big")
        request_der = build_timestamp_request(payload_hash, nonce=nonce)

        logger.info("Requesting RFC 3161 timestamp from %s", tsa_url)
        t0 = time.monotonic()

        try:
            with self._open_client(self.timeout_seconds) as client:
                resp = client.post(
                    tsa_url,
                    content=request_der,
                    headers=self._request_headers(),
                )
        except httpx.TimeoutException as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.error(
                "TSA timeout after %dms: %s", elapsed, self._scrub(str(exc))
            )
            raise TSATimeoutError(
                f"TSA server at {tsa_url} timed out after {self.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise TSAClientError(
                self._scrub(f"TSA HTTP error talking to {tsa_url}: {exc}")
            ) from exc

        elapsed_ms = int((time.monotonic() - t0) * 1000)

        if resp.status_code != 200:
            body = self._scrub(resp.text[:500])
            raise TSAClientError(
                f"TSA at {tsa_url} returned HTTP {resp.status_code}: {body}"
            )

        response_der = resp.content
        if not response_der:
            raise TSAClientError(f"TSA at {tsa_url} returned an empty response body")

        try:
            status = parse_timestamp_response_status(response_der)
        except (ValueError, IndexError) as exc:
            raise TSAClientError(
                f"Failed to parse TSA response from {tsa_url}: {exc}"
            ) from exc

        if status not in (0, 1):  # granted or grantedWithMods
            raise TSAClientError(
                f"TSA at {tsa_url} rejected timestamp request with status={status}"
            )

        logger.info("RFC 3161 timestamp granted in %dms (status=%d)", elapsed_ms, status)

        return TimestampToken(
            tsa_url=tsa_url,
            hash_algorithm="sha256",
            message_hash=payload_hash.hex(),
            timestamp_token_b64=base64.b64encode(response_der).decode("ascii"),
            serial_number=str(nonce),
            requested_at=datetime.now(timezone.utc),
        )

    def health_check(self) -> bool:
        """Quick check that the TSA URL is reachable."""
        try:
            with self._open_client(5.0) as client:
                resp = client.head(self.tsa_url, headers=self._authorization_headers())
                return resp.status_code < 500
        except httpx.HTTPError:
            return False

    def _open_client(self, timeout: float) -> httpx.Client:
        kwargs: dict[str, object] = {
            "timeout": timeout,
            "verify": self.ca_bundle if self.ca_bundle else True,
        }
        cert = self._client_cert()
        if cert is not None:
            kwargs["cert"] = cert
        return httpx.Client(**kwargs)

    def _client_cert(self) -> str | tuple[str, str] | None:
        if self.client_cert and self.client_key:
            return (self.client_cert, self.client_key)
        if self.client_cert:
            return self.client_cert
        return None

    def _authorization_headers(self) -> dict[str, str]:
        if not self.bearer_token:
            return {}
        return {"Authorization": f"Bearer {self.bearer_token}"}

    def _request_headers(self) -> dict[str, str]:
        headers = {"Content-Type": self.CONTENT_TYPE_REQUEST}
        headers.update(self._authorization_headers())
        return headers

    def _scrub(self, text: str) -> str:
        """Remove the bearer token from text that might be logged or raised."""
        token = self.bearer_token
        if token and token in text:
            return text.replace(token, "[redacted]")
        return text
