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
    """HTTP client for requesting RFC 3161 timestamps from a TSA."""

    CONTENT_TYPE_REQUEST = "application/timestamp-query"
    CONTENT_TYPE_RESPONSE = "application/timestamp-reply"

    def __init__(self, tsa_url: str, timeout_seconds: float = 10.0) -> None:
        self.tsa_url = tsa_url
        self.timeout_seconds = timeout_seconds

    def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
        """Request an RFC 3161 timestamp for a SHA-256 hash.

        Args:
            payload_hash: 32-byte SHA-256 digest to be timestamped.

        Returns:
            TimestampToken with the TSA's signed response.

        Raises:
            TSATimeoutError: If the TSA does not respond in time.
            TSAClientError: If the TSA rejects the request or returns an error.
        """
        if len(payload_hash) != 32:
            raise ValueError(f"Expected 32-byte SHA-256 hash, got {len(payload_hash)} bytes")

        nonce = int.from_bytes(os.urandom(16), "big")
        request_der = build_timestamp_request(payload_hash, nonce=nonce)

        logger.info("Requesting RFC 3161 timestamp from %s", self.tsa_url)
        t0 = time.monotonic()

        try:
            with httpx.Client(timeout=self.timeout_seconds) as client:
                resp = client.post(
                    self.tsa_url,
                    content=request_der,
                    headers={"Content-Type": self.CONTENT_TYPE_REQUEST},
                )
        except httpx.TimeoutException as exc:
            elapsed = int((time.monotonic() - t0) * 1000)
            logger.error("TSA timeout after %dms: %s", elapsed, exc)
            raise TSATimeoutError(
                f"TSA server at {self.tsa_url} timed out after {self.timeout_seconds}s"
            ) from exc
        except httpx.HTTPError as exc:
            raise TSAClientError(f"TSA HTTP error: {exc}") from exc

        elapsed_ms = int((time.monotonic() - t0) * 1000)

        if resp.status_code != 200:
            raise TSAClientError(
                f"TSA returned HTTP {resp.status_code}: {resp.text[:500]}"
            )

        response_der = resp.content
        if not response_der:
            raise TSAClientError("TSA returned empty response body")

        try:
            status = parse_timestamp_response_status(response_der)
        except (ValueError, IndexError) as exc:
            raise TSAClientError(f"Failed to parse TSA response: {exc}") from exc

        if status not in (0, 1):  # granted or grantedWithMods
            raise TSAClientError(f"TSA rejected timestamp request with status={status}")

        logger.info("RFC 3161 timestamp granted in %dms (status=%d)", elapsed_ms, status)

        return TimestampToken(
            tsa_url=self.tsa_url,
            hash_algorithm="sha256",
            message_hash=payload_hash.hex(),
            timestamp_token_b64=base64.b64encode(response_der).decode("ascii"),
            serial_number=str(nonce),
            requested_at=datetime.now(timezone.utc),
        )

    def health_check(self) -> bool:
        """Quick check that the TSA URL is reachable."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.head(self.tsa_url)
                return resp.status_code < 500
        except httpx.HTTPError:
            return False
