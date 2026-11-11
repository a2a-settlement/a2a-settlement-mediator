"""DSSE v1 envelopes for in-toto statement payloads.

The signature covers the Pre-Authentication Encoding, not the JSON envelope.
Payload bytes are standard base64 (RFC 4648), and the ECDSA signature is DER.
"""

from __future__ import annotations

import base64
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from a2a_settlement_mediator.receipts.signer import JwkError, Signer, public_key_from_jwk

# Media type of an in-toto statement body. This is the DSSE payloadType, not
# the statement's ``_type`` URI.
IN_TOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json"


class DsseVerificationError(ValueError):
    """A DSSE envelope failed verification."""


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE v1 Pre-Authentication Encoding.

    ``PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body``
    where ``SP`` is a single ASCII space and ``LEN`` is the octet length in
    ASCII decimal with no leading zeros.
    """
    if not isinstance(payload_type, str):
        raise TypeError("payload_type must be a string")
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    type_bytes = payload_type.encode("utf-8")
    body = bytes(payload)
    return b" ".join(
        (
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(body)).encode("ascii"),
            body,
        )
    )


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64decode(value: str, what: str) -> bytes:
    if not isinstance(value, str):
        raise DsseVerificationError(f"DSSE {what} must be standard base64")
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise DsseVerificationError(f"DSSE {what} is not valid standard base64") from exc


def sign_envelope(payload: bytes, payload_type: str, signer: Signer) -> dict[str, Any]:
    """Sign ``payload`` and return a DSSE v1 envelope.

    The signer sees the PAE of ``payload_type`` and ``payload``. The returned
    object is ``{payloadType, payload, signatures: [{keyid, sig}]}`` with
    standard base64 for the payload and the DER signature.
    """
    if not isinstance(payload, (bytes, bytearray)):
        raise TypeError("payload must be bytes")
    if not isinstance(payload_type, str) or not payload_type:
        raise ValueError("payload_type must be a non-empty string")
    body = bytes(payload)
    signature = signer.sign(pae(payload_type, body))
    if not isinstance(signature, (bytes, bytearray)) or not signature:
        raise ValueError("signer returned an empty signature")
    return {
        "payloadType": payload_type,
        "payload": _b64encode(body),
        "signatures": [
            {
                "keyid": signer.key_id,
                "sig": _b64encode(bytes(signature)),
            }
        ],
    }


def verify_envelope(envelope: dict[str, Any], jwk: dict[str, Any]) -> bytes:
    """Verify a DSSE envelope and return the payload bytes.

    Raises ``DsseVerificationError`` on a malformed envelope, a payload-type
    or key mismatch, or an invalid ES256 signature over the PAE.
    """
    if not isinstance(envelope, dict):
        raise DsseVerificationError("DSSE envelope must be an object")
    payload_type = envelope.get("payloadType")
    payload_b64 = envelope.get("payload")
    signatures = envelope.get("signatures")
    if not isinstance(payload_type, str) or payload_type == "":
        raise DsseVerificationError("DSSE envelope is missing payloadType")
    if not isinstance(payload_b64, str):
        raise DsseVerificationError("DSSE envelope is missing payload")
    if not isinstance(signatures, list) or not signatures:
        raise DsseVerificationError("DSSE envelope is missing signatures")
    payload = _b64decode(payload_b64, "payload")
    try:
        public_key = public_key_from_jwk(jwk)
    except JwkError as exc:
        raise DsseVerificationError(str(exc)) from exc

    message = pae(payload_type, payload)
    kid = jwk.get("kid")
    saw_candidate = False
    last_error: Exception | None = None
    for entry in signatures:
        if not isinstance(entry, dict):
            raise DsseVerificationError("DSSE signature entry must be an object")
        entry_kid = entry.get("keyid")
        if isinstance(kid, str) and isinstance(entry_kid, str) and entry_kid != kid:
            continue
        sig_b64 = entry.get("sig")
        if not isinstance(sig_b64, str):
            raise DsseVerificationError("DSSE signature is missing sig")
        saw_candidate = True
        signature = _b64decode(sig_b64, "signature")
        try:
            public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as exc:
            last_error = exc
            continue
        return payload
    if not saw_candidate:
        raise DsseVerificationError("no DSSE signature matches the JWK kid")
    raise DsseVerificationError("DSSE signature verification failed") from last_error
