"""ES256 signers for proof-of-fix receipts.

Public receipts are signed by an AWS KMS ECC_NIST_P256 key. The private half
never leaves KMS and is never read from the environment. ``LocalSigner`` holds
an in-memory key for tests and non-public development only.
"""

from __future__ import annotations

import hashlib
from typing import Any, Protocol, runtime_checkable

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.serialization import load_der_public_key

from a2a_settlement_mediator.config import MediatorSettings

_P256_OCTETS = 32
_KMS_KEY_SPEC = "ECC_NIST_P256"
_KMS_SIGNING_ALGORITHM = "ECDSA_SHA_256"
_KMS_MESSAGE_TYPE = "DIGEST"


class SigningConfigError(RuntimeError):
    """Receipt signing is not configured for the requested mode."""


class KmsKeySpecError(ValueError):
    """The KMS key is not an ECC_NIST_P256 signing key."""


class JwkError(ValueError):
    """An EC P-256 JWK could not be encoded or decoded."""


def _b64url(data: bytes) -> str:
    """Base64url without padding, as required by RFC 7515."""
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    import base64

    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except (ValueError, TypeError) as exc:
        raise JwkError("JWK coordinate is not base64url") from exc


def ec_public_jwk(public_key: ec.EllipticCurvePublicKey, key_id: str) -> dict[str, str]:
    """EC P-256 JWK with ``kid``, ``alg`` ES256, and ``use`` sig."""
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise JwkError(f"expected P-256 public key, got {public_key.curve.name}")
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(_P256_OCTETS, "big")),
        "y": _b64url(numbers.y.to_bytes(_P256_OCTETS, "big")),
        "kid": key_id,
        "alg": "ES256",
        "use": "sig",
    }


def public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Reconstruct a P-256 public key from an ES256 JWK."""
    if not isinstance(jwk, dict):
        raise JwkError("JWK must be an object")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise JwkError("JWK must be an EC P-256 key")
    if jwk.get("alg") != "ES256":
        raise JwkError("JWK alg must be ES256")
    if "use" in jwk and jwk.get("use") != "sig":
        raise JwkError("JWK use must be sig")
    x_b64 = jwk.get("x")
    y_b64 = jwk.get("y")
    if not isinstance(x_b64, str) or not isinstance(y_b64, str):
        raise JwkError("JWK is missing x or y")
    x = _b64url_decode(x_b64)
    y = _b64url_decode(y_b64)
    if len(x) != _P256_OCTETS or len(y) != _P256_OCTETS:
        raise JwkError("P-256 coordinates must be 32 octets")
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"),
            int.from_bytes(y, "big"),
            ec.SECP256R1(),
        ).public_key()
    except ValueError as exc:
        raise JwkError("JWK point is not on P-256") from exc


def _require_message(message: bytes) -> bytes:
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    return bytes(message)


@runtime_checkable
class Signer(Protocol):
    """DER ECDSA-SHA-256 signer identified by a JWK ``kid``."""

    key_id: str

    def sign(self, message: bytes) -> bytes:
        """Return a DER ECDSA signature over SHA-256 of ``message``."""

    def public_jwk(self) -> dict[str, str]:
        """Return the EC P-256 public JWK (``kid``, ``alg`` ES256, ``use`` sig)."""


class KmsSigner:
    """Sign with an AWS KMS ECC_NIST_P256 key. The private key stays in KMS.

    ``client`` may be injected (tests). Otherwise a ``boto3`` KMS client is
    created on first use, scoped to ``region``.
    """

    def __init__(
        self,
        key_arn: str,
        key_id: str,
        region: str,
        client: Any | None = None,
    ) -> None:
        if not key_arn:
            raise ValueError("key_arn is required")
        self.key_arn = key_arn
        self.key_id = key_id
        self.region = region
        self._client = client
        self._public_key: ec.EllipticCurvePublicKey | None = None

    def _kms(self) -> Any:
        if self._client is None:
            self._client = _boto3_kms_client(self.region)
        return self._client

    def _verified_public_key(self) -> ec.EllipticCurvePublicKey:
        if self._public_key is not None:
            return self._public_key
        response = self._kms().get_public_key(KeyId=self.key_arn)
        spec = response.get("KeySpec")
        if spec != _KMS_KEY_SPEC:
            raise KmsKeySpecError(
                f"KMS key spec must be {_KMS_KEY_SPEC} for ES256 receipts, got {spec!r}"
            )
        der = response.get("PublicKey")
        if not isinstance(der, (bytes, bytearray)):
            raise KmsKeySpecError("KMS GetPublicKey did not return DER SubjectPublicKeyInfo")
        try:
            parsed = load_der_public_key(bytes(der))
        except (ValueError, TypeError) as exc:
            raise KmsKeySpecError("KMS public key is not DER SubjectPublicKeyInfo") from exc
        if not isinstance(parsed, ec.EllipticCurvePublicKey) or not isinstance(
            parsed.curve, ec.SECP256R1
        ):
            raise KmsKeySpecError("KMS public key must be an ECDSA P-256 key")
        self._public_key = parsed
        return parsed

    def sign(self, message: bytes) -> bytes:
        """Ask KMS to sign SHA-256(message). ``MessageType`` is ``DIGEST``."""
        payload = _require_message(message)
        self._verified_public_key()
        digest = hashlib.sha256(payload).digest()
        response = self._kms().sign(
            KeyId=self.key_arn,
            Message=digest,
            MessageType=_KMS_MESSAGE_TYPE,
            SigningAlgorithm=_KMS_SIGNING_ALGORITHM,
        )
        signature = response["Signature"]
        if not isinstance(signature, (bytes, bytearray)) or not signature:
            raise KmsKeySpecError("KMS Sign did not return a DER signature")
        # Touch the DER structure so a raw r||s blob fails closed.
        try:
            decode_dss_signature(bytes(signature))
        except ValueError as exc:
            raise KmsKeySpecError("KMS signature is not DER-encoded ECDSA") from exc
        return bytes(signature)

    def public_jwk(self) -> dict[str, str]:
        return ec_public_jwk(self._verified_public_key(), self.key_id)


class LocalSigner:
    """In-memory P-256 signer for tests and non-public development.

    The key is generated in-process unless one is injected. It is never loaded
    from an environment variable.
    """

    def __init__(
        self,
        key_id: str = "local-dev",
        private_key: ec.EllipticCurvePrivateKey | None = None,
    ) -> None:
        if private_key is None:
            private_key = ec.generate_private_key(ec.SECP256R1())
        elif not isinstance(private_key.curve, ec.SECP256R1):
            raise ValueError("LocalSigner requires an EC P-256 private key")
        self.key_id = key_id
        self._private_key = private_key

    def sign(self, message: bytes) -> bytes:
        payload = _require_message(message)
        return self._private_key.sign(payload, ec.ECDSA(hashes.SHA256()))

    def public_jwk(self) -> dict[str, str]:
        return ec_public_jwk(self._private_key.public_key(), self.key_id)


def _boto3_kms_client(region: str) -> Any:
    """Construct a regional KMS client. Imported lazily so tests need no network."""
    import boto3

    return boto3.client("kms", region_name=region)


def signer_from_settings(settings: MediatorSettings) -> Signer:
    """Select the receipt signer.

    A configured ``receipt_kms_key_arn`` always wins. ``LocalSigner`` is
    returned only when receipts are not public. Public receipts with no KMS
    ARN raise ``SigningConfigError``. The private key is never read from the
    environment.
    """
    arn = str(getattr(settings, "receipt_kms_key_arn", "") or "").strip()
    region = str(getattr(settings, "receipt_kms_region", "") or "").strip()
    key_id = str(getattr(settings, "receipt_key_id", "") or "").strip()
    public = bool(getattr(settings, "receipts_public", False))
    if arn:
        return KmsSigner(key_arn=arn, key_id=key_id, region=region)
    if public:
        raise SigningConfigError(
            "Public proof-of-fix receipts require MEDIATOR_RECEIPT_KMS_KEY_ARN. "
            "Refusing to sign with an in-memory key."
        )
    return LocalSigner(key_id=key_id or "local-dev")
