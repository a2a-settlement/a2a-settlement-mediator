"""DSSE envelopes and ES256 signers for proof-of-fix receipts."""

from __future__ import annotations

import base64
import hashlib
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from a2a_settlement_mediator.receipts import (
    IN_TOTO_PAYLOAD_TYPE,
    DsseVerificationError,
    KmsKeySpecError,
    KmsSigner,
    LocalSigner,
    SigningConfigError,
    pae,
    sign_envelope,
    verify_envelope,
)
from a2a_settlement_mediator.receipts.signer import public_key_from_jwk, signer_from_settings

_ARN = "arn:aws:kms:us-east-1:123456789012:key/abcd-ef"


def test_pae_matches_dsse_spec_vectors():
    """Vectors from the DSSE v1 PAE definition.

    Empty inputs leave the spaces that surround the empty type and body.
    The HelloWorld vector is the one published with the DSSE protocol.
    """
    assert pae("", b"") == b"DSSEv1 0  0 "
    assert pae("http://example.com/HelloWorld", b"hello world") == (
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    )
    # Lengths are octet counts, so an embedded NUL is three bytes, not two.
    assert pae("x", b"a\x00b") == b"DSSEv1 1 x 3 a\x00b"


def test_local_signer_round_trip_and_der_signature():
    signer = LocalSigner("kid-1")
    payload = b'{"_type":"https://in-toto.io/Statement/v1"}'
    envelope = sign_envelope(payload, IN_TOTO_PAYLOAD_TYPE, signer)

    assert envelope["payloadType"] == IN_TOTO_PAYLOAD_TYPE
    assert base64.b64decode(envelope["payload"]) == payload
    assert envelope["signatures"][0]["keyid"] == "kid-1"
    signature = base64.b64decode(envelope["signatures"][0]["sig"])
    assert signature[0] == 0x30  # DER SEQUENCE

    jwk = signer.public_jwk()
    assert jwk["kty"] == "EC"
    assert jwk["crv"] == "P-256"
    assert jwk["alg"] == "ES256"
    assert jwk["use"] == "sig"
    assert jwk["kid"] == "kid-1"
    assert verify_envelope(envelope, jwk) == payload

    public_key_from_jwk(jwk).verify(
        signature,
        pae(IN_TOTO_PAYLOAD_TYPE, payload),
        ec.ECDSA(hashes.SHA256()),
    )


def test_verify_rejects_tampered_payload():
    signer = LocalSigner("kid-1")
    envelope = sign_envelope(b'{"ok":true}', IN_TOTO_PAYLOAD_TYPE, signer)
    raw = base64.b64decode(envelope["payload"])
    envelope["payload"] = base64.b64encode(raw + b" ").decode("ascii")
    with pytest.raises(DsseVerificationError):
        verify_envelope(envelope, signer.public_jwk())


def test_verify_rejects_tampered_payload_type():
    signer = LocalSigner("kid-1")
    envelope = sign_envelope(b'{"ok":true}', IN_TOTO_PAYLOAD_TYPE, signer)
    envelope["payloadType"] = IN_TOTO_PAYLOAD_TYPE + ";tampered"
    with pytest.raises(DsseVerificationError):
        verify_envelope(envelope, signer.public_jwk())


def test_verify_rejects_wrong_key_with_the_same_kid():
    signer = LocalSigner("kid-1")
    other = LocalSigner("kid-1")
    envelope = sign_envelope(b"payload", IN_TOTO_PAYLOAD_TYPE, signer)
    with pytest.raises(DsseVerificationError):
        verify_envelope(envelope, other.public_jwk())


class _RecordingKms:
    """In-process stand-in for kms.sign / kms.get_public_key. No network."""

    def __init__(self, private_key: EllipticCurvePrivateKey, key_spec: str | None) -> None:
        self._private_key = private_key
        self._key_spec = key_spec
        self.sign_calls: list[dict] = []
        self.public_calls: list[dict] = []

    def sign(self, **kwargs):
        self.sign_calls.append(kwargs)
        # KMS MessageType=DIGEST signs the supplied digest; it does not hash again.
        signature = self._private_key.sign(
            kwargs["Message"],
            ec.ECDSA(utils.Prehashed(hashes.SHA256())),
        )
        return {"Signature": signature, "KeyId": kwargs["KeyId"]}

    def get_public_key(self, **kwargs):
        self.public_calls.append(kwargs)
        der = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        response = {"PublicKey": der, "KeyId": kwargs["KeyId"]}
        if self._key_spec is not None:
            response["KeySpec"] = self._key_spec
        return response


def test_kms_signer_signs_digest_with_injected_client(monkeypatch):
    def fail_client(region: str):
        raise AssertionError(f"boto3 client constructed for {region}")

    monkeypatch.setattr(
        "a2a_settlement_mediator.receipts.signer._boto3_kms_client",
        fail_client,
    )
    private_key = ec.generate_private_key(ec.SECP256R1())
    client = _RecordingKms(private_key, "ECC_NIST_P256")
    signer = KmsSigner(_ARN, "sb-key-1", "us-east-1", client=client)
    message = b"DSSEv1 28 application/vnd.in-toto+json 2 {}"

    signature = signer.sign(message)

    assert client.sign_calls == [
        {
            "KeyId": _ARN,
            "Message": hashlib.sha256(message).digest(),
            "MessageType": "DIGEST",
            "SigningAlgorithm": "ECDSA_SHA_256",
        }
    ]
    assert signature[0] == 0x30
    jwk = signer.public_jwk()
    assert jwk["kid"] == "sb-key-1"
    assert jwk["alg"] == "ES256"
    assert jwk["use"] == "sig"
    assert jwk["crv"] == "P-256"
    public_key_from_jwk(jwk).verify(signature, message, ec.ECDSA(hashes.SHA256()))
    envelope = sign_envelope(message, IN_TOTO_PAYLOAD_TYPE, signer)
    assert verify_envelope(envelope, jwk) == message


@pytest.mark.parametrize("spec", ["ECC_NIST_P384", "RSA_2048", None])
def test_kms_rejects_wrong_key_spec(spec):
    private_key = ec.generate_private_key(ec.SECP256R1())
    client = _RecordingKms(private_key, spec)
    signer = KmsSigner(_ARN, "sb-key-1", "us-east-1", client=client)
    with pytest.raises(KmsKeySpecError, match="ECC_NIST_P256"):
        signer.public_jwk()
    with pytest.raises(KmsKeySpecError, match="ECC_NIST_P256"):
        signer.sign(b"message")


def test_kms_rejects_non_p256_spki_even_when_spec_claims_p256():
    private_key = ec.generate_private_key(ec.SECP384R1())
    client = _RecordingKms(private_key, "ECC_NIST_P256")
    signer = KmsSigner(_ARN, "sb-key-1", "us-east-1", client=client)
    with pytest.raises(KmsKeySpecError, match="P-256"):
        signer.public_jwk()


def _settings(*, arn: str, public: bool, key_id: str = "sb-key-1", region: str = "us-east-1"):
    return SimpleNamespace(
        receipt_kms_key_arn=arn,
        receipt_kms_region=region,
        receipt_key_id=key_id,
        receipts_public=public,
    )


def test_signer_from_settings_matrix():
    public_kms = signer_from_settings(_settings(arn=_ARN, public=True))
    assert isinstance(public_kms, KmsSigner)
    assert public_kms.key_id == "sb-key-1"
    assert public_kms.key_arn == _ARN
    assert public_kms.region == "us-east-1"

    private_kms = signer_from_settings(_settings(arn=_ARN, public=False, region="eu-west-1"))
    assert isinstance(private_kms, KmsSigner)
    assert private_kms.region == "eu-west-1"

    local = signer_from_settings(_settings(arn="", public=False, key_id="dev-kid"))
    assert isinstance(local, LocalSigner)
    assert local.key_id == "dev-kid"
    assert (
        verify_envelope(
            sign_envelope(b"dev", IN_TOTO_PAYLOAD_TYPE, local),
            local.public_jwk(),
        )
        == b"dev"
    )

    with pytest.raises(SigningConfigError, match="KMS"):
        signer_from_settings(_settings(arn="", public=True))
    with pytest.raises(SigningConfigError, match="KMS"):
        signer_from_settings(_settings(arn="   ", public=True))

    blank_arn = signer_from_settings(_settings(arn="   ", public=False, key_id=""))
    assert isinstance(blank_arn, LocalSigner)
    assert blank_arn.key_id == "local-dev"


def test_private_key_is_not_read_from_the_environment(monkeypatch):
    monkeypatch.setenv("MEDIATOR_RECEIPT_PRIVATE_KEY", "not-a-real-key")
    monkeypatch.setenv("RECEIPT_SIGNING_KEY", "-----BEGIN PRIVATE KEY-----")
    signer = signer_from_settings(_settings(arn="", public=False, key_id="dev-kid"))
    assert isinstance(signer, LocalSigner)
    signer.sign(b"environment-was-ignored")
