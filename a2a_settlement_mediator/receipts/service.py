"""Issue and verify proof-of-fix receipts.

One RFC 3161 token covers both DSSE envelopes. The preimage is::

    SHA-256(
        b"settlebridge-receipt-v1\\x00"
        || canonical(statement envelope)
        || b"\\x00"
        || canonical(vsa envelope)
    )

The Merkle leaf is that 32-byte digest. Verification checks each DSSE
signature against the published JWKS (including retired keys), checks that
the timestamp token's message imprint is that digest, checks the inclusion
proof, and checks the subject when a repo or commit is supplied.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from typing import Any, Protocol

from pydantic import ValidationError

from a2a_settlement_mediator.config import MediatorSettings
from a2a_settlement_mediator.merkle import MerkleTree
from a2a_settlement_mediator.receipts.dsse import (
    IN_TOTO_PAYLOAD_TYPE,
    DsseVerificationError,
    sign_envelope,
    verify_envelope,
)
from a2a_settlement_mediator.receipts.predicate import (
    ProofOfFixDraft,
    ProofOfFixStatement,
    SolverKind,
    Verdict,
    build_proof_of_fix_statement,
    canonical_json_bytes,
    github_subject_name,
)
from a2a_settlement_mediator.receipts.signer import LocalSigner, Signer, signer_from_settings
from a2a_settlement_mediator.receipts.store import (
    ChainVerification,
    ReceiptStore,
    canonical_bytes,
)
from a2a_settlement_mediator.receipts.vsa import VerificationResult, VsaStatement, build_vsa
from a2a_settlement_mediator.tsa_client import (
    RFC3161Client,
    parse_timestamp_response_status,
)
from a2a_settlement_mediator.worm_schemas import TimestampToken

logger = logging.getLogger(__name__)

_DIGEST_PREFIX = b"settlebridge-receipt-v1\x00"
_IMPRINT_VALUE_PREFIX = bytes.fromhex("300d060960864801650304020105000420")
_MAX_DER_DEPTH = 40


class ReceiptIssueError(RuntimeError):
    """The timestamp token does not bind the envelopes that were just signed."""


class ReceiptPolicyError(ValueError):
    """A receipt violated a proof-of-fix issuance rule."""


class ReceiptNotFound(LookupError):
    """No stored receipt has this id."""

    def __init__(self, receipt_id: str) -> None:
        self.receipt_id = receipt_id
        super().__init__(receipt_id)


class ReceiptVerifyInputError(ValueError):
    """The verify request did not identify a receipt to check."""


class TsaBindingError(ValueError):
    """A timestamp token did not yield exactly one SHA-256 message imprint."""


class TimestampRequester(Protocol):
    """The slice of :class:`RFC3161Client` receipt issuance uses."""

    def request_timestamp(self, payload_hash: bytes) -> TimestampToken:
        """Return a granted token over ``payload_hash``."""


def combined_envelope_digest(
    statement_envelope: dict[str, Any], vsa_envelope: dict[str, Any]
) -> bytes:
    """SHA-256 over the statement envelope and then the VSA envelope."""
    return hashlib.sha256(
        _DIGEST_PREFIX
        + canonical_bytes(statement_envelope)
        + b"\x00"
        + canonical_bytes(vsa_envelope)
    ).digest()


def build_granted_timestamp_der(message_hash: bytes) -> bytes:
    """Minimal granted TimeStampResp carrying one SHA-256 imprint.

    The imprint is inside an OCTET STRING, as CMS encapsulates TSTInfo, so a
    parser has to walk the token instead of reading a flat field.
    """
    if len(message_hash) != 32:
        raise ValueError("SHA-256 digest must be 32 bytes")
    status = _der_tlv(0x30, _der_tlv(0x02, b"\x00"))
    imprint = _der_tlv(0x30, _IMPRINT_VALUE_PREFIX + message_hash)
    tst_info = _der_tlv(0x30, _der_tlv(0x02, b"\x01") + imprint)
    encapsulated = _der_tlv(0x04, tst_info)
    content_info = _der_tlv(0x30, encapsulated)
    return _der_tlv(0x30, status + content_info)


def granted_timestamp_token(message_hash: bytes, tsa_url: str) -> TimestampToken:
    """Token whose DER imprint and ``message_hash`` are ``message_hash``."""
    der = build_granted_timestamp_der(message_hash)
    return TimestampToken(
        tsa_url=tsa_url,
        hash_algorithm="sha256",
        message_hash=message_hash.hex(),
        timestamp_token_b64=base64.b64encode(der).decode("ascii"),
        serial_number="1",
    )


def message_imprint_sha256(token_der: bytes) -> bytes:
    """Return the single SHA-256 message imprint embedded in a TimeStampResp."""
    if not isinstance(token_der, (bytes, bytearray)) or not token_der:
        raise TsaBindingError("timestamp token is empty")
    found = _collect_imprints(bytes(token_der))
    unique = set(found)
    if len(unique) != 1:
        raise TsaBindingError("timestamp token must contain one SHA-256 message imprint")
    return found[0]


class ReceiptService:
    """Signs, timestamps, stores, and checks proof-of-fix receipts."""

    def __init__(self, signer: Signer, tsa: TimestampRequester, store: ReceiptStore) -> None:
        self._signer = signer
        self._tsa = tsa
        self._store = store
        # A local key is generated in memory and changes on every process start.
        # Keep the previous public key verifiable instead of refusing to boot.
        self._store.register_public_key(
            signer.public_jwk(),
            allow_replacement=isinstance(signer, LocalSigner),
        )

    @classmethod
    def from_settings(cls, current: MediatorSettings) -> ReceiptService:
        """KMS signer when configured, otherwise the local signer policy."""
        return cls(
            signer=signer_from_settings(current),
            tsa=RFC3161Client(current.tsa_url, current.tsa_timeout_seconds),
            store=ReceiptStore(),
        )

    def issue(self, draft: ProofOfFixDraft) -> dict[str, Any]:
        """Sign a draft, timestamp both envelopes once, and append the row."""
        statement = build_proof_of_fix_statement(draft)
        statement_payload = canonical_json_bytes(statement)
        _reject_house_independence_claim(statement, statement_payload)
        vsa = build_vsa(statement)
        _reject_inconsistent_vsa(statement, vsa)
        statement_envelope = sign_envelope(
            statement_payload, IN_TOTO_PAYLOAD_TYPE, self._signer
        )
        vsa_envelope = sign_envelope(
            canonical_json_bytes(vsa), IN_TOTO_PAYLOAD_TYPE, self._signer
        )
        digest = combined_envelope_digest(statement_envelope, vsa_envelope)
        token = self._tsa.request_timestamp(digest)
        _require_token_binds(token, digest)
        document = self._store.append(
            receipt_id=statement.predicate.receipt_id,
            nonce=statement.predicate.nonce,
            statement_envelope=statement_envelope,
            vsa_envelope=vsa_envelope,
            timestamp_token_b64=token.timestamp_token_b64,
            tsa_url=token.tsa_url,
            message_hash=digest.hex(),
        )
        logger.info("issued proof-of-fix receipt %s", statement.predicate.receipt_id)
        return document

    def get(self, receipt_id: str) -> dict[str, Any] | None:
        return self._store.get(receipt_id)

    def verify_chain(self) -> ChainVerification:
        return self._store.verify_chain()

    def jwks(self) -> dict[str, Any]:
        return self._store.jwks()

    def rotate_signer(self, signer: Signer) -> dict[str, Any]:
        """Retire the active key and sign later receipts with ``signer``."""
        self._store.register_public_key(signer.public_jwk())
        self._signer = signer
        return self.jwks()

    def verify(
        self,
        *,
        receipt_id: str | None = None,
        statement_envelope: dict[str, Any] | None = None,
        vsa_envelope: dict[str, Any] | None = None,
        timestamp_token_b64: str | None = None,
        merkle_proof: dict[str, Any] | None = None,
        repo: str | None = None,
        commit: str | None = None,
    ) -> dict[str, Any]:
        """Check a stored receipt, or the envelopes and proof the caller sent."""
        _require_optional_str(receipt_id, "receipt_id")
        _require_optional_str(repo, "repo")
        _require_optional_str(commit, "commit")
        material = _Material(
            statement_envelope, vsa_envelope, timestamp_token_b64, merkle_proof
        )
        if not material.any_supplied():
            if not receipt_id:
                raise ReceiptVerifyInputError(
                    "receipt_id or statement_envelope, vsa_envelope, "
                    "timestamp_token_b64, and merkle_proof are required"
                )
            stored = self._store.get(receipt_id)
            if stored is None:
                raise ReceiptNotFound(receipt_id)
            material = _Material(
                stored["statement_envelope"],
                stored["vsa_envelope"],
                stored["timestamp_token_b64"],
                stored["merkle_proof"],
            )
        material.require_complete()

        statement, statement_detail = self._open_statement(material.statement_envelope)
        vsa, vsa_detail = self._open_vsa(material.vsa_envelope)
        checks = {
            "dsse_statement": _check(
                statement is not None, statement_detail or "statement verified"
            ),
            "dsse_vsa": _check(vsa is not None, vsa_detail or "VSA verified"),
            "vsa_consistency": _vsa_consistency(statement, vsa),
            "tsa_binding": _tsa_binding(
                material.statement_envelope, material.vsa_envelope, material.timestamp_token_b64
            ),
            "merkle_inclusion": _merkle_inclusion(
                material.statement_envelope, material.vsa_envelope, material.merkle_proof
            ),
            "subject": _subject(statement, vsa, repo, commit),
        }
        return {"valid": all(item["ok"] for item in checks.values()), "checks": checks}

    def _open_statement(
        self, envelope: dict[str, Any]
    ) -> tuple[ProofOfFixStatement | None, str | None]:
        try:
            payload = self._verify_dsse_payload(envelope)
            statement = ProofOfFixStatement.model_validate_json(payload)
        except DsseVerificationError as exc:
            return None, str(exc)
        except (ValidationError, ValueError):
            return None, "payload is not a proof-of-fix statement"
        if canonical_json_bytes(statement) != payload:
            return None, "statement payload is not canonical"
        return statement, None

    def _open_vsa(self, envelope: dict[str, Any]) -> tuple[VsaStatement | None, str | None]:
        try:
            payload = self._verify_dsse_payload(envelope)
            vsa = VsaStatement.model_validate_json(payload)
        except DsseVerificationError as exc:
            return None, str(exc)
        except (ValidationError, ValueError):
            return None, "payload is not a SLSA verification summary"
        if canonical_json_bytes(vsa) != payload:
            return None, "VSA payload is not canonical"
        return vsa, None

    def _verify_dsse_payload(self, envelope: dict[str, Any]) -> bytes:
        if not isinstance(envelope, dict):
            raise DsseVerificationError("DSSE envelope must be an object")
        if envelope.get("payloadType") != IN_TOTO_PAYLOAD_TYPE:
            raise DsseVerificationError("DSSE payloadType is not an in-toto statement")
        signatures = envelope.get("signatures")
        if not isinstance(signatures, list) or not signatures:
            raise DsseVerificationError("DSSE envelope is missing signatures")
        kids = [
            entry["keyid"]
            for entry in signatures
            if isinstance(entry, dict) and isinstance(entry.get("keyid"), str)
        ]
        keys = self._store.jwks()["keys"]
        matched = [key for key in keys if key.get("kid") in kids]
        if not matched:
            raise DsseVerificationError("no JWKS key matches the DSSE keyid")
        last_error: DsseVerificationError | None = None
        for key in matched:
            try:
                return verify_envelope(envelope, key)
            except DsseVerificationError as exc:
                last_error = exc
        raise DsseVerificationError("DSSE signature verification failed") from last_error


class _Material:
    def __init__(
        self,
        statement_envelope: dict[str, Any] | None,
        vsa_envelope: dict[str, Any] | None,
        timestamp_token_b64: str | None,
        merkle_proof: dict[str, Any] | None,
    ) -> None:
        self.statement_envelope = statement_envelope
        self.vsa_envelope = vsa_envelope
        self.timestamp_token_b64 = timestamp_token_b64
        self.merkle_proof = merkle_proof

    def any_supplied(self) -> bool:
        return any(
            value is not None
            for value in (
                self.statement_envelope,
                self.vsa_envelope,
                self.timestamp_token_b64,
                self.merkle_proof,
            )
        )

    def require_complete(self) -> None:
        if not isinstance(self.statement_envelope, dict):
            raise ReceiptVerifyInputError("statement_envelope must be an object")
        if not isinstance(self.vsa_envelope, dict):
            raise ReceiptVerifyInputError("vsa_envelope must be an object")
        if not isinstance(self.timestamp_token_b64, str) or not self.timestamp_token_b64:
            raise ReceiptVerifyInputError("timestamp_token_b64 must be a string")
        if not isinstance(self.merkle_proof, dict):
            raise ReceiptVerifyInputError("merkle_proof must be an object")


def _require_optional_str(value: str | None, name: str) -> None:
    if value is not None and not isinstance(value, str):
        raise ReceiptVerifyInputError(f"{name} must be a string")


def _check(ok: bool, detail: str, *, skipped: bool = False) -> dict[str, Any]:
    return {"ok": ok, "detail": detail, "skipped": skipped}


def _reject_house_independence_claim(statement: ProofOfFixStatement, payload: bytes) -> None:
    if statement.predicate.independence.solver_kind is not SolverKind.HOUSE:
        return
    if b"verifier_independent_of_solver" in payload:
        raise ReceiptPolicyError(
            "house solver receipt must not contain verifier_independent_of_solver"
        )


def _reject_inconsistent_vsa(statement: ProofOfFixStatement, vsa: VsaStatement) -> None:
    expected = (
        VerificationResult.PASSED
        if statement.predicate.verdict is Verdict.VERIFIED
        else VerificationResult.FAILED
    )
    if vsa.predicate.verificationResult is not expected:
        raise ReceiptPolicyError(
            "VSA verificationResult does not match the proof-of-fix verdict"
        )


def _require_token_binds(token: TimestampToken, digest: bytes) -> None:
    if str(token.message_hash).lower() != digest.hex():
        raise ReceiptIssueError("TSA message_hash does not match the combined envelope digest")
    try:
        der = base64.b64decode(token.timestamp_token_b64, validate=True)
        status = parse_timestamp_response_status(der)
        imprint = message_imprint_sha256(der)
    except (ValueError, TsaBindingError) as exc:
        raise ReceiptIssueError(
            "TSA token does not bind the combined envelope digest"
        ) from exc
    if status not in (0, 1) or imprint != digest:
        raise ReceiptIssueError("TSA token does not bind the combined envelope digest")


def _vsa_consistency(
    statement: ProofOfFixStatement | None, vsa: VsaStatement | None
) -> dict[str, Any]:
    if statement is None or vsa is None:
        return _check(False, "signed statement and VSA are required")
    expected = "PASSED" if statement.predicate.verdict is Verdict.VERIFIED else "FAILED"
    reasons: list[str] = []
    if vsa.predicate.verificationResult.value != expected:
        reasons.append("verificationResult does not match the verdict")
    statement_subject = statement.subject[0]
    vsa_subject = vsa.subject[0]
    if (
        vsa_subject.name != statement_subject.name
        or vsa_subject.digest.gitCommit != statement_subject.digest.gitCommit
    ):
        reasons.append("VSA subject does not match the proof-of-fix subject")
    fix_commit = statement.predicate.fix_commit
    if vsa.predicate.resourceUri != f"{statement_subject.name}@{fix_commit}":
        reasons.append("resourceUri does not match the subject")
    policy_hex = hashlib.sha256(canonical_json_bytes(statement.predicate)).hexdigest()
    statement_hex = hashlib.sha256(canonical_json_bytes(statement)).hexdigest()
    if vsa.predicate.policy.digest.sha256 != policy_hex:
        reasons.append("policy digest does not match the proof-of-fix predicate")
    attestation = vsa.predicate.inputAttestations[0]
    if attestation.digest.sha256 != statement_hex:
        reasons.append("input attestation digest does not match the proof-of-fix statement")
    if attestation.uri != f"urn:settlebridge:receipt:{statement.predicate.receipt_id}":
        reasons.append("input attestation uri does not match the receipt id")
    if reasons:
        return _check(False, "; ".join(reasons))
    verdict = statement.predicate.verdict.value
    return _check(True, f"verificationResult {expected} matches verdict {verdict}")


def _tsa_binding(
    statement_envelope: dict[str, Any],
    vsa_envelope: dict[str, Any],
    timestamp_token_b64: str,
) -> dict[str, Any]:
    try:
        der = base64.b64decode(timestamp_token_b64, validate=True)
        status = parse_timestamp_response_status(der)
        imprint = message_imprint_sha256(der)
    except (ValueError, TsaBindingError) as exc:
        return _check(False, str(exc))
    if status not in (0, 1):
        return _check(False, f"TSA status {status} is not granted")
    digest = combined_envelope_digest(statement_envelope, vsa_envelope)
    if imprint != digest:
        return _check(False, "TSA message imprint does not match the combined envelope digest")
    return _check(True, "RFC 3161 imprint matches the combined envelope digest")


def _merkle_inclusion(
    statement_envelope: dict[str, Any],
    vsa_envelope: dict[str, Any],
    proof: dict[str, Any],
) -> dict[str, Any]:
    try:
        siblings = [bytes.fromhex(str(item)) for item in proof["siblings"]]
        directions = [str(item) for item in proof["directions"]]
        root = bytes.fromhex(str(proof["root_hash"]))
        stated_leaf = bytes.fromhex(str(proof["leaf_hash"]))
    except (KeyError, TypeError, ValueError):
        return _check(False, "merkle proof is malformed")
    if len(siblings) != len(directions):
        return _check(False, "merkle proof siblings and directions differ in length")
    if any(direction not in {"left", "right"} for direction in directions):
        return _check(False, "merkle proof direction is invalid")
    digest = combined_envelope_digest(statement_envelope, vsa_envelope)
    leaf = MerkleTree.hash_leaf(digest)
    if stated_leaf != leaf:
        return _check(False, "leaf hash does not match the combined envelope digest")
    if not MerkleTree.verify_proof(leaf, siblings, directions, root):
        return _check(False, "merkle inclusion proof does not reconstruct the root")
    return _check(True, "inclusion proof matches the receipt root")


def _subject(
    statement: ProofOfFixStatement | None,
    vsa: VsaStatement | None,
    repo: str | None,
    commit: str | None,
) -> dict[str, Any]:
    if repo is None and commit is None:
        return _check(True, "repo and commit were not provided", skipped=True)
    if statement is None:
        return _check(False, "statement signature did not verify")
    reasons: list[str] = []
    if repo is not None and (
        statement.predicate.repo != repo
        or statement.subject[0].name != github_subject_name(repo)
    ):
        reasons.append("repo does not match the signed subject")
    if commit is not None and (
        statement.predicate.fix_commit != commit
        or statement.subject[0].digest.gitCommit != commit
    ):
        reasons.append("commit does not match the signed subject")
    if vsa is not None and repo is not None and vsa.subject[0].name != github_subject_name(repo):
        reasons.append("VSA subject repo does not match")
    if vsa is not None and commit is not None and vsa.subject[0].digest.gitCommit != commit:
        reasons.append("VSA subject commit does not match")
    if reasons:
        return _check(False, "; ".join(reasons))
    return _check(True, "signed subject matches the requested repo and commit")


def _collect_imprints(token_der: bytes) -> list[bytes]:
    found: list[bytes] = []
    _walk_der(token_der, found, 0)
    return found


def _walk_der(buf: bytes, found: list[bytes], depth: int) -> None:
    if depth > _MAX_DER_DEPTH:
        return
    offset = 0
    while offset < len(buf):
        try:
            tag, value, offset = _read_tlv(buf, offset)
        except ValueError:
            return
        if tag == 0x30:
            imprint = _imprint_hash(value)
            if imprint is not None:
                found.append(imprint)
                continue
        if tag == 0x04 or tag & 0x20:
            _walk_der(value, found, depth + 1)


def _imprint_hash(value: bytes) -> bytes | None:
    if len(value) != 49 or not value.startswith(_IMPRINT_VALUE_PREFIX):
        return None
    return value[17:49]


def _read_tlv(buf: bytes, offset: int) -> tuple[int, bytes, int]:
    if offset >= len(buf):
        raise ValueError("truncated DER")
    tag = buf[offset]
    if tag & 0x1F == 0x1F:
        raise ValueError("unsupported DER tag")
    length, offset = _read_der_length(buf, offset + 1)
    end = offset + length
    if end > len(buf):
        raise ValueError("truncated DER value")
    return tag, buf[offset:end], end


def _read_der_length(buf: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(buf):
        raise ValueError("truncated DER length")
    first = buf[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    if first == 0x80:
        raise ValueError("indefinite DER length")
    nbytes = first & 0x7F
    if nbytes == 0 or nbytes > 3 or offset + nbytes > len(buf):
        raise ValueError("unsupported DER length")
    length = int.from_bytes(buf[offset : offset + nbytes], "big")
    return length, offset + nbytes


def _der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(value)) + value


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    if length < 0x100:
        return bytes([0x81, length])
    return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])
