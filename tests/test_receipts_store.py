"""Append-only receipt log: hash chain, Merkle proofs, and key publication."""

from __future__ import annotations

import hashlib
import json
import sqlite3

import pytest

from a2a_settlement_mediator.merkle import MerkleTree
from a2a_settlement_mediator.receipts.store import (
    GENESIS_PREV_HASH,
    ChainVerification,
    DuplicateReceipt,
    ReceiptStore,
    StoreIntegrityError,
    canonical_bytes,
    compute_row_hash,
)

_NONCE_A = "a" * 32
_NONCE_B = "b" * 32
_NONCE_C = "c" * 32


def _jwk(kid: str, x: str = "AA") -> dict[str, str]:
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": x,
        "y": "BB",
        "kid": kid,
        "alg": "ES256",
        "use": "sig",
    }


def _envelope(marker: str) -> dict[str, str]:
    return {"payloadType": "application/vnd.in-toto+json", "payload": marker}


def _append(store: ReceiptStore, *, receipt_id: str, nonce: str, marker: str) -> dict:
    digest = hashlib.sha256(marker.encode("utf-8")).hexdigest()
    return store.append(
        receipt_id=receipt_id,
        nonce=nonce,
        statement_envelope=_envelope(marker),
        vsa_envelope=_envelope(marker + "-vsa"),
        timestamp_token_b64="dG9rZW4=",
        tsa_url="https://tsa.example.com/rfc3161",
        message_hash=digest,
    )


def test_chain_links_and_merkle_proofs(tmp_path):
    store = ReceiptStore(str(tmp_path / "receipts.db"))
    assert store.verify_chain() == ChainVerification(True, 0, "empty receipt chain")

    first = _append(store, receipt_id="rcpt-1", nonce=_NONCE_A, marker="one")
    second = _append(store, receipt_id="rcpt-2", nonce=_NONCE_B, marker="two")

    assert first["prev_hash"] == GENESIS_PREV_HASH
    assert first["sequence"] == 0
    assert second["prev_hash"] == first["row_hash"]
    assert second["sequence"] == 1
    assert first["merkle_proof"]["root_hash"] != second["merkle_proof"]["root_hash"]
    assert first["merkle_proof"]["tree_size"] == 1
    assert second["merkle_proof"]["tree_size"] == 2

    body = {key: value for key, value in first.items() if key != "row_hash"}
    assert compute_row_hash(body, first["prev_hash"]) == first["row_hash"]
    assert store.verify_chain().ok is True
    assert store.get("rcpt-1") == first
    assert store.get("missing") is None

    for document in (first, second):
        proof = document["merkle_proof"]
        leaf = bytes.fromhex(proof["leaf_hash"])
        assert leaf == MerkleTree.hash_leaf(bytes.fromhex(document["message_hash"]))
        assert MerkleTree.verify_proof(
            leaf,
            [bytes.fromhex(item) for item in proof["siblings"]],
            proof["directions"],
            bytes.fromhex(proof["root_hash"]),
        )


def test_duplicate_does_not_extend_the_chain(tmp_path):
    store = ReceiptStore(str(tmp_path / "receipts.db"))
    _append(store, receipt_id="rcpt-1", nonce=_NONCE_A, marker="one")

    with pytest.raises(DuplicateReceipt) as by_id:
        _append(store, receipt_id="rcpt-1", nonce=_NONCE_B, marker="two")
    assert by_id.value.field == "receipt_id"

    with pytest.raises(DuplicateReceipt) as by_nonce:
        _append(store, receipt_id="rcpt-2", nonce=_NONCE_A, marker="two")
    assert by_nonce.value.field == "nonce"

    assert store.verify_chain().rows == 1
    third = _append(store, receipt_id="rcpt-3", nonce=_NONCE_C, marker="three")
    assert third["sequence"] == 1
    assert store.verify_chain().ok is True


def test_reopen_continues_the_chain(tmp_path):
    path = str(tmp_path / "receipts.db")
    first = _append(ReceiptStore(path), receipt_id="rcpt-1", nonce=_NONCE_A, marker="one")
    reopened = ReceiptStore(path)
    second = _append(reopened, receipt_id="rcpt-2", nonce=_NONCE_B, marker="two")
    assert second["prev_hash"] == first["row_hash"]
    assert reopened.verify_chain().ok is True
    assert reopened.get("rcpt-1")["row_hash"] == first["row_hash"]


def test_modified_body_breaks_the_chain(tmp_path):
    path = str(tmp_path / "receipts.db")
    store = ReceiptStore(path)
    _append(store, receipt_id="rcpt-1", nonce=_NONCE_A, marker="one")
    _append(store, receipt_id="rcpt-2", nonce=_NONCE_B, marker="two")

    with sqlite3.connect(path) as conn:
        raw = conn.execute(
            "SELECT body_json FROM proof_of_fix_receipts WHERE sequence = 0"
        ).fetchone()[0]
        body = json.loads(raw)
        body["tsa_url"] = "https://tampered.example/tsr"
        conn.execute(
            "UPDATE proof_of_fix_receipts SET body_json = ? WHERE sequence = 0",
            (canonical_bytes(body).decode("ascii"),),
        )

    status = store.verify_chain()
    assert status.ok is False
    assert "row 0" in status.detail
    assert "row_hash" in status.detail
    with pytest.raises(StoreIntegrityError):
        _append(store, receipt_id="rcpt-3", nonce=_NONCE_C, marker="three")


def test_modified_row_hash_breaks_the_chain(tmp_path):
    path = str(tmp_path / "receipts.db")
    store = ReceiptStore(path)
    _append(store, receipt_id="rcpt-1", nonce=_NONCE_A, marker="one")
    with sqlite3.connect(path) as conn:
        conn.execute(
            "UPDATE proof_of_fix_receipts SET row_hash = ? WHERE sequence = 0",
            ("ab" * 32,),
        )
    status = store.verify_chain()
    assert status.ok is False
    assert "row_hash" in status.detail


def test_store_api_is_append_only():
    public = {name for name in dir(ReceiptStore) if not name.startswith("_")}
    assert {"append", "get", "verify_chain", "register_public_key", "jwks"} <= public
    for banned in ("update", "delete", "remove", "overwrite"):
        assert banned not in public


def test_key_rotation_keeps_retired_keys(tmp_path):
    path = str(tmp_path / "receipts.db")
    store = ReceiptStore(path)
    store.register_public_key(_jwk("kid-a", x="AA"))
    store.register_public_key(_jwk("kid-a", x="AA"))
    assert store.jwks()["keys"] == [{**_jwk("kid-a", x="AA"), "retired": False}]

    store.register_public_key(_jwk("kid-b", x="CC"))
    keys = store.jwks()["keys"]
    assert keys[0]["kid"] == "kid-b"
    assert keys[0]["retired"] is False
    assert keys[1]["kid"] == "kid-a"
    assert keys[1]["retired"] is True

    with pytest.raises(StoreIntegrityError, match="different public key"):
        store.register_public_key(_jwk("kid-b", x="DD"))

    reopened = ReceiptStore(path)
    assert reopened.jwks() == store.jwks()
