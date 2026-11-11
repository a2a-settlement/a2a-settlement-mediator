"""Append-only hash-chained store for proof-of-fix receipts.

Rows are inserted and never updated or deleted through this API. Each row's
``row_hash`` is SHA-256 of the canonical JSON of the row (every field except
``row_hash``) concatenated with ``prev_hash``:

    row_hash = sha256(canonical(row without row_hash) + prev_hash)

``prev_hash`` is inside that canonical JSON and is also the suffix. The first
row uses :data:`GENESIS_PREV_HASH`. The Merkle leaf is the 32-byte combined
envelope digest (``message_hash``), not the row JSON.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from a2a_settlement_mediator.merkle import MerkleTree

GENESIS_PREV_HASH = "0" * 64

_JWK_FIELDS = ("kty", "crv", "x", "y", "kid", "alg", "use")

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS proof_of_fix_receipts (
    sequence INTEGER PRIMARY KEY,
    receipt_id TEXT NOT NULL UNIQUE,
    nonce TEXT NOT NULL UNIQUE,
    prev_hash TEXT NOT NULL,
    row_hash TEXT NOT NULL,
    body_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS receipt_signing_keys (
    seq INTEGER PRIMARY KEY,
    kid TEXT NOT NULL,
    jwk_json TEXT NOT NULL,
    retired INTEGER NOT NULL
);
"""


class DuplicateReceipt(Exception):
    """A receipt_id or nonce is already in the log."""

    def __init__(self, field: str) -> None:
        self.field = field
        super().__init__(f"duplicate {field}")


class StoreIntegrityError(RuntimeError):
    """The receipt log failed hash-chain verification."""


@dataclass(frozen=True)
class ChainVerification:
    """Result of walking the receipt log from the genesis prev_hash."""

    ok: bool
    rows: int
    detail: str


def canonical_bytes(value: Any) -> bytes:
    """UTF-8 canonical JSON: sorted keys, compact separators, ASCII escapes."""
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def compute_row_hash(body: dict[str, Any], prev_hash: str) -> str:
    """SHA-256 of canonical(row without row_hash) concatenated with prev_hash."""
    if "row_hash" in body:
        raise ValueError("row_hash is not part of the canonical row")
    return hashlib.sha256(canonical_bytes(body) + prev_hash.encode("utf-8")).hexdigest()


def _default_db_path() -> str:
    from a2a_settlement_mediator import storage

    return storage.DB_PATH


def _same_jwk(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(left.get(field) == right.get(field) for field in _JWK_FIELDS)


def _jwk_material(jwk: dict[str, Any]) -> dict[str, str]:
    kid = jwk.get("kid")
    if not isinstance(kid, str) or not kid:
        raise ValueError("receipt JWK is missing kid")
    material: dict[str, str] = {}
    for field in _JWK_FIELDS:
        value = jwk.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"receipt JWK is missing {field}")
        material[field] = value
    return material


class ReceiptStore:
    """SQLite receipt log plus the in-memory Merkle tree rebuilt from it."""

    def __init__(self, db_path: str | None = None) -> None:
        self._path = db_path if db_path is not None else _default_db_path()
        self._lock = threading.Lock()
        self._tree = MerkleTree()
        with self._lock:
            with self._conn() as conn:
                conn.executescript(_CREATE_SQL)
                if self._verify_conn(conn).ok:
                    self._rebuild_tree(conn)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def append(
        self,
        *,
        receipt_id: str,
        nonce: str,
        statement_envelope: dict[str, Any],
        vsa_envelope: dict[str, Any],
        timestamp_token_b64: str,
        tsa_url: str,
        message_hash: str,
    ) -> dict[str, Any]:
        """Append one receipt. Duplicate receipt_id or nonce raises."""
        digest = _digest_bytes(message_hash)
        with self._lock:
            with self._conn() as conn:
                status = self._verify_conn(conn)
                if not status.ok:
                    raise StoreIntegrityError(status.detail)
                duplicate = self._duplicate_field(conn, receipt_id, nonce)
                if duplicate is not None:
                    raise DuplicateReceipt(duplicate)
                sequence, prev_hash = self._tail(conn)
                if self._tree.size != sequence:
                    self._rebuild_tree(conn)
                if self._tree.size != sequence:
                    raise StoreIntegrityError("merkle tree does not match the receipt log")
                index, leaf_hash, siblings, directions, root = self._tree.append_and_prove(digest)
                try:
                    if index != sequence:
                        raise StoreIntegrityError("merkle index diverged from the receipt chain")
                    body = _receipt_body(
                        sequence=sequence,
                        receipt_id=receipt_id,
                        nonce=nonce,
                        statement_envelope=statement_envelope,
                        vsa_envelope=vsa_envelope,
                        timestamp_token_b64=timestamp_token_b64,
                        tsa_url=tsa_url,
                        message_hash=digest.hex(),
                        leaf_index=index,
                        leaf_hash=leaf_hash,
                        siblings=siblings,
                        directions=directions,
                        root_hash=root,
                        prev_hash=prev_hash,
                    )
                    encoded = canonical_bytes(body)
                    row_hash = hashlib.sha256(encoded + prev_hash.encode("utf-8")).hexdigest()
                    conn.execute(
                        "INSERT INTO proof_of_fix_receipts "
                        "(sequence, receipt_id, nonce, prev_hash, row_hash, body_json) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            sequence,
                            receipt_id,
                            nonce,
                            prev_hash,
                            row_hash,
                            encoded.decode("ascii"),
                        ),
                    )
                except Exception:
                    self._rebuild_tree(conn)
                    raise
        document = json.loads(encoded)
        document["row_hash"] = row_hash
        return document

    def get(self, receipt_id: str) -> dict[str, Any] | None:
        """Return one receipt document, including ``row_hash``, or None."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT body_json, row_hash FROM proof_of_fix_receipts WHERE receipt_id = ?",
                    (receipt_id,),
                ).fetchone()
        if row is None:
            return None
        document = json.loads(row["body_json"])
        document["row_hash"] = row["row_hash"]
        return document

    def verify_chain(self) -> ChainVerification:
        """Recompute every row hash, link, and Merkle proof from the log."""
        with self._lock:
            with self._conn() as conn:
                return self._verify_conn(conn)

    def register_public_key(self, jwk: dict[str, Any], *, allow_replacement: bool = False) -> None:
        """Publish ``jwk`` as the active signing key, retiring the previous one.

        Registering the current key again is a no-op. Reusing the active kid
        with a different public key raises :class:`StoreIntegrityError` unless
        ``allow_replacement`` is set. Local signers set that flag because a new
        process generates a new in-memory key; the previous public key stays
        listed so receipts it signed still verify.
        """
        material = _jwk_material(jwk)
        with self._lock:
            with self._conn() as conn:
                keys = self._public_keys_conn(conn)
                active = [key for key in keys if not key["retired"]]
                if len(active) > 1:
                    raise StoreIntegrityError("more than one active receipt signing key")
                if active and _same_jwk(active[0], material):
                    return
                if active and active[0]["kid"] == material["kid"] and not allow_replacement:
                    raise StoreIntegrityError(
                        "receipt signing kid "
                        f"{material['kid']} is already published with a different public key"
                    )
                if active:
                    self._insert_key(conn, _jwk_material(active[0]), retired=True)
                self._insert_key(conn, material, retired=False)

    def jwks(self) -> dict[str, Any]:
        """Public keys. The active key is first; retired keys stay listed."""
        with self._lock:
            with self._conn() as conn:
                keys = self._public_keys_conn(conn)
        active = [key for key in keys if not key["retired"]]
        retired = [key for key in keys if key["retired"]]
        return {"keys": active + retired}

    def _verify_conn(self, conn: sqlite3.Connection) -> ChainVerification:
        rows = conn.execute(
            "SELECT sequence, receipt_id, nonce, prev_hash, row_hash, body_json "
            "FROM proof_of_fix_receipts ORDER BY sequence"
        ).fetchall()
        if not rows:
            return ChainVerification(True, 0, "empty receipt chain")
        expected_prev = GENESIS_PREV_HASH
        for index, row in enumerate(rows):
            sequence = int(row["sequence"])
            if sequence != index:
                return ChainVerification(
                    False, len(rows), f"row {sequence}: sequence is not contiguous"
                )
            try:
                stored = row["body_json"].encode("utf-8")
                body = json.loads(stored)
                rebuilt = canonical_bytes(body)
            except (UnicodeError, json.JSONDecodeError, TypeError, ValueError):
                return ChainVerification(
                    False, len(rows), f"row {sequence}: body is not canonical JSON"
                )
            if not isinstance(body, dict) or rebuilt != stored:
                return ChainVerification(
                    False, len(rows), f"row {sequence}: body is not canonical JSON"
                )
            problem = _row_problem(body, row, expected_prev, rebuilt, sequence)
            if problem:
                return ChainVerification(False, len(rows), f"row {sequence}: {problem}")
            expected_prev = str(row["row_hash"])
        return ChainVerification(True, len(rows), f"{len(rows)} receipt rows verified")

    def _rebuild_tree(self, conn: sqlite3.Connection) -> None:
        tree = MerkleTree()
        rows = conn.execute(
            "SELECT body_json FROM proof_of_fix_receipts ORDER BY sequence"
        ).fetchall()
        for row in rows:
            body = json.loads(row["body_json"])
            tree.append(_digest_bytes(body["message_hash"]))
        self._tree = tree

    def _duplicate_field(
        self, conn: sqlite3.Connection, receipt_id: str, nonce: str
    ) -> str | None:
        by_id = conn.execute(
            "SELECT 1 FROM proof_of_fix_receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if by_id is not None:
            return "receipt_id"
        by_nonce = conn.execute(
            "SELECT 1 FROM proof_of_fix_receipts WHERE nonce = ?",
            (nonce,),
        ).fetchone()
        if by_nonce is not None:
            return "nonce"
        return None

    def _tail(self, conn: sqlite3.Connection) -> tuple[int, str]:
        row = conn.execute(
            "SELECT sequence, row_hash FROM proof_of_fix_receipts "
            "ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return 0, GENESIS_PREV_HASH
        return int(row["sequence"]) + 1, str(row["row_hash"])

    def _public_keys_conn(self, conn: sqlite3.Connection) -> list[dict[str, Any]]:
        rows = conn.execute(
            "SELECT kid, jwk_json, retired FROM receipt_signing_keys ORDER BY seq"
        ).fetchall()
        order: list[tuple[str, str, str]] = []
        latest: dict[tuple[str, str, str], dict[str, Any]] = {}
        for row in rows:
            jwk = json.loads(row["jwk_json"])
            jwk["retired"] = bool(row["retired"])
            identity = (str(jwk["kid"]), str(jwk["x"]), str(jwk["y"]))
            if identity not in latest:
                order.append(identity)
            latest[identity] = jwk
        return [latest[identity] for identity in order]

    def _insert_key(self, conn: sqlite3.Connection, jwk: dict[str, str], *, retired: bool) -> None:
        conn.execute(
            "INSERT INTO receipt_signing_keys (kid, jwk_json, retired) VALUES (?, ?, ?)",
            (
                jwk["kid"],
                json.dumps(jwk, sort_keys=True, separators=(",", ":")),
                1 if retired else 0,
            ),
        )


def _digest_bytes(message_hash: str) -> bytes:
    if not isinstance(message_hash, str):
        raise ValueError("message_hash must be a SHA-256 hex digest")
    try:
        digest = bytes.fromhex(message_hash)
    except ValueError as exc:
        raise ValueError("message_hash must be a SHA-256 hex digest") from exc
    if len(digest) != 32:
        raise ValueError("message_hash must be a SHA-256 hex digest")
    return digest


def _receipt_body(
    *,
    sequence: int,
    receipt_id: str,
    nonce: str,
    statement_envelope: dict[str, Any],
    vsa_envelope: dict[str, Any],
    timestamp_token_b64: str,
    tsa_url: str,
    message_hash: str,
    leaf_index: int,
    leaf_hash: bytes,
    siblings: list[bytes],
    directions: list[str],
    root_hash: bytes,
    prev_hash: str,
) -> dict[str, Any]:
    return {
        "sequence": sequence,
        "receipt_id": receipt_id,
        "nonce": nonce,
        "statement_envelope": statement_envelope,
        "vsa_envelope": vsa_envelope,
        "timestamp_token_b64": timestamp_token_b64,
        "tsa_url": tsa_url,
        "message_hash": message_hash,
        "merkle_proof": {
            "leaf_index": leaf_index,
            "leaf_hash": leaf_hash.hex(),
            "siblings": [sibling.hex() for sibling in siblings],
            "directions": list(directions),
            "root_hash": root_hash.hex(),
            "tree_size": leaf_index + 1,
        },
        "prev_hash": prev_hash,
    }


def _row_problem(
    body: dict[str, Any],
    row: sqlite3.Row,
    expected_prev: str,
    rebuilt: bytes,
    sequence: int,
) -> str | None:
    if body.get("prev_hash") != expected_prev or row["prev_hash"] != expected_prev:
        return "prev_hash does not continue the chain"
    if body.get("sequence") != sequence:
        return "sequence does not match the chain position"
    if body.get("receipt_id") != row["receipt_id"]:
        return "receipt_id does not match the chain row"
    if body.get("nonce") != row["nonce"]:
        return "nonce does not match the chain row"
    computed = hashlib.sha256(rebuilt + expected_prev.encode("utf-8")).hexdigest()
    if computed != row["row_hash"]:
        return "row_hash does not match the canonical body"
    return _merkle_problem(body, sequence)


def _merkle_problem(body: dict[str, Any], sequence: int) -> str | None:
    proof = body.get("merkle_proof")
    if not isinstance(proof, dict):
        return "merkle proof is missing"
    try:
        digest = _digest_bytes(str(body.get("message_hash")))
        leaf_hash = bytes.fromhex(str(proof["leaf_hash"]))
        siblings = [bytes.fromhex(str(item)) for item in proof["siblings"]]
        root = bytes.fromhex(str(proof["root_hash"]))
        directions = list(proof["directions"])
    except (KeyError, TypeError, ValueError):
        return "merkle proof is malformed"
    if proof.get("leaf_index") != sequence:
        return "leaf index does not match the chain sequence"
    if proof.get("tree_size") != sequence + 1:
        return "tree size does not match the leaf index"
    if len(siblings) != len(directions):
        return "merkle proof siblings and directions differ in length"
    if any(direction not in {"left", "right"} for direction in directions):
        return "merkle proof direction is invalid"
    expected_leaf = MerkleTree.hash_leaf(digest)
    if leaf_hash != expected_leaf:
        return "stored leaf hash does not match the timestamped digest"
    if not MerkleTree.verify_proof(expected_leaf, siblings, directions, root):
        return "merkle inclusion proof does not reconstruct the root"
    return None
