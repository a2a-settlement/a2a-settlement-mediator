"""Persistent storage for mediator audit records and settlement results.

Uses SQLite for durable storage of mediation audit trails, WORM settlement
results and their execution state, and the leaves of the settlement Merkle
tree.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

DB_PATH = os.getenv("MEDIATOR_DB_PATH", "mediator.db")

_CREATE_SQL = """
CREATE TABLE IF NOT EXISTS audit_records (
    escrow_id TEXT NOT NULL,
    data TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (escrow_id, created_at)
);

CREATE TABLE IF NOT EXISTS settlement_results (
    settlement_hash TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'confirmed',
    error TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_settlement_status ON settlement_results(status);

-- One row per leaf of the settlement Merkle tree, in insertion order. The
-- tree is rebuilt from leaf_hash at startup. root_hash is the root after this
-- leaf was appended. leaf_data is the exact text that was hashed into the
-- leaf; it is NULL for leaves adopted from results stored before this table
-- existed, whose leaf text was never stored.
CREATE TABLE IF NOT EXISTS merkle_leaves (
    leaf_index INTEGER PRIMARY KEY,
    leaf_hash TEXT NOT NULL,
    root_hash TEXT NOT NULL,
    leaf_data TEXT,
    settlement_hash TEXT,
    origin TEXT NOT NULL DEFAULT 'append',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ledger_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS compliance_queue (
    id TEXT PRIMARY KEY,
    escrow_id TEXT NOT NULL,
    queue_type TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    reviewed_at TEXT,
    reviewer_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_compliance_queue_escrow ON compliance_queue(escrow_id);
CREATE INDEX IF NOT EXISTS idx_compliance_queue_type ON compliance_queue(queue_type);

CREATE TABLE IF NOT EXISTS patch_assessments (
    assessment_key TEXT PRIMARY KEY,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS verify_patch_signatures (
    signature TEXT PRIMARY KEY,
    expires_at REAL NOT NULL
);
"""


def _get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


@contextmanager
def _db():
    conn = _get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextmanager
def write_transaction():
    """A transaction that holds SQLite's write lock from its first statement.

    ``BEGIN IMMEDIATE`` makes a read-then-write sequence atomic against other
    threads and other processes using the same database file: a second writer
    waits (up to the connection's busy timeout) instead of reading a state
    that is about to change.
    """
    conn = sqlite3.connect(DB_PATH, timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
    finally:
        conn.close()


def initialize_db() -> None:
    """Create any missing tables, then bring stored settlement JSON in line.

    Safe to run on every startup and against a database created by an older
    release: every statement is ``CREATE ... IF NOT EXISTS`` and no existing
    table is altered.
    """
    with _db() as conn:
        conn.executescript(_CREATE_SQL)
    repaired = reconcile_settlement_status()
    if repaired:
        logger.warning(
            "Carried the execution status of %d stored settlement(s) from the status "
            "column into the stored result",
            repaired,
        )
    logger.info("Mediator database initialized at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Audit records
# ---------------------------------------------------------------------------


def save_audit_record(escrow_id: str, audit_json: str) -> None:
    with _db() as conn:
        conn.execute(
            "INSERT INTO audit_records (escrow_id, data) VALUES (?, ?)",
            (escrow_id, audit_json),
        )


def get_audit_record(escrow_id: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute(
            "SELECT data FROM audit_records WHERE escrow_id = ? ORDER BY created_at DESC LIMIT 1",
            (escrow_id,),
        ).fetchone()
    if row:
        return json.loads(row["data"])
    return None


def list_audit_records(limit: int = 20, offset: int = 0) -> tuple[list[dict], int]:
    with _db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM audit_records").fetchone()[0]
        rows = conn.execute(
            "SELECT data FROM audit_records ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [json.loads(r["data"]) for r in rows], total


# ---------------------------------------------------------------------------
# Settlement results
# ---------------------------------------------------------------------------
#
# The row is the source of truth for whether a settlement's mandate has been
# executed. ``status`` holds 'confirmed' (not yet executed), 'executed' or
# 'failed'; the same fact is kept in the stored result as ``execution_status``
# ('pending', 'executed', 'failed') and, for a failure, ``error``. Both are
# written in one transaction.

STATUS_CONFIRMED = "confirmed"
STATUS_EXECUTED = "executed"
STATUS_FAILED = "failed"

_EXECUTION_STATUS = {
    STATUS_CONFIRMED: "pending",
    STATUS_EXECUTED: "executed",
    STATUS_FAILED: "failed",
}

ACK_UPDATED = "updated"
ACK_UNCHANGED = "unchanged"
ACK_CONFLICT = "conflict"
ACK_NOT_FOUND = "not_found"


def save_settlement_result(
    settlement_hash: str, result_json: str, leaf_index: Optional[int] = None
) -> bool:
    """Store a new settlement result as not yet executed.

    Returns False, changing nothing, when the hash is already stored, so that
    storing a result twice can never reset an acknowledgement. With
    ``leaf_index``, the Merkle leaf is linked to the settlement in the same
    transaction.
    """
    with _db() as conn:
        cur = conn.execute(
            "INSERT INTO settlement_results (settlement_hash, data) VALUES (?, ?) "
            "ON CONFLICT(settlement_hash) DO NOTHING",
            (settlement_hash, result_json),
        )
        if leaf_index is not None:
            conn.execute(
                "UPDATE merkle_leaves SET settlement_hash = ? "
                "WHERE leaf_index = ? AND settlement_hash IS NULL",
                (settlement_hash, leaf_index),
            )
    return cur.rowcount > 0


def get_settlement_result(settlement_hash: str) -> Optional[dict]:
    with _db() as conn:
        row = conn.execute(
            "SELECT data FROM settlement_results WHERE settlement_hash = ?",
            (settlement_hash,),
        ).fetchone()
    if row:
        return json.loads(row["data"])
    return None


def list_settlement_results(limit: int = 20, offset: int = 0) -> tuple[list[dict], int]:
    with _db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM settlement_results").fetchone()[0]
        rows = conn.execute(
            "SELECT data FROM settlement_results ORDER BY created_at DESC, rowid DESC "
            "LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [json.loads(r["data"]) for r in rows], total


def list_pending_settlement_results() -> list[dict]:
    """Stored settlements not yet acknowledged, oldest first."""
    with _db() as conn:
        rows = conn.execute(
            "SELECT data FROM settlement_results WHERE status = 'confirmed' "
            "ORDER BY created_at, rowid",
        ).fetchall()
    return [json.loads(r["data"]) for r in rows]


def acknowledge_settlement(
    settlement_hash: str, status: str, error: Optional[str] = None
) -> tuple[str, Optional[str]]:
    """Record that a settlement's mandate was executed or failed.

    The first acknowledgement wins. Returns ``(outcome, stored_status)``:

    * ``ACK_UPDATED``: the settlement was waiting and now has ``status``.
    * ``ACK_UNCHANGED``: it already had ``status``; nothing is written, and a
      failure keeps the error recorded first.
    * ``ACK_CONFLICT``: it already had the other status; nothing is written.
    * ``ACK_NOT_FOUND``: no such settlement is stored.

    The status column and the stored result are updated in one transaction
    that holds the write lock, so two concurrent acknowledgements cannot both
    be the first.
    """
    if status not in (STATUS_EXECUTED, STATUS_FAILED):
        raise ValueError(f"Invalid status: {status!r}")
    with write_transaction() as conn:
        row = conn.execute(
            "SELECT data, status FROM settlement_results WHERE settlement_hash = ?",
            (settlement_hash,),
        ).fetchone()
        if row is None:
            return ACK_NOT_FOUND, None
        current = row["status"]
        if current == status:
            return ACK_UNCHANGED, current
        if current != STATUS_CONFIRMED:
            return ACK_CONFLICT, current

        data = json.loads(row["data"])
        data["execution_status"] = _EXECUTION_STATUS[status]
        if status == STATUS_FAILED:
            data["error"] = error
        conn.execute(
            "UPDATE settlement_results SET status = ?, error = ?, data = ? "
            "WHERE settlement_hash = ?",
            (
                status,
                error if status == STATUS_FAILED else None,
                json.dumps(data),
                settlement_hash,
            ),
        )
    return ACK_UPDATED, status


def mark_settlement_executed(settlement_hash: str) -> bool:
    """True when the settlement is stored and is, or now is, executed."""
    outcome, _ = acknowledge_settlement(settlement_hash, STATUS_EXECUTED)
    return outcome in (ACK_UPDATED, ACK_UNCHANGED)


def mark_settlement_failed(settlement_hash: str, error: str) -> bool:
    """True when the settlement is stored and is, or now is, failed."""
    outcome, _ = acknowledge_settlement(settlement_hash, STATUS_FAILED, error)
    return outcome in (ACK_UPDATED, ACK_UNCHANGED)


def reconcile_settlement_status() -> int:
    """Make each stored result agree with its row's status column.

    Earlier releases recorded an acknowledgement in the status column only,
    leaving ``execution_status: pending`` in the stored result. The column is
    authoritative. Returns the number of rows rewritten; a second run finds
    nothing to do.
    """
    repaired = 0
    with write_transaction() as conn:
        rows = conn.execute(
            "SELECT settlement_hash, data, status, error FROM settlement_results"
        ).fetchall()
        for row in rows:
            expected = _EXECUTION_STATUS.get(row["status"])
            if expected is None:
                continue
            data = json.loads(row["data"])
            wrong_status = data.get("execution_status", "pending") != expected
            wrong_error = row["status"] == STATUS_FAILED and data.get("error") != row["error"]
            if not (wrong_status or wrong_error):
                continue
            data["execution_status"] = expected
            if row["status"] == STATUS_FAILED:
                data["error"] = row["error"]
            conn.execute(
                "UPDATE settlement_results SET data = ? WHERE settlement_hash = ?",
                (json.dumps(data), row["settlement_hash"]),
            )
            repaired += 1
    return repaired


# ---------------------------------------------------------------------------
# Merkle leaves
# ---------------------------------------------------------------------------


def load_merkle_leaves(conn: sqlite3.Connection, start: int = 0) -> list[sqlite3.Row]:
    """Stored leaves with ``leaf_index >= start``, in insertion order."""
    return conn.execute(
        "SELECT leaf_index, leaf_hash, root_hash, leaf_data, settlement_hash, origin "
        "FROM merkle_leaves WHERE leaf_index >= ? ORDER BY leaf_index",
        (start,),
    ).fetchall()


def insert_merkle_leaf(
    conn: sqlite3.Connection,
    leaf_index: int,
    leaf_hash: str,
    root_hash: str,
    leaf_data: Optional[str],
    settlement_hash: Optional[str] = None,
    origin: str = "append",
) -> None:
    """Insert one leaf. The primary key refuses a second leaf at an index."""
    conn.execute(
        "INSERT INTO merkle_leaves "
        "(leaf_index, leaf_hash, root_hash, leaf_data, settlement_hash, origin) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (leaf_index, leaf_hash, root_hash, leaf_data, settlement_hash, origin),
    )


def settlement_results_in_insertion_order(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT settlement_hash, data FROM settlement_results ORDER BY rowid"
    ).fetchall()


def get_meta(conn: sqlite3.Connection, key: str) -> Optional[str]:
    row = conn.execute("SELECT value FROM ledger_meta WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def set_meta(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO ledger_meta (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )


# ---------------------------------------------------------------------------
# Compliance queue
# ---------------------------------------------------------------------------


def add_compliance_queue_entry(escrow_id: str, queue_type: str) -> str:
    """Add a compliance queue entry. Returns the new entry id."""
    import uuid as _uuid_mod

    entry_id = str(_uuid_mod.uuid4())
    with _db() as conn:
        conn.execute(
            "INSERT INTO compliance_queue (id, escrow_id, queue_type) VALUES (?, ?, ?)",
            (entry_id, escrow_id, queue_type),
        )
    logger.info("Compliance queue entry added: escrow=%s type=%s id=%s", escrow_id, queue_type, entry_id)
    return entry_id


def list_compliance_queue(
    queue_type: Optional[str] = None,
    reviewed: Optional[bool] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """List compliance queue entries with optional filters."""
    filters: list[str] = []
    params: list = []

    if queue_type:
        filters.append("queue_type = ?")
        params.append(queue_type)
    if reviewed is True:
        filters.append("reviewed_at IS NOT NULL")
    elif reviewed is False:
        filters.append("reviewed_at IS NULL")

    where = f"WHERE {' AND '.join(filters)}" if filters else ""

    with _db() as conn:
        total = conn.execute(
            f"SELECT COUNT(*) FROM compliance_queue {where}", params
        ).fetchone()[0]
        rows = conn.execute(
            f"SELECT * FROM compliance_queue {where} ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

    return [dict(r) for r in rows], total


# ---------------------------------------------------------------------------
# Patch assessments
# ---------------------------------------------------------------------------


def save_patch_assessment(assessment_key: str, assessment_json: str) -> None:
    """Insert or replace a patch assessment.

    The same key overwrites the previous row. Audit records stay append-only;
    patch assessments are keyed for one current result per PR head and spec.
    """
    with _db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO patch_assessments "
            "(assessment_key, data, updated_at) VALUES (?, ?, datetime('now'))",
            (assessment_key, assessment_json),
        )


def get_patch_assessment(assessment_key: str) -> Optional[dict]:
    """Return the stored patch assessment for ``assessment_key``, if any."""
    with _db() as conn:
        row = conn.execute(
            "SELECT data FROM patch_assessments WHERE assessment_key = ?",
            (assessment_key,),
        ).fetchone()
    if row:
        return json.loads(row["data"])
    return None


# ---------------------------------------------------------------------------
# Verify-patch replay cache
# ---------------------------------------------------------------------------


def remember_patch_signature(signature: str, expires_at: float, now: float) -> bool:
    """Record a verified verify-patch signature until ``expires_at``.

    Deletes rows with ``expires_at < now``, then inserts ``signature``.
    Returns True when the row is new and False when it already exists.
    The delete is committed even when the insert conflicts.
    """
    with _db() as conn:
        conn.execute(
            "DELETE FROM verify_patch_signatures WHERE expires_at < ?",
            (now,),
        )
        try:
            conn.execute(
                "INSERT INTO verify_patch_signatures (signature, expires_at) VALUES (?, ?)",
                (signature, expires_at),
            )
        except sqlite3.IntegrityError:
            return False
    return True
