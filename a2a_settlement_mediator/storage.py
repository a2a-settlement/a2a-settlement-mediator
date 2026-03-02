"""Persistent storage for mediator audit records and settlement results.

Uses SQLite for durable storage of mediation audit trails and WORM
settlement proofs. Replaces the in-memory lists that were lost on restart.
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


def initialize_db() -> None:
    with _db() as conn:
        conn.executescript(_CREATE_SQL)
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


def save_settlement_result(settlement_hash: str, result_json: str) -> None:
    with _db() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO settlement_results (settlement_hash, data) VALUES (?, ?)",
            (settlement_hash, result_json),
        )


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
            "SELECT data FROM settlement_results ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
    return [json.loads(r["data"]) for r in rows], total


def list_pending_settlement_results() -> list[dict]:
    with _db() as conn:
        rows = conn.execute(
            "SELECT data FROM settlement_results WHERE status = 'confirmed' ORDER BY created_at",
        ).fetchall()
    return [json.loads(r["data"]) for r in rows]


def mark_settlement_executed(settlement_hash: str) -> bool:
    with _db() as conn:
        cur = conn.execute(
            "UPDATE settlement_results SET status = 'executed' WHERE settlement_hash = ?",
            (settlement_hash,),
        )
    return cur.rowcount > 0


def mark_settlement_failed(settlement_hash: str, error: str) -> bool:
    with _db() as conn:
        cur = conn.execute(
            "UPDATE settlement_results SET status = 'failed', error = ? WHERE settlement_hash = ?",
            (error, settlement_hash),
        )
    return cur.rowcount > 0
