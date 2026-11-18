"""The settlement ledger and the Merkle tree survive a restart.

A restart is simulated by throwing away the pipeline's module state (the
in-memory tree and ledger) and running the app's startup again against the
same database file. The pipeline runs for real, with only the arbitration LLM
and the timestamp authority replaced.
"""

from __future__ import annotations

import base64
import json
import sqlite3
import subprocess
import sys
import textwrap
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator import settlement_pipeline, storage
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.merkle import MerkleTree
from a2a_settlement_mediator.webhook_listener import app
from a2a_settlement_mediator.worm_schemas import (
    ArbitrationDecision,
    ArbitrationVerdict,
    TimestampToken,
)

# The schema exactly as created by the code on main at ba48857, before this
# change. Used to build a database "created by the previous release".
_MAIN_SCHEMA = """
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


def _body(n: int = 0) -> dict:
    return {
        "transcript_hash": f"{n:02x}" * 32,
        "source_service": "crewai",
        "mandates": [
            {"mandate_id": "M-001", "description": "Deliver within 24 hours", "conditions": ["sla"]}
        ],
        "escrow_id": f"esc-{n}",
    }


def _verdict() -> ArbitrationVerdict:
    return ArbitrationVerdict(
        decision=ArbitrationDecision.APPROVED,
        confidence=0.92,
        reasoning="Test verdict.",
        factors=["test"],
        mandate_compliance={"M-001": True},
        llm_model="test-model",
    )


def _timestamp() -> TimestampToken:
    return TimestampToken(
        tsa_url="http://tsa.invalid/tsr",
        hash_algorithm="sha256",
        message_hash="abcd" * 16,
        timestamp_token_b64=base64.b64encode(b"mock-tsa-response").decode(),
        serial_number="1",
    )


def _forget_process_state(monkeypatch) -> None:
    """Drop everything the pipeline holds in process memory, as a restart does."""
    monkeypatch.setattr(settlement_pipeline, "_merkle_tree", MerkleTree())
    monkeypatch.setattr(settlement_pipeline, "_confirmed_settlements", {})
    # State added with the durable ledger; absent on older code.
    monkeypatch.setattr(settlement_pipeline, "_durable", False, raising=False)
    monkeypatch.setattr(settlement_pipeline, "_ledger_problems", [], raising=False)
    monkeypatch.setattr(settlement_pipeline, "_legacy_report", None, raising=False)


@pytest.fixture
def db_path(tmp_path, monkeypatch):
    path = str(tmp_path / "mediator.db")
    monkeypatch.setattr(storage, "DB_PATH", path)
    monkeypatch.setattr(settings, "webhook_secret", "")
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    with patch(
        "a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm",
        return_value=_verdict(),
    ), patch(
        "a2a_settlement_mediator.settlement_pipeline._request_timestamp",
        return_value=_timestamp(),
    ):
        yield path
    # Leave the module in its in-memory default for the other test files.
    _forget_process_state(monkeypatch)


@pytest.fixture
def boot(db_path, monkeypatch):
    """``with boot() as client:`` is one process lifetime of the service."""

    @contextmanager
    def _boot():
        _forget_process_state(monkeypatch)
        with TestClient(app) as client:
            yield client

    return _boot


def _settle(client, n: int = 0) -> dict:
    resp = client.post("/settle", json=_body(n))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert data["success"] is True, data
    return data


def _hash(result: dict) -> str:
    return result["proof"]["settlement_hash"]


def _row(db_path: str, settlement_hash: str) -> sqlite3.Row:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return conn.execute(
            "SELECT * FROM settlement_results WHERE settlement_hash = ?", (settlement_hash,)
        ).fetchone()
    finally:
        conn.close()


def _listed(client, settlement_hash: str) -> dict:
    listing = client.get("/settlements").json()["settlements"]
    return next(s for s in listing if _hash(s) == settlement_hash)


# ---------------------------------------------------------------------------
# Defect 1: an ack after a restart
# ---------------------------------------------------------------------------


class TestAckAfterRestart:
    def test_ack_finds_a_settlement_made_before_the_restart(self, boot, db_path):
        with boot() as client:
            settlement_hash = _hash(_settle(client))

        with boot() as client:
            resp = client.post(
                "/settlements/ack", json={"settlement_hash": settlement_hash, "status": "executed"}
            )
            assert resp.status_code == 200, resp.text
            assert resp.json() == {"settlement_hash": settlement_hash, "status": "executed"}

        assert _row(db_path, settlement_hash)["status"] == "executed"

    def test_unknown_settlement_is_still_404(self, boot):
        with boot() as client:
            resp = client.post(
                "/settlements/ack", json={"settlement_hash": "00" * 32, "status": "executed"}
            )
            assert resp.status_code == 404

    def test_invalid_status_is_still_400(self, boot):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            resp = client.post(
                "/settlements/ack", json={"settlement_hash": settlement_hash, "status": "maybe"}
            )
            assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Defect 2: an ack is visible in every read path
# ---------------------------------------------------------------------------


class TestAckIsReflectedEverywhere:
    def test_executed_shows_in_the_listing_the_row_and_the_json(self, boot, db_path):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            assert _listed(client, settlement_hash)["execution_status"] == "pending"

            client.post(
                "/settlements/ack", json={"settlement_hash": settlement_hash, "status": "executed"}
            )

            assert _listed(client, settlement_hash)["execution_status"] == "executed"
            assert client.get("/settlements/pending").json() == {"pending": [], "count": 0}

        row = _row(db_path, settlement_hash)
        assert row["status"] == "executed"
        assert json.loads(row["data"])["execution_status"] == "executed"

    def test_failed_shows_with_its_error(self, boot, db_path):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            resp = client.post(
                "/settlements/ack",
                json={"settlement_hash": settlement_hash, "status": "failed", "error": "bank down"},
            )
            assert resp.status_code == 200

            listed = _listed(client, settlement_hash)
            assert listed["execution_status"] == "failed"
            assert listed["error"] == "bank down"
            assert client.get("/settlements/pending").json()["count"] == 0

        row = _row(db_path, settlement_hash)
        assert (row["status"], row["error"]) == ("failed", "bank down")
        stored = json.loads(row["data"])
        assert (stored["execution_status"], stored["error"]) == ("failed", "bank down")

    def test_the_proof_is_not_altered_by_an_ack(self, boot):
        with boot() as client:
            result = _settle(client)
            client.post(
                "/settlements/ack", json={"settlement_hash": _hash(result), "status": "executed"}
            )
            listed = _listed(client, _hash(result))
            assert listed["proof"] == result["proof"]
            assert {**listed, "execution_status": "pending"} == result


class TestAckRules:
    """The first terminal acknowledgement wins."""

    def _ack(self, client, settlement_hash, status, error=None):
        body = {"settlement_hash": settlement_hash, "status": status}
        if error is not None:
            body["error"] = error
        return client.post("/settlements/ack", json=body)

    def test_repeating_executed_is_idempotent(self, boot, db_path):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            first = self._ack(client, settlement_hash, "executed")
            second = self._ack(client, settlement_hash, "executed")
            assert first.status_code == second.status_code == 200
            assert first.json() == second.json()
        assert _row(db_path, settlement_hash)["status"] == "executed"

    def test_repeating_failed_is_idempotent_and_keeps_the_first_error(self, boot, db_path):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            assert self._ack(client, settlement_hash, "failed", "first").status_code == 200
            assert self._ack(client, settlement_hash, "failed", "second").status_code == 200
            assert _listed(client, settlement_hash)["error"] == "first"
        assert _row(db_path, settlement_hash)["error"] == "first"

    def test_failed_after_executed_is_refused(self, boot, db_path):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            self._ack(client, settlement_hash, "executed")
            resp = self._ack(client, settlement_hash, "failed", "too late")
            assert resp.status_code == 409
            assert "executed" in resp.json()["detail"]
            assert _listed(client, settlement_hash)["execution_status"] == "executed"
            assert _listed(client, settlement_hash)["error"] is None
        row = _row(db_path, settlement_hash)
        assert (row["status"], row["error"]) == ("executed", None)

    def test_executed_after_failed_is_refused(self, boot, db_path):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            self._ack(client, settlement_hash, "failed", "bank down")
            resp = self._ack(client, settlement_hash, "executed")
            assert resp.status_code == 409
            assert "failed" in resp.json()["detail"]
            assert _listed(client, settlement_hash)["execution_status"] == "failed"
        row = _row(db_path, settlement_hash)
        assert (row["status"], row["error"]) == ("failed", "bank down")

    def test_conflict_is_still_refused_after_a_restart(self, boot):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
            self._ack(client, settlement_hash, "executed")
        with boot() as client:
            assert self._ack(client, settlement_hash, "executed").status_code == 200
            assert self._ack(client, settlement_hash, "failed").status_code == 409


# ---------------------------------------------------------------------------
# Defect 3: pending settlements after a restart
# ---------------------------------------------------------------------------


class TestPendingAfterRestart:
    def test_unexecuted_settlements_are_listed_after_a_restart(self, boot):
        with boot() as client:
            first = _settle(client, 1)
            second = _settle(client, 2)
            done = _settle(client, 3)
            client.post(
                "/settlements/ack", json={"settlement_hash": _hash(done), "status": "executed"}
            )
            before = client.get("/settlements/pending").json()

        with boot() as client:
            after = client.get("/settlements/pending").json()

        assert after["count"] == 2
        assert [_hash(p) for p in after["pending"]] == [_hash(first), _hash(second)]
        assert after == before
        assert after["pending"][0] == first

    def test_an_ack_after_the_restart_empties_the_list_for_good(self, boot):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
        with boot() as client:
            client.post(
                "/settlements/ack", json={"settlement_hash": settlement_hash, "status": "executed"}
            )
            assert client.get("/settlements/pending").json()["count"] == 0
        with boot() as client:
            assert client.get("/settlements/pending").json()["count"] == 0

    def test_the_heartbeat_sees_stale_settlements_after_a_restart(self, boot):
        with boot() as client:
            settlement_hash = _hash(_settle(client))
        with boot():
            stale = settlement_pipeline.get_stale_settlements(-1.0)
            assert [r.proof.settlement_hash for r in stale] == [settlement_hash]
            assert settlement_pipeline.mark_executed(settlement_hash) is True
            assert settlement_pipeline.get_stale_settlements(-1.0) == []


# ---------------------------------------------------------------------------
# Defect 4: the Merkle tree after a restart
# ---------------------------------------------------------------------------


def _verifies(result: dict, root_hex: str | None = None) -> bool:
    proof = result["proof"]["merkle_result"]["proof"]
    return MerkleTree.verify_proof(
        bytes.fromhex(proof["leaf_hash"]),
        [bytes.fromhex(s) for s in proof["siblings"]],
        proof["directions"],
        bytes.fromhex(root_hex or proof["root_hash"]),
    )


class TestMerkleTreeAfterRestart:
    def test_size_and_root_are_restored(self, boot):
        with boot() as client:
            results = [_settle(client, n) for n in range(3)]
            before = client.get("/merkle").json()
            assert before["tree_size"] == 3
            assert before["root_hash"] == results[-1]["proof"]["merkle_result"]["root_hash"]

        with boot() as client:
            after = client.get("/merkle").json()
            assert after["tree_size"] == 3
            assert after["root_hash"] == before["root_hash"]
            assert after["consistent"] is True

    def test_new_leaves_continue_the_same_tree(self, boot):
        with boot() as client:
            old = [_settle(client, n) for n in range(3)]

        with boot() as client:
            new = _settle(client, 3)
            merkle = new["proof"]["merkle_result"]
            assert merkle["leaf"]["leaf_index"] == 3
            assert merkle["tree_size"] == 4
            assert _verifies(new)

            # The tree the new proof was issued from still contains the old
            # leaves at their old positions: a current proof for each old leaf
            # verifies against the new root.
            tree = settlement_pipeline.get_merkle_tree()
            for result in old:
                leaf = result["proof"]["merkle_result"]["leaf"]
                siblings, directions = tree.get_proof(leaf["leaf_index"])
                assert MerkleTree.verify_proof(
                    bytes.fromhex(leaf["leaf_hash"]),
                    siblings,
                    directions,
                    bytes.fromhex(merkle["root_hash"]),
                )
                # And the proof stored at the time still verifies against the
                # root stored with it.
                assert _verifies(result)

    def test_stored_leaf_data_reproduces_the_leaf_hash(self, boot, db_path):
        with boot() as client:
            result = _settle(client)
        leaf = result["proof"]["merkle_result"]["leaf"]
        conn = sqlite3.connect(db_path)
        try:
            leaf_hash, leaf_data, settlement_hash = conn.execute(
                "SELECT leaf_hash, leaf_data, settlement_hash FROM merkle_leaves "
                "WHERE leaf_index = ?",
                (leaf["leaf_index"],),
            ).fetchone()
        finally:
            conn.close()
        assert leaf_hash == leaf["leaf_hash"]
        assert MerkleTree.hash_leaf(leaf_data.encode("utf-8")).hex() == leaf_hash
        assert settlement_hash == _hash(result)

    def test_a_mismatch_is_exposed_and_blocks_settlement(self, boot, db_path, caplog):
        with boot() as client:
            for n in range(3):
                _settle(client, n)
            good_root = client.get("/merkle").json()["root_hash"]

        conn = sqlite3.connect(db_path)
        conn.execute(
            "UPDATE merkle_leaves SET leaf_hash = ?, leaf_data = NULL WHERE leaf_index = 1",
            ("ee" * 32,),
        )
        conn.commit()
        conn.close()

        with caplog.at_level("ERROR"), boot() as client:
            status = client.get("/merkle").json()
            assert status["consistent"] is False
            assert status["problems"]
            # Not a fresh tree: the stored leaves are still reported.
            assert status["tree_size"] == 3
            assert status["root_hash"] != good_root

            resp = client.post("/settle", json=_body(9))
            assert resp.status_code == 503
            assert client.get("/merkle").json()["tree_size"] == 3
            # Execution state does not depend on the tree.
            assert client.get("/settlements/pending").json()["count"] == 3

        assert any("MERKLE LEDGER INCONSISTENT" in r.getMessage() for r in caplog.records)

    def test_a_missing_leaf_is_a_mismatch(self, boot, db_path):
        with boot() as client:
            for n in range(3):
                _settle(client, n)
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM merkle_leaves WHERE leaf_index = 1")
        conn.commit()
        conn.close()
        with boot() as client:
            assert client.get("/merkle").json()["consistent"] is False
            assert client.post("/settle", json=_body(9)).status_code == 503

    def test_altered_leaf_data_is_a_mismatch(self, boot, db_path):
        with boot() as client:
            _settle(client)
        conn = sqlite3.connect(db_path)
        conn.execute("UPDATE merkle_leaves SET leaf_data = leaf_data || ' '")
        conn.commit()
        conn.close()
        with boot() as client:
            assert client.get("/merkle").json()["consistent"] is False

    def test_empty_database_starts_an_empty_consistent_tree(self, boot):
        with boot() as client:
            status = client.get("/merkle").json()
            assert status["tree_size"] == 0
            assert status["root_hash"] is None
            assert status["consistent"] is True


# ---------------------------------------------------------------------------
# More than one writer
# ---------------------------------------------------------------------------


class TestConcurrentWriters:
    def test_threads_get_distinct_consecutive_leaves(self, boot):
        with boot() as client:
            with ThreadPoolExecutor(max_workers=8) as pool:
                results = list(pool.map(lambda n: _settle(client, n), range(16)))
            indices = sorted(r["proof"]["merkle_result"]["leaf"]["leaf_index"] for r in results)
            assert indices == list(range(16))
            assert all(_verifies(r) for r in results)
            root = client.get("/merkle").json()["root_hash"]

        with boot() as client:
            status = client.get("/merkle").json()
            assert (status["tree_size"], status["root_hash"], status["consistent"]) == (
                16,
                root,
                True,
            )
            assert client.get("/settlements/pending").json()["count"] == 16

    def test_a_worker_with_a_stale_tree_catches_up_before_appending(self, boot, monkeypatch):
        """Two processes share the database; each holds its own copy of the tree."""
        with boot() as client:
            first = _settle(client, 0)
            # "Worker B" restored the tree when it held one leaf...
            stale = MerkleTree()
            stale.append_leaf_hash(
                bytes.fromhex(first["proof"]["merkle_result"]["leaf"]["leaf_hash"])
            )
            # ...then "worker A" appended a second leaf.
            second = _settle(client, 1)

            monkeypatch.setattr(settlement_pipeline, "_merkle_tree", stale)
            # Reads on worker B see worker A's leaf.
            assert client.get("/merkle").json() == {
                **client.get("/merkle").json(),
                "tree_size": 2,
                "root_hash": second["proof"]["merkle_result"]["root_hash"],
            }
            third = _settle(client, 2)
            merkle = third["proof"]["merkle_result"]
            assert merkle["leaf"]["leaf_index"] == 2
            assert merkle["tree_size"] == 3
            assert _verifies(third)

        with boot() as client:
            status = client.get("/merkle").json()
            assert status["consistent"] is True
            assert status["root_hash"] == merkle["root_hash"]

    def test_two_processes_append_to_one_tree(self, boot, db_path):
        with boot():
            pass  # create the schema

        script = textwrap.dedent(
            """
            import sys
            from a2a_settlement_mediator import settlement_pipeline, storage
            storage.DB_PATH = sys.argv[1]
            settlement_pipeline.restore_ledger()
            for i in range(25):
                settlement_pipeline._append_to_merkle_tree(f"{sys.argv[2]}-{i}".encode())
            """
        )
        procs = [
            subprocess.Popen([sys.executable, "-c", script, db_path, name]) for name in ("a", "b")
        ]
        assert [p.wait(timeout=120) for p in procs] == [0, 0]

        conn = sqlite3.connect(db_path)
        rows = conn.execute(
            "SELECT leaf_index, leaf_hash, root_hash FROM merkle_leaves ORDER BY leaf_index"
        ).fetchall()
        conn.close()
        assert [r[0] for r in rows] == list(range(50))
        tree = MerkleTree()
        for _, leaf_hash, root_hash in rows:
            tree.append_leaf_hash(bytes.fromhex(leaf_hash))
            assert tree.root_hash.hex() == root_hash

        with boot() as client:
            status = client.get("/merkle").json()
            assert (status["tree_size"], status["consistent"]) == (50, True)

    def test_more_than_one_worker_is_warned_about(self, boot, monkeypatch, caplog):
        monkeypatch.setenv("WEB_CONCURRENCY", "2")
        with caplog.at_level("WARNING"), boot():
            pass
        assert any("WEB_CONCURRENCY=2" in r.getMessage() for r in caplog.records)


# ---------------------------------------------------------------------------
# Upgrading a database created by the previous release
# ---------------------------------------------------------------------------


def _legacy_lifetime(db_path: str, monkeypatch, numbers: list[int], skip: set[int] = frozenset()):
    """One process lifetime of the previous release: an in-memory tree that
    starts empty, and one ``settlement_results`` row per successful settlement,
    written the way the previous ``save_settlement_result`` wrote it."""
    monkeypatch.setattr(settlement_pipeline, "_merkle_tree", MerkleTree())
    monkeypatch.setattr(settlement_pipeline, "_confirmed_settlements", {})
    monkeypatch.setattr(settlement_pipeline, "_durable", False, raising=False)
    from a2a_settlement_mediator.worm_schemas import AP2Mandate, NegotiationTranscript

    results = []
    conn = sqlite3.connect(db_path)
    for n in numbers:
        body = _body(n)
        result = settlement_pipeline.settle(
            NegotiationTranscript(
                transcript_hash=body["transcript_hash"], source_service="crewai"
            ),
            [AP2Mandate(**m) for m in body["mandates"]],
            escrow_id=body["escrow_id"],
        )
        assert result.success
        if n in skip:
            continue
        conn.execute(
            "INSERT OR REPLACE INTO settlement_results (settlement_hash, data) VALUES (?, ?)",
            (result.proof.settlement_hash, result.model_dump_json()),
        )
        results.append(json.loads(result.model_dump_json()))
    conn.commit()
    conn.close()
    return results


@pytest.fixture
def main_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.executescript(_MAIN_SCHEMA)
    conn.execute(
        "INSERT INTO audit_records (escrow_id, data) VALUES (?, ?)",
        ("esc-audit", json.dumps({"escrow_id": "esc-audit", "note": "kept"})),
    )
    conn.commit()
    conn.close()
    return db_path


class TestUpgradeFromMainDatabase:
    def test_new_tables_are_added_and_existing_rows_kept(self, main_db, boot, monkeypatch):
        rows = _legacy_lifetime(main_db, monkeypatch, [1, 2])
        with boot() as client:
            assert client.get("/audits").json()["total"] == 1
            assert client.get("/audits/esc-audit").json()["note"] == "kept"
            listing = client.get("/settlements").json()
            assert listing["total"] == 2
            assert {_hash(s) for s in listing["settlements"]} == {_hash(r) for r in rows}

        conn = sqlite3.connect(main_db)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        columns = [r[1] for r in conn.execute("PRAGMA table_info(settlement_results)")]
        conn.close()
        assert {"merkle_leaves", "ledger_meta", "audit_records", "settlement_results"} <= tables
        # Additive only: the existing table is unchanged.
        assert columns == ["settlement_hash", "data", "status", "error", "created_at"]

    def test_upgrade_is_idempotent(self, main_db, boot, monkeypatch):
        _legacy_lifetime(main_db, monkeypatch, [1, 2, 3])
        with boot() as client:
            first = client.get("/merkle").json()
        with boot() as client:
            second = client.get("/merkle").json()
        storage.initialize_db()
        storage.initialize_db()
        with boot() as client:
            third = client.get("/merkle").json()
        assert first == second == third
        assert first["tree_size"] == 3

    def test_pending_rows_from_main_are_recovered(self, main_db, boot, monkeypatch):
        rows = _legacy_lifetime(main_db, monkeypatch, [1, 2])
        with boot() as client:
            pending = client.get("/settlements/pending").json()
            assert [_hash(p) for p in pending["pending"]] == [_hash(r) for r in rows]
            resp = client.post(
                "/settlements/ack", json={"settlement_hash": _hash(rows[0]), "status": "executed"}
            )
            assert resp.status_code == 200
            assert client.get("/settlements/pending").json()["count"] == 1

    def test_acks_recorded_by_main_in_the_column_only_are_carried_into_the_json(
        self, main_db, boot, monkeypatch
    ):
        rows = _legacy_lifetime(main_db, monkeypatch, [1, 2, 3])
        conn = sqlite3.connect(main_db)
        # What main's mark_settlement_executed / mark_settlement_failed did.
        conn.execute(
            "UPDATE settlement_results SET status = 'executed' WHERE settlement_hash = ?",
            (_hash(rows[0]),),
        )
        conn.execute(
            "UPDATE settlement_results SET status = 'failed', error = ? WHERE settlement_hash = ?",
            ("bank down", _hash(rows[1])),
        )
        conn.commit()
        conn.close()

        with boot() as client:
            assert _listed(client, _hash(rows[0]))["execution_status"] == "executed"
            failed = _listed(client, _hash(rows[1]))
            assert (failed["execution_status"], failed["error"]) == ("failed", "bank down")
            assert _listed(client, _hash(rows[2]))["execution_status"] == "pending"
            assert [_hash(p) for p in client.get("/settlements/pending").json()["pending"]] == [
                _hash(rows[2])
            ]
        assert json.loads(_row(main_db, _hash(rows[0]))["data"])["execution_status"] == "executed"

    def test_a_single_lifetime_tree_is_adopted_and_continued(self, main_db, boot, monkeypatch):
        rows = _legacy_lifetime(main_db, monkeypatch, [1, 2, 3])
        last_root = rows[-1]["proof"]["merkle_result"]["root_hash"]

        with boot() as client:
            status = client.get("/merkle").json()
            assert (status["tree_size"], status["root_hash"]) == (3, last_root)
            assert status["consistent"] is True
            assert status["legacy"]["adopted_leaves"] == 3
            assert status["legacy"]["rows_outside_tree"] == 0

            new = _settle(client, 9)
            assert new["proof"]["merkle_result"]["leaf"]["leaf_index"] == 3

    def test_only_the_last_lifetime_is_adopted_when_there_were_restarts(
        self, main_db, boot, monkeypatch
    ):
        earlier = _legacy_lifetime(main_db, monkeypatch, [1, 2])
        last = _legacy_lifetime(main_db, monkeypatch, [3, 4, 5])

        with boot() as client:
            status = client.get("/merkle").json()
            assert status["tree_size"] == 3
            assert status["root_hash"] == last[-1]["proof"]["merkle_result"]["root_hash"]
            assert status["consistent"] is True
            assert status["legacy"]["trees_detected"] == 2
            assert status["legacy"]["adopted_leaves"] == 3
            assert status["legacy"]["rows_outside_tree"] == 2
            # Rows from the earlier tree are still listed, still pending, and
            # their stored proofs still verify against their own stored root,
            # which is not a root of the current tree.
            assert client.get("/settlements/pending").json()["count"] == 5
            assert all(_verifies(r) for r in earlier)
            assert earlier[-1]["proof"]["merkle_result"]["root_hash"] != status["root_hash"]

    def test_an_incomplete_last_lifetime_is_not_adopted(self, main_db, boot, monkeypatch, caplog):
        # The leaf at index 1 was appended but its result never reached the
        # database, so the tree cannot be rebuilt from the stored rows.
        _legacy_lifetime(main_db, monkeypatch, [1, 2, 3], skip={2})

        with caplog.at_level("WARNING"), boot() as client:
            status = client.get("/merkle").json()
            assert status["tree_size"] == 0
            assert status["consistent"] is True
            assert status["legacy"]["adopted_leaves"] == 0
            assert status["legacy"]["rows_outside_tree"] == 2
            assert status["legacy"]["reason"]
            assert _settle(client, 9)["proof"]["merkle_result"]["leaf"]["leaf_index"] == 0
        assert any("not adopted" in r.getMessage() for r in caplog.records)

    def test_the_leaf_payload_of_a_main_row_cannot_be_recomputed(self, main_db, monkeypatch):
        """Documents what is not recoverable: the bytes that were hashed into a
        leaf included the agent identities and currency precision, which the
        stored result does not contain."""
        (row,) = _legacy_lifetime(main_db, monkeypatch, [1])
        assert "agent_identities" not in json.dumps(row)
        assert "currency_precision" not in json.dumps(row)


class TestRollbackToAnInMemoryRelease:
    def test_settlements_stored_without_a_leaf_are_reported_not_adopted(
        self, boot, db_path, monkeypatch
    ):
        with boot() as client:
            _settle(client, 1)
            root = client.get("/merkle").json()["root_hash"]

        # The previous release runs against the upgraded database and stores a
        # settlement from its own in-memory tree.
        _legacy_lifetime(db_path, monkeypatch, [2])

        with boot() as client:
            status = client.get("/merkle").json()
            assert status["consistent"] is False
            assert (status["tree_size"], status["root_hash"]) == (1, root)
            assert client.post("/settle", json=_body(3)).status_code == 503
            # Recovery still covers the settlement the old release stored.
            assert client.get("/settlements/pending").json()["count"] == 2

        # An operator who has accounted for those rows clears the recorded
        # import, and the next startup counts them as outside the tree.
        conn = sqlite3.connect(db_path)
        conn.execute("DELETE FROM ledger_meta WHERE key = 'merkle_legacy_import'")
        conn.commit()
        conn.close()

        with boot() as client:
            status = client.get("/merkle").json()
            assert status["consistent"] is True
            assert (status["tree_size"], status["root_hash"]) == (1, root)
            assert status["legacy"]["rows_outside_tree"] == 1
            assert _settle(client, 3)["proof"]["merkle_result"]["leaf"]["leaf_index"] == 1
