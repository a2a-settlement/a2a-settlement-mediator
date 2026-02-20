"""Tests for the heartbeat recovery worker."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from a2a_settlement_mediator.heartbeat import HeartbeatWorker
from a2a_settlement_mediator.settlement_pipeline import (
    _confirmed_lock,
    _confirmed_settlements,
    get_stale_settlements,
)
from a2a_settlement_mediator.worm_schemas import (
    ExecutionStatus,
    SettlementProof,
    SettlementResult,
    SettlementStage,
)


def _make_stale_result(settlement_hash: str, age_seconds: float) -> SettlementResult:
    """Create a SettlementResult that completed *age_seconds* ago."""
    completed = datetime.now(timezone.utc) - timedelta(seconds=age_seconds)
    proof = MagicMock(spec=SettlementProof)
    proof.settlement_hash = settlement_hash
    return SettlementResult(
        success=True,
        proof=proof,
        stage_reached=SettlementStage.COMPLETE,
        execution_status=ExecutionStatus.PENDING,
        completed_at=completed,
    )


# ---------------------------------------------------------------------------
# get_stale_settlements tests
# ---------------------------------------------------------------------------


class TestGetStaleSettlements:
    @pytest.fixture(autouse=True)
    def _clear_ledger(self):
        with _confirmed_lock:
            _confirmed_settlements.clear()
        yield
        with _confirmed_lock:
            _confirmed_settlements.clear()

    def test_no_settlements_returns_empty(self):
        assert get_stale_settlements(60.0) == []

    def test_fresh_settlement_not_stale(self):
        result = _make_stale_result("hash-fresh", age_seconds=10)
        with _confirmed_lock:
            _confirmed_settlements["hash-fresh"] = result
        assert get_stale_settlements(60.0) == []

    def test_old_settlement_is_stale(self):
        result = _make_stale_result("hash-old", age_seconds=200)
        with _confirmed_lock:
            _confirmed_settlements["hash-old"] = result
        stale = get_stale_settlements(60.0)
        assert len(stale) == 1
        assert stale[0].proof.settlement_hash == "hash-old"

    def test_executed_settlement_not_stale(self):
        result = _make_stale_result("hash-exec", age_seconds=200)
        result.execution_status = ExecutionStatus.EXECUTED
        with _confirmed_lock:
            _confirmed_settlements["hash-exec"] = result
        assert get_stale_settlements(60.0) == []

    def test_mixed_settlements(self):
        fresh = _make_stale_result("fresh", age_seconds=5)
        old = _make_stale_result("old", age_seconds=300)
        executed = _make_stale_result("exec", age_seconds=300)
        executed.execution_status = ExecutionStatus.EXECUTED

        with _confirmed_lock:
            _confirmed_settlements["fresh"] = fresh
            _confirmed_settlements["old"] = old
            _confirmed_settlements["exec"] = executed

        stale = get_stale_settlements(60.0)
        assert len(stale) == 1
        assert stale[0].proof.settlement_hash == "old"


# ---------------------------------------------------------------------------
# HeartbeatWorker lifecycle tests
# ---------------------------------------------------------------------------


class TestHeartbeatLifecycle:
    def test_start_and_stop(self):
        worker = HeartbeatWorker(interval=0.1, threshold=0.0, callback_url="")
        assert not worker.running
        worker.start()
        assert worker.running
        worker.stop(timeout=2.0)
        assert not worker.running

    def test_double_start_is_idempotent(self):
        worker = HeartbeatWorker(interval=0.1, threshold=0.0, callback_url="")
        worker.start()
        worker.start()
        assert worker.running
        worker.stop(timeout=2.0)

    def test_status_before_scan(self):
        worker = HeartbeatWorker(interval=60.0, threshold=120.0, callback_url="")
        status = worker.status()
        assert status["running"] is False
        assert status["last_scan_at"] is None
        assert status["last_stale_count"] == 0

    def test_status_after_scan(self):
        worker = HeartbeatWorker(interval=0.05, threshold=0.0, callback_url="")
        worker.start()
        time.sleep(0.2)
        status = worker.status()
        assert status["running"] is True
        assert status["last_scan_at"] is not None
        worker.stop(timeout=2.0)


# ---------------------------------------------------------------------------
# HeartbeatWorker callback tests
# ---------------------------------------------------------------------------


class TestHeartbeatCallback:
    @pytest.fixture(autouse=True)
    def _clear_ledger(self):
        with _confirmed_lock:
            _confirmed_settlements.clear()
        yield
        with _confirmed_lock:
            _confirmed_settlements.clear()

    @patch("a2a_settlement_mediator.heartbeat.httpx.Client")
    def test_successful_callback_marks_executed(self, mock_client_cls):
        result = _make_stale_result("hash-callback", age_seconds=200)
        with _confirmed_lock:
            _confirmed_settlements["hash-callback"] = result

        mock_resp = MagicMock()
        mock_resp.is_success = True
        mock_resp.status_code = 200
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_ctx.post.return_value = mock_resp
        mock_client_cls.return_value = mock_ctx

        worker = HeartbeatWorker(
            interval=0.05, threshold=0.0, callback_url="http://exec.test/run"
        )
        worker._tick()

        assert result.execution_status == ExecutionStatus.EXECUTED
        mock_ctx.post.assert_called_once()
        call_url = mock_ctx.post.call_args[0][0]
        assert call_url == "http://exec.test/run"

    @patch("a2a_settlement_mediator.heartbeat.httpx.Client")
    def test_failed_callback_leaves_pending(self, mock_client_cls):
        result = _make_stale_result("hash-fail", age_seconds=200)
        with _confirmed_lock:
            _confirmed_settlements["hash-fail"] = result

        mock_resp = MagicMock()
        mock_resp.is_success = False
        mock_resp.status_code = 500
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_ctx.post.return_value = mock_resp
        mock_client_cls.return_value = mock_ctx

        worker = HeartbeatWorker(
            interval=0.05, threshold=0.0, callback_url="http://exec.test/run"
        )
        worker._tick()

        assert result.execution_status == ExecutionStatus.PENDING

    def test_no_callback_url_skips_post(self):
        result = _make_stale_result("hash-nocb", age_seconds=200)
        with _confirmed_lock:
            _confirmed_settlements["hash-nocb"] = result

        worker = HeartbeatWorker(interval=0.05, threshold=0.0, callback_url="")
        worker._tick()

        assert result.execution_status == ExecutionStatus.PENDING
        assert worker.last_stale_count == 1


# ---------------------------------------------------------------------------
# Heartbeat status endpoint test
# ---------------------------------------------------------------------------


class TestHeartbeatEndpoint:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from a2a_settlement_mediator.webhook_listener import app

        return TestClient(app)

    def test_heartbeat_status_endpoint(self, client):
        resp = client.get("/heartbeat/status")
        assert resp.status_code == 200
        data = resp.json()
        assert "running" in data
        assert "interval_seconds" in data
        assert "threshold_seconds" in data
        assert "last_stale_count" in data
