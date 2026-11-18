"""POST /settle stores successful settlements; GET /settlements lists them.

The pipeline runs for real here, with only the arbitration LLM and the
timestamp authority replaced, so the handler sees the result object the
pipeline actually returns.
"""

from __future__ import annotations

import base64
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator import settlement_pipeline, storage
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.settlement_pipeline import SettlementHardFail
from a2a_settlement_mediator.webhook_listener import app
from a2a_settlement_mediator.worm_schemas import (
    ArbitrationDecision,
    ArbitrationVerdict,
    TimestampToken,
)

_BODY = {
    "transcript_hash": "ab" * 32,
    "source_service": "crewai",
    "mandates": [
        {"mandate_id": "M-001", "description": "Deliver within 24 hours", "conditions": ["sla"]}
    ],
    "escrow_id": "esc-settle-1",
}


def _verdict(decision: ArbitrationDecision) -> ArbitrationVerdict:
    return ArbitrationVerdict(
        decision=decision,
        confidence=0.92,
        reasoning="Test verdict.",
        factors=["test"],
        mandate_compliance={"M-001": decision == ArbitrationDecision.APPROVED},
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


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "mediator.db"))
    storage.initialize_db()
    monkeypatch.setattr(settings, "webhook_secret", "")
    monkeypatch.setattr(settings, "allow_unauthenticated", True)
    monkeypatch.setattr(settlement_pipeline, "_confirmed_settlements", {})
    return TestClient(app)


@pytest.fixture
def pipeline():
    """Approved arbitration and a working timestamp authority, both replaceable."""
    with patch(
        "a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm",
        return_value=_verdict(ArbitrationDecision.APPROVED),
    ) as llm, patch(
        "a2a_settlement_mediator.settlement_pipeline._request_timestamp",
        return_value=_timestamp(),
    ) as tsa:
        yield {"llm": llm, "tsa": tsa}


class TestSuccessfulSettlementIsStored:
    def test_stored_under_the_proof_hash(self, client, pipeline):
        resp = client.post("/settle", json=_BODY)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        settlement_hash = data["proof"]["settlement_hash"]
        assert len(settlement_hash) == 64

        stored = storage.get_settlement_result(settlement_hash)
        assert stored is not None
        assert stored["proof"]["settlement_hash"] == settlement_hash
        assert stored == data

    def test_listed_by_get_settlements(self, client, pipeline):
        settlement_hash = client.post("/settle", json=_BODY).json()["proof"]["settlement_hash"]

        listing = client.get("/settlements").json()
        assert listing["total"] == 1
        assert [s["proof"]["settlement_hash"] for s in listing["settlements"]] == [settlement_hash]

    def test_each_settlement_gets_its_own_row(self, client, pipeline):
        first = client.post("/settle", json=_BODY).json()["proof"]["settlement_hash"]
        second = client.post(
            "/settle", json={**_BODY, "transcript_hash": "cd" * 32}
        ).json()["proof"]["settlement_hash"]

        assert first != second
        listing = client.get("/settlements").json()
        assert listing["total"] == 2
        assert {s["proof"]["settlement_hash"] for s in listing["settlements"]} == {first, second}

    def test_ack_updates_the_stored_row(self, client, pipeline):
        settlement_hash = client.post("/settle", json=_BODY).json()["proof"]["settlement_hash"]
        assert len(storage.list_pending_settlement_results()) == 1

        resp = client.post(
            "/settlements/ack", json={"settlement_hash": settlement_hash, "status": "executed"}
        )
        assert resp.status_code == 200
        assert storage.list_pending_settlement_results() == []
        # The row is kept; only its status column changes.
        assert client.get("/settlements").json()["total"] == 1


class TestResultsWithoutAProofAreNotStored:
    def test_hard_failure_is_returned_but_not_stored(self, client, pipeline):
        pipeline["tsa"].side_effect = SettlementHardFail("timestamp authority timed out")

        resp = client.post("/settle", json=_BODY)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert data["proof"] is None
        assert data["error"]

        assert client.get("/settlements").json() == {"settlements": [], "total": 0}
        assert storage.list_pending_settlement_results() == []

    def test_rejected_arbitration_is_returned_but_not_stored(self, client, pipeline):
        pipeline["llm"].return_value = _verdict(ArbitrationDecision.REJECTED)

        resp = client.post("/settle", json=_BODY)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert data["proof"] is None

        assert client.get("/settlements").json() == {"settlements": [], "total": 0}
