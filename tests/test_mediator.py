"""Tests for the A2A Settlement Mediator.

All tests mock the exchange API and LLM to run without external dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.mediator import _build_verdict, mediate
from a2a_settlement_mediator.schemas import (
    AccountEvidence,
    Deliverable,
    EscrowEvidence,
    EvidenceBundle,
    Resolution,
    Verdict,
    VerdictOutcome,
)
from a2a_settlement_mediator.webhook_listener import app


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_evidence():
    return EvidenceBundle(
        escrow=EscrowEvidence(
            escrow_id="esc-001",
            requester_id="req-001",
            provider_id="prov-001",
            amount=500,
            fee_amount=2,
            status="disputed",
            dispute_reason="Provider never delivered the report",
            task_id="task-abc",
            task_type="research",
            deliverables=[
                Deliverable(
                    description="Market research report",
                    artifact_hash=None,
                    acceptance_criteria="Minimum 2000 words covering Q1 2025 trends",
                ),
            ],
            created_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
            expires_at=datetime(2025, 6, 1, 0, 30, tzinfo=timezone.utc),
        ),
        requester=AccountEvidence(
            account_id="req-001",
            bot_name="research-buyer",
            reputation=0.85,
            status="active",
            skills=["data-analysis"],
            total_earned=0,
            total_spent=5000,
        ),
        provider=AccountEvidence(
            account_id="prov-001",
            bot_name="research-writer",
            reputation=0.40,
            status="active",
            skills=["research", "writing"],
            total_earned=2000,
            total_spent=0,
        ),
        requester_recent_disputes=0,
        provider_recent_disputes=3,
    )


def _webhook_body(escrow_id: str = "esc-001") -> dict:
    return {
        "event": "escrow.disputed",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "escrow_id": escrow_id,
            "requester_id": "req-001",
            "provider_id": "prov-001",
            "amount": 500,
            "fee_amount": 2,
            "status": "disputed",
        },
    }


def _sign(body: bytes, secret: str = "test-secret") -> str:
    sig = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={sig}"


# ---------------------------------------------------------------------------
# Verdict construction tests
# ---------------------------------------------------------------------------


class TestBuildVerdict:
    def test_high_confidence_release(self):
        llm_output = {
            "resolution": "release",
            "confidence": 0.95,
            "reasoning": "Clear delivery",
            "factors": ["artifact_hash_present"],
        }
        verdict = _build_verdict("esc-001", llm_output)
        assert verdict.outcome == VerdictOutcome.AUTO_RELEASE
        assert verdict.resolution == Resolution.RELEASE
        assert verdict.confidence == 0.95

    def test_high_confidence_refund(self):
        llm_output = {
            "resolution": "refund",
            "confidence": 0.92,
            "reasoning": "No deliverables submitted",
            "factors": ["no_artifact"],
        }
        verdict = _build_verdict("esc-001", llm_output)
        assert verdict.outcome == VerdictOutcome.AUTO_REFUND
        assert verdict.resolution == Resolution.REFUND

    def test_low_confidence_escalates(self):
        llm_output = {
            "resolution": "release",
            "confidence": 0.55,
            "reasoning": "Ambiguous case",
            "factors": [],
        }
        verdict = _build_verdict("esc-001", llm_output)
        assert verdict.outcome == VerdictOutcome.ESCALATE
        assert verdict.resolution is None

    def test_unrecognized_resolution_escalates(self):
        llm_output = {
            "resolution": "partial_refund",
            "confidence": 0.90,
            "reasoning": "Wanted partial",
            "factors": [],
        }
        verdict = _build_verdict("esc-001", llm_output)
        assert verdict.outcome == VerdictOutcome.ESCALATE
        assert verdict.confidence == 0.0

    def test_confidence_clamped(self):
        llm_output = {
            "resolution": "release",
            "confidence": 1.5,
            "reasoning": "Overcounting",
            "factors": [],
        }
        verdict = _build_verdict("esc-001", llm_output)
        assert verdict.confidence == 1.0

    def test_negative_confidence_clamped(self):
        llm_output = {
            "resolution": "refund",
            "confidence": -0.2,
            "reasoning": "Undercounting",
            "factors": [],
        }
        verdict = _build_verdict("esc-001", llm_output)
        assert verdict.confidence == 0.0


# ---------------------------------------------------------------------------
# Full mediation pipeline tests (mocked exchange + LLM)
# ---------------------------------------------------------------------------


class TestMediate:
    @patch("a2a_settlement_mediator.mediator._execute_resolution")
    @patch("a2a_settlement_mediator.mediator._call_llm")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_auto_release(self, mock_evidence, mock_llm, mock_resolve, sample_evidence):
        mock_evidence.return_value = sample_evidence
        mock_llm.return_value = (
            {
                "resolution": "refund",
                "confidence": 0.93,
                "reasoning": "No artifact hash, no evidence of delivery",
                "factors": ["no_artifact", "low_provider_reputation", "multiple_disputes"],
            },
            500,
            120,
            850,
        )
        mock_resolve.return_value = {"escrow_id": "esc-001", "status": "refunded"}

        audit = mediate("esc-001")

        assert audit.verdict.outcome == VerdictOutcome.AUTO_REFUND
        assert audit.verdict.confidence == 0.93
        mock_resolve.assert_called_once_with("esc-001", Resolution.REFUND)
        assert audit.llm_latency_ms == 850

    @patch("a2a_settlement_mediator.mediator._notify_escalation")
    @patch("a2a_settlement_mediator.mediator._call_llm")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_escalation(self, mock_evidence, mock_llm, mock_notify, sample_evidence):
        mock_evidence.return_value = sample_evidence
        mock_llm.return_value = (
            {
                "resolution": "release",
                "confidence": 0.60,
                "reasoning": "Ambiguous — work appears partial",
                "factors": ["partial_delivery"],
            },
            400,
            100,
            600,
        )

        audit = mediate("esc-001")

        assert audit.verdict.outcome == VerdictOutcome.ESCALATE
        assert audit.verdict.resolution is None
        mock_notify.assert_called_once()

    @patch("a2a_settlement_mediator.mediator._call_llm")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_llm_failure_escalates(self, mock_evidence, mock_llm, sample_evidence):
        mock_evidence.return_value = sample_evidence
        mock_llm.side_effect = RuntimeError("LLM provider unavailable")

        audit = mediate("esc-001")

        assert audit.verdict.outcome == VerdictOutcome.ESCALATE
        assert audit.error is not None
        assert "unavailable" in audit.error


# ---------------------------------------------------------------------------
# Webhook listener tests
# ---------------------------------------------------------------------------


class TestWebhookListener:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "a2a-settlement-mediator"

    @patch("a2a_settlement_mediator.webhook_listener._run_mediation")
    def test_disputed_event_accepted(self, mock_mediate, client):
        """Disputed events are accepted and trigger background mediation."""
        body = _webhook_body()
        resp = client.post(
            "/webhook",
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "accepted"
        assert data["escrow_id"] == "esc-001"

    def test_non_disputed_event_ignored(self, client):
        """Non-dispute events are acknowledged but ignored."""
        body = {
            "event": "escrow.released",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"escrow_id": "esc-002"},
        }
        resp = client.post(
            "/webhook",
            content=json.dumps(body),
            headers={"Content-Type": "application/json"},
        )
        assert resp.status_code == 200
        assert resp.json()["status"] == "ignored"

    def test_signature_verification_rejects_bad_sig(self, client):
        """Bad signature is rejected when webhook_secret is configured."""
        original_secret = settings.webhook_secret
        settings.webhook_secret = "test-secret"
        try:
            body = json.dumps(_webhook_body()).encode()
            resp = client.post(
                "/webhook",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "X-A2ASE-Signature": "sha256=bad",
                },
            )
            assert resp.status_code == 401
        finally:
            settings.webhook_secret = original_secret

    def test_signature_verification_accepts_good_sig(self, client):
        """Valid signature is accepted."""
        original_secret = settings.webhook_secret
        settings.webhook_secret = "test-secret"
        try:
            body = json.dumps(_webhook_body()).encode()
            sig = _sign(body, "test-secret")
            with patch("a2a_settlement_mediator.webhook_listener._run_mediation"):
                resp = client.post(
                    "/webhook",
                    content=body,
                    headers={
                        "Content-Type": "application/json",
                        "X-A2ASE-Signature": sig,
                    },
                )
            assert resp.status_code == 200
        finally:
            settings.webhook_secret = original_secret

    @patch("a2a_settlement_mediator.webhook_listener.mediate")
    def test_manual_trigger(self, mock_mediate, client):
        """POST /mediate/{escrow_id} runs synchronous mediation."""
        mock_mediate.return_value = MagicMock(
            model_dump=lambda mode: {"escrow_id": "esc-test", "verdict": {}},
        )
        resp = client.post("/mediate/esc-test")
        assert resp.status_code == 200
        mock_mediate.assert_called_once_with("esc-test")

    def test_audits_empty(self, client):
        resp = client.get("/audits")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 0


# ---------------------------------------------------------------------------
# Schema tests
# ---------------------------------------------------------------------------


class TestSchemas:
    def test_evidence_bundle_serialization(self, sample_evidence):
        data = json.loads(sample_evidence.model_dump_json())
        assert data["escrow"]["escrow_id"] == "esc-001"
        assert len(data["escrow"]["deliverables"]) == 1
        assert data["requester"]["reputation"] == 0.85
        assert data["provider_recent_disputes"] == 3

    def test_verdict_serialization(self):
        v = Verdict(
            escrow_id="esc-001",
            outcome=VerdictOutcome.AUTO_RELEASE,
            resolution=Resolution.RELEASE,
            confidence=0.92,
            reasoning="Work clearly delivered",
            factors=["artifact_present", "criteria_met"],
        )
        data = json.loads(v.model_dump_json())
        assert data["outcome"] == "auto_release"
        assert data["resolution"] == "release"
        assert data["confidence"] == 0.92
