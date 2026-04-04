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
from a2a_settlement_mediator.digest import (
    build_digest,
    check_deliverable_integrity,
    estimate_tokens,
)
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

# Small delivered_content used by most fixtures so the integrity check passes
# and tests can exercise the LLM routing path.
_SMALL_DELIVERABLE = json.dumps({"summary": "Q1 2025 market research report.", "findings": ["Finding A"]})

# A large JSON deliverable that exceeds the 24 K token budget (≈96 K chars)
_LARGE_DELIVERABLE = json.dumps(
    {
        "findings": [{"id": i, "title": f"Finding {i}", "evidence": "https://example.com/src"} for i in range(3000)],
        "summary": "Comprehensive recon output",
    }
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    from a2a_settlement_mediator import storage
    storage.initialize_db()
    return TestClient(app)


@pytest.fixture
def sample_evidence():
    """Evidence bundle with a small delivered_content so integrity check passes."""
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
            delivered_content=_SMALL_DELIVERABLE,
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


@pytest.fixture
def large_deliverable_evidence():
    """Evidence bundle with a >24 K-token JSON deliverable for digest routing tests."""
    return EvidenceBundle(
        escrow=EscrowEvidence(
            escrow_id="esc-large",
            requester_id="req-001",
            provider_id="prov-sentinel",
            amount=2000,
            fee_amount=10,
            status="disputed",
            dispute_reason="Output quality dispute",
            task_id="task-sentinel",
            task_type="recon",
            deliverables=[
                Deliverable(
                    description="Sentinel recon output",
                    artifact_hash=None,
                    acceptance_criteria='Requires "findings" and "summary" fields',
                ),
            ],
            delivered_content=_LARGE_DELIVERABLE,
            created_at=datetime(2025, 6, 1, tzinfo=timezone.utc),
            expires_at=datetime(2025, 6, 2, tzinfo=timezone.utc),
        ),
        requester=AccountEvidence(
            account_id="req-001",
            bot_name="recon-buyer",
            reputation=0.90,
            status="active",
            skills=[],
            total_earned=0,
            total_spent=10000,
        ),
        provider=AccountEvidence(
            account_id="prov-sentinel",
            bot_name="sentinel-recon",
            reputation=0.75,
            status="active",
            skills=["recon"],
            total_earned=8000,
            total_spent=0,
        ),
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
        assert audit.evaluation_method == "direct"
        mock_resolve.assert_called_once()
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
            model_dump_json=lambda: '{"escrow_id": "esc-test", "verdict": {}}',
        )
        resp = client.post("/mediate/esc-test")
        assert resp.status_code == 200
        mock_mediate.assert_called_once()
        assert mock_mediate.call_args.args[0] == "esc-test"

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

    def test_audit_record_evaluation_method_defaults_to_direct(self, sample_evidence):
        """AuditRecord defaults evaluation_method to 'direct' for backwards compatibility."""
        v = Verdict(
            escrow_id="esc-001",
            outcome=VerdictOutcome.ESCALATE,
            confidence=0.0,
            reasoning="test",
        )
        from a2a_settlement_mediator.schemas import AuditRecord
        audit = AuditRecord(
            escrow_id="esc-001",
            evidence=sample_evidence,
            verdict=v,
            llm_model="test-model",
        )
        assert audit.evaluation_method == "direct"
        assert audit.deliverable_size_bytes is None
        assert audit.digest_size_tokens is None


# ---------------------------------------------------------------------------
# Deliverable integrity check tests
# ---------------------------------------------------------------------------


class TestDeliverableIntegrity:
    def test_empty_content_returns_error(self):
        result = check_deliverable_integrity(None)
        assert result["ok"] is False
        assert result["code"] == "DELIVERABLE_EMPTY"

    def test_whitespace_only_returns_error(self):
        result = check_deliverable_integrity("   \n  ")
        assert result["ok"] is False
        assert result["code"] == "DELIVERABLE_EMPTY"

    def test_plaintext_passes(self):
        result = check_deliverable_integrity("This is a plain-text research report with lots of words.")
        assert result["ok"] is True

    def test_valid_json_passes(self):
        content = json.dumps({"summary": "report", "findings": ["a", "b"]})
        result = check_deliverable_integrity(content)
        assert result["ok"] is True

    def test_malformed_json_detected(self):
        result = check_deliverable_integrity('{"summary": "broken"')
        assert result["ok"] is False
        assert result["code"] == "DELIVERABLE_MALFORMED"

    def test_schema_mismatch_detected(self):
        content = json.dumps({"output": "something"})
        # acceptance criteria references "findings" which is absent
        result = check_deliverable_integrity(content, acceptance_criteria='"findings" must be present')
        assert result["ok"] is False
        assert result["code"] == "DELIVERABLE_SCHEMA_MISMATCH"
        assert "findings" in result["reason"]

    def test_schema_match_passes(self):
        content = json.dumps({"findings": ["a"], "summary": "done"})
        result = check_deliverable_integrity(content, acceptance_criteria='"findings" and "summary" required')
        assert result["ok"] is True

    def test_json_array_passes(self):
        content = json.dumps([{"id": 1}, {"id": 2}])
        result = check_deliverable_integrity(content)
        assert result["ok"] is True


# ---------------------------------------------------------------------------
# Digest builder tests
# ---------------------------------------------------------------------------


class TestBuildDigest:
    def test_digest_has_required_keys(self):
        content = json.dumps({"findings": [{"id": 1, "text": "x"}], "summary": "done"})
        digest = build_digest(content)
        assert "total_size_bytes" in digest
        assert "structure" in digest
        assert "schema_compliance" in digest
        assert "sample_content" in digest
        assert "evidence_check" in digest

    def test_top_level_keys_captured(self):
        content = json.dumps({"findings": [], "metadata": {}, "urls": []})
        digest = build_digest(content)
        assert set(digest["structure"]["top_level_keys"]) == {"findings", "metadata", "urls"}

    def test_samples_extracted(self):
        content = json.dumps({"findings": [{"id": i} for i in range(10)]})
        digest = build_digest(content)
        samples = digest["sample_content"]["samples"]
        # Should capture up to 3 samples from the "findings" section
        assert len(samples) <= 3
        assert all(s["section"] == "findings" for s in samples)

    def test_url_extraction(self):
        content = json.dumps({
            "findings": [
                {"url": "https://example.com/source1"},
                {"url": "https://example.com/source2"},
            ]
        })
        digest = build_digest(content)
        assert digest["evidence_check"]["total_evidence_urls"] == 2
        assert "https://example.com/source1" in digest["evidence_check"]["sample_urls"]

    def test_missing_fields_reported(self):
        content = json.dumps({"output": "something"})
        digest = build_digest(content, acceptance_criteria='"findings" and "summary" required')
        assert "findings" in digest["schema_compliance"]["missing_fields"]

    def test_large_deliverable_produces_compact_digest(self):
        digest = build_digest(_LARGE_DELIVERABLE)
        digest_str = json.dumps(digest)
        # Digest should be well under 24 K tokens (≈96 K chars)
        assert estimate_tokens(digest_str) < 6000

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="valid JSON"):
            build_digest('{"broken"')

    def test_array_deliverable(self):
        content = json.dumps([{"id": 1}, {"id": 2}])
        digest = build_digest(content)
        assert digest["structure"]["top_level_keys"] == ["[array]"]
        assert digest["structure"]["section_count"] == 1


# ---------------------------------------------------------------------------
# Large deliverable routing tests (digest pipeline)
# ---------------------------------------------------------------------------


class TestLargeDeliverableRouting:
    @patch("a2a_settlement_mediator.mediator._execute_resolution")
    @patch("a2a_settlement_mediator.mediator._call_llm_digest")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_large_deliverable_routes_to_digest(
        self, mock_evidence, mock_llm_digest, mock_resolve, large_deliverable_evidence
    ):
        """Deliverables exceeding the token budget are evaluated via the digest path."""
        mock_evidence.return_value = large_deliverable_evidence
        mock_llm_digest.return_value = (
            {
                "resolution": "release",
                "confidence": 0.82,
                "reasoning": "Digest shows substantive findings with evidence URLs.",
                "factors": ["high_finding_count", "evidence_urls_present"],
            },
            600,
            120,
            1200,
        )
        mock_resolve.return_value = {"escrow_id": "esc-large", "status": "released"}

        audit = mediate("esc-large")

        assert audit.evaluation_method == "digest"
        assert audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE
        assert audit.verdict.confidence == 0.82
        assert audit.deliverable_size_bytes is not None and audit.deliverable_size_bytes > 0
        assert audit.digest_size_tokens is not None and audit.digest_size_tokens > 0
        mock_llm_digest.assert_called_once()
        mock_resolve.assert_called_once()

    @patch("a2a_settlement_mediator.mediator._call_llm")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_small_deliverable_uses_direct_path(self, mock_evidence, mock_llm, sample_evidence):
        """Deliverables within the token budget use the existing direct LLM path."""
        mock_evidence.return_value = sample_evidence
        mock_llm.return_value = (
            {
                "resolution": "release",
                "confidence": 0.88,
                "reasoning": "Delivered adequately.",
                "factors": ["content_present"],
            },
            300,
            80,
            500,
        )

        audit = mediate("esc-001")

        assert audit.evaluation_method == "direct"
        assert audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE
        mock_llm.assert_called_once()

    @patch("a2a_settlement_mediator.mediator._execute_resolution")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_digest_pipeline_failure_escalates_without_scoring(
        self, mock_evidence, mock_resolve, large_deliverable_evidence
    ):
        """If the digest pipeline itself fails, escalate without calling _execute_resolution."""
        mock_evidence.return_value = large_deliverable_evidence

        with patch(
            "a2a_settlement_mediator.mediator.build_digest",
            side_effect=RuntimeError("digest builder exploded"),
        ):
            audit = mediate("esc-large")

        assert audit.evaluation_method == "system_error"
        assert audit.verdict.outcome == VerdictOutcome.ESCALATE
        assert audit.verdict.confidence == 0.0
        assert "MEDIATION_PROCESSING_FAILURE" in audit.verdict.reasoning
        # Critical: exchange resolution must NOT be called — no reputation impact
        mock_resolve.assert_not_called()
        assert audit.error is not None


# ---------------------------------------------------------------------------
# Structural integrity failure tests (provider-side failures, scored)
# ---------------------------------------------------------------------------


class TestStructuralIntegrityFailures:
    @patch("a2a_settlement_mediator.mediator._execute_resolution")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_empty_deliverable_auto_refunds(self, mock_evidence, mock_resolve, sample_evidence):
        """Empty deliverable is caught pre-LLM and auto-refunded as a provider failure."""
        sample_evidence.escrow.delivered_content = None
        mock_evidence.return_value = sample_evidence
        mock_resolve.return_value = {"escrow_id": "esc-001", "status": "refunded"}

        audit = mediate("esc-001")

        assert audit.evaluation_method == "structural_error"
        assert audit.verdict.outcome == VerdictOutcome.AUTO_REFUND
        assert audit.verdict.resolution == Resolution.REFUND
        assert audit.verdict.confidence == 0.95
        assert "DELIVERABLE_EMPTY" in audit.verdict.factors
        # Exchange IS called — this is the provider's fault, reputation should update
        mock_resolve.assert_called_once()

    @patch("a2a_settlement_mediator.mediator._execute_resolution")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_malformed_json_deliverable_auto_refunds(self, mock_evidence, mock_resolve, sample_evidence):
        """Provider submitting malformed JSON is scored as a quality failure."""
        sample_evidence.escrow.delivered_content = '{"broken json'
        mock_evidence.return_value = sample_evidence
        mock_resolve.return_value = {"escrow_id": "esc-001", "status": "refunded"}

        audit = mediate("esc-001")

        assert audit.evaluation_method == "structural_error"
        assert audit.verdict.outcome == VerdictOutcome.AUTO_REFUND
        assert "DELIVERABLE_MALFORMED" in audit.verdict.factors
        mock_resolve.assert_called_once()
        # LLM should NOT have been called at all
        # (no need to patch _call_llm — if it were called without a mock it would raise)

    @patch("a2a_settlement_mediator.mediator._execute_resolution")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_schema_mismatch_auto_refunds(self, mock_evidence, mock_resolve, sample_evidence):
        """Deliverable missing required fields is scored as a quality failure."""
        sample_evidence.escrow.delivered_content = json.dumps({"output": "wrong field"})
        sample_evidence.escrow.deliverables[0].acceptance_criteria = '"findings" field required'
        mock_evidence.return_value = sample_evidence
        mock_resolve.return_value = {"escrow_id": "esc-001", "status": "refunded"}

        audit = mediate("esc-001")

        assert audit.evaluation_method == "structural_error"
        assert audit.verdict.outcome == VerdictOutcome.AUTO_REFUND
        assert "DELIVERABLE_SCHEMA_MISMATCH" in audit.verdict.factors
        mock_resolve.assert_called_once()

    @patch("a2a_settlement_mediator.mediator._execute_resolution")
    @patch("a2a_settlement_mediator.mediator.collect_evidence")
    def test_structural_error_no_llm_call(self, mock_evidence, mock_resolve, sample_evidence):
        """Structural errors must not reach the LLM — verified by absence of LLM mock."""
        sample_evidence.escrow.delivered_content = None
        mock_evidence.return_value = sample_evidence
        mock_resolve.return_value = {"status": "refunded"}

        # If _call_llm were invoked without a mock it would throw a real network call.
        # The test passing without patching _call_llm proves the LLM is not reached.
        with patch("a2a_settlement_mediator.mediator._call_llm") as mock_llm:
            audit = mediate("esc-001")
            mock_llm.assert_not_called()

        assert audit.evaluation_method == "structural_error"
