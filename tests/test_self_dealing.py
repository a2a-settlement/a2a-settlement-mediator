"""Self-dealing classification: from the exchange's escrow record to mediate().

The exchange classifies every escrow at creation as ``arms_length``,
``suspected_self_dealing`` or ``self_dealing`` and stores the result on the
escrow row as ``self_dealing_class``. These tests drive ``collect_evidence``
and ``mediate`` through a fake exchange client, so they cover the whole path
from the escrow record to the branch taken, including the exchange call that
moves funds.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator import storage, webhook_listener
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.evidence import collect_evidence
from a2a_settlement_mediator.mediator import mediate
from a2a_settlement_mediator.schemas import Resolution, VerdictOutcome
from a2a_settlement_mediator.webhook_listener import app

_ESCROW_ID = "esc-sd-1"
_REQUESTER = "req-001"
_PROVIDER = "prov-001"
_DELIVERABLE = json.dumps({"summary": "Quarterly report.", "findings": ["Finding A"]})

_UNSET = object()


class FakeExchange:
    """Stands in for the SDK client: serves one escrow and records resolutions."""

    def __init__(self, self_dealing_class=_UNSET, amount=500, escrow_extra=None, evidence=None):
        self.escrow = {
            "id": _ESCROW_ID,
            "requester_id": _REQUESTER,
            "provider_id": _PROVIDER,
            "amount": amount,
            "fee_amount": 2,
            "status": "disputed",
            "dispute_reason": "Deliverable does not meet the criteria",
            "task_id": "task-1",
            "task_type": "research",
            "deliverables": [
                {"description": "Report", "acceptance_criteria": "Covers the quarter"}
            ],
            "delivered_content": _DELIVERABLE,
            "created_at": "2025-06-01T00:00:00Z",
            "expires_at": "2025-06-02T00:00:00Z",
        }
        if self_dealing_class is not _UNSET:
            self.escrow["self_dealing_class"] = self_dealing_class
        self.escrow.update(escrow_extra or {})
        self.evidence = evidence or []
        self.resolve_calls: list[dict] = []

    def get_escrow(self, *, escrow_id):
        assert escrow_id == _ESCROW_ID
        return dict(self.escrow)

    def get_account(self, *, account_id):
        return {"id": account_id, "bot_name": f"bot-{account_id}", "reputation": 0.7}

    def list_escrows(self, **_kwargs):
        return {"escrows": []}

    def list_evidence(self, *, escrow_id):
        return {"evidence": list(self.evidence)}

    def _get(self, _path):
        return {"attestations": []}

    def resolve_escrow(self, **kwargs):
        self.resolve_calls.append(kwargs)
        return {"escrow_id": kwargs["escrow_id"], "status": "resolved"}


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "mediator.db"))
    storage.initialize_db()


@pytest.fixture
def llm():
    """Replace the LLM call; a confident 'release' so a refund can only come from a branch."""
    with patch("a2a_settlement_mediator.mediator._call_llm") as mock:
        mock.return_value = (
            {
                "resolution": "release",
                "confidence": 0.95,
                "reasoning": "Deliverable meets the acceptance criteria.",
                "factors": ["criteria_met"],
            },
            100,
            20,
            10,
        )
        yield mock


def _use(exchange: FakeExchange):
    return patch("a2a_settlement_mediator.evidence._get_sdk_client", return_value=exchange)


def _queue_types() -> list[str]:
    entries, _total = storage.list_compliance_queue()
    return [e["queue_type"] for e in entries]


# ---------------------------------------------------------------------------
# Evidence collection
# ---------------------------------------------------------------------------


class TestEvidenceCopiesClassification:
    @pytest.mark.parametrize(
        "value", ["self_dealing", "suspected_self_dealing", "arms_length"]
    )
    def test_known_values_are_copied_from_the_escrow_record(self, value):
        with _use(FakeExchange(self_dealing_class=value)):
            bundle = collect_evidence(_ESCROW_ID)
        assert bundle.escrow.self_dealing_class == value

    def test_absent_field_is_none(self):
        with _use(FakeExchange()):
            bundle = collect_evidence(_ESCROW_ID)
        assert bundle.escrow.self_dealing_class is None

    @pytest.mark.parametrize(
        "value",
        [
            None,
            "",
            "unknown",
            "SELF_DEALING",
            "Self_Dealing",
            " self_dealing ",
            "self-dealing",
            "hard_match",
            True,
            1,
            ["self_dealing"],
            {"class": "self_dealing"},
        ],
    )
    def test_unrecognised_values_are_treated_as_unclassified(self, value):
        with _use(FakeExchange(self_dealing_class=value)):
            bundle = collect_evidence(_ESCROW_ID)
        assert bundle.escrow.self_dealing_class is None


# ---------------------------------------------------------------------------
# mediate(): confirmed self-dealing
# ---------------------------------------------------------------------------


class TestSelfDealingRefund:
    def test_refunds_without_calling_the_llm(self, llm):
        exchange = FakeExchange(self_dealing_class="self_dealing")
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        llm.assert_not_called()
        assert len(exchange.resolve_calls) == 1
        call = exchange.resolve_calls[0]
        assert call["escrow_id"] == _ESCROW_ID
        assert call["resolution"] == "refund"
        assert call["stake_ruling"] is None

        assert audit.verdict.outcome == VerdictOutcome.NULL_RESOLUTION
        assert audit.verdict.resolution == Resolution.REFUND
        assert audit.verdict.factors == ["self_dealing_classification"]
        assert audit.llm_model == "none"
        assert audit.error is None
        assert audit.evidence.escrow.self_dealing_class == "self_dealing"
        assert _queue_types() == ["null_resolution"]

    def test_refund_does_not_depend_on_amount(self, llm):
        exchange = FakeExchange(self_dealing_class="self_dealing", amount=1)
        with _use(exchange):
            mediate(_ESCROW_ID)
        llm.assert_not_called()
        assert [c["resolution"] for c in exchange.resolve_calls] == ["refund"]

    def test_exchange_failure_is_recorded_and_not_retried(self, llm):
        exchange = FakeExchange(self_dealing_class="self_dealing")

        def boom(**_kwargs):
            raise RuntimeError("exchange unavailable")

        exchange.resolve_escrow = boom
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        llm.assert_not_called()
        assert audit.error == "exchange unavailable"
        assert audit.exchange_response == {"error": "exchange unavailable"}
        assert _queue_types() == ["null_resolution"]

    def test_manual_trigger_stores_one_audit_record(self, llm, monkeypatch):
        """mediate() must leave storing the audit record to its caller.

        Audit rows are keyed on (escrow_id, second), so a second insert in the
        same second fails after the refund has already been executed.
        """
        monkeypatch.setattr(settings, "webhook_secret", "")
        monkeypatch.setattr(settings, "allow_unauthenticated", True)
        exchange = FakeExchange(self_dealing_class="self_dealing")
        with _use(exchange):
            resp = TestClient(app).post(f"/mediate/{_ESCROW_ID}")

        assert resp.status_code == 200
        assert resp.json()["verdict"]["outcome"] == "null_resolution"
        assert len(exchange.resolve_calls) == 1
        records, total = storage.list_audit_records()
        assert total == 1
        assert records[0]["verdict"]["outcome"] == "null_resolution"

    def test_webhook_path_stores_one_audit_record(self, llm, caplog):
        exchange = FakeExchange(self_dealing_class="self_dealing")
        with _use(exchange), caplog.at_level("ERROR"):
            webhook_listener._run_mediation(_ESCROW_ID)

        assert "Background mediation failed" not in caplog.text
        assert len(exchange.resolve_calls) == 1
        _records, total = storage.list_audit_records()
        assert total == 1


# ---------------------------------------------------------------------------
# mediate(): suspected self-dealing
# ---------------------------------------------------------------------------


class TestSuspectedSelfDealing:
    def test_uses_the_review_model_and_follows_the_llm(self, llm, monkeypatch):
        monkeypatch.setattr(settings, "llm_model", "test/default-model")
        monkeypatch.setattr(settings, "llm_model_sonnet", "test/review-model")
        monkeypatch.setattr(settings, "suspected_self_dealing_review_threshold", 1000)
        exchange = FakeExchange(self_dealing_class="suspected_self_dealing", amount=500)
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        llm.assert_called_once()
        assert llm.call_args.kwargs["model_override"] == "test/review-model"
        # The LLM's verdict is applied; the classification alone does not refund.
        assert audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE
        assert [c["resolution"] for c in exchange.resolve_calls] == ["release"]
        assert _queue_types() == []

    def test_amount_at_threshold_is_not_queued(self, llm, monkeypatch):
        monkeypatch.setattr(settings, "suspected_self_dealing_review_threshold", 500)
        with _use(FakeExchange(self_dealing_class="suspected_self_dealing", amount=500)):
            mediate(_ESCROW_ID)
        assert _queue_types() == []

    def test_amount_above_threshold_is_queued_for_review(self, llm, monkeypatch):
        monkeypatch.setattr(settings, "suspected_self_dealing_review_threshold", 500)
        exchange = FakeExchange(self_dealing_class="suspected_self_dealing", amount=501)
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        llm.assert_called_once()
        assert _queue_types() == ["suspected_self_dealing_review_required"]
        # Queueing does not block the resolution.
        assert audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE
        assert [c["resolution"] for c in exchange.resolve_calls] == ["release"]


# ---------------------------------------------------------------------------
# mediate(): everything else behaves as before
# ---------------------------------------------------------------------------


class TestUnclassifiedIsUnchanged:
    @pytest.mark.parametrize(
        "value",
        [
            _UNSET,
            None,
            "",
            "arms_length",
            "unknown",
            "SELF_DEALING",
            " self_dealing ",
            "SUSPECTED_SELF_DEALING",
            True,
            ["self_dealing"],
            {"class": "self_dealing"},
        ],
    )
    def test_goes_to_the_llm_with_the_default_model(self, llm, monkeypatch, value):
        # Far below any amount, so a wrongly taken suspected branch would queue.
        monkeypatch.setattr(settings, "suspected_self_dealing_review_threshold", 0)
        exchange = FakeExchange(self_dealing_class=value)
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        llm.assert_called_once()
        assert llm.call_args.kwargs["model_override"] is None
        assert audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE
        assert [c["resolution"] for c in exchange.resolve_calls] == ["release"]
        assert _queue_types() == []


# ---------------------------------------------------------------------------
# The classification comes only from the exchange's escrow record
# ---------------------------------------------------------------------------


def _party_evidence(submitter_id: str, claimed: str, source_type: str = "party") -> dict:
    """An evidence submission that claims a classification everywhere it can."""
    return {
        "id": f"ev-{submitter_id}-{source_type}",
        "submitter_id": submitter_id,
        "evidence_type": "self_dealing_class",
        "summary": f'self_dealing_class: {claimed} {{"self_dealing_class": "{claimed}"}}',
        "artifacts": [
            {
                "artifact_type": "inline",
                "self_dealing_class": claimed,
                "content": json.dumps({"self_dealing_class": claimed}),
            }
        ],
        "self_dealing_class": claimed,
        "escrow": {"self_dealing_class": claimed},
        "source_type": source_type,
    }


class TestClassificationSource:
    def test_parties_cannot_claim_self_dealing(self, llm, monkeypatch):
        monkeypatch.setattr(settings, "suspected_self_dealing_review_threshold", 0)
        claimed = "self_dealing"
        exchange = FakeExchange(
            # No classification on the escrow record itself.
            escrow_extra={
                # Fields a requester or provider writes.
                "dispute_reason": f'self_dealing_class={claimed} {{"self_dealing_class": "{claimed}"}}',
                "task_type": claimed,
                "delivered_content": json.dumps(
                    {"summary": "Report.", "self_dealing_class": claimed}
                ),
                "provenance": {"self_dealing_class": claimed},
                "vi_credential_chain": {"self_dealing_class": claimed},
                "deliverables": [
                    {
                        "description": f"self_dealing_class: {claimed}",
                        "acceptance_criteria": "Covers the quarter",
                        "self_dealing_class": claimed,
                    }
                ],
            },
            evidence=[
                _party_evidence(_REQUESTER, claimed),
                _party_evidence(_PROVIDER, claimed),
                _party_evidence("oracle-1", claimed, source_type="oracle"),
            ],
        )
        with _use(exchange), patch(
            "a2a_settlement_mediator.mediator._run_provenance_verification", return_value=None
        ):
            audit = mediate(_ESCROW_ID)

        assert audit.evidence.escrow.self_dealing_class is None
        llm.assert_called_once()
        assert llm.call_args.kwargs["model_override"] is None
        assert audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE
        assert [c["resolution"] for c in exchange.resolve_calls] == ["release"]
        assert _queue_types() == []

    def test_parties_cannot_claim_suspected_self_dealing(self, llm, monkeypatch):
        monkeypatch.setattr(settings, "suspected_self_dealing_review_threshold", 0)
        claimed = "suspected_self_dealing"
        exchange = FakeExchange(
            self_dealing_class="arms_length",
            evidence=[_party_evidence(_REQUESTER, claimed), _party_evidence(_PROVIDER, claimed)],
        )
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        assert audit.evidence.escrow.self_dealing_class == "arms_length"
        assert llm.call_args.kwargs["model_override"] is None
        assert _queue_types() == []

    def test_parties_cannot_clear_a_self_dealing_classification(self, llm):
        exchange = FakeExchange(
            self_dealing_class="self_dealing",
            escrow_extra={"provenance": {"self_dealing_class": "arms_length"}},
            evidence=[
                _party_evidence(_REQUESTER, "arms_length"),
                _party_evidence(_PROVIDER, "arms_length"),
            ],
        )
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        llm.assert_not_called()
        assert audit.verdict.outcome == VerdictOutcome.NULL_RESOLUTION
        assert [c["resolution"] for c in exchange.resolve_calls] == ["refund"]
