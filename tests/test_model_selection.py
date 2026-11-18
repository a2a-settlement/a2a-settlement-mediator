"""Which model judges a dispute, and what the audit trail says about it.

``mediate()`` picks the model once (the review model for an escrow the
exchange marks ``suspected_self_dealing``, the default otherwise) and then
takes one of several paths: direct, digest (oversized deliverable), or one of
the paths that call no LLM. These tests patch ``litellm.completion`` itself,
so they see the model that is really requested on each path, and compare it
with every place the model is recorded: ``AuditRecord.llm_model``,
``AuditRecord.mediator_context`` and the ``mediator_context`` sent to the
exchange with the resolution.
"""

from __future__ import annotations

import hashlib
import json
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from a2a_settlement_mediator import storage
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.mediator import mediate
from a2a_settlement_mediator.prompts import DIGEST_SYSTEM_PROMPT, SYSTEM_PROMPT
from a2a_settlement_mediator.schemas import Resolution, VerdictOutcome
from tests.test_self_dealing import _ESCROW_ID, FakeExchange, _use

_DEFAULT = "test/default-model"
_REVIEW = "test/review-model"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(storage, "DB_PATH", str(tmp_path / "mediator.db"))
    storage.initialize_db()


@pytest.fixture(autouse=True)
def _models(monkeypatch):
    monkeypatch.setattr(settings, "llm_model", _DEFAULT)
    monkeypatch.setattr(settings, "llm_model_sonnet", _REVIEW)
    monkeypatch.setattr(settings, "suspected_self_dealing_review_threshold", 10_000)


@pytest.fixture
def completion():
    """Replace the provider call; a confident 'release'."""
    response = SimpleNamespace(
        choices=[
            SimpleNamespace(
                message=SimpleNamespace(
                    content=json.dumps(
                        {
                            "resolution": "release",
                            "confidence": 0.95,
                            "reasoning": "Deliverable meets the acceptance criteria.",
                            "factors": ["criteria_met"],
                        }
                    )
                )
            )
        ],
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=20),
    )
    with patch(
        "a2a_settlement_mediator.mediator.litellm.completion", return_value=response
    ) as mock:
        yield mock


@pytest.fixture
def oversized(monkeypatch):
    """Make every evidence bundle exceed the token budget, forcing the digest path."""
    monkeypatch.setattr(settings, "mediator_token_budget", 10)


def _system_prompt(completion) -> str:
    return completion.call_args.kwargs["messages"][0]["content"]


def _assert_recorded(audit, exchange, *, model: str, prompt: str) -> None:
    """Every record of the model agrees, including the copy the exchange stores."""
    assert audit.llm_model == model
    assert audit.mediator_context.model_version == model
    assert audit.mediator_context.system_prompt_hash == _sha(prompt)
    assert len(exchange.resolve_calls) == 1
    sent = exchange.resolve_calls[0]["mediator_context"]
    assert sent["model_version"] == model
    assert sent["system_prompt_hash"] == _sha(prompt)


# ---------------------------------------------------------------------------
# Direct path
# ---------------------------------------------------------------------------


class TestDirectPath:
    def test_default_model_is_called_and_recorded(self, completion):
        exchange = FakeExchange(self_dealing_class="arms_length")
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        completion.assert_called_once()
        assert completion.call_args.kwargs["model"] == _DEFAULT
        assert _system_prompt(completion) == SYSTEM_PROMPT
        assert audit.evaluation_method == "direct"
        _assert_recorded(audit, exchange, model=_DEFAULT, prompt=SYSTEM_PROMPT)

    def test_review_model_is_called_and_recorded(self, completion):
        exchange = FakeExchange(self_dealing_class="suspected_self_dealing")
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        completion.assert_called_once()
        assert completion.call_args.kwargs["model"] == _REVIEW
        assert audit.evaluation_method == "direct"
        _assert_recorded(audit, exchange, model=_REVIEW, prompt=SYSTEM_PROMPT)

    def test_failed_call_records_the_model_that_was_asked(self):
        exchange = FakeExchange(self_dealing_class="suspected_self_dealing")
        with _use(exchange), patch(
            "a2a_settlement_mediator.mediator.litellm.completion",
            side_effect=RuntimeError("provider unavailable"),
        ) as completion:
            audit = mediate(_ESCROW_ID)

        assert completion.call_args.kwargs["model"] == _REVIEW
        assert audit.verdict.outcome == VerdictOutcome.ESCALATE
        assert audit.llm_model == _REVIEW
        assert audit.mediator_context.model_version == _REVIEW
        assert exchange.resolve_calls == []


# ---------------------------------------------------------------------------
# Digest path (oversized deliverable)
# ---------------------------------------------------------------------------


class TestDigestPath:
    def test_default_model_is_called_and_recorded(self, completion, oversized):
        exchange = FakeExchange(self_dealing_class="arms_length")
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        completion.assert_called_once()
        assert completion.call_args.kwargs["model"] == _DEFAULT
        assert _system_prompt(completion) == DIGEST_SYSTEM_PROMPT
        assert audit.evaluation_method == "digest"
        _assert_recorded(audit, exchange, model=_DEFAULT, prompt=DIGEST_SYSTEM_PROMPT)

    def test_review_model_is_called_and_recorded(self, completion, oversized):
        """An oversized deliverable must not drop a suspected escrow to the default model."""
        exchange = FakeExchange(self_dealing_class="suspected_self_dealing")
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        completion.assert_called_once()
        assert completion.call_args.kwargs["model"] == _REVIEW
        assert _system_prompt(completion) == DIGEST_SYSTEM_PROMPT
        assert audit.evaluation_method == "digest"
        assert audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE
        _assert_recorded(audit, exchange, model=_REVIEW, prompt=DIGEST_SYSTEM_PROMPT)

    def test_failed_call_records_the_model_that_was_asked(self, oversized):
        exchange = FakeExchange(self_dealing_class="suspected_self_dealing")
        with _use(exchange), patch(
            "a2a_settlement_mediator.mediator.litellm.completion",
            side_effect=RuntimeError("provider unavailable"),
        ) as completion:
            audit = mediate(_ESCROW_ID)

        assert completion.call_args.kwargs["model"] == _REVIEW
        assert audit.evaluation_method == "system_error"
        assert audit.llm_model == _REVIEW
        assert audit.mediator_context.model_version == _REVIEW
        assert exchange.resolve_calls == []

    def test_digest_build_failure_records_no_model(self, completion, oversized):
        """The digest builder failed before any LLM call was made."""
        exchange = FakeExchange(self_dealing_class="suspected_self_dealing")
        with _use(exchange), patch(
            "a2a_settlement_mediator.mediator.build_digest",
            side_effect=RuntimeError("digest builder exploded"),
        ):
            audit = mediate(_ESCROW_ID)

        completion.assert_not_called()
        assert audit.evaluation_method == "system_error"
        assert audit.llm_model == "none"
        assert audit.mediator_context.model_version == "none"
        assert exchange.resolve_calls == []


# ---------------------------------------------------------------------------
# Paths that call no LLM
# ---------------------------------------------------------------------------


class TestNoLlmPaths:
    def test_self_dealing_refund_has_its_own_label(self, completion):
        exchange = FakeExchange(self_dealing_class="self_dealing")
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        completion.assert_not_called()
        assert audit.verdict.outcome == VerdictOutcome.NULL_RESOLUTION
        assert audit.evaluation_method == "null_resolution"
        assert audit.llm_model == "none"
        assert audit.mediator_context.model_version == "none"
        assert exchange.resolve_calls[0]["mediator_context"]["model_version"] == "none"

    def test_structural_refund_keeps_its_label_and_records_no_model(self, completion):
        exchange = FakeExchange(
            self_dealing_class="suspected_self_dealing",
            escrow_extra={"delivered_content": '{"broken json'},
        )
        with _use(exchange):
            audit = mediate(_ESCROW_ID)

        completion.assert_not_called()
        assert audit.verdict.resolution == Resolution.REFUND
        assert audit.evaluation_method == "structural_error"
        assert audit.llm_model == "none"
        assert audit.mediator_context.model_version == "none"
        assert exchange.resolve_calls[0]["mediator_context"]["model_version"] == "none"
