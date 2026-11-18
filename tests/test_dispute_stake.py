"""The dispute stake follows the ruling: the filer keeps it on a win, loses it on a loss.

Driven through ``mediate`` with a fake exchange client, so each test checks the
``stake_ruling`` actually sent with the resolution that moves funds.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from a2a_settlement_mediator.mediator import mediate
from a2a_settlement_mediator.schemas import VerdictOutcome
from tests.test_self_dealing import (  # noqa: F401  (fixtures)
    _ESCROW_ID,
    _PROVIDER,
    _REQUESTER,
    FakeExchange,
    _isolated_db,
    _use,
)


def _llm(resolution: str, confidence: float = 0.95):
    return patch(
        "a2a_settlement_mediator.mediator._call_llm",
        return_value=(
            {
                "resolution": resolution,
                "confidence": confidence,
                "reasoning": "Decided on the evidence.",
                "factors": ["evidence"],
            },
            100,
            20,
            10,
        ),
    )


def _mediate(filer, resolution, confidence=0.95, escrow_extra=None):
    extra = {"dispute_filed_by": filer} if filer is not None else {}
    extra.update(escrow_extra or {})
    exchange = FakeExchange(escrow_extra=extra)
    with _use(exchange), _llm(resolution, confidence) as llm:
        audit = mediate(_ESCROW_ID)
    return exchange, audit, llm


@pytest.mark.parametrize(
    ("filer", "resolution", "expected"),
    [
        (_REQUESTER, "refund", "return"),
        (_REQUESTER, "release", "forfeit"),
        (_PROVIDER, "release", "return"),
        (_PROVIDER, "refund", "forfeit"),
    ],
)
def test_llm_ruling_returns_or_forfeits_by_who_filed(filer, resolution, expected):
    exchange, audit, _ = _mediate(filer, resolution)

    assert len(exchange.resolve_calls) == 1
    call = exchange.resolve_calls[0]
    assert call["resolution"] == resolution
    assert call["stake_ruling"] == expected
    assert audit.evidence.escrow.dispute_filed_by == filer


@pytest.mark.parametrize("filer", [None, "someone-else"])
def test_unknown_filer_sends_no_ruling(filer):
    exchange, _, _ = _mediate(filer, "release")

    assert exchange.resolve_calls[0]["stake_ruling"] is None


@pytest.mark.parametrize("filer", [_REQUESTER, _PROVIDER])
def test_low_confidence_escalates_and_leaves_the_stake_held(filer):
    exchange, audit, _ = _mediate(filer, "release", confidence=0.4)

    assert exchange.resolve_calls == []
    assert audit.verdict.outcome == VerdictOutcome.ESCALATE


@pytest.mark.parametrize(
    ("filer", "expected"), [(_REQUESTER, "return"), (_PROVIDER, "forfeit")]
)
def test_structural_failure_refund_does_not_penalise_a_requester_who_filed(filer, expected):
    """An empty deliverable is refunded without the LLM; the requester who filed keeps the stake."""
    exchange, audit, llm = _mediate(filer, "release", escrow_extra={"delivered_content": ""})

    llm.assert_not_called()
    assert audit.verdict.outcome == VerdictOutcome.AUTO_REFUND
    call = exchange.resolve_calls[0]
    assert call["resolution"] == "refund"
    assert call["stake_ruling"] == expected


def test_the_llm_is_not_told_who_filed():
    _, _, llm = _mediate(_REQUESTER, "refund")

    sent = " ".join(str(a) for a in llm.call_args.args) + str(llm.call_args.kwargs)
    assert "dispute_filed_by" not in sent
