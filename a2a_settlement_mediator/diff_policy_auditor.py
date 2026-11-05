"""Deterministic policy auditor for unified diffs.

Reports findings against a frozen PatchPolicy. Findings describe what a diff
changed relative to agreed restrictions; they make no claim about intent.
"""

from __future__ import annotations

from a2a_settlement_mediator.schemas import PatchPolicy, PolicyFinding


def audit_diff(diff_text: str, policy: PatchPolicy) -> list[PolicyFinding]:
    raise NotImplementedError
