"""Assess a git diff against a frozen PatchPolicy.

Deterministic policy findings decide the outcome. The LLM reviewer may add
findings and cannot remove them. Agent-supplied spans are checked for
internal consistency only and never change the outcome.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable

import litellm

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.diff_policy_auditor import audit_diff
from a2a_settlement_mediator.prompts import (
    PATCH_REVIEW_SYSTEM_PROMPT,
    build_patch_review_prompt,
)
from a2a_settlement_mediator.schemas import (
    FindingSeverity,
    PatchAssessment,
    PatchOutcome,
    PolicyFinding,
    PolicyRule,
    ReviewerOpinion,
    TraceConsistency,
    VerifyPatchRequest,
)

logger = logging.getLogger(__name__)

litellm.suppress_debug_info = True


def assess_patch(
    req: VerifyPatchRequest,
    *,
    llm_call: Callable[[str], str] | None = None,
) -> PatchAssessment:
    """Return a patch assessment for ``req``.

    ``llm_call`` replaces the litellm request in tests. It receives the
    user prompt and returns the model text.
    """
    diff_bytes = req.git_diff.encode("utf-8")
    diff_sha256 = hashlib.sha256(diff_bytes).hexdigest()
    trace = _trace_consistency(req, diff_sha256)
    identity = {
        "trace_consistency": trace,
        "diff_sha256": diff_sha256,
        "spec_hash": req.spec_hash,
        "repo": req.repo,
        "pr_number": req.pr_number,
        "head_sha": req.head_sha,
    }

    if len(diff_bytes) > settings.max_patch_diff_bytes:
        return PatchAssessment(
            outcome=PatchOutcome.REJECTED_TOO_LARGE,
            findings=[],
            reviewer_opinion=ReviewerOpinion(status="skipped"),
            **identity,
        )

    findings = list(audit_diff(req.git_diff, req.policy))
    has_violation = any(item.severity == FindingSeverity.VIOLATION for item in findings)
    if req.enable_reviewer and not has_violation:
        opinion, extra = _run_reviewer(req, findings, llm_call)
        findings.extend(extra)
    else:
        opinion = ReviewerOpinion(status="skipped")

    return PatchAssessment(
        outcome=_outcome_from_findings(findings),
        findings=findings,
        reviewer_opinion=opinion,
        **identity,
    )


def _outcome_from_findings(findings: list[PolicyFinding]) -> PatchOutcome:
    """Map severities to an outcome. Reviewer text is not an input."""
    if any(item.severity == FindingSeverity.VIOLATION for item in findings):
        return PatchOutcome.POLICY_VIOLATION
    if any(item.severity == FindingSeverity.REVIEW for item in findings):
        return PatchOutcome.NEEDS_REVIEW
    return PatchOutcome.ACCEPTABLE


def _run_reviewer(
    req: VerifyPatchRequest,
    findings: list[PolicyFinding],
    llm_call: Callable[[str], str] | None,
) -> tuple[ReviewerOpinion, list[PolicyFinding]]:
    """Run the advisory reviewer. A failure adds a REVIEWER_UNAVAILABLE finding."""
    reported_model = None if llm_call is not None else settings.llm_model
    call = llm_call or _default_llm_call
    try:
        prompt = build_patch_review_prompt(req.git_diff, findings, req.policy)
        summary, concerns = _parse_reviewer_output(call(prompt))
    except Exception as exc:
        logger.warning(
            "Patch reviewer unavailable for %s#%s: %s",
            req.repo,
            req.pr_number,
            exc,
        )
        unavailable = PolicyFinding(
            rule=PolicyRule.REVIEWER_UNAVAILABLE,
            severity=req.policy.severity_for(PolicyRule.REVIEWER_UNAVAILABLE),
            path="",
            evidence="requested reviewer did not return a usable opinion",
            source="deterministic",
        )
        return ReviewerOpinion(status="unavailable", model=reported_model), [unavailable]

    severity = req.policy.severity_for(PolicyRule.REVIEWER_CONCERN)
    extra = [
        PolicyFinding(
            rule=PolicyRule.REVIEWER_CONCERN,
            severity=severity,
            path="",
            evidence=concern,
            source="reviewer",
        )
        for concern in concerns
    ]
    opinion = ReviewerOpinion(
        status="completed",
        summary=summary,
        concerns=concerns,
        model=reported_model,
    )
    return opinion, extra


def _default_llm_call(prompt: str) -> str:
    """Call litellm the same way the dispute mediator does."""
    response = litellm.completion(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": PATCH_REVIEW_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        temperature=settings.llm_temperature,
        max_tokens=settings.llm_max_tokens,
        timeout=settings.llm_timeout_seconds,
    )
    content = response.choices[0].message.content
    if not isinstance(content, str):
        raise ValueError("reviewer response was empty")
    return content


def _parse_reviewer_output(raw: object) -> tuple[str, list[str]]:
    if not isinstance(raw, str):
        raise ValueError("reviewer output was not text")
    parsed = json.loads(_strip_fences(raw.strip()))
    if not isinstance(parsed, dict):
        raise ValueError("reviewer output was not a JSON object")
    summary = parsed.get("summary")
    concerns = parsed.get("concerns")
    if not isinstance(summary, str) or not isinstance(concerns, list):
        raise ValueError("reviewer output missing summary or concerns")
    if not all(isinstance(item, str) for item in concerns):
        raise ValueError("reviewer concerns were not strings")
    return summary.strip(), [item.strip() for item in concerns if item.strip()]


def _strip_fences(text: str) -> str:
    if not text.startswith("```"):
        return text
    newline = text.find("\n")
    if newline == -1:
        return text.strip("`").strip()
    body = text[newline + 1 :]
    stripped = body.rstrip()
    if stripped.endswith("```"):
        body = stripped[:-3]
    return body.strip()


def _trace_consistency(req: VerifyPatchRequest, diff_sha256: str) -> TraceConsistency:
    """Check agent-supplied spans against each other. Never changes outcome."""
    spans = req.otel_spans
    if not spans:
        return TraceConsistency(status="absent")

    checks: dict[str, bool] = {}
    if req.solver_agent_id is not None:
        checks["agent_id_matches"] = any(
            _span_attr(span, "agent.id") == req.solver_agent_id for span in spans
        )
    if req.bounty_id is not None:
        checks["root_task_matches"] = any(
            _span_attr(span, "agent.provenance.chain.root_task_id") == req.bounty_id
            for span in spans
        )
    checks["diff_hash_matches"] = any(
        _span_attr(span, "agent.output.hash.value") == diff_sha256 for span in spans
    )
    status = "consistent" if all(checks.values()) else "inconsistent"
    return TraceConsistency(status=status, checks=checks)


def _span_attr(span: object, key: str) -> object:
    if not isinstance(span, dict):
        return None
    attributes = span.get("attributes")
    if not isinstance(attributes, dict):
        return None
    return attributes.get(key)
