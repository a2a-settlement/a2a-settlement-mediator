"""Deliverable integrity checking and digest building for large-payload mediation.

When a deliverable's serialised evidence bundle exceeds the mediator's token
budget, it cannot be sent raw to the LLM without risking silent truncation and
false verdicts.  This module provides:

- ``estimate_tokens`` — fast char-count approximation (no tokeniser dependency)
- ``check_deliverable_integrity`` — structural validation before any LLM call
- ``build_digest`` — programmatic summary targeting 4-6 K tokens

All functions are pure (no I/O, no LLM calls) so they are cheap and testable.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Token estimation
# ---------------------------------------------------------------------------

_CHARS_PER_TOKEN = 4  # conservative approximation for JSON content


def estimate_tokens(text: str) -> int:
    """Estimate token count using a simple char-count heuristic.

    Accuracy is intentionally conservative: 1 token ≈ 4 characters for JSON.
    This avoids a tokeniser dependency while remaining safe for routing decisions.
    """
    return len(text) // _CHARS_PER_TOKEN


# ---------------------------------------------------------------------------
# Structural integrity check
# ---------------------------------------------------------------------------

_INTEGRITY_OK: dict[str, Any] = {"ok": True}


def check_deliverable_integrity(
    delivered_content: str | None,
    acceptance_criteria: str | None = None,
) -> dict[str, Any]:
    """Validate deliverable structure before any LLM evaluation.

    This runs on every deliverable regardless of size — it is fast (no LLM,
    no network) and catches provider-side failures early.

    Returns a dict with shape:
        {"ok": True}
    or:
        {"ok": False, "code": "<ERROR_CODE>", "reason": "<human-readable>"}

    Error codes:
    - ``DELIVERABLE_EMPTY`` — no content was submitted at all.
    - ``DELIVERABLE_MALFORMED`` — content appears to be JSON but fails to parse.
    - ``DELIVERABLE_SCHEMA_MISMATCH`` — parsed JSON is missing fields that the
      acceptance criteria explicitly require.

    Plaintext deliverables (content that does not start with ``{`` or ``[``)
    are not JSON-parsed; they pass this check as long as they are non-empty.
    """
    if not delivered_content or not delivered_content.strip():
        return {
            "ok": False,
            "code": "DELIVERABLE_EMPTY",
            "reason": "No deliverable content was submitted by the provider.",
        }

    stripped = delivered_content.strip()

    # Only attempt JSON parse when content looks like a JSON object/array
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return _INTEGRITY_OK

    try:
        parsed = json.loads(stripped)
    except json.JSONDecodeError as exc:
        return {
            "ok": False,
            "code": "DELIVERABLE_MALFORMED",
            "reason": f"Deliverable claimed to be JSON but failed to parse: {exc}",
        }

    # Schema compliance: best-effort check against acceptance criteria keywords
    if acceptance_criteria and isinstance(parsed, dict):
        missing = _find_missing_fields(parsed, acceptance_criteria)
        if missing:
            return {
                "ok": False,
                "code": "DELIVERABLE_SCHEMA_MISMATCH",
                "reason": (
                    f"Deliverable JSON is missing fields referenced in the "
                    f"acceptance criteria: {', '.join(missing)}"
                ),
            }

    return _INTEGRITY_OK


def _find_missing_fields(parsed: dict, acceptance_criteria: str) -> list[str]:
    """Return top-level keys mentioned in acceptance_criteria that are absent from parsed.

    Extracts quoted identifiers and snake_case/camelCase words from the
    acceptance criteria string and checks whether any are required top-level
    keys that are missing.  This is intentionally conservative: we only flag
    a mismatch when the evidence is clear (explicit field names in quotes).
    """
    top_keys = {k.lower() for k in parsed.keys()}

    # Extract quoted field names from acceptance criteria (e.g. "findings", 'summary')
    quoted = re.findall(r'["\']([a-zA-Z_][a-zA-Z0-9_]*)["\']', acceptance_criteria)
    missing = [f for f in quoted if f.lower() not in top_keys]
    return missing


# ---------------------------------------------------------------------------
# Verification artifact hash check
# ---------------------------------------------------------------------------


def verify_verification_artifacts(delivered_content: str | None) -> dict | None:
    """Programmatically verify sha256(api_call_raw) == content_hash.

    Many bounties (e.g. AlphaSignal ensemble forecasts) embed a raw API
    response string and a SHA-256 hash of that string inside a
    ``verification_artifacts`` object.  The LLM cannot recompute hashes, so
    it reports "cannot verify" and applies a confidence penalty.  This
    function does the check in pure Python before the LLM is called and
    returns a structured result for the evidence bundle.  The provider supplies
    both fields, so a match proves consistency, not that the response came from
    the endpoint; a mismatch is evidence of alteration.

    Looks for the following shape anywhere in the top-level deliverable JSON:

        {
          "verification_artifacts": {
            "api_call_raw": "<raw JSON-RPC response string>",
            "content_hash": "<64-char sha256 hex OR sha256:<hex>>",
            "endpoint_url": "<optional, for informational purposes>"
          }
        }

    Returns:
        A dict with keys ``hash_match`` (bool), ``field`` (str),
        ``expected`` (str), ``computed`` (str), and optionally
        ``endpoint_url`` (str) — or ``None`` if the required fields are
        absent (so callers can treat absence as neutral, not a failure).
    """
    if not delivered_content or not delivered_content.strip():
        return None

    try:
        parsed = json.loads(delivered_content.strip())
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(parsed, dict):
        return None

    artifacts = parsed.get("verification_artifacts")
    if not isinstance(artifacts, dict):
        return None

    raw_value = artifacts.get("api_call_raw")
    expected_hash = artifacts.get("content_hash")

    if not raw_value or not expected_hash:
        return None

    # Normalise: strip optional "sha256:" prefix so we always compare bare hex
    normalised_expected = expected_hash
    if normalised_expected.startswith("sha256:"):
        normalised_expected = normalised_expected[len("sha256:"):]

    computed_hex = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()
    match = computed_hex == normalised_expected

    result: dict = {
        "hash_match": match,
        "field": "api_call_raw",
        "expected": normalised_expected,
        "computed": computed_hex,
    }

    endpoint_url = artifacts.get("endpoint_url")
    if endpoint_url:
        result["endpoint_url"] = endpoint_url

    if not match:
        logger.warning(
            "verification_artifacts hash mismatch: expected=%s computed=%s",
            normalised_expected[:16] + "…",
            computed_hex[:16] + "…",
        )

    return result


# ---------------------------------------------------------------------------
# Digest builder
# ---------------------------------------------------------------------------

_MAX_SAMPLES_PER_SECTION = 3
_MAX_SAMPLE_STRING_CHARS = 400
_MAX_EVIDENCE_URLS = 10
_URL_PATTERN = re.compile(r'https?://[^\s"\'<>]+')


def build_digest(deliverable_str: str, acceptance_criteria: str | None = None) -> dict:
    """Build a structured digest of a large JSON deliverable for LLM evaluation.

    The digest is designed to fit within 4–6 K tokens so there is ample room
    in the LLM context window for the system prompt and evidence metadata.

    Args:
        deliverable_str: The raw deliverable string (must be valid JSON — call
            ``check_deliverable_integrity`` first).
        acceptance_criteria: The acceptance criteria string from the task, used
            to drive schema compliance reporting.

    Returns:
        A dict with keys: ``total_size_bytes``, ``structure``,
        ``schema_compliance``, ``sample_content``, ``evidence_check``.

    Raises:
        ValueError: If ``deliverable_str`` is not valid JSON.
    """
    try:
        deliverable: Any = json.loads(deliverable_str)
    except json.JSONDecodeError as exc:
        raise ValueError(f"build_digest requires valid JSON: {exc}") from exc

    total_size = len(deliverable_str.encode("utf-8"))

    if isinstance(deliverable, dict):
        top_level_keys = list(deliverable.keys())
        section_count = len(deliverable)
    elif isinstance(deliverable, list):
        top_level_keys = ["[array]"]
        section_count = 1
    else:
        top_level_keys = [type(deliverable).__name__]
        section_count = 1

    total_findings = _count_nested_items(deliverable)
    samples = _extract_samples(deliverable)
    evidence_urls = _extract_urls(deliverable_str)

    # Schema compliance
    if acceptance_criteria and isinstance(deliverable, dict):
        missing = _find_missing_fields(deliverable, acceptance_criteria)
        expected_present = [k for k in top_level_keys if k.lower() in acceptance_criteria.lower()]
    else:
        missing = []
        expected_present = top_level_keys

    return {
        "total_size_bytes": total_size,
        "structure": {
            "top_level_keys": top_level_keys,
            "section_count": section_count,
            "total_findings": total_findings,
        },
        "schema_compliance": {
            "expected_fields_present": expected_present,
            "missing_fields": missing,
        },
        "sample_content": {
            "samples": samples,
        },
        "evidence_check": {
            "total_evidence_urls": len(evidence_urls),
            "sample_urls": evidence_urls[:_MAX_EVIDENCE_URLS],
        },
    }


# ---------------------------------------------------------------------------
# Digest helpers
# ---------------------------------------------------------------------------


def _count_nested_items(obj: Any) -> int:
    """Count total items/findings nested within the deliverable structure.

    For dicts: sum the lengths of all list-valued top-level fields.
    For lists: return the list length.
    Falls back to 1 for scalar values.
    """
    if isinstance(obj, list):
        return len(obj)
    if isinstance(obj, dict):
        total = 0
        for v in obj.values():
            if isinstance(v, list):
                total += len(v)
            elif isinstance(v, dict):
                total += 1
        return total or len(obj)
    return 1


def _extract_samples(deliverable: Any) -> list[dict]:
    """Pull representative samples from each top-level section of the deliverable.

    For each section that contains a list, we take up to ``_MAX_SAMPLES_PER_SECTION``
    items and truncate long string values so the digest stays compact.
    """
    samples: list[dict] = []

    if isinstance(deliverable, list):
        for item in deliverable[:_MAX_SAMPLES_PER_SECTION]:
            samples.append({"section": "[root]", "item": _truncate_strings(item)})
        return samples

    if not isinstance(deliverable, dict):
        return samples

    for key, value in deliverable.items():
        if isinstance(value, list) and value:
            for item in value[:_MAX_SAMPLES_PER_SECTION]:
                samples.append({"section": key, "item": _truncate_strings(item)})
        elif isinstance(value, dict):
            samples.append({"section": key, "item": _truncate_strings(value)})
        # Skip scalars — they're captured in structure.top_level_keys

    return samples


def _truncate_strings(obj: Any, max_chars: int = _MAX_SAMPLE_STRING_CHARS) -> Any:
    """Recursively truncate long strings within a nested structure."""
    if isinstance(obj, str):
        return obj[:max_chars] + "…" if len(obj) > max_chars else obj
    if isinstance(obj, dict):
        return {k: _truncate_strings(v, max_chars) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_truncate_strings(item, max_chars) for item in obj]
    return obj


def _extract_urls(deliverable_str: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from the raw deliverable string.

    Uses a simple regex so we don't need to traverse the parsed structure
    looking for URL-shaped values across arbitrary nesting.
    """
    seen: set[str] = set()
    urls: list[str] = []
    for url in _URL_PATTERN.findall(deliverable_str):
        # Strip trailing punctuation that regex might capture
        url = url.rstrip(".,;:)")
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls
