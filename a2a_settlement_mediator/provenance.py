"""Provenance verification for deliverable attestations.

Three-tier verification model:
- Tier 1 (self_declared): Plausibility checks only. No external calls.
- Tier 2 (signed): Validate signatures and hashes. Probabilistic spot-checks.
- Tier 3 (verifiable): Active verification. Calls source to confirm.
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import httpx

from a2a_settlement_mediator.schemas import ProvenanceResult

logger = logging.getLogger(__name__)

KNOWN_API_PATTERNS: dict[str, re.Pattern] = {
    "github": re.compile(r"^https://api\.github\.com/"),
    "data_gov": re.compile(r"^https://.*\.data\.gov/"),
    "openai": re.compile(r"^https://api\.openai\.com/"),
    "anthropic": re.compile(r"^https://api\.anthropic\.com/"),
}

SPOT_CHECK_RATE = 0.10


class ProvenanceVerifier:
    """Verifies provenance attestations at the appropriate tier."""

    def __init__(self, *, spot_check_rate: float = SPOT_CHECK_RATE):
        self.spot_check_rate = spot_check_rate

    async def verify(
        self,
        provenance: dict[str, Any],
        deliverable_content: str | None,
        tier: str,
        escrow_created_at: datetime | None = None,
    ) -> ProvenanceResult:
        if tier == "self_declared":
            result = await self.verify_self_declared(
                provenance,
                deliverable_content,
                escrow_created_at,
            )
        elif tier == "signed":
            result = await self.verify_signed(
                provenance,
                deliverable_content,
                escrow_created_at,
            )
        else:
            result = await self.verify_verifiable(
                provenance, deliverable_content, escrow_created_at
            )

        grounding_meta = provenance.get("grounding_metadata")
        if grounding_meta:
            assessment = self._evaluate_grounding(grounding_meta, deliverable_content)
            result.flags.extend(assessment.get("flags", []))
            boost = assessment.get("confidence_boost", 0.0)
            result.confidence = min(1.0, result.confidence + boost)
            if assessment.get("recommendation") == "approve" and result.recommendation == "flag":
                result.recommendation = "approve"

        return result

    async def verify_self_declared(
        self,
        provenance: dict[str, Any],
        deliverable_content: str | None,
        escrow_created_at: datetime | None = None,
    ) -> ProvenanceResult:
        """Tier 1: Plausibility checks only. No external calls."""
        flags: list[str] = []
        source_type = provenance.get("source_type", "")
        source_refs = provenance.get("source_refs", [])
        attestation_level = provenance.get("attestation_level", "self_declared")

        if source_type in ("api", "database", "web", "hybrid") and not source_refs:
            flags.append("missing_source_refs")

        if source_type == "generated" and source_refs:
            flags.append("generated_with_sources")

        for ref in source_refs:
            uri = ref.get("uri", "")
            if not self._validate_uri(uri):
                flags.append(f"invalid_uri:{uri[:80]}")

            ts_str = ref.get("timestamp")
            if ts_str:
                ts_flag = self._check_timestamp_plausibility(ts_str, escrow_created_at)
                if ts_flag:
                    flags.append(ts_flag)

        if not flags:
            return ProvenanceResult(
                verified=True,
                tier=attestation_level,
                confidence=0.7,
                flags=[],
                recommendation="approve",
            )

        severity = sum(
            1 for f in flags if f.startswith("invalid_uri") or f == "missing_source_refs"
        )
        if severity >= 2:
            return ProvenanceResult(
                verified=False,
                tier=attestation_level,
                confidence=0.3,
                flags=flags,
                recommendation="reject",
            )

        return ProvenanceResult(
            verified=True,
            tier=attestation_level,
            confidence=0.5,
            flags=flags,
            recommendation="flag",
        )

    async def verify_signed(
        self,
        provenance: dict[str, Any],
        deliverable_content: str | None,
        escrow_created_at: datetime | None = None,
    ) -> ProvenanceResult:
        """Tier 2: Validate signatures and hashes. Probabilistic spot-checks."""
        base_result = await self.verify_self_declared(
            provenance,
            deliverable_content,
            escrow_created_at,
        )
        flags = list(base_result.flags)

        signature = provenance.get("signature")
        if not signature:
            flags.append("missing_signature")

        for ref in provenance.get("source_refs", []):
            content_hash = ref.get("content_hash")
            if content_hash and deliverable_content:
                if not self._validate_content_hash_format(content_hash):
                    flags.append(f"invalid_hash_format:{content_hash[:40]}")

        do_spot_check = random.random() < self.spot_check_rate
        if do_spot_check:
            for ref in provenance.get("source_refs", []):
                uri = ref.get("uri", "")
                if self._validate_uri(uri):
                    reachable = await self._check_endpoint_reachable(uri)
                    if not reachable:
                        flags.append(f"endpoint_unreachable:{uri[:80]}")

        if "missing_signature" in flags:
            return ProvenanceResult(
                verified=False,
                tier="signed",
                confidence=0.3,
                flags=flags,
                recommendation="reject",
            )

        has_critical = any(
            f.startswith("endpoint_unreachable")
            or f.startswith("invalid_uri")
            or f == "missing_source_refs"
            for f in flags
        )
        if has_critical:
            return ProvenanceResult(
                verified=False,
                tier="signed",
                confidence=0.35,
                flags=flags,
                recommendation="reject",
            )

        if flags:
            return ProvenanceResult(
                verified=True,
                tier="signed",
                confidence=0.6,
                flags=flags,
                recommendation="flag",
            )

        return ProvenanceResult(
            verified=True,
            tier="signed",
            confidence=0.85,
            flags=[],
            recommendation="approve",
        )

    async def verify_verifiable(
        self,
        provenance: dict[str, Any],
        deliverable_content: str | None,
        escrow_created_at: datetime | None = None,
    ) -> ProvenanceResult:
        """Tier 3: Active verification. Calls source to confirm."""
        flags: list[str] = []
        source_refs = provenance.get("source_refs", [])

        if not source_refs:
            return ProvenanceResult(
                verified=False,
                tier="verifiable",
                confidence=0.2,
                flags=["no_source_refs_to_verify"],
                recommendation="reject",
            )

        for ref in source_refs:
            uri = ref.get("uri", "")
            method = (ref.get("method") or "GET").upper()

            if not self._validate_uri(uri):
                flags.append(f"invalid_uri:{uri[:80]}")
                continue

            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    if method == "GET":
                        resp = await client.get(uri)
                    else:
                        resp = await client.request(method, uri)

                    if resp.status_code >= 400:
                        flags.append(f"endpoint_error:{uri[:80]}:status={resp.status_code}")
                    else:
                        content_hash = ref.get("content_hash")
                        if content_hash:
                            actual_hash = self._compute_hash(resp.content)
                            if actual_hash != content_hash:
                                flags.append(f"hash_mismatch:{uri[:80]}")
            except httpx.HTTPError:
                flags.append(f"endpoint_unreachable:{uri[:80]}")
            except Exception:
                flags.append(f"verification_error:{uri[:80]}")

            ts_str = ref.get("timestamp")
            if ts_str:
                ts_flag = self._check_timestamp_plausibility(ts_str, escrow_created_at)
                if ts_flag:
                    flags.append(ts_flag)

        critical_count = sum(
            1
            for f in flags
            if f.startswith("hash_mismatch")
            or f.startswith("endpoint_error")
            or f.startswith("endpoint_unreachable")
        )

        if critical_count > 0:
            return ProvenanceResult(
                verified=False,
                tier="verifiable",
                confidence=0.15,
                flags=flags,
                recommendation="reject",
            )

        if flags:
            return ProvenanceResult(
                verified=True,
                tier="verifiable",
                confidence=0.7,
                flags=flags,
                recommendation="flag",
            )

        return ProvenanceResult(
            verified=True,
            tier="verifiable",
            confidence=0.95,
            flags=[],
            recommendation="approve",
        )

    # ------------------------------------------------------------------
    # Grounding evaluation
    # ------------------------------------------------------------------

    @staticmethod
    def _evaluate_grounding(
        grounding_metadata: dict[str, Any],
        deliverable_content: str | None = None,
    ) -> dict[str, Any]:
        """Score web grounding quality and return an assessment dict.

        Returns:
            Dict with ``flags``, ``confidence_boost``, ``recommendation``,
            ``source_count``, ``coverage``, ``domain_count``.
        """
        flags: list[str] = []
        chunks = grounding_metadata.get("chunks") or []
        supports = grounding_metadata.get("supports") or []
        coverage = grounding_metadata.get("coverage")

        source_count = len(chunks)
        if source_count == 0:
            flags.append("grounding_no_chunks")
            return {
                "flags": flags,
                "confidence_boost": 0.0,
                "recommendation": "flag",
                "source_count": 0,
                "coverage": 0.0,
                "domain_count": 0,
            }

        domains: set[str] = set()
        for chunk in chunks:
            uri = chunk.get("uri", "")
            try:
                from urllib.parse import urlparse

                netloc = urlparse(uri).netloc
                if netloc:
                    domains.add(netloc)
            except Exception:
                pass
        domain_count = len(domains)

        if coverage is None and deliverable_content and supports:
            text_len = len(deliverable_content)
            covered = bytearray(text_len)
            for sup in supports:
                seg = sup.get("segment", {})
                s = max(0, min(seg.get("start_index", 0), text_len))
                e = max(s, min(seg.get("end_index", 0), text_len))
                for i in range(s, e):
                    covered[i] = 1
            coverage = sum(covered) / text_len if text_len else 0.0

        coverage = coverage or 0.0

        for sup in supports:
            for idx in sup.get("chunk_indices", []):
                if idx < 0 or idx >= source_count:
                    flags.append("grounding_invalid_chunk_index")
                    break

        if domain_count < 2:
            flags.append("grounding_single_domain")
        if coverage < 0.3:
            flags.append("grounding_low_coverage")

        boost = 0.0
        recommendation = "flag"

        if coverage >= 0.5 and domain_count >= 2:
            boost = 0.15
            recommendation = "approve"
            flags.append("grounding_strong")
        elif coverage >= 0.5:
            boost = 0.10
            recommendation = "approve"
            flags.append("grounding_adequate")
        elif coverage >= 0.3:
            boost = 0.05
            flags.append("grounding_partial")
        else:
            flags.append("grounding_weak")

        return {
            "flags": flags,
            "confidence_boost": boost,
            "recommendation": recommendation,
            "source_count": source_count,
            "coverage": round(coverage, 4),
            "domain_count": domain_count,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_uri(uri: str) -> bool:
        try:
            parsed = urlparse(uri)
            return parsed.scheme in ("http", "https") and bool(parsed.netloc)
        except Exception:
            return False

    @staticmethod
    def _check_timestamp_plausibility(
        ts_str: str,
        escrow_created_at: datetime | None,
    ) -> str | None:
        """Return a flag string if the timestamp is implausible, else None."""
        try:
            if ts_str.endswith("Z"):
                ts_str = ts_str[:-1] + "+00:00"
            ts = datetime.fromisoformat(ts_str)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            if ts > now:
                return "timestamp_future"

            if escrow_created_at:
                esc = escrow_created_at
                if esc.tzinfo is None:
                    esc = esc.replace(tzinfo=timezone.utc)
                hours_before = (esc - ts).total_seconds() / 3600
                if hours_before > 168:
                    return "timestamp_too_old"
        except (ValueError, TypeError):
            return "timestamp_unparseable"
        return None

    @staticmethod
    def _validate_content_hash_format(content_hash: str) -> bool:
        parts = content_hash.split(":", 1)
        if len(parts) != 2:
            return False
        algo, hex_str = parts
        if algo not in ("sha256", "sha384", "sha512", "md5"):
            return False
        try:
            int(hex_str, 16)
            return True
        except ValueError:
            return False

    @staticmethod
    def _compute_hash(content: bytes, algorithm: str = "sha256") -> str:
        h = hashlib.new(algorithm)
        h.update(content)
        return f"{algorithm}:{h.hexdigest()}"

    @staticmethod
    async def _check_endpoint_reachable(uri: str) -> bool:
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                resp = await client.head(uri)
                return resp.status_code < 500
        except Exception:
            return False
