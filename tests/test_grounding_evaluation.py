"""Tests for ProvenanceVerifier._evaluate_grounding and grounding-aware verify."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from a2a_settlement_mediator.provenance import ProvenanceVerifier


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


NOW = datetime.now(timezone.utc)
ESCROW_CREATED = NOW - timedelta(hours=1)


class TestEvaluateGrounding:
    def test_strong_grounding(self):
        gm = {
            "chunks": [
                {"uri": "https://worldbank.org/gdp", "title": "WB"},
                {"uri": "https://imf.org/data", "title": "IMF"},
            ],
            "supports": [
                {
                    "segment": {"text": "GDP data", "start_index": 0, "end_index": 8},
                    "chunk_indices": [0, 1],
                }
            ],
            "search_queries": ["GDP data"],
            "coverage": 0.85,
        }
        result = ProvenanceVerifier._evaluate_grounding(gm, "GDP data is here")
        assert result["source_count"] == 2
        assert result["domain_count"] == 2
        assert result["coverage"] == 0.85
        assert result["confidence_boost"] == 0.15
        assert result["recommendation"] == "approve"
        assert "grounding_strong" in result["flags"]

    def test_adequate_grounding_single_domain(self):
        gm = {
            "chunks": [
                {"uri": "https://example.com/a", "title": "A"},
                {"uri": "https://example.com/b", "title": "B"},
            ],
            "supports": [],
            "coverage": 0.7,
        }
        result = ProvenanceVerifier._evaluate_grounding(gm, "test")
        assert result["domain_count"] == 1
        assert result["confidence_boost"] == 0.10
        assert result["recommendation"] == "approve"
        assert "grounding_adequate" in result["flags"]
        assert "grounding_single_domain" in result["flags"]

    def test_partial_grounding(self):
        gm = {
            "chunks": [{"uri": "https://a.com/x", "title": "X"}],
            "supports": [],
            "coverage": 0.35,
        }
        result = ProvenanceVerifier._evaluate_grounding(gm, "text")
        assert result["confidence_boost"] == 0.05
        assert "grounding_partial" in result["flags"]

    def test_weak_grounding(self):
        gm = {
            "chunks": [{"uri": "https://a.com/x", "title": "X"}],
            "supports": [],
            "coverage": 0.1,
        }
        result = ProvenanceVerifier._evaluate_grounding(gm, "text")
        assert result["confidence_boost"] == 0.0
        assert result["recommendation"] == "flag"
        assert "grounding_weak" in result["flags"]
        assert "grounding_low_coverage" in result["flags"]

    def test_no_chunks(self):
        gm = {"chunks": [], "supports": [], "coverage": 0.0}
        result = ProvenanceVerifier._evaluate_grounding(gm, "text")
        assert result["source_count"] == 0
        assert result["confidence_boost"] == 0.0
        assert "grounding_no_chunks" in result["flags"]

    def test_invalid_chunk_index_flagged(self):
        gm = {
            "chunks": [{"uri": "https://a.com/x", "title": "X"}],
            "supports": [
                {
                    "segment": {"text": "t", "start_index": 0, "end_index": 1},
                    "chunk_indices": [5],
                }
            ],
            "coverage": 0.6,
        }
        result = ProvenanceVerifier._evaluate_grounding(gm, "t")
        assert "grounding_invalid_chunk_index" in result["flags"]

    def test_coverage_computed_from_supports_when_missing(self):
        gm = {
            "chunks": [
                {"uri": "https://a.com", "title": "A"},
                {"uri": "https://b.com", "title": "B"},
            ],
            "supports": [
                {
                    "segment": {"text": "hello", "start_index": 0, "end_index": 5},
                    "chunk_indices": [0],
                }
            ],
        }
        content = "hello world"  # 11 chars, 5 covered
        result = ProvenanceVerifier._evaluate_grounding(gm, content)
        assert abs(result["coverage"] - 5 / 11) < 0.01


class TestGroundingIntegrationWithVerify:
    def test_grounding_boosts_self_declared_confidence(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "web",
            "source_refs": [
                {
                    "uri": "https://worldbank.org/gdp",
                    "timestamp": (NOW - timedelta(minutes=10)).isoformat(),
                }
            ],
            "attestation_level": "self_declared",
            "grounding_metadata": {
                "chunks": [
                    {"uri": "https://worldbank.org/gdp", "title": "WB"},
                    {"uri": "https://imf.org/data", "title": "IMF"},
                ],
                "supports": [
                    {
                        "segment": {"text": "GDP data", "start_index": 0, "end_index": 8},
                        "chunk_indices": [0, 1],
                    }
                ],
                "coverage": 0.9,
            },
        }
        result = _run(verifier.verify(provenance, "GDP data here", "self_declared"))
        assert result.confidence > 0.7
        assert any("grounding_strong" in f for f in result.flags)

    def test_no_grounding_metadata_unchanged(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "generated",
            "source_refs": [],
            "attestation_level": "self_declared",
        }
        result = _run(verifier.verify(provenance, "content", "self_declared"))
        assert not any("grounding" in f for f in result.flags)
