"""Tests for the ProvenanceVerifier."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from a2a_settlement_mediator.provenance import ProvenanceVerifier
from a2a_settlement_mediator.schemas import ProvenanceResult


def _run(coro):
    """Helper to run an async coroutine in tests."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


NOW = datetime.now(timezone.utc)
ESCROW_CREATED = NOW - timedelta(hours=1)


class TestVerifySelfDeclared:
    def test_valid_api_provenance(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "api",
            "source_refs": [
                {
                    "uri": "https://api.github.com/repos/org/repo/commits",
                    "method": "GET",
                    "timestamp": (NOW - timedelta(minutes=30)).isoformat(),
                }
            ],
            "attestation_level": "self_declared",
        }
        result = _run(verifier.verify_self_declared(provenance, "some content", ESCROW_CREATED))
        assert result.verified is True
        assert result.confidence >= 0.7
        assert result.recommendation == "approve"
        assert result.flags == []

    def test_missing_source_refs_for_api(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "api",
            "source_refs": [],
            "attestation_level": "self_declared",
        }
        result = _run(verifier.verify_self_declared(provenance, "content", ESCROW_CREATED))
        assert "missing_source_refs" in result.flags

    def test_generated_type_no_sources_ok(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "generated",
            "source_refs": [],
            "attestation_level": "self_declared",
        }
        result = _run(
            verifier.verify_self_declared(
                provenance,
                "generated content",
                ESCROW_CREATED,
            )
        )
        assert result.verified is True
        assert result.recommendation == "approve"

    def test_generated_with_sources_flagged(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "generated",
            "source_refs": [{"uri": "https://example.com/data", "timestamp": NOW.isoformat()}],
            "attestation_level": "self_declared",
        }
        result = _run(verifier.verify_self_declared(provenance, "content", ESCROW_CREATED))
        assert "generated_with_sources" in result.flags

    def test_invalid_uri_detected(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "api",
            "source_refs": [
                {"uri": "not-a-valid-url", "timestamp": NOW.isoformat()},
                {"uri": "ftp://invalid.scheme", "timestamp": NOW.isoformat()},
            ],
            "attestation_level": "self_declared",
        }
        result = _run(verifier.verify_self_declared(provenance, "content", ESCROW_CREATED))
        assert result.verified is False
        assert result.recommendation == "reject"
        invalid_flags = [f for f in result.flags if f.startswith("invalid_uri")]
        assert len(invalid_flags) == 2

    def test_future_timestamp_flagged(self):
        verifier = ProvenanceVerifier()
        future = NOW + timedelta(hours=2)
        provenance = {
            "source_type": "api",
            "source_refs": [
                {"uri": "https://api.example.com/data", "timestamp": future.isoformat()}
            ],
            "attestation_level": "self_declared",
        }
        result = _run(verifier.verify_self_declared(provenance, "content", ESCROW_CREATED))
        assert "timestamp_future" in result.flags

    def test_old_timestamp_flagged(self):
        verifier = ProvenanceVerifier()
        old = ESCROW_CREATED - timedelta(days=10)
        provenance = {
            "source_type": "api",
            "source_refs": [{"uri": "https://api.example.com/data", "timestamp": old.isoformat()}],
            "attestation_level": "self_declared",
        }
        result = _run(verifier.verify_self_declared(provenance, "content", ESCROW_CREATED))
        assert "timestamp_too_old" in result.flags


class TestVerifySigned:
    def test_valid_signed_provenance(self):
        verifier = ProvenanceVerifier(spot_check_rate=0.0)
        provenance = {
            "source_type": "api",
            "source_refs": [
                {
                    "uri": "https://api.github.com/repos/org/repo/commits",
                    "method": "GET",
                    "timestamp": (NOW - timedelta(minutes=30)).isoformat(),
                    "content_hash": "sha256:a1b2c3d4e5f6",
                }
            ],
            "attestation_level": "signed",
            "signature": "x-request-id-abc123",
        }
        result = _run(verifier.verify_signed(provenance, "content", ESCROW_CREATED))
        assert result.verified is True
        assert result.confidence >= 0.8
        assert result.recommendation == "approve"

    def test_missing_signature_rejected(self):
        verifier = ProvenanceVerifier(spot_check_rate=0.0)
        provenance = {
            "source_type": "api",
            "source_refs": [
                {
                    "uri": "https://api.github.com/repos/org/repo",
                    "timestamp": NOW.isoformat(),
                }
            ],
            "attestation_level": "signed",
        }
        result = _run(verifier.verify_signed(provenance, "content", ESCROW_CREATED))
        assert result.verified is False
        assert "missing_signature" in result.flags
        assert result.recommendation == "reject"

    def test_invalid_hash_format_flagged(self):
        verifier = ProvenanceVerifier(spot_check_rate=0.0)
        provenance = {
            "source_type": "api",
            "source_refs": [
                {
                    "uri": "https://api.example.com/data",
                    "timestamp": NOW.isoformat(),
                    "content_hash": "bad-hash-format",
                }
            ],
            "attestation_level": "signed",
            "signature": "sig123",
        }
        result = _run(verifier.verify_signed(provenance, "content", ESCROW_CREATED))
        assert any(f.startswith("invalid_hash_format") for f in result.flags)


class TestVerifyVerifiable:
    def test_no_source_refs_rejected(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "api",
            "source_refs": [],
            "attestation_level": "verifiable",
        }
        result = _run(verifier.verify_verifiable(provenance, "content", ESCROW_CREATED))
        assert result.verified is False
        assert result.recommendation == "reject"

    def test_invalid_uri_flagged(self):
        verifier = ProvenanceVerifier()
        provenance = {
            "source_type": "api",
            "source_refs": [{"uri": "not-a-url", "timestamp": NOW.isoformat()}],
            "attestation_level": "verifiable",
        }
        result = _run(verifier.verify_verifiable(provenance, "content", ESCROW_CREATED))
        assert any(f.startswith("invalid_uri") for f in result.flags)


class TestVerifyDispatch:
    def test_dispatches_to_correct_tier(self):
        verifier = ProvenanceVerifier(spot_check_rate=0.0)
        provenance = {
            "source_type": "generated",
            "source_refs": [],
            "attestation_level": "self_declared",
        }

        result = _run(verifier.verify(provenance, None, "self_declared"))
        assert result.tier == "self_declared"


class TestHelpers:
    def test_validate_uri(self):
        assert ProvenanceVerifier._validate_uri("https://api.github.com/repos") is True
        assert ProvenanceVerifier._validate_uri("http://localhost:3000") is True
        assert ProvenanceVerifier._validate_uri("ftp://invalid") is False
        assert ProvenanceVerifier._validate_uri("not-a-url") is False
        assert ProvenanceVerifier._validate_uri("") is False

    def test_validate_content_hash_format(self):
        assert ProvenanceVerifier._validate_content_hash_format("sha256:a1b2c3") is True
        assert ProvenanceVerifier._validate_content_hash_format("sha512:deadbeef") is True
        assert ProvenanceVerifier._validate_content_hash_format("bad-format") is False
        assert ProvenanceVerifier._validate_content_hash_format("sha256:not-hex!") is False
        assert ProvenanceVerifier._validate_content_hash_format("unknown:abc") is False

    def test_timestamp_plausibility_future(self):
        future = (NOW + timedelta(hours=1)).isoformat()
        result = ProvenanceVerifier._check_timestamp_plausibility(
            future,
            ESCROW_CREATED,
        )
        assert result == "timestamp_future"

    def test_timestamp_plausibility_ok(self):
        recent = (NOW - timedelta(minutes=10)).isoformat()
        result = ProvenanceVerifier._check_timestamp_plausibility(
            recent,
            ESCROW_CREATED,
        )
        assert result is None

    def test_timestamp_plausibility_too_old(self):
        old = (ESCROW_CREATED - timedelta(days=10)).isoformat()
        result = ProvenanceVerifier._check_timestamp_plausibility(
            old,
            ESCROW_CREATED,
        )
        assert result == "timestamp_too_old"

    def test_timestamp_plausibility_unparseable(self):
        result = ProvenanceVerifier._check_timestamp_plausibility(
            "not-a-date",
            ESCROW_CREATED,
        )
        assert result == "timestamp_unparseable"


class TestProvenanceResultModel:
    def test_basic_construction(self):
        r = ProvenanceResult(
            verified=True,
            tier="self_declared",
            confidence=0.8,
            flags=[],
            recommendation="approve",
        )
        assert r.verified is True
        assert r.tier == "self_declared"

    def test_serialization(self):
        r = ProvenanceResult(
            verified=False,
            tier="signed",
            confidence=0.3,
            flags=["missing_signature", "endpoint_unreachable:https://api.example.com"],
            recommendation="reject",
        )
        data = r.model_dump()
        assert data["verified"] is False
        assert data["tier"] == "signed"
        assert len(data["flags"]) == 2
