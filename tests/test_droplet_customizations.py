"""Behaviour that ran only on the production droplet before it was committed.

Caddy routes ``/mediator/guide`` to ``GET /guide``, so the guide must keep serving.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

from a2a_settlement_mediator import provenance as provenance_module
from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.digest import verify_verification_artifacts
from a2a_settlement_mediator.prompts import build_evaluation_prompt
from a2a_settlement_mediator.provenance import ProvenanceVerifier
from a2a_settlement_mediator.webhook_listener import app

NOW = datetime.now(timezone.utc)

_STRONG_GROUNDING = {
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
}


def _deliverable(raw: str, content_hash: str) -> str:
    return json.dumps(
        {"verification_artifacts": {"api_call_raw": raw, "content_hash": content_hash}}
    )


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@pytest.fixture
def endpoint_status(monkeypatch):
    """Answer every provenance HTTP call with the given status, without network."""

    def install(status: int) -> None:
        transport = httpx.MockTransport(lambda request: httpx.Response(status, content=b"{}"))
        real_client = httpx.AsyncClient

        def client(*args, **kwargs):
            kwargs["transport"] = transport
            return real_client(*args, **kwargs)

        monkeypatch.setattr(provenance_module.httpx, "AsyncClient", client)

    return install


def _verifiable(grounding: dict | None = None) -> dict:
    provenance = {
        "source_type": "api",
        "source_refs": [
            {
                "uri": "https://provider.example.com/api/a2a/forecast",
                "timestamp": (NOW - timedelta(minutes=5)).isoformat(),
            }
        ],
        "attestation_level": "verifiable",
    }
    if grounding is not None:
        provenance["grounding_metadata"] = grounding
    return provenance


def test_guide_serves_bounty_design_guide():
    client = TestClient(app)
    response = client.get("/guide")
    assert response.status_code == 200
    body = response.json()
    assert body["format"] == "text/markdown"
    assert body["content"].strip()
    assert client.get("/health").json()["guide_url"] == body["public_url"]


def test_guide_url_comes_from_public_url(monkeypatch):
    client = TestClient(app)
    monkeypatch.setattr(settings, "public_url", "")
    assert client.get("/health").json()["guide_url"] == "/guide"
    monkeypatch.setattr(settings, "public_url", "https://mediator.example.org/prefix")
    assert client.get("/health").json()["guide_url"] == "https://mediator.example.org/prefix/guide"
    assert client.get("/guide").json()["public_url"] == "https://mediator.example.org/prefix/guide"


def test_hash_check_accepts_prefixed_and_bare_hex():
    raw = '{"jsonrpc":"2.0","result":1}'
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    assert verify_verification_artifacts(_deliverable(raw, digest))["hash_match"] is True
    prefixed = verify_verification_artifacts(_deliverable(raw, f"sha256:{digest}"))
    assert prefixed["hash_match"] is True


def test_hash_check_reports_mismatch():
    result = verify_verification_artifacts(_deliverable("altered", "0" * 64))
    assert result["hash_match"] is False
    assert result["expected"] == "0" * 64


def test_hash_check_is_neutral_without_artifacts():
    assert verify_verification_artifacts(json.dumps({"answer": 42})) is None
    assert verify_verification_artifacts("not json") is None
    assert verify_verification_artifacts(None) is None


def test_hash_match_is_not_presented_as_authenticity():
    prompt = build_evaluation_prompt(
        "{}", hash_verification_result={"hash_match": True, "field": "api_call_raw"}
    )
    assert "internally consistent" in prompt
    assert "does not show that the response came from" in prompt
    assert "cryptographically verified" not in prompt
    assert "Do not penalise" not in prompt


def test_hash_mismatch_is_a_warning():
    prompt = build_evaluation_prompt(
        "{}", hash_verification_result={"hash_match": False, "field": "api_call_raw"}
    )
    assert "does NOT match" in prompt


@pytest.mark.parametrize("status", [401, 403])
def test_tier3_auth_gated_source_is_not_verified(endpoint_status, status):
    endpoint_status(status)
    result = _run(ProvenanceVerifier().verify_verifiable(_verifiable(), "content"))
    assert result.verified is False
    assert result.recommendation == "flag"
    assert any(f.startswith("endpoint_auth_required") for f in result.flags)
    assert "tier_mismatch:auth_gated_source_use_signed_tier" in result.flags


def test_tier3_other_client_errors_still_reject(endpoint_status):
    endpoint_status(404)
    result = _run(ProvenanceVerifier().verify_verifiable(_verifiable(), "content"))
    assert result.verified is False
    assert result.recommendation == "reject"


def test_tier3_public_source_still_verifies(endpoint_status):
    endpoint_status(200)
    result = _run(ProvenanceVerifier().verify_verifiable(_verifiable(), "content"))
    assert result.verified is True
    assert result.recommendation == "approve"


def test_grounding_cannot_upgrade_unverified_provenance(endpoint_status):
    endpoint_status(401)
    result = _run(
        ProvenanceVerifier().verify(
            _verifiable(_STRONG_GROUNDING), "GDP data here", "verifiable"
        )
    )
    assert result.verified is False
    assert result.recommendation == "flag"
