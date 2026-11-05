"""Behaviour that ran only on the production droplet before it was committed.

Caddy routes ``/mediator/guide`` to ``GET /guide``, so the guide must keep serving.
"""

from __future__ import annotations

import hashlib
import json

from fastapi.testclient import TestClient

from a2a_settlement_mediator.digest import verify_verification_artifacts
from a2a_settlement_mediator.webhook_listener import app


def _deliverable(raw: str, content_hash: str) -> str:
    return json.dumps(
        {"verification_artifacts": {"api_call_raw": raw, "content_hash": content_hash}}
    )


def test_guide_serves_bounty_design_guide():
    client = TestClient(app)
    response = client.get("/guide")
    assert response.status_code == 200
    body = response.json()
    assert body["format"] == "text/markdown"
    assert body["content"].strip()
    assert client.get("/health").json()["guide_url"] == body["public_url"]


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
