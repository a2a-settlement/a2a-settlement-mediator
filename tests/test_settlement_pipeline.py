"""Tests for the SEC 17a-4 WORM-compliant settlement pipeline.

Covers:
- Merkle Tree correctness (append, proof, verify, edge cases)
- RFC 3161 DER encoding and TSA client behaviour
- Arbitration prompt construction
- Full pipeline: APPROVED path → proof, REJECTED path → no proof
- Hard-fail semantics: TSA timeout, Merkle verification failure
"""

from __future__ import annotations

import base64
import hashlib
import json
from unittest.mock import MagicMock, patch

import pytest

from a2a_settlement_mediator.merkle import MerkleTree
from a2a_settlement_mediator.settlement_pipeline import (
    IngestionLimitExceeded,
    SettlementHardFail,
    _build_attestation_payload,
    _call_arbitration_llm,
    _confirmed_settlements,
    _validate_ingestion,
    get_pending_settlements,
    mark_executed,
    mark_failed,
    settle,
)
from a2a_settlement_mediator.tsa_client import (
    RFC3161Client,
    TSAClientError,
    TSATimeoutError,
    build_timestamp_request,
    parse_timestamp_response_status,
)
from a2a_settlement_mediator.worm_schemas import (
    AgentIdentity,
    AP2Mandate,
    ArbitrationDecision,
    ArbitrationRequest,
    ArbitrationVerdict,
    CurrencyPrecision,
    ExecutionStatus,
    MerkleLeafPayload,
    NegotiationTranscript,
    PreDisputeAttestationPayload,
    SCHEMA_VERSION,
    SettlementResult,
    SettlementStage,
    TimestampToken,
    export_json_schemas,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_transcript():
    return NegotiationTranscript(
        transcript_hash="a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
        source_service="crewai",
        session_id="session-001",
    )


@pytest.fixture
def sample_mandates():
    return [
        AP2Mandate(
            mandate_id="M-001",
            description="Provider must deliver signed artifacts within 24 hours",
            conditions=["artifact_hash_present", "delivery_within_sla"],
            severity="critical",
        ),
        AP2Mandate(
            mandate_id="M-002",
            description="Both parties acknowledge escrow terms",
            conditions=["mutual_acknowledgement"],
            severity="standard",
        ),
    ]


@pytest.fixture
def sample_verdict():
    return ArbitrationVerdict(
        decision=ArbitrationDecision.APPROVED,
        confidence=0.92,
        reasoning="All critical mandates are feasible and consistent.",
        factors=["clear_conditions", "mutual_assent"],
        mandate_compliance={"M-001": True, "M-002": True},
        llm_model="test-model",
        prompt_tokens=500,
        completion_tokens=120,
        latency_ms=850,
    )


@pytest.fixture
def sample_timestamp():
    return TimestampToken(
        tsa_url="http://freetsa.org/tsr",
        hash_algorithm="sha256",
        message_hash="abcd" * 16,
        timestamp_token_b64=base64.b64encode(b"mock-tsa-response").decode(),
        serial_number="12345",
    )


@pytest.fixture
def sample_agent_identities():
    return [
        AgentIdentity(agent_id="agent-buyer-001", role="buyer"),
        AgentIdentity(agent_id="agent-seller-002", role="seller"),
    ]


@pytest.fixture
def sample_currency_precision():
    return CurrencyPrecision(currency_code="USD", decimal_places=2)


def _make_approved_llm_response() -> dict:
    return {
        "decision": "APPROVED",
        "confidence": 0.92,
        "reasoning": "All critical mandates are feasible and consistent.",
        "factors": ["clear_conditions", "mutual_assent"],
        "mandate_compliance": {"M-001": True, "M-002": True},
    }


def _make_rejected_llm_response() -> dict:
    return {
        "decision": "REJECTED",
        "confidence": 0.88,
        "reasoning": "Mandate M-001 references impossible deliverable.",
        "factors": ["impossible_condition"],
        "mandate_compliance": {"M-001": False, "M-002": True},
    }


# ---------------------------------------------------------------------------
# Merkle Tree tests
# ---------------------------------------------------------------------------


class TestMerkleTree:
    def test_empty_tree_has_deterministic_root(self):
        tree = MerkleTree()
        assert tree.root_hash == hashlib.sha256(b"").digest()
        assert tree.size == 0

    def test_single_leaf(self):
        tree = MerkleTree()
        idx, leaf_hash = tree.append(b"hello")
        assert idx == 0
        assert tree.size == 1
        assert tree.root_hash == leaf_hash

    def test_two_leaves(self):
        tree = MerkleTree()
        _, h0 = tree.append(b"leaf-0")
        _, h1 = tree.append(b"leaf-1")
        expected_root = MerkleTree.hash_node(h0, h1)
        assert tree.root_hash == expected_root

    def test_three_leaves(self):
        tree = MerkleTree()
        _, h0 = tree.append(b"a")
        _, h1 = tree.append(b"b")
        _, h2 = tree.append(b"c")
        left = MerkleTree.hash_node(h0, h1)
        expected_root = MerkleTree.hash_node(left, h2)
        assert tree.root_hash == expected_root

    def test_proof_single_leaf(self):
        tree = MerkleTree()
        _, leaf_hash = tree.append(b"only")
        siblings, directions = tree.get_proof(0)
        assert siblings == []
        assert directions == []
        assert MerkleTree.verify_proof(leaf_hash, siblings, directions, tree.root_hash)

    def test_proof_two_leaves_left(self):
        tree = MerkleTree()
        _, h0 = tree.append(b"L")
        _, h1 = tree.append(b"R")
        siblings, directions = tree.get_proof(0)
        assert len(siblings) == 1
        assert directions == ["right"]
        assert siblings[0] == h1
        assert MerkleTree.verify_proof(h0, siblings, directions, tree.root_hash)

    def test_proof_two_leaves_right(self):
        tree = MerkleTree()
        _, h0 = tree.append(b"L")
        _, h1 = tree.append(b"R")
        siblings, directions = tree.get_proof(1)
        assert len(siblings) == 1
        assert directions == ["left"]
        assert siblings[0] == h0
        assert MerkleTree.verify_proof(h1, siblings, directions, tree.root_hash)

    def test_proof_four_leaves_all_valid(self):
        tree = MerkleTree()
        hashes = []
        for i in range(4):
            _, h = tree.append(f"leaf-{i}".encode())
            hashes.append(h)

        root = tree.root_hash
        for i in range(4):
            siblings, directions = tree.get_proof(i)
            assert MerkleTree.verify_proof(
                hashes[i], siblings, directions, root
            ), f"Proof failed for leaf {i}"

    def test_proof_invalid_with_wrong_root(self):
        tree = MerkleTree()
        _, h0 = tree.append(b"data")
        tree.append(b"other")
        siblings, directions = tree.get_proof(0)
        fake_root = b"\x00" * 32
        assert not MerkleTree.verify_proof(h0, siblings, directions, fake_root)

    def test_proof_out_of_range_raises(self):
        tree = MerkleTree()
        tree.append(b"x")
        with pytest.raises(IndexError):
            tree.get_proof(1)
        with pytest.raises(IndexError):
            tree.get_proof(-1)

    def test_append_and_prove_atomic(self):
        tree = MerkleTree()
        tree.append(b"first")

        idx, leaf_hash, siblings, directions, root = tree.append_and_prove(b"second")
        assert idx == 1
        assert tree.size == 2
        assert root == tree.root_hash
        assert MerkleTree.verify_proof(leaf_hash, siblings, directions, root)

    def test_domain_separation(self):
        """Leaf hash and node hash of the same input must differ."""
        data = b"test"
        leaf_h = MerkleTree.hash_leaf(data)
        node_h = MerkleTree.hash_node(data, data)
        assert leaf_h != node_h

    def test_many_leaves_all_proofs_valid(self):
        tree = MerkleTree()
        hashes = []
        for i in range(17):
            _, h = tree.append(f"record-{i}".encode())
            hashes.append(h)

        root = tree.root_hash
        for i in range(17):
            siblings, directions = tree.get_proof(i)
            assert MerkleTree.verify_proof(hashes[i], siblings, directions, root)


# ---------------------------------------------------------------------------
# RFC 3161 DER encoding tests
# ---------------------------------------------------------------------------


class TestRFC3161DER:
    def test_timestamp_request_starts_with_sequence(self):
        h = hashlib.sha256(b"test data").digest()
        req = build_timestamp_request(h)
        assert req[0] == 0x30  # SEQUENCE tag

    def test_timestamp_request_contains_hash(self):
        h = hashlib.sha256(b"test data").digest()
        req = build_timestamp_request(h)
        assert h in req

    def test_timestamp_request_with_nonce(self):
        h = hashlib.sha256(b"test").digest()
        req1 = build_timestamp_request(h, nonce=42)
        req2 = build_timestamp_request(h, nonce=9999)
        assert req1 != req2

    def test_parse_granted_status(self):
        """Minimal DER: SEQUENCE { SEQUENCE { INTEGER 0 } }"""
        # Outer SEQUENCE(inner_seq), inner SEQUENCE(integer_0)
        integer_0 = b"\x02\x01\x00"  # INTEGER 0
        inner_seq = b"\x30" + bytes([len(integer_0)]) + integer_0
        outer_seq = b"\x30" + bytes([len(inner_seq)]) + inner_seq
        assert parse_timestamp_response_status(outer_seq) == 0

    def test_parse_rejection_status(self):
        integer_2 = b"\x02\x01\x02"  # INTEGER 2 (rejection)
        inner_seq = b"\x30" + bytes([len(integer_2)]) + integer_2
        outer_seq = b"\x30" + bytes([len(inner_seq)]) + inner_seq
        assert parse_timestamp_response_status(outer_seq) == 2

    def test_parse_too_short_raises(self):
        with pytest.raises(ValueError, match="too short"):
            parse_timestamp_response_status(b"\x30\x00")


# ---------------------------------------------------------------------------
# TSA client tests (mocked HTTP)
# ---------------------------------------------------------------------------


class TestRFC3161Client:
    @patch("a2a_settlement_mediator.tsa_client.httpx.Client")
    def test_successful_timestamp(self, mock_client_cls):
        # Build a minimal "granted" DER response
        integer_0 = b"\x02\x01\x00"
        inner_seq = b"\x30" + bytes([len(integer_0)]) + integer_0
        tsa_resp_der = b"\x30" + bytes([len(inner_seq)]) + inner_seq

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = tsa_resp_der
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_ctx.post.return_value = mock_resp
        mock_client_cls.return_value = mock_ctx

        client = RFC3161Client("http://tsa.example.com/tsr", timeout_seconds=5.0)
        token = client.request_timestamp(hashlib.sha256(b"test").digest())

        assert token.tsa_url == "http://tsa.example.com/tsr"
        assert token.hash_algorithm == "sha256"
        assert token.timestamp_token_b64 == base64.b64encode(tsa_resp_der).decode()

    @patch("a2a_settlement_mediator.tsa_client.httpx.Client")
    def test_timeout_raises_tsa_timeout_error(self, mock_client_cls):
        import httpx

        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_ctx.post.side_effect = httpx.ReadTimeout("Connection timed out")
        mock_client_cls.return_value = mock_ctx

        client = RFC3161Client("http://tsa.example.com/tsr", timeout_seconds=1.0)
        with pytest.raises(TSATimeoutError, match="timed out"):
            client.request_timestamp(hashlib.sha256(b"data").digest())

    @patch("a2a_settlement_mediator.tsa_client.httpx.Client")
    def test_rejection_raises_tsa_client_error(self, mock_client_cls):
        # Build a "rejection" DER response (status=2)
        integer_2 = b"\x02\x01\x02"
        inner_seq = b"\x30" + bytes([len(integer_2)]) + integer_2
        tsa_resp_der = b"\x30" + bytes([len(inner_seq)]) + inner_seq

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = tsa_resp_der
        mock_ctx = MagicMock()
        mock_ctx.__enter__ = MagicMock(return_value=mock_ctx)
        mock_ctx.__exit__ = MagicMock(return_value=False)
        mock_ctx.post.return_value = mock_resp
        mock_client_cls.return_value = mock_ctx

        client = RFC3161Client("http://tsa.example.com/tsr")
        with pytest.raises(TSAClientError, match="rejected"):
            client.request_timestamp(hashlib.sha256(b"data").digest())

    def test_wrong_hash_length_raises(self):
        client = RFC3161Client("http://tsa.example.com/tsr")
        with pytest.raises(ValueError, match="32-byte"):
            client.request_timestamp(b"too-short")


# ---------------------------------------------------------------------------
# Attestation payload tests
# ---------------------------------------------------------------------------


class TestAttestationPayload:
    def test_hash_is_deterministic(self, sample_transcript, sample_mandates, sample_verdict):
        h1 = PreDisputeAttestationPayload.compute_hash(
            sample_transcript, sample_mandates, sample_verdict
        )
        h2 = PreDisputeAttestationPayload.compute_hash(
            sample_transcript, sample_mandates, sample_verdict
        )
        assert h1 == h2
        assert len(h1) == 64  # hex SHA-256

    def test_hash_changes_with_different_input(
        self, sample_transcript, sample_mandates, sample_verdict
    ):
        h1 = PreDisputeAttestationPayload.compute_hash(
            sample_transcript, sample_mandates, sample_verdict
        )
        different_transcript = NegotiationTranscript(
            transcript_hash="ff" * 32,
            source_service="other",
        )
        h2 = PreDisputeAttestationPayload.compute_hash(
            different_transcript, sample_mandates, sample_verdict
        )
        assert h1 != h2

    def test_build_attestation_payload(self, sample_transcript, sample_mandates, sample_verdict):
        payload = _build_attestation_payload(
            sample_transcript, sample_mandates, sample_verdict
        )
        assert payload.payload_version == SCHEMA_VERSION
        assert payload.verdict.decision == ArbitrationDecision.APPROVED
        assert len(payload.payload_hash) == 64


# ---------------------------------------------------------------------------
# Full pipeline tests (mocked LLM + TSA)
# ---------------------------------------------------------------------------


class TestSettlePipeline:
    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_approved_settlement_returns_proof(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(sample_transcript, sample_mandates, escrow_id="esc-001")

        assert result.success is True
        assert result.proof is not None
        assert result.stage_reached == SettlementStage.COMPLETE
        assert result.proof.merkle_result.verified is True
        assert len(result.proof.settlement_hash) == 64
        assert result.proof.attestation_payload.verdict.decision == ArbitrationDecision.APPROVED

    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_rejected_settlement_returns_no_proof(
        self, mock_llm, sample_transcript, sample_mandates
    ):
        mock_llm.return_value = ArbitrationVerdict(
            decision=ArbitrationDecision.REJECTED,
            confidence=0.88,
            reasoning="Mandate M-001 references impossible deliverable.",
            factors=["impossible_condition"],
            mandate_compliance={"M-001": False, "M-002": True},
            llm_model="test-model",
        )

        result = settle(sample_transcript, sample_mandates)

        assert result.success is False
        assert result.proof is None
        assert result.stage_reached == SettlementStage.ARBITRATION
        assert "REJECTED" in result.error
        assert result.arbitration_verdict.decision == ArbitrationDecision.REJECTED

    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_llm_failure_returns_error(self, mock_llm, sample_transcript, sample_mandates):
        mock_llm.side_effect = RuntimeError("LLM provider unreachable")

        result = settle(sample_transcript, sample_mandates)

        assert result.success is False
        assert result.stage_reached == SettlementStage.ARBITRATION
        assert "unreachable" in result.error

    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_tsa_timeout_hard_fails(
        self, mock_llm, mock_timestamp, sample_transcript, sample_mandates, sample_verdict
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.side_effect = SettlementHardFail("TSA timeout")

        result = settle(sample_transcript, sample_mandates)

        assert result.success is False
        assert result.stage_reached == SettlementStage.TIMESTAMPING
        assert "TSA timeout" in result.error

    @patch("a2a_settlement_mediator.settlement_pipeline._merkle_tree")
    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_merkle_append_failure_hard_fails(
        self,
        mock_llm,
        mock_timestamp,
        mock_tree,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp
        mock_tree.append_and_prove.side_effect = RuntimeError("Disk full")

        result = settle(sample_transcript, sample_mandates)

        assert result.success is False
        assert result.stage_reached == SettlementStage.MERKLE_APPEND
        assert "HARD FAIL" in result.error

    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_merkle_proof_is_independently_verifiable(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        """After a successful settlement, the Merkle proof can be verified
        independently using only the proof data (no tree access needed)."""
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(sample_transcript, sample_mandates)
        assert result.success is True

        proof = result.proof.merkle_result.proof
        leaf_hash = bytes.fromhex(proof.leaf_hash)
        siblings = [bytes.fromhex(s) for s in proof.siblings]
        root_hash = bytes.fromhex(proof.root_hash)

        assert MerkleTree.verify_proof(leaf_hash, siblings, proof.directions, root_hash)

    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_settlement_hash_ties_all_components(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(sample_transcript, sample_mandates)
        assert result.success is True

        sp = result.proof
        expected_input = (
            f"{sp.attestation_payload.payload_hash}:"
            f"{sp.timestamp.message_hash}:"
            f"{sp.merkle_result.root_hash}"
        )
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()
        assert sp.settlement_hash == expected_hash


# ---------------------------------------------------------------------------
# Arbitration LLM tests (mocked litellm)
# ---------------------------------------------------------------------------


class TestArbitrationLLM:
    @patch("a2a_settlement_mediator.settlement_pipeline.litellm.completion")
    def test_approved_verdict(self, mock_completion, sample_transcript, sample_mandates):
        llm_resp = _make_approved_llm_response()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(llm_resp)
        mock_response.usage.prompt_tokens = 500
        mock_response.usage.completion_tokens = 120
        mock_completion.return_value = mock_response

        request = ArbitrationRequest(
            transcript=sample_transcript, mandates=sample_mandates
        )
        verdict = _call_arbitration_llm(request)

        assert verdict.decision == ArbitrationDecision.APPROVED
        assert verdict.confidence == 0.92

    @patch("a2a_settlement_mediator.settlement_pipeline.litellm.completion")
    def test_rejected_verdict(self, mock_completion, sample_transcript, sample_mandates):
        llm_resp = _make_rejected_llm_response()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(llm_resp)
        mock_response.usage.prompt_tokens = 400
        mock_response.usage.completion_tokens = 100
        mock_completion.return_value = mock_response

        request = ArbitrationRequest(
            transcript=sample_transcript, mandates=sample_mandates
        )
        verdict = _call_arbitration_llm(request)

        assert verdict.decision == ArbitrationDecision.REJECTED
        assert verdict.confidence == 0.88

    @patch("a2a_settlement_mediator.settlement_pipeline.litellm.completion")
    def test_low_confidence_forces_rejected(
        self, mock_completion, sample_transcript, sample_mandates
    ):
        llm_resp = _make_approved_llm_response()
        llm_resp["confidence"] = 0.30  # Below 0.5 threshold
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = json.dumps(llm_resp)
        mock_response.usage.prompt_tokens = 300
        mock_response.usage.completion_tokens = 80
        mock_completion.return_value = mock_response

        request = ArbitrationRequest(
            transcript=sample_transcript, mandates=sample_mandates
        )
        verdict = _call_arbitration_llm(request)

        assert verdict.decision == ArbitrationDecision.REJECTED

    @patch("a2a_settlement_mediator.settlement_pipeline.litellm.completion")
    def test_invalid_json_raises(self, mock_completion, sample_transcript, sample_mandates):
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "not valid json at all"
        mock_response.usage.prompt_tokens = 200
        mock_response.usage.completion_tokens = 50
        mock_completion.return_value = mock_response

        request = ArbitrationRequest(
            transcript=sample_transcript, mandates=sample_mandates
        )
        with pytest.raises(json.JSONDecodeError):
            _call_arbitration_llm(request)

    @patch("a2a_settlement_mediator.settlement_pipeline.litellm.completion")
    def test_markdown_fences_stripped(self, mock_completion, sample_transcript, sample_mandates):
        llm_resp = _make_approved_llm_response()
        raw = f"```json\n{json.dumps(llm_resp)}\n```"
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = raw
        mock_response.usage.prompt_tokens = 500
        mock_response.usage.completion_tokens = 120
        mock_completion.return_value = mock_response

        request = ArbitrationRequest(
            transcript=sample_transcript, mandates=sample_mandates
        )
        verdict = _call_arbitration_llm(request)
        assert verdict.decision == ArbitrationDecision.APPROVED


# ---------------------------------------------------------------------------
# Webhook endpoint tests for settlement
# ---------------------------------------------------------------------------


class TestSettlementEndpoints:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from a2a_settlement_mediator.webhook_listener import app

        return TestClient(app)

    @patch("a2a_settlement_mediator.webhook_listener.settle")
    def test_settle_endpoint(self, mock_settle, client, sample_verdict, sample_timestamp):
        from a2a_settlement_mediator.worm_schemas import SettlementResult, SettlementStage

        mock_settle.return_value = SettlementResult(
            success=True,
            stage_reached=SettlementStage.COMPLETE,
            arbitration_verdict=sample_verdict,
        )

        body = {
            "transcript_hash": "ab" * 32,
            "source_service": "crewai",
            "mandates": [
                {
                    "mandate_id": "M-001",
                    "description": "Test mandate",
                    "conditions": ["cond1"],
                }
            ],
            "escrow_id": "esc-test",
        }

        resp = client.post("/settle", json=body)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        mock_settle.assert_called_once()

    def test_merkle_endpoint(self, client):
        resp = client.get("/merkle")
        assert resp.status_code == 200
        data = resp.json()
        assert "tree_size" in data
        assert "root_hash" in data

    def test_settlements_list_endpoint(self, client):
        resp = client.get("/settlements")
        assert resp.status_code == 200
        data = resp.json()
        assert "settlements" in data
        assert "total" in data


# ---------------------------------------------------------------------------
# WORM schema serialization tests
# ---------------------------------------------------------------------------


class TestWORMSchemas:
    def test_negotiation_transcript_serialization(self, sample_transcript):
        data = json.loads(sample_transcript.model_dump_json())
        assert data["transcript_hash"] == sample_transcript.transcript_hash
        assert data["source_service"] == "crewai"
        assert "ingested_at" in data

    def test_ap2_mandate_serialization(self, sample_mandates):
        data = json.loads(sample_mandates[0].model_dump_json())
        assert data["mandate_id"] == "M-001"
        assert data["severity"] == "critical"
        assert len(data["conditions"]) == 2

    def test_settlement_result_serialization(self, sample_verdict):
        result = SettlementResult(
            success=False,
            error="Test error",
            stage_reached=SettlementStage.ARBITRATION,
            arbitration_verdict=sample_verdict,
        )
        data = json.loads(result.model_dump_json())
        assert data["success"] is False
        assert data["stage_reached"] == "arbitration"
        assert data["arbitration_verdict"]["decision"] == "APPROVED"

    def test_settlement_result_has_execution_status(self, sample_verdict):
        result = SettlementResult(
            success=True,
            stage_reached=SettlementStage.COMPLETE,
            arbitration_verdict=sample_verdict,
        )
        assert result.execution_status == ExecutionStatus.PENDING


# ---------------------------------------------------------------------------
# Ingestion validation tests (Context Bomb mitigation)
# ---------------------------------------------------------------------------


class TestIngestionValidation:
    def test_valid_ingestion_passes(self, sample_transcript, sample_mandates):
        _validate_ingestion(sample_transcript, sample_mandates)

    def test_oversized_transcript_hash_rejected(self):
        transcript = NegotiationTranscript(
            transcript_hash="a" * 200,
            source_service="crewai",
        )
        with pytest.raises(IngestionLimitExceeded, match="transcript_hash length"):
            _validate_ingestion(transcript, [])

    def test_too_many_mandates_rejected(self, sample_transcript):
        mandates = [
            AP2Mandate(mandate_id=f"M-{i:04d}", description="test")
            for i in range(60)
        ]
        with pytest.raises(IngestionLimitExceeded, match="mandate count"):
            _validate_ingestion(sample_transcript, mandates)

    def test_oversized_mandate_description_rejected(self, sample_transcript):
        mandates = [
            AP2Mandate(mandate_id="M-001", description="x" * 6000)
        ]
        with pytest.raises(IngestionLimitExceeded, match="description length"):
            _validate_ingestion(sample_transcript, mandates)

    def test_too_many_conditions_rejected(self, sample_transcript):
        mandates = [
            AP2Mandate(
                mandate_id="M-001",
                description="test",
                conditions=[f"cond-{i}" for i in range(25)],
            )
        ]
        with pytest.raises(IngestionLimitExceeded, match="conditions"):
            _validate_ingestion(sample_transcript, mandates)

    def test_total_payload_chars_rejected(self, sample_transcript):
        mandates = [
            AP2Mandate(mandate_id=f"M-{i:04d}", description="x" * 4000)
            for i in range(30)
        ]
        with pytest.raises(IngestionLimitExceeded, match="total mandate payload"):
            _validate_ingestion(sample_transcript, mandates)

    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_settle_rejects_oversized_ingestion(self, mock_llm):
        transcript = NegotiationTranscript(
            transcript_hash="a" * 200,
            source_service="crewai",
        )
        result = settle(transcript, [])
        assert result.success is False
        assert "Ingestion limit exceeded" in result.error
        mock_llm.assert_not_called()


# ---------------------------------------------------------------------------
# Gatekeeper recovery ledger tests
# ---------------------------------------------------------------------------


class TestGatekeeperRecovery:
    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_successful_settlement_is_pending(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(sample_transcript, sample_mandates)
        assert result.success is True
        assert result.execution_status == ExecutionStatus.PENDING

        pending = get_pending_settlements()
        hashes = [r.proof.settlement_hash for r in pending]
        assert result.proof.settlement_hash in hashes

    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_mark_executed_removes_from_pending(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(sample_transcript, sample_mandates)
        settlement_hash = result.proof.settlement_hash

        assert mark_executed(settlement_hash) is True

        pending = get_pending_settlements()
        hashes = [r.proof.settlement_hash for r in pending]
        assert settlement_hash not in hashes

    def test_mark_executed_unknown_hash_returns_false(self):
        assert mark_executed("nonexistent") is False

    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_mark_failed_records_error(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(sample_transcript, sample_mandates)
        settlement_hash = result.proof.settlement_hash

        assert mark_failed(settlement_hash, "network error") is True

        from a2a_settlement_mediator.settlement_pipeline import get_confirmed_settlement

        updated = get_confirmed_settlement(settlement_hash)
        assert updated.execution_status == ExecutionStatus.FAILED

    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_rejected_settlement_not_in_ledger(
        self, mock_llm, sample_transcript, sample_mandates
    ):
        mock_llm.return_value = ArbitrationVerdict(
            decision=ArbitrationDecision.REJECTED,
            confidence=0.88,
            reasoning="Rejected",
            llm_model="test",
        )

        initial_pending = len(get_pending_settlements())
        result = settle(sample_transcript, sample_mandates)
        assert result.success is False
        assert len(get_pending_settlements()) == initial_pending


# ---------------------------------------------------------------------------
# JSON Schema export tests
# ---------------------------------------------------------------------------


class TestJSONSchemaExport:
    def test_export_returns_all_models(self):
        schemas = export_json_schemas()
        expected_models = {
            "NegotiationTranscript",
            "AP2Mandate",
            "ArbitrationVerdict",
            "PreDisputeAttestationPayload",
            "TimestampToken",
            "AgentIdentity",
            "CurrencyPrecision",
            "MerkleLeafPayload",
            "MerkleProof",
            "MerkleAppendResult",
            "SettlementProof",
            "SettlementResult",
        }
        assert set(schemas.keys()) == expected_models

    def test_schemas_have_id_and_version(self):
        schemas = export_json_schemas()
        for name, schema in schemas.items():
            assert "$id" in schema
            assert SCHEMA_VERSION in schema["$id"]
            assert "$schema" in schema

    def test_export_to_directory(self, tmp_path):
        schemas = export_json_schemas(output_dir=tmp_path)
        for name in schemas:
            path = tmp_path / f"{name}.v{SCHEMA_VERSION}.schema.json"
            assert path.exists()
            content = json.loads(path.read_text())
            assert content["$id"] == schemas[name]["$id"]

    def test_settlement_proof_has_schema_version(self):
        schemas = export_json_schemas()
        proof_schema = schemas["SettlementProof"]
        props = proof_schema.get("properties", {})
        assert "schema_version" in props


# ---------------------------------------------------------------------------
# Settlement endpoint recovery tests
# ---------------------------------------------------------------------------


class TestSettlementRecoveryEndpoints:
    @pytest.fixture
    def client(self):
        from fastapi.testclient import TestClient

        from a2a_settlement_mediator.webhook_listener import app

        return TestClient(app)

    def test_pending_endpoint(self, client):
        resp = client.get("/settlements/pending")
        assert resp.status_code == 200
        data = resp.json()
        assert "pending" in data
        assert "count" in data

    def test_ack_unknown_hash_returns_404(self, client):
        resp = client.post(
            "/settlements/ack",
            json={"settlement_hash": "nonexistent", "status": "executed"},
        )
        assert resp.status_code == 404

    def test_ack_invalid_status_returns_400(self, client):
        resp = client.post(
            "/settlements/ack",
            json={"settlement_hash": "abc", "status": "invalid_status"},
        )
        assert resp.status_code == 400

    def test_schemas_endpoint(self, client):
        resp = client.get("/schemas")
        assert resp.status_code == 200
        data = resp.json()
        assert "schema_version" in data
        assert data["schema_version"] == SCHEMA_VERSION
        assert "SettlementProof" in data["schemas"]


# ---------------------------------------------------------------------------
# Schema hardening tests (AgentIdentity, CurrencyPrecision, MerkleLeafPayload)
# ---------------------------------------------------------------------------


class TestAgentIdentity:
    def test_valid_identity(self):
        ai = AgentIdentity(agent_id="agent-001", role="buyer")
        assert ai.agent_id == "agent-001"
        assert ai.role == "buyer"
        assert ai.protocol_version == "2.0"

    def test_custom_protocol_version(self):
        ai = AgentIdentity(agent_id="agent-001", role="seller", protocol_version="3.0")
        assert ai.protocol_version == "3.0"

    def test_empty_agent_id_rejected(self):
        with pytest.raises(Exception):
            AgentIdentity(agent_id="", role="buyer")

    def test_empty_role_rejected(self):
        with pytest.raises(Exception):
            AgentIdentity(agent_id="agent-001", role="")


class TestCurrencyPrecision:
    def test_valid_usd(self):
        cp = CurrencyPrecision(currency_code="USD", decimal_places=2)
        assert cp.currency_code == "USD"
        assert cp.decimal_places == 2

    def test_valid_btc(self):
        cp = CurrencyPrecision(currency_code="BTC", decimal_places=8)
        assert cp.decimal_places == 8

    def test_invalid_currency_code_lowercase(self):
        with pytest.raises(Exception):
            CurrencyPrecision(currency_code="usd", decimal_places=2)

    def test_invalid_currency_code_too_long(self):
        with pytest.raises(Exception):
            CurrencyPrecision(currency_code="USDT", decimal_places=2)

    def test_invalid_currency_code_too_short(self):
        with pytest.raises(Exception):
            CurrencyPrecision(currency_code="US", decimal_places=2)

    def test_negative_decimal_places_rejected(self):
        with pytest.raises(Exception):
            CurrencyPrecision(currency_code="USD", decimal_places=-1)

    def test_excessive_decimal_places_rejected(self):
        with pytest.raises(Exception):
            CurrencyPrecision(currency_code="USD", decimal_places=19)

    def test_max_decimal_places_accepted(self):
        cp = CurrencyPrecision(currency_code="ETH", decimal_places=18)
        assert cp.decimal_places == 18


class TestMerkleLeafPayload:
    def test_compute_hash_deterministic(
        self,
        sample_agent_identities,
        sample_currency_precision,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        attestation = _build_attestation_payload(
            sample_transcript, sample_mandates, sample_verdict
        )
        h1 = MerkleLeafPayload.compute_hash(
            sample_agent_identities, sample_currency_precision, attestation, sample_timestamp
        )
        h2 = MerkleLeafPayload.compute_hash(
            sample_agent_identities, sample_currency_precision, attestation, sample_timestamp
        )
        assert h1 == h2
        assert len(h1) == 64

    def test_compute_hash_changes_with_different_identities(
        self,
        sample_agent_identities,
        sample_currency_precision,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        attestation = _build_attestation_payload(
            sample_transcript, sample_mandates, sample_verdict
        )
        h1 = MerkleLeafPayload.compute_hash(
            sample_agent_identities, sample_currency_precision, attestation, sample_timestamp
        )
        different_ids = [
            AgentIdentity(agent_id="other-buyer", role="buyer"),
            AgentIdentity(agent_id="other-seller", role="seller"),
        ]
        h2 = MerkleLeafPayload.compute_hash(
            different_ids, sample_currency_precision, attestation, sample_timestamp
        )
        assert h1 != h2

    def test_compute_hash_changes_with_different_currency(
        self,
        sample_agent_identities,
        sample_currency_precision,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        attestation = _build_attestation_payload(
            sample_transcript, sample_mandates, sample_verdict
        )
        h1 = MerkleLeafPayload.compute_hash(
            sample_agent_identities, sample_currency_precision, attestation, sample_timestamp
        )
        different_cp = CurrencyPrecision(currency_code="EUR", decimal_places=2)
        h2 = MerkleLeafPayload.compute_hash(
            sample_agent_identities, different_cp, attestation, sample_timestamp
        )
        assert h1 != h2

    def test_construct_full_payload(
        self,
        sample_agent_identities,
        sample_currency_precision,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        attestation = _build_attestation_payload(
            sample_transcript, sample_mandates, sample_verdict
        )
        h = MerkleLeafPayload.compute_hash(
            sample_agent_identities, sample_currency_precision, attestation, sample_timestamp
        )
        payload = MerkleLeafPayload(
            agent_identities=sample_agent_identities,
            currency_precision=sample_currency_precision,
            attestation=attestation,
            timestamp=sample_timestamp,
            payload_hash=h,
        )
        assert payload.leaf_version == SCHEMA_VERSION
        assert len(payload.agent_identities) == 2
        assert payload.currency_precision.currency_code == "USD"
        assert len(payload.payload_hash) == 64

    def test_too_few_identities_rejected(
        self,
        sample_currency_precision,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        attestation = _build_attestation_payload(
            sample_transcript, sample_mandates, sample_verdict
        )
        with pytest.raises(Exception):
            MerkleLeafPayload(
                agent_identities=[AgentIdentity(agent_id="solo", role="buyer")],
                currency_precision=sample_currency_precision,
                attestation=attestation,
                timestamp=sample_timestamp,
                payload_hash="a" * 64,
            )

    def test_serialization_roundtrip(
        self,
        sample_agent_identities,
        sample_currency_precision,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        attestation = _build_attestation_payload(
            sample_transcript, sample_mandates, sample_verdict
        )
        h = MerkleLeafPayload.compute_hash(
            sample_agent_identities, sample_currency_precision, attestation, sample_timestamp
        )
        payload = MerkleLeafPayload(
            agent_identities=sample_agent_identities,
            currency_precision=sample_currency_precision,
            attestation=attestation,
            timestamp=sample_timestamp,
            payload_hash=h,
        )
        data = json.loads(payload.model_dump_json())
        assert data["leaf_version"] == SCHEMA_VERSION
        assert len(data["agent_identities"]) == 2
        assert data["agent_identities"][0]["agent_id"] == "agent-buyer-001"
        assert data["currency_precision"]["currency_code"] == "USD"
        assert data["currency_precision"]["decimal_places"] == 2


class TestSettlePipelineWithSchemaHardening:
    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_settle_with_explicit_identities_and_precision(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
        sample_agent_identities,
        sample_currency_precision,
    ):
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(
            sample_transcript,
            sample_mandates,
            agent_identities=sample_agent_identities,
            currency_precision=sample_currency_precision,
        )

        assert result.success is True
        assert result.proof is not None
        assert result.proof.merkle_result.verified is True

    @patch("a2a_settlement_mediator.settlement_pipeline._request_timestamp")
    @patch("a2a_settlement_mediator.settlement_pipeline._call_arbitration_llm")
    def test_settle_defaults_identities_and_precision(
        self,
        mock_llm,
        mock_timestamp,
        sample_transcript,
        sample_mandates,
        sample_verdict,
        sample_timestamp,
    ):
        """settle() works with no agent_identities/currency_precision (uses defaults)."""
        mock_llm.return_value = sample_verdict
        mock_timestamp.return_value = sample_timestamp

        result = settle(sample_transcript, sample_mandates)

        assert result.success is True
        assert result.proof is not None
