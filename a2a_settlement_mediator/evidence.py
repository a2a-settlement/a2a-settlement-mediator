"""Evidence collection from the A2A Settlement Exchange.

Gathers all relevant context about a disputed escrow so the LLM mediator
can make an informed decision. Uses the official a2a-settlement SDK
(SettlementExchangeClient) for all exchange calls.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from a2a_settlement.client import SettlementExchangeClient

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.schemas import (
    AccountEvidence,
    Deliverable,
    EscrowEvidence,
    EvidenceBundle,
    StructuredEvidence,
)

logger = logging.getLogger(__name__)

# The values the exchange stores in an escrow's ``self_dealing_class`` column.
_SELF_DEALING_CLASSES = frozenset({"arms_length", "suspected_self_dealing", "self_dealing"})


def _get_sdk_client() -> SettlementExchangeClient:
    base = settings.exchange_url.rstrip("/")
    if base.endswith("/v1"):
        base = base[:-3]
    return SettlementExchangeClient(
        base_url=base,
        api_key=settings.operator_api_key,
    )


def _check_attestation_freshness(client: SettlementExchangeClient, account_id: str) -> dict | None:
    """Check whether an agent's attestations are still valid (OCSP-style).

    Returns a dict with freshness info, or None if the check is unavailable.
    """
    try:
        resp = client._get(f"/exchange/attestations?account_id={account_id}&status=active&limit=10")
        attestations = resp.get("attestations", [])
        if not attestations:
            return {"valid": True, "note": "no_attestations_found"}

        flags = []
        for att in attestations:
            remaining = att.get("ttl_remaining_seconds")
            att_type = att.get("attestation_type", "unknown")
            status = att.get("status", "active")
            if status != "active":
                flags.append(f"{att_type}:{status}")
            elif remaining is not None and remaining <= 0:
                flags.append(f"{att_type}:expired")

        return {
            "valid": len(flags) == 0,
            "flags": flags,
            "attestation_count": len(attestations),
        }
    except Exception:
        logger.warning("Attestation freshness check failed for %s", account_id)
        return None


def _self_dealing_class(escrow_data: dict) -> str | None:
    """Return the exchange's self-dealing classification for an escrow.

    The exchange classifies each escrow when it is created and stores the
    result on the escrow row. Only the top-level ``self_dealing_class`` key of
    the escrow record is read: nothing a requester or provider can write
    (dispute reason, deliverables, provenance, submitted evidence) is
    consulted. A missing key, ``None`` or any value other than the three the
    exchange defines is treated as unclassified, so the dispute takes the same
    path as one with no classification.
    """
    value = escrow_data.get("self_dealing_class")
    if value is None:
        return None
    if isinstance(value, str) and value in _SELF_DEALING_CLASSES:
        return value
    logger.warning(
        "Escrow %s has unrecognised self_dealing_class %r; treating as unclassified",
        escrow_data.get("id"),
        value,
    )
    return None


def collect_evidence(escrow_id: str) -> EvidenceBundle:
    """Fetch all evidence for a disputed escrow from the exchange.

    Gathers:
    - Full escrow details (deliverables, acceptance criteria, dispute reason)
    - Requester account (reputation, history)
    - Provider account (reputation, history)
    - Recent dispute counts for both parties
    - Attestation freshness for both parties
    """
    client = _get_sdk_client()

    escrow_data = client.get_escrow(escrow_id=escrow_id)

    deliverables = []
    for d in escrow_data.get("deliverables") or []:
        deliverables.append(
            Deliverable(
                description=d.get("description", ""),
                artifact_hash=d.get("artifact_hash"),
                acceptance_criteria=d.get("acceptance_criteria"),
            )
        )

    escrow_evidence = EscrowEvidence(
        escrow_id=escrow_data["id"],
        requester_id=escrow_data["requester_id"],
        provider_id=escrow_data["provider_id"],
        amount=escrow_data["amount"],
        fee_amount=escrow_data["fee_amount"],
        status=escrow_data["status"],
        dispute_reason=escrow_data.get("dispute_reason"),
        task_id=escrow_data.get("task_id"),
        task_type=escrow_data.get("task_type"),
        deliverables=deliverables,
        required_attestation_level=escrow_data.get("required_attestation_level"),
        delivered_content=escrow_data.get("delivered_content"),
        provenance=escrow_data.get("provenance"),
        vi_credential_chain=escrow_data.get("vi_credential_chain"),
        delivered_at=escrow_data.get("delivered_at"),
        created_at=escrow_data.get("created_at"),
        expires_at=escrow_data.get("expires_at"),
        self_dealing_class=_self_dealing_class(escrow_data),
    )

    requester = _fetch_account_evidence(client, escrow_data["requester_id"])
    provider = _fetch_account_evidence(client, escrow_data["provider_id"])

    requester_disputes = _count_recent_disputes(client, escrow_data["requester_id"])
    provider_disputes = _count_recent_disputes(client, escrow_data["provider_id"])

    requester_evidence, provider_evidence, oracle_evidence = _fetch_structured_evidence(
        client, escrow_id, escrow_data["requester_id"], escrow_data["provider_id"]
    )

    requester_freshness = _check_attestation_freshness(client, escrow_data["requester_id"])
    provider_freshness = _check_attestation_freshness(client, escrow_data["provider_id"])

    return EvidenceBundle(
        escrow=escrow_evidence,
        requester=requester,
        provider=provider,
        requester_recent_disputes=requester_disputes,
        provider_recent_disputes=provider_disputes,
        requester_evidence=requester_evidence,
        provider_evidence=provider_evidence,
        oracle_evidence=oracle_evidence,
        requester_attestation_freshness=requester_freshness,
        provider_attestation_freshness=provider_freshness,
        collected_at=datetime.now(timezone.utc),
    )


def _fetch_account_evidence(client: SettlementExchangeClient, account_id: str) -> AccountEvidence:
    acct = client.get_account(account_id=account_id)
    return AccountEvidence(
        account_id=acct["id"],
        bot_name=acct["bot_name"],
        reputation=acct.get("reputation", 0.5),
        status=acct.get("status", "active"),
        skills=acct.get("skills", []),
        total_earned=acct.get("total_earned", 0),
        total_spent=acct.get("total_spent", 0),
    )


def _count_recent_disputes(client: SettlementExchangeClient, account_id: str) -> int:
    count = 0
    for status in ("disputed", "refunded"):
        try:
            data = client.list_escrows(status=status, limit=50)
            for esc in data.get("escrows", []):
                if account_id in (esc.get("requester_id"), esc.get("provider_id")):
                    count += 1
        except Exception:
            logger.warning("Failed to fetch %s escrows for dispute count", status)
    return count


def _fetch_structured_evidence(
    client: SettlementExchangeClient,
    escrow_id: str,
    requester_id: str,
    provider_id: str,
) -> tuple[list[StructuredEvidence], list[StructuredEvidence], list[StructuredEvidence]]:
    """Fetch structured evidence submissions from both parties and any oracles."""
    requester_evidence: list[StructuredEvidence] = []
    provider_evidence: list[StructuredEvidence] = []
    oracle_evidence: list[StructuredEvidence] = []

    try:
        data = client.list_evidence(escrow_id=escrow_id)
        for item in data.get("evidence", []):
            se = StructuredEvidence(
                id=item["id"],
                submitter_id=item["submitter_id"],
                evidence_type=item.get("evidence_type", ""),
                summary=item.get("summary", ""),
                artifacts=item.get("artifacts", []),
                encrypted=item.get("encrypted", False),
                content_hash=item.get("content_hash", ""),
                attestor_id=item.get("attestor_id"),
                attestor_signature=item.get("attestor_signature"),
                source_type=item.get("source_type", "party"),
                oracle_id=item.get("oracle_id"),
                submitted_at=item.get("submitted_at"),
            )
            if se.source_type == "oracle":
                oracle_evidence.append(se)
            elif se.submitter_id == requester_id:
                requester_evidence.append(se)
            elif se.submitter_id == provider_id:
                provider_evidence.append(se)
    except Exception:
        logger.warning("Failed to fetch structured evidence for escrow %s", escrow_id)

    return requester_evidence, provider_evidence, oracle_evidence
