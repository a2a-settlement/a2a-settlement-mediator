"""Evidence collection from the A2A Settlement Exchange.

Gathers all relevant context about a disputed escrow so the LLM mediator
can make an informed decision. Uses the exchange REST API via httpx
(mirroring the SDK client pattern but tailored for operator access).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import httpx

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.schemas import (
    AccountEvidence,
    Deliverable,
    EscrowEvidence,
    EvidenceBundle,
)

logger = logging.getLogger(__name__)


def _url(path: str) -> str:
    return settings.exchange_url.rstrip("/") + "/" + path.lstrip("/")


def _headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.operator_api_key}",
        "Content-Type": "application/json",
    }


def _client() -> httpx.Client:
    return httpx.Client(timeout=10.0, headers=_headers())


def collect_evidence(escrow_id: str) -> EvidenceBundle:
    """Fetch all evidence for a disputed escrow from the exchange.

    Gathers:
    - Full escrow details (deliverables, acceptance criteria, dispute reason)
    - Requester account (reputation, history)
    - Provider account (reputation, history)
    - Recent dispute counts for both parties
    """
    with _client() as client:
        # 1. Fetch escrow details
        escrow_resp = client.get(_url(f"exchange/escrows/{escrow_id}"))
        escrow_resp.raise_for_status()
        escrow_data = escrow_resp.json()

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
            created_at=escrow_data.get("created_at"),
            expires_at=escrow_data.get("expires_at"),
        )

        # 2. Fetch requester account + balance
        requester = _fetch_account_evidence(client, escrow_data["requester_id"])

        # 3. Fetch provider account + balance
        provider = _fetch_account_evidence(client, escrow_data["provider_id"])

        # 4. Count recent disputes for both parties
        requester_disputes = _count_recent_disputes(client, escrow_data["requester_id"])
        provider_disputes = _count_recent_disputes(client, escrow_data["provider_id"])

    return EvidenceBundle(
        escrow=escrow_evidence,
        requester=requester,
        provider=provider,
        requester_recent_disputes=requester_disputes,
        provider_recent_disputes=provider_disputes,
        collected_at=datetime.now(timezone.utc),
    )


def _fetch_account_evidence(client: httpx.Client, account_id: str) -> AccountEvidence:
    """Fetch account details and balance for a participant."""
    acct_resp = client.get(_url(f"accounts/{account_id}"))
    acct_resp.raise_for_status()
    acct = acct_resp.json()

    # Balance is fetched via the account's own perspective, but since we're
    # the operator we can read it from the account endpoint if available.
    # Fall back to zeros if balance fields aren't exposed on the account endpoint.
    return AccountEvidence(
        account_id=acct["id"],
        bot_name=acct["bot_name"],
        reputation=acct.get("reputation", 0.5),
        status=acct.get("status", "active"),
        skills=acct.get("skills", []),
        total_earned=acct.get("total_earned", 0),
        total_spent=acct.get("total_spent", 0),
    )


def _count_recent_disputes(client: httpx.Client, account_id: str) -> int:
    """Count how many disputed/refunded escrows an account has been involved in recently.

    Uses the escrow list endpoint filtered by status. This is an approximation —
    a production system would track dispute history in a dedicated table.
    """
    count = 0
    for status in ("disputed", "refunded"):
        try:
            resp = client.get(
                _url("exchange/escrows"),
                params={"status": status, "limit": 50},
            )
            resp.raise_for_status()
            data = resp.json()
            for esc in data.get("escrows", []):
                if account_id in (esc.get("requester_id"), esc.get("provider_id")):
                    count += 1
        except httpx.HTTPStatusError:
            logger.warning("Failed to fetch %s escrows for dispute count", status)
    return count
