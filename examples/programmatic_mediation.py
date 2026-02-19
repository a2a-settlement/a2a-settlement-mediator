"""Example: Programmatic mediation of a disputed escrow.

This example shows how to use the mediator as a library rather than
running it as a webhook listener service. Useful for testing, batch
processing, or integrating into custom orchestration pipelines.

Prerequisites:
    export A2A_EXCHANGE_URL=http://127.0.0.1:3000/v1
    export A2A_OPERATOR_API_KEY=ate_your_operator_key
    export ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY for OpenAI models

Usage:
    python examples/programmatic_mediation.py <escrow_id>
"""

from __future__ import annotations

import json
import sys

from a2a_settlement_mediator import (
    VerdictOutcome,
    collect_evidence,
    mediate,
)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python examples/programmatic_mediation.py <escrow_id>")
        sys.exit(1)

    escrow_id = sys.argv[1]

    # Step 1: Preview the evidence (optional — mediate() does this internally)
    print("=" * 60)
    print(f"Collecting evidence for escrow: {escrow_id}")
    print("=" * 60)
    evidence = collect_evidence(escrow_id)
    print(f"  Requester: {evidence.requester.bot_name} (rep: {evidence.requester.reputation:.2f})")
    print(f"  Provider:  {evidence.provider.bot_name} (rep: {evidence.provider.reputation:.2f})")
    print(f"  Amount:    {evidence.escrow.amount} ATE")
    print(f"  Dispute:   {evidence.escrow.dispute_reason}")
    print(f"  Deliverables: {len(evidence.escrow.deliverables)}")
    print()

    # Step 2: Run full mediation
    print("Running AI mediation...")
    print("-" * 60)
    audit = mediate(escrow_id)

    # Step 3: Display results
    v = audit.verdict
    print(f"\n{'=' * 60}")
    print(f"VERDICT: {v.outcome.value}")
    print(f"  Confidence:  {v.confidence:.0%}")
    print(f"  Resolution:  {v.resolution.value if v.resolution else 'N/A (escalated)'}")
    print(f"  Reasoning:   {v.reasoning}")
    print(f"  Factors:     {', '.join(v.factors)}")
    print(f"  LLM:         {audit.llm_model} ({audit.llm_latency_ms}ms)")
    print(f"  Tokens:      {audit.llm_prompt_tokens} prompt + {audit.llm_completion_tokens} completion")

    if v.outcome == VerdictOutcome.ESCALATE:
        print("\n⚠️  This dispute was ESCALATED — confidence below threshold.")
        print("   A human operator should review and call POST /exchange/resolve manually.")
    elif audit.exchange_response:
        print(f"\n✅ Resolution executed on exchange:")
        print(f"   {json.dumps(audit.exchange_response, indent=2)}")

    if audit.error:
        print(f"\n❌ Error: {audit.error}")


if __name__ == "__main__":
    main()
