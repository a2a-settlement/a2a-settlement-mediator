# A2A Settlement Mediator

AI-powered dispute resolution for the [A2A Settlement Exchange](https://github.com/a2a-settlement/a2a-settlement). Autonomously evaluates disputed escrows and resolves clear-cut cases, escalating ambiguous disputes to human operators.

## How It Works

```
Agent A disputes escrow
        │
        ▼
  ┌─────────────┐     escrow.disputed
  │  Exchange    │────webhook────▶┌──────────────┐
  │  (core)      │                │  Mediator     │
  └─────────────┘◀───resolve─────│  (this repo)  │
                                  └──────┬───────┘
                                         │
                              ┌──────────┴──────────┐
                              │                     │
                        confidence ≥ 80%      confidence < 80%
                              │                     │
                        Auto-resolve          Escalate to
                        (release/refund)      human operator
```

The mediator runs as a **sidecar service** alongside the exchange. When a dispute is filed:

1. **Evidence Collection** — Fetches escrow details, deliverables, acceptance criteria, dispute reason, and both parties' reputation and dispute history from the exchange API.

2. **LLM Evaluation** — Sends the evidence bundle to an LLM (Claude, GPT-4, etc. via LiteLLM) with a structured decision framework that weighs deliverable completeness, acceptance criteria specificity, dispute substantiation, reputation signals, and proportionality.

3. **Confidence Gating** — The LLM produces a resolution (release or refund) with a confidence score (0.0–1.0). If confidence meets the threshold (default 80%), the mediator auto-resolves by calling `POST /exchange/resolve` with operator credentials. Below threshold, it escalates via webhook (e.g., Slack).

4. **Audit Trail** — Every mediation produces a full audit record: evidence snapshot, LLM reasoning, token usage, latency, and exchange response.

## Quick Start

```bash
# Clone
git clone https://github.com/a2a-settlement/a2a-settlement-mediator.git
cd a2a-settlement-mediator

# Install
pip install -e .

# Configure
cp .env.example .env
# Edit .env with your exchange URL, operator API key, and LLM API key

# Run webhook listener
a2a-mediator

# Or mediate a single dispute
a2a-mediator --once <escrow_id>
```

## Configuration

All settings via environment variables (see `.env.example`):

| Variable | Default | Description |
|---|---|---|
| `A2A_EXCHANGE_URL` | `http://127.0.0.1:3000/v1` | Exchange API base URL |
| `A2A_OPERATOR_API_KEY` | — | Operator-level API key for resolving disputes |
| `MEDIATOR_LLM_MODEL` | `anthropic/claude-sonnet-4-20250514` | LiteLLM model string |
| `MEDIATOR_AUTO_RESOLVE_THRESHOLD` | `0.80` | Confidence threshold for auto-resolution |
| `MEDIATOR_PORT` | `3100` | Webhook listener port |
| `MEDIATOR_WEBHOOK_SECRET` | — | HMAC secret for verifying exchange webhooks |
| `MEDIATOR_ESCALATION_WEBHOOK_URL` | — | Slack/webhook URL for escalation notices |

## Exchange Setup

The mediator needs an **operator-level account** on the exchange to call `POST /exchange/resolve`. Register the mediator's webhook URL on the exchange:

```python
from a2a_settlement import SettlementExchangeClient

client = SettlementExchangeClient(
    base_url="http://127.0.0.1:3000/v1",
    api_key="ate_operator_key",
)

# Register webhook to receive dispute events
client.set_webhook(
    url="http://mediator-host:3100/webhook",
    events=["escrow.disputed"],
)
```

## API Endpoints

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check with config summary |
| `POST` | `/webhook` | Receive exchange webhook events |
| `POST` | `/mediate/{escrow_id}` | Manually trigger mediation (sync) |
| `GET` | `/audits` | List mediation audit records |
| `GET` | `/audits/{escrow_id}` | Get audit record for a specific escrow |

## Decision Framework

The LLM evaluates five factors:

1. **Deliverable Completeness** — Were artifacts submitted? Do hashes match?
2. **Acceptance Criteria** — Were criteria specific? Is the dispute about objective non-delivery or subjective quality?
3. **Dispute Reason** — Is the complaint specific and substantiated?
4. **Reputation History** — Pattern of disputes from either party?
5. **Proportionality** — Economic motivation vs. quality motivation?

## Programmatic Usage

```python
from a2a_settlement_mediator import mediate, VerdictOutcome

audit = mediate("escrow-id-here")

if audit.verdict.outcome == VerdictOutcome.AUTO_RELEASE:
    print(f"Released with {audit.verdict.confidence:.0%} confidence")
elif audit.verdict.outcome == VerdictOutcome.AUTO_REFUND:
    print(f"Refunded with {audit.verdict.confidence:.0%} confidence")
else:
    print(f"Escalated — confidence {audit.verdict.confidence:.0%}")
    print(f"LLM suggested: {audit.verdict.resolution}")
```

## Testing

```bash
pip install -e ".[dev]"
pytest
```

## Architecture

```
a2a_settlement_mediator/
├── __init__.py          # Public API
├── __main__.py          # CLI entrypoint
├── config.py            # Environment-driven settings
├── schemas.py           # Evidence, Verdict, AuditRecord models
├── evidence.py          # Evidence collection from exchange API
├── prompts.py           # LLM prompt templates
├── mediator.py          # Core mediation pipeline
└── webhook_listener.py  # FastAPI webhook receiver
```

## Roadmap

- [ ] Persistent audit storage (SQLite/Postgres)
- [ ] Artifact content inspection (fetch and verify deliverable content)
- [ ] Multi-LLM consensus (2-of-3 agreement for high-value disputes)
- [ ] Partial resolution support (split escrow between parties)
- [ ] A2A task history integration (review full task conversation)
- [ ] Prometheus metrics endpoint

## Related

- [a2a-settlement](https://github.com/a2a-settlement/a2a-settlement) — Core exchange + SDK
- [crewai-a2a-settlement](https://github.com/a2a-settlement/crewai-a2a-settlement) — CrewAI integration
- [litellm-a2a-settlement](https://github.com/a2a-settlement/litellm-a2a-settlement) — LiteLLM proxy integration

## License

MIT
