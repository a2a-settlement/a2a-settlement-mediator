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
| `MEDIATOR_TSA_URL` | `http://freetsa.org/tsr` | RFC 3161 Time Stamp Authority URL |
| `MEDIATOR_TSA_TIMEOUT` | `15` | Seconds before TSA hard-fail |

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

### Mediation

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health check with config summary |
| `POST` | `/webhook` | Receive exchange webhook events |
| `POST` | `/mediate/{escrow_id}` | Manually trigger mediation (sync) |
| `GET` | `/audits` | List mediation audit records |
| `GET` | `/audits/{escrow_id}` | Get audit record for a specific escrow |

### SEC 17a-4 WORM Settlement

| Method | Path | Description |
|---|---|---|
| `POST` | `/settle` | Run the full settlement pipeline (arbitration → timestamp → Merkle → proof) |
| `GET` | `/settlements` | List recent settlement results |
| `GET` | `/merkle` | Current Merkle Tree state (size + root hash) |
| `GET` | `/settlements/pending` | Confirmed settlements awaiting mandate execution (recovery) |
| `POST` | `/settlements/ack` | Acknowledge mandate execution (mark executed/failed) |
| `GET` | `/schemas` | Versioned JSON Schema definitions for all attestation models |

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

## SEC 17a-4 WORM Settlement Pipeline

The mediator includes a separate settlement pipeline designed for SEC 17a-4 WORM compliance. It consumes negotiation transcripts from CrewAI and aligns them with AP2 mandates to create a formal bridge between "Natural Language Intent" and "Cryptographic Execution."

```
CrewAI transcript (hashed)
+ AP2 mandates
        │
        ▼
┌───────────────┐  1. ARBITRATION     LLM evaluates mandate compliance
│  Orchestrator │  2. ATTESTATION     Build immutable payload + SHA-256 seal
│               │  3. TIMESTAMPING    RFC 3161 timestamp from TSA
│               │  4. MERKLE APPEND   Append to append-only Merkle Tree
│               │  5. VERIFY          Mathematical proof verification
│               │  6. PROOF           Assemble cryptographic proof bundle
└───────┬───────┘
        │
        ▼
┌───────────────┐
│  Gatekeeper   │──── Mandate released ONLY after Merkle leaf confirmed
│               │──── Recovery: re-emit for confirmed-but-unexecuted leaves
└───────────────┘
```

### Merkle Tree Specification

The Scribe uses a **SHA-256 binary Merkle Tree** with domain-separated hashing (prevents second-preimage attacks):

- **Leaf nodes:** `H(0x00 || data)`
- **Internal nodes:** `H(0x01 || left || right)`
- **Tree structure:** Unbalanced binary tree (RFC 6962 §2.1 style). When the leaf count is not a power of two, the last leaf at each level is promoted without a sibling. The shape is fully deterministic given the leaf count.
- **Append-only:** Leaves are never removed or mutated (WORM semantics).
- **Thread-safe:** All mutations serialized via lock.

Third-party verification requires only the leaf data, sibling path, and the root hash at insertion time — no tree access needed.

### Gatekeeper Recovery

If the Merkle append succeeds but the network fails before the mandate is released to the execution engine:

1. The pipeline records every confirmed settlement in a recovery ledger (`GET /settlements/pending`)
2. The execution engine polls for pending mandates and re-emits them
3. After successful execution, it acknowledges via `POST /settlements/ack`

This prevents "Phantom Settlements" where a payment occurs without an audit trail, and also prevents the inverse — a confirmed audit leaf with no corresponding execution.

### Attestation Schema

All attestation payloads carry a `payload_version` / `schema_version` field. Versioned JSON Schema definitions are available at `GET /schemas` for external auditors and peer mediators to validate settlement proofs without the mediator's source code.

### Ingestion Limits (Context Bomb Mitigation)

To prevent malicious agents from flooding the mediator with oversized payloads (driving up LLM costs or causing timeouts), the pipeline enforces configurable limits:

| Variable | Default | Description |
|---|---|---|
| `MEDIATOR_MAX_TRANSCRIPT_HASH_LENGTH` | `128` | Max hex chars in transcript hash |
| `MEDIATOR_MAX_MANDATES` | `50` | Max AP2 mandates per request |
| `MEDIATOR_MAX_MANDATE_PAYLOAD_CHARS` | `100000` | Max total chars across all mandate text |
| `MEDIATOR_MAX_MANDATE_DESC_LENGTH` | `5000` | Max chars per mandate description |
| `MEDIATOR_MAX_CONDITIONS_PER_MANDATE` | `20` | Max conditions per mandate |

HTTP requests exceeding 1 MiB are rejected at the middleware layer before any parsing occurs.

## Architecture

```
a2a_settlement_mediator/
├── __init__.py              # Public API
├── __main__.py              # CLI entrypoint
├── config.py                # Environment-driven settings
├── schemas.py               # Evidence, Verdict, AuditRecord models
├── worm_schemas.py          # WORM compliance models + JSON Schema export
├── evidence.py              # Evidence collection from exchange API
├── prompts.py               # LLM prompt templates (mediation)
├── arbitration_prompts.py   # LLM prompt templates (WORM arbitration)
├── mediator.py              # Core mediation pipeline
├── settlement_pipeline.py   # WORM settlement pipeline + Gatekeeper recovery
├── merkle.py                # SHA-256 Merkle Tree (RFC 6962 §2.1 style)
├── tsa_client.py            # RFC 3161 TSA client (minimal DER encoder)
└── webhook_listener.py      # FastAPI webhook receiver + settlement API
```

## Roadmap

- [ ] Persistent audit + Merkle storage (SQLite/Postgres backing for WORM tree and recovery ledger)
- [ ] Artifact content inspection (fetch and verify deliverable content)
- [ ] Multi-LLM consensus (2-of-3 agreement for high-value disputes)
- [ ] **Multi-Sig / Consensus Mediator** — Support multiple auditors that must agree before the Gatekeeper releases a mandate (threshold signatures or BFT consensus)
- [ ] Partial resolution support (split escrow between parties)
- [ ] A2A task history integration (review full task conversation)
- [ ] Prometheus metrics endpoint
- [ ] Streaming transcript ingestion with back-pressure (complement to Context Bomb limits)

## Related

- [a2a-settlement](https://github.com/a2a-settlement/a2a-settlement) — Core exchange + SDK
- [crewai-a2a-settlement](https://github.com/a2a-settlement/crewai-a2a-settlement) — CrewAI integration
- [litellm-a2a-settlement](https://github.com/a2a-settlement/litellm-a2a-settlement) — LiteLLM proxy integration

## License

MIT
