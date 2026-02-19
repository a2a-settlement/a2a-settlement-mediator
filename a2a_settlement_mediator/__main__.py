"""CLI entrypoint for the A2A Settlement Mediator.

Usage:
    a2a-mediator                  # Start webhook listener
    a2a-mediator --once ESCROW_ID # Mediate a single dispute and exit
"""

from __future__ import annotations

import argparse
import json
import logging
import sys

import uvicorn

from a2a_settlement_mediator.config import settings


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    parser = argparse.ArgumentParser(description="A2A Settlement Mediator")
    parser.add_argument(
        "--once",
        metavar="ESCROW_ID",
        help="Mediate a single disputed escrow and exit (no webhook listener)",
    )
    parser.add_argument(
        "--host",
        default=settings.webhook_host,
        help=f"Webhook listener host (default: {settings.webhook_host})",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=settings.webhook_port,
        help=f"Webhook listener port (default: {settings.webhook_port})",
    )
    args = parser.parse_args()

    if not settings.operator_api_key:
        print("ERROR: A2A_OPERATOR_API_KEY must be set", file=sys.stderr)
        sys.exit(1)

    if args.once:
        # Single-shot mediation mode
        from a2a_settlement_mediator.mediator import mediate

        audit = mediate(args.once)
        print(json.dumps(audit.model_dump(mode="json"), indent=2))
        sys.exit(0 if audit.error is None else 1)

    # Start webhook listener
    print(f"🧑‍⚖️ A2A Settlement Mediator v0.1.0")
    print(f"   Exchange: {settings.exchange_url}")
    print(f"   LLM:      {settings.llm_model}")
    print(f"   Threshold: {settings.auto_resolve_threshold:.0%}")
    print(f"   Listening: http://{args.host}:{args.port}/webhook")
    print()

    uvicorn.run(
        "a2a_settlement_mediator.webhook_listener:app",
        host=args.host,
        port=args.port,
        log_level="info",
    )


if __name__ == "__main__":
    main()
