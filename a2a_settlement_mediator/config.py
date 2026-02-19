"""Configuration for the A2A Settlement Mediator.

All settings are driven by environment variables with sensible defaults.
The mediator needs operator-level credentials on the exchange to call
POST /exchange/resolve.
"""

from __future__ import annotations

import os


def _get_int(name: str, default: int) -> int:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    return int(val)


def _get_float(name: str, default: float) -> float:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    return float(val)


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


class MediatorSettings:
    # --- Exchange connection ---
    exchange_url: str = os.getenv("A2A_EXCHANGE_URL", "http://127.0.0.1:3000/v1")
    operator_api_key: str = os.getenv("A2A_OPERATOR_API_KEY", "")

    # --- LLM provider (via LiteLLM) ---
    llm_model: str = os.getenv("MEDIATOR_LLM_MODEL", "anthropic/claude-sonnet-4-20250514")
    llm_temperature: float = _get_float("MEDIATOR_LLM_TEMPERATURE", 0.1)
    llm_max_tokens: int = _get_int("MEDIATOR_LLM_MAX_TOKENS", 4096)

    # --- Mediation policy ---
    # Confidence threshold (0.0–1.0). Verdicts below this are escalated to human.
    auto_resolve_threshold: float = _get_float("MEDIATOR_AUTO_RESOLVE_THRESHOLD", 0.80)
    # Maximum seconds to wait for LLM response before escalating.
    llm_timeout_seconds: int = _get_int("MEDIATOR_LLM_TIMEOUT", 30)
    # If True, log full LLM prompts and responses for audit.
    audit_log_enabled: bool = _get_bool("MEDIATOR_AUDIT_LOG", True)

    # --- Webhook listener ---
    webhook_host: str = os.getenv("MEDIATOR_HOST", "127.0.0.1")
    webhook_port: int = _get_int("MEDIATOR_PORT", 3100)
    # The webhook secret assigned by the exchange when the mediator registers its webhook.
    webhook_secret: str = os.getenv("MEDIATOR_WEBHOOK_SECRET", "")

    # --- Escalation ---
    # Webhook URL to POST escalation notices to (e.g., Slack incoming webhook).
    escalation_webhook_url: str = os.getenv("MEDIATOR_ESCALATION_WEBHOOK_URL", "")


settings = MediatorSettings()
