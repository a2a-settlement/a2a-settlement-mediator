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

    # --- SEC 17a-4 WORM Settlement Pipeline ---
    # RFC 3161 Time Stamp Authority URL (e.g., http://freetsa.org/tsr)
    tsa_url: str = os.getenv("MEDIATOR_TSA_URL", "http://freetsa.org/tsr")
    # Maximum seconds to wait for TSA response before hard-failing the settlement.
    tsa_timeout_seconds: float = _get_float("MEDIATOR_TSA_TIMEOUT", 15.0)

    # --- Ingestion limits (Context Bomb mitigation) ---
    # Maximum length of the transcript_hash field (hex chars). SHA-256 = 64.
    max_transcript_hash_length: int = _get_int("MEDIATOR_MAX_TRANSCRIPT_HASH_LENGTH", 128)
    # Maximum number of AP2 mandates per settlement request.
    max_mandates_per_settlement: int = _get_int("MEDIATOR_MAX_MANDATES", 50)
    # Maximum total characters across all mandate descriptions + conditions.
    max_mandate_payload_chars: int = _get_int("MEDIATOR_MAX_MANDATE_PAYLOAD_CHARS", 100_000)
    # Maximum length of a single mandate description (chars).
    max_mandate_description_length: int = _get_int("MEDIATOR_MAX_MANDATE_DESC_LENGTH", 5_000)
    # Maximum number of conditions per mandate.
    max_conditions_per_mandate: int = _get_int("MEDIATOR_MAX_CONDITIONS_PER_MANDATE", 20)


settings = MediatorSettings()
