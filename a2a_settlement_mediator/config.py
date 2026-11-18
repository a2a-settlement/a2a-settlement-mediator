"""Configuration for the A2A Settlement Mediator.

All settings are driven by environment variables with sensible defaults.
The mediator needs operator-level credentials on the exchange to call
POST /exchange/resolve.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse


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


def _get_optional_float(name: str, default: float | None) -> float | None:
    """Like _get_float, but "none" means the setting is not sent at all."""
    val = os.getenv(name)
    if val is None or val == "":
        return default
    if val.strip().lower() == "none":
        return None
    return float(val)


def _get_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None or val == "":
        return default
    return val.strip().lower() in {"1", "true", "yes", "y", "on"}


# Commercial RFC 3161 presets. Lookup is case-insensitive.
# ``timestamp.sectigo.com`` is also on FREE_TSA_HOSTS, so public receipts still
# refuse the sectigo preset. digicert is a commercial URL they can use.
COMMERCIAL_TSA_PRESETS = {
    "digicert": "http://timestamp.digicert.com",
    "sectigo": "http://timestamp.sectigo.com",
}


def resolve_tsa_url(raw: str) -> str:
    """Map a commercial preset name to its URL, otherwise return ``raw`` stripped.

    ``MEDIATOR_TSA_URL=digicert`` and a full ``http(s)`` URL both resolve.
    Unknown names are returned unchanged so enterprise URLs pass through.
    """
    text = raw.strip()
    return COMMERCIAL_TSA_PRESETS.get(text.lower(), text)


def _optional_tsa_url(name: str) -> str:
    """Resolve an optional TSA URL env var. Blank stays blank."""
    raw = os.getenv(name, "")
    if not raw.strip():
        return ""
    return resolve_tsa_url(raw)


class MediatorSettings:
    # --- Exchange connection ---
    exchange_url: str = os.getenv("A2A_EXCHANGE_URL", "http://127.0.0.1:3000/v1")
    operator_api_key: str = os.getenv("A2A_OPERATOR_API_KEY", "")

    # --- LLM provider (via LiteLLM) ---
    llm_model: str = os.getenv("MEDIATOR_LLM_MODEL", "anthropic/claude-sonnet-5-5")
    llm_model_sonnet: str = os.getenv("MEDIATOR_LLM_MODEL_SONNET", "anthropic/claude-sonnet-5-5")
    # Unset or "none" sends no temperature: the default model (Claude 5.x) rejects
    # one. Set a number (e.g. 0.1) for models that accept it.
    llm_temperature: float | None = _get_optional_float("MEDIATOR_LLM_TEMPERATURE", None)
    llm_max_tokens: int = _get_int("MEDIATOR_LLM_MAX_TOKENS", 4096)

    # --- Anti-self-dealing ---
    # Suspected self-dealing disputes above this ATE amount require human review
    # before the mediator finalizes its resolution.
    suspected_self_dealing_review_threshold: int = _get_int(
        "MEDIATOR_SUSPECTED_SD_REVIEW_THRESHOLD", 1000
    )

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
    # It keys /webhook, and every other signed route that has no secret of its own.
    webhook_secret: str = os.getenv("MEDIATOR_WEBHOOK_SECRET", "")
    # Optional per-purpose secrets. Empty means that purpose uses webhook_secret.
    # When one is set, the webhook secret is no longer accepted for that purpose
    # (except while secret_transition_accept_fallback is on).
    operator_secret: str = os.getenv("MEDIATOR_OPERATOR_SECRET", "")
    verify_patch_secret: str = os.getenv("MEDIATOR_VERIFY_PATCH_SECRET", "")
    receipts_secret: str = os.getenv("MEDIATOR_RECEIPTS_SECRET", "")
    # Rollout aid, off by default. While on, a purpose that has its own secret
    # also accepts the webhook secret, so callers can be switched over without a
    # failed request. Turn it off again once every caller signs with its own secret.
    secret_transition_accept_fallback: bool = _get_bool(
        "MEDIATOR_SECRET_TRANSITION_ACCEPT_FALLBACK", False
    )
    # Verify-patch and the operator routes reject timestamps farther than this
    # many seconds from now.
    signature_tolerance_seconds: int = _get_int("MEDIATOR_SIGNATURE_TOLERANCE_S", 300)
    # Local development only. With no webhook secret, /webhook and the operator
    # routes refuse every request unless this is on. Ignored when a secret is set.
    allow_unauthenticated: bool = _get_bool("MEDIATOR_INSECURE_ALLOW_UNAUTHENTICATED", False)
    # Public base URL clients use to reach this mediator, e.g. behind a path-prefix proxy.
    # Empty means advertise relative paths.
    public_url: str = os.getenv("MEDIATOR_PUBLIC_URL", "").rstrip("/")

    # --- Escalation ---
    # Webhook URL to POST escalation notices to (e.g., Slack incoming webhook).
    escalation_webhook_url: str = os.getenv("MEDIATOR_ESCALATION_WEBHOOK_URL", "")

    # --- SEC 17a-4 WORM Settlement Pipeline ---
    # RFC 3161 Time Stamp Authority URL, or a commercial preset (digicert, sectigo).
    tsa_url: str = resolve_tsa_url(
        os.getenv("MEDIATOR_TSA_URL", "http://freetsa.org/tsr")
    )
    # Maximum seconds to wait for TSA response before hard-failing the settlement.
    tsa_timeout_seconds: float = _get_float("MEDIATOR_TSA_TIMEOUT", 15.0)
    # Tried only after the primary TSA raises a transport, HTTP, or TSA error.
    tsa_fallback_url: str = _optional_tsa_url("MEDIATOR_TSA_FALLBACK_URL")
    # Enterprise TSA authentication. Never log this value.
    tsa_bearer_token: str = os.getenv("MEDIATOR_TSA_BEARER_TOKEN", "")
    # Optional mTLS. Both paths, or a single PEM in the cert setting.
    tsa_client_cert: str = os.getenv("MEDIATOR_TSA_CLIENT_CERT", "")
    tsa_client_key: str = os.getenv("MEDIATOR_TSA_CLIENT_KEY", "")
    tsa_ca_bundle: str = os.getenv("MEDIATOR_TSA_CA_BUNDLE", "")

    # --- Heartbeat recovery worker ---
    heartbeat_interval_seconds: float = _get_float("MEDIATOR_HEARTBEAT_INTERVAL", 30.0)
    stale_settlement_threshold_seconds: float = _get_float(
        "MEDIATOR_STALE_SETTLEMENT_THRESHOLD", 120.0
    )
    execution_callback_url: str = os.getenv("MEDIATOR_EXECUTION_CALLBACK_URL", "")

    # --- Provenance verification ---
    # Rate at which Tier 2 (signed) transactions are spot-checked via endpoint re-fetch.
    provenance_spot_check_rate: float = _get_float("MEDIATOR_PROVENANCE_SPOT_CHECK_RATE", 0.10)
    # Escrow amount threshold above which Tier 3 (verifiable) is auto-triggered.
    provenance_verifiable_threshold: int = _get_int(
        "MEDIATOR_PROVENANCE_VERIFIABLE_THRESHOLD",
        1000,
    )
    # Local development and tests only. Provenance URLs are written by escrow
    # parties; by default the mediator refuses to fetch any that resolve to a
    # loopback, private, link-local or otherwise non-public address.
    allow_private_fetch_addresses: bool = _get_bool(
        "MEDIATOR_INSECURE_ALLOW_PRIVATE_FETCH_ADDRESSES", False
    )

    # --- Deliverable size routing ---
    # Token budget for the full evidence bundle sent to the LLM.
    # Deliverables exceeding this limit are routed through the digest pipeline
    # instead of being passed raw, preventing silent truncation and false verdicts.
    # Rough estimate: 1 token ≈ 4 chars for JSON. Default leaves ample room for
    # the system prompt and acceptance criteria within a 32K-token context window.
    mediator_token_budget: int = _get_int("MEDIATOR_TOKEN_BUDGET", 24_000)

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

    # --- Patch assessment ---
    # Maximum UTF-8 size of a git diff accepted by POST /api/v1/verify-patch.
    max_patch_diff_bytes: int = _get_int("MEDIATOR_MAX_PATCH_DIFF_BYTES", 524288)

    # --- Proof-of-fix receipts ---
    receipts_enabled: bool = _get_bool("MEDIATOR_RECEIPTS_ENABLED", False)
    # Public receipts refuse to start with a free TSA; set a commercial MEDIATOR_TSA_URL.
    receipts_public: bool = _get_bool("MEDIATOR_RECEIPTS_PUBLIC", False)
    # AWS KMS asymmetric key (ECC_NIST_P256, ECDSA_SHA_256). Only the ARN lives here;
    # the private key never leaves KMS.
    receipt_kms_key_arn: str = os.getenv("MEDIATOR_RECEIPT_KMS_KEY_ARN", "")
    receipt_kms_region: str = os.getenv("MEDIATOR_RECEIPT_KMS_REGION", "")
    receipt_key_id: str = os.getenv("MEDIATOR_RECEIPT_KID", "")


settings = MediatorSettings()


def temperature_kwargs() -> dict[str, float]:
    """The temperature argument for litellm.completion, or nothing when unset."""
    if settings.llm_temperature is None:
        return {}
    return {"temperature": settings.llm_temperature}


class ReceiptsConfigError(RuntimeError):
    """Public receipts are configured with a TSA this process must not use."""


# Hosts of free or publicly shared RFC 3161 authorities. Public proof-of-fix
# receipts must not be anchored at one of these, including subdomains.
FREE_TSA_HOSTS = frozenset(
    {
        "freetsa.org",
        "timestamp.sectigo.com",
        "timestamp.comodoca.com",
        "timestamp.globalsign.com",
        "time.certum.pl",
        "timestamp.entrust.net",
        "timestamp.apple.com",
    }
)


def tsa_hostname(tsa_url: str) -> str:
    """Lowercase host of a TSA URL, or an empty string when it has none."""
    try:
        host = urlparse(tsa_url).hostname
    except ValueError:
        return ""
    if not host:
        return ""
    return host.lower().rstrip(".")


def is_free_tsa_url(tsa_url: str) -> bool:
    """True when ``tsa_url`` points at a host on the free-TSA denylist."""
    host = tsa_hostname(tsa_url)
    if not host:
        return False
    return any(host == denied or host.endswith("." + denied) for denied in FREE_TSA_HOSTS)


def assert_public_receipts_tsa(
    receipts_public: bool,
    tsa_url: str,
    fallback_tsa_url: str = "",
) -> None:
    """Refuse to start when public receipts would be timestamped by a free TSA.

    ``MEDIATOR_RECEIPTS_PUBLIC=false`` is always allowed, including the default
    freetsa.org URL used by the settlement pipeline. Public receipts require a
    commercial ``MEDIATOR_TSA_URL``. When ``fallback_tsa_url`` is set, it is held
    to the same rule so a free TSA cannot silently anchor public receipts.
    Preset names are resolved before the host check. The two-argument form is
    unchanged: omitting the fallback does not consult process settings.
    """
    if not receipts_public:
        return
    _reject_free_public_tsa(tsa_url, setting="MEDIATOR_TSA_URL")
    if fallback_tsa_url.strip():
        _reject_free_public_tsa(
            fallback_tsa_url, setting="MEDIATOR_TSA_FALLBACK_URL"
        )


def _reject_free_public_tsa(raw_url: str, *, setting: str) -> None:
    resolved = resolve_tsa_url(raw_url)
    if not is_free_tsa_url(resolved):
        return
    host = tsa_hostname(resolved) or resolved
    if setting == "MEDIATOR_TSA_FALLBACK_URL":
        raise ReceiptsConfigError(
            "Refusing to start: MEDIATOR_RECEIPTS_PUBLIC=true and "
            "MEDIATOR_TSA_FALLBACK_URL "
            f"points at free timestamp authority {host}. Public proof-of-fix "
            "receipts require a commercial TSA; a fallback to a free TSA such as "
            "freetsa.org is not acceptable."
        )
    raise ReceiptsConfigError(
        "Refusing to start: MEDIATOR_RECEIPTS_PUBLIC=true and MEDIATOR_TSA_URL "
        f"points at free timestamp authority {host}. Public proof-of-fix receipts "
        "require a commercial TSA; a free TSA such as freetsa.org is not acceptable."
    )
