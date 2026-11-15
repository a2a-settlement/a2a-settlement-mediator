"""Operator preflight for the RFC 3161 time-stamp authority.

Run before ``MEDIATOR_RECEIPTS_PUBLIC=true``::

    python -m a2a_settlement_mediator.tsa_probe
    python -m a2a_settlement_mediator.tsa_probe --tsa-url digicert --json

The default mode refuses a free TSA (including a free fallback) and then
stamps a deterministic SHA-256 digest. Exit 0 prints the issuing TSA. Exit 2
is configuration. Exit 1 is a failed round-trip or a token that does not echo
the probe digest.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
from collections.abc import Callable
from datetime import datetime
from typing import Any, TextIO

from a2a_settlement_mediator.config import (
    ReceiptsConfigError,
    assert_public_receipts_tsa,
    resolve_tsa_url,
)
from a2a_settlement_mediator.tsa_client import RFC3161Client, TSAClientError

PROBE_PAYLOAD = b"a2a-settlement-mediator-tsa-probe-v1"

EXIT_OK = 0
EXIT_PROBE_FAILED = 1
EXIT_CONFIG = 2


class _UsageError(Exception):
    """argparse rejected the command line."""


class ProbeTokenError(Exception):
    """The TSA response was not a usable SHA-256 timestamp token."""


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _UsageError(message)


def probe_digest() -> bytes:
    """Deterministic SHA-256 digest stamped by the preflight probe."""
    return hashlib.sha256(PROBE_PAYLOAD).digest()


def main(
    argv: list[str] | None = None,
    *,
    client_factory: Callable[..., Any] | None = None,
) -> int:
    """Probe the configured TSA. Returns a process exit code."""
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except _UsageError as exc:
        return _fail(str(exc), EXIT_CONFIG, _wants_json(argv))
    except SystemExit as exc:
        code = exc.code
        if code is None or code == EXIT_OK:
            return EXIT_OK
        return code if isinstance(code, int) else EXIT_CONFIG

    raw_url = args.tsa_url
    if raw_url is None:
        raw_url = os.getenv("MEDIATOR_TSA_URL", "http://freetsa.org/tsr")
    tsa_url = resolve_tsa_url(raw_url)
    if args.fallback_url is None:
        raw_fallback = os.getenv("MEDIATOR_TSA_FALLBACK_URL", "")
    else:
        raw_fallback = args.fallback_url
    fallback_url = resolve_tsa_url(raw_fallback) if raw_fallback.strip() else ""

    if not tsa_url:
        return _fail(
            "TSA URL is empty. Set --tsa-url or MEDIATOR_TSA_URL.",
            EXIT_CONFIG,
            args.json,
        )

    if args.require_commercial:
        try:
            assert_public_receipts_tsa(True, tsa_url, fallback_url)
        except ReceiptsConfigError as exc:
            return _fail(str(exc), EXIT_CONFIG, args.json)

    try:
        timeout = _timeout_seconds()
    except ValueError as exc:
        return _fail(str(exc), EXIT_CONFIG, args.json)

    digest = probe_digest()
    factory = client_factory or RFC3161Client
    try:
        client = factory(
            tsa_url,
            timeout,
            fallback_url=fallback_url,
            bearer_token=os.getenv("MEDIATOR_TSA_BEARER_TOKEN", ""),
            client_cert=os.getenv("MEDIATOR_TSA_CLIENT_CERT", ""),
            client_key=os.getenv("MEDIATOR_TSA_CLIENT_KEY", ""),
            ca_bundle=os.getenv("MEDIATOR_TSA_CA_BUNDLE", ""),
        )
        token = client.request_timestamp(digest)
        _check_token(token, digest)
    except ProbeTokenError as exc:
        return _fail(_scrub(str(exc)), EXIT_PROBE_FAILED, args.json)
    except TSAClientError as exc:
        return _fail(_scrub(str(exc)), EXIT_PROBE_FAILED, args.json)
    except ValueError as exc:
        return _fail(_scrub(str(exc)), EXIT_CONFIG, args.json)

    _emit_ok(token, digest, args.json)
    return EXIT_OK


def _build_parser() -> _Parser:
    parser = _Parser(
        prog="python -m a2a_settlement_mediator.tsa_probe",
        description=(
            "Validate a commercial RFC 3161 TSA and stamp a probe digest "
            "before enabling public receipts."
        ),
    )
    parser.add_argument(
        "--tsa-url",
        default=None,
        help="TSA URL or preset (digicert, sectigo). Default: MEDIATOR_TSA_URL.",
    )
    parser.add_argument(
        "--fallback-url",
        default=None,
        help="Fallback TSA URL or preset. Default: MEDIATOR_TSA_FALLBACK_URL.",
    )
    parser.add_argument(
        "--require-commercial",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Reject free TSA hosts (default). Use --no-require-commercial to skip.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print a JSON object on stdout (errors on stderr).",
    )
    return parser


def _timeout_seconds() -> float:
    raw = os.getenv("MEDIATOR_TSA_TIMEOUT", "").strip()
    if not raw:
        return 15.0
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"MEDIATOR_TSA_TIMEOUT is not a number: {raw}") from exc
    if value <= 0:
        raise ValueError("MEDIATOR_TSA_TIMEOUT must be positive")
    return value


def _check_token(token: Any, digest: bytes) -> None:
    encoded = getattr(token, "timestamp_token_b64", "")
    if not isinstance(encoded, str) or not encoded.strip():
        raise ProbeTokenError("TSA returned an empty DER TimestampToken")
    try:
        der = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ProbeTokenError("TSA timestamp token is not valid base64 DER") from exc
    if not der:
        raise ProbeTokenError("TSA returned an empty DER TimestampToken")
    if der[0] != 0x30:
        raise ProbeTokenError("TSA timestamp token is not a DER SEQUENCE")
    if digest not in der:
        raise ProbeTokenError(
            "TSA timestamp token did not echo the SHA-256 probe digest"
        )
    echoed = getattr(token, "message_hash", "")
    if not isinstance(echoed, str) or echoed.lower() != digest.hex():
        raise ProbeTokenError(
            "TSA timestamp token message_hash did not echo the SHA-256 probe digest"
        )
    tsa_url = getattr(token, "tsa_url", "")
    if not isinstance(tsa_url, str) or not tsa_url:
        raise ProbeTokenError("TSA timestamp token is missing tsa_url")


def _emit_ok(token: Any, digest: bytes, as_json: bool) -> None:
    gen_time = _gen_time(token)
    serial = getattr(token, "serial_number", None)
    serial_text = "" if serial is None else str(serial)
    if as_json:
        _write_json(
            {
                "ok": True,
                "tsa_url": token.tsa_url,
                "gen_time": gen_time,
                "serial": serial_text,
                "message_hash": digest.hex(),
            },
            sys.stdout,
        )
        return
    print(f"OK tsa_url={token.tsa_url} gen_time={gen_time} serial={serial_text}")


def _gen_time(token: Any) -> str:
    value = getattr(token, "requested_at", None)
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return ""
    return str(value)


def _fail(message: str, code: int, as_json: bool) -> int:
    text = _scrub(message)
    if as_json:
        _write_json({"ok": False, "error": text}, sys.stderr)
    else:
        print(f"error: {text}", file=sys.stderr)
    return code


def _write_json(payload: dict[str, Any], stream: TextIO) -> None:
    json.dump(payload, stream, sort_keys=True)
    stream.write("\n")


def _wants_json(argv: list[str] | None) -> bool:
    return bool(argv and "--json" in argv)


def _scrub(text: str) -> str:
    token = os.getenv("MEDIATOR_TSA_BEARER_TOKEN", "").strip()
    if token and token in text:
        return text.replace(token, "[redacted]")
    return text


if __name__ == "__main__":
    raise SystemExit(main())
