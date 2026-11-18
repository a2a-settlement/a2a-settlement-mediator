"""SEC 17a-4 WORM-compliant settlement orchestration pipeline.

This is the core engine that wires together:
1. Ingestion of hashed negotiation transcripts + AP2 mandates
2. LLM arbitration via LiteLLM
3. Pre-Dispute Attestation Payload construction
4. RFC 3161 timestamping via a Time Stamp Authority
5. Append to an immutable Merkle Tree with mathematical verification
6. Final cryptographic proof assembly

Hard-fail semantics: if the Merkle append fails verification or the TSA
times out, the entire settlement is rejected.  No partial results escape.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from datetime import datetime, timezone

import litellm

from a2a_settlement_mediator.arbitration_prompts import (
    ARBITRATION_SYSTEM_PROMPT,
    build_arbitration_prompt,
)
from a2a_settlement_mediator import storage
from a2a_settlement_mediator.config import settings, temperature_kwargs
from a2a_settlement_mediator.merkle import MerkleTree
from a2a_settlement_mediator.tsa_client import (
    RFC3161Client,
    TSAClientError,
    TSATimeoutError,
)
from a2a_settlement_mediator.worm_schemas import (
    AgentIdentity,
    AP2Mandate,
    ArbitrationDecision,
    ArbitrationRequest,
    ArbitrationVerdict,
    CurrencyPrecision,
    ExecutionStatus,
    MerkleAppendResult,
    MerkleLeaf,
    MerkleLeafPayload,
    MerkleProof,
    NegotiationTranscript,
    PreDisputeAttestationPayload,
    SettlementProof,
    SettlementResult,
    SettlementStage,
    TimestampToken,
)

logger = logging.getLogger(__name__)

litellm.suppress_debug_info = True

# Module-level Merkle Tree: append-only, shared by every pipeline invocation
# in this process.
#
# The module has two modes. As imported, the tree and the recovery ledger live
# in process memory only, which is what a library caller or a unit test gets.
# The service calls ``restore_ledger()`` at startup, which switches to the
# durable mode: the tree is rebuilt from the ``merkle_leaves`` table and every
# append is written to it, and the recovery ledger is the
# ``settlement_results`` table.
_merkle_tree = MerkleTree()

# True once restore_ledger() has run: SQLite is the source of truth.
_durable = False
# Non-empty when the stored leaves do not rebuild to the stored root. While it
# is non-empty no leaf is appended.
_ledger_problems: list[str] = []
# What the one-time import of results stored by earlier releases found.
_legacy_report: dict | None = None
# Set when an append failed after the in-memory tree was extended, so the tree
# holds a leaf that was never committed and must be rebuilt before reuse.
_uncommitted = False
# Serializes appends and catch-up within this process. Across processes the
# database write lock does the same job.
_persist_lock = threading.RLock()

_LEGACY_IMPORT_KEY = "merkle_legacy_import"


def get_merkle_tree() -> MerkleTree:
    """Return the module-level Merkle Tree (useful for inspection/testing)."""
    return _merkle_tree


def ledger_problems() -> list[str]:
    """Why the stored Merkle tree is inconsistent; empty when it is sound."""
    return list(_ledger_problems)


def _report_problem(problem: str) -> None:
    logger.error("MERKLE LEDGER INCONSISTENT: %s", problem)
    if problem not in _ledger_problems:
        _ledger_problems.append(problem)


def _extend_from_rows(tree: MerkleTree, rows: list) -> list[str]:
    """Append stored leaves to *tree* in order and return what is wrong with them.

    Checks that the indexes continue the tree without a gap, that each leaf
    whose text was stored still hashes to its stored leaf hash, and that the
    root after the last row equals the root stored with that row.
    """
    problems: list[str] = []
    for row in rows:
        index, leaf_hex = row["leaf_index"], row["leaf_hash"]
        if index != tree.size:
            problems.append(
                f"stored leaves are not consecutive: expected leaf {tree.size}, found {index}"
            )
        if row["leaf_data"] is not None:
            recomputed = MerkleTree.hash_leaf(row["leaf_data"].encode("utf-8")).hex()
            if recomputed != leaf_hex:
                problems.append(
                    f"leaf {index}: stored leaf data hashes to {recomputed}, "
                    f"stored leaf hash is {leaf_hex}"
                )
        try:
            tree.append_leaf_hash(bytes.fromhex(leaf_hex))
        except ValueError:
            problems.append(f"leaf {index}: stored leaf hash is not a SHA-256 digest")
            tree.append_leaf_hash(bytes(32))
    if rows:
        rebuilt, stored = tree.root_hash.hex(), rows[-1]["root_hash"]
        if rebuilt != stored:
            problems.append(
                f"rebuilt root {rebuilt} over {tree.size} leaves does not match the root "
                f"{stored} stored with leaf {rows[-1]['leaf_index']}"
            )
    return problems


def _adopt_legacy_tree(conn) -> dict:
    """One-time import of results stored before the ``merkle_leaves`` table existed.

    Earlier releases kept the tree in process memory and started a new, empty
    tree at every restart, so the stored results can belong to several
    unrelated trees. Only the most recent one can be continued, and only when
    every one of its leaves is stored: its rows must carry leaf indexes
    0..n-1 in insertion order, each row's root must be the root of the leaves
    up to it, and each row's own proof must verify. If so, its leaf hashes
    become the first n leaves of the durable tree. Otherwise nothing is
    adopted and the durable tree starts empty.

    The outcome is recorded in ``ledger_meta`` so this runs once.
    """
    recorded = storage.get_meta(conn, _LEGACY_IMPORT_KEY)
    if recorded is not None:
        return json.loads(recorded)

    rows = storage.settlement_results_in_insertion_order(conn)
    report: dict = {
        "stored_results": len(rows),
        "trees_detected": 0,
        "adopted_leaves": 0,
        "rows_outside_tree": len(rows),
        "reason": None,
    }

    if storage.load_merkle_leaves(conn):
        linked = conn.execute(
            "SELECT COUNT(*) FROM settlement_results s WHERE EXISTS "
            "(SELECT 1 FROM merkle_leaves l WHERE l.settlement_hash = s.settlement_hash)"
        ).fetchone()[0]
        report["rows_outside_tree"] = len(rows) - linked
        report["reason"] = "the durable tree already had leaves; nothing was adopted"
    elif rows:
        entries: list[dict | None] = []
        for row in rows:
            try:
                merkle = json.loads(row["data"])["proof"]["merkle_result"]
                entries.append(
                    {
                        "settlement_hash": row["settlement_hash"],
                        "leaf_index": int(merkle["leaf"]["leaf_index"]),
                        "leaf_hash": bytes.fromhex(merkle["leaf"]["leaf_hash"]),
                        "root_hash": merkle["root_hash"],
                        "tree_size": int(merkle["tree_size"]),
                        "siblings": [bytes.fromhex(x) for x in merkle["proof"]["siblings"]],
                        "directions": list(merkle["proof"]["directions"]),
                    }
                )
            except (KeyError, TypeError, ValueError):
                entries.append(None)

        # A tree starts wherever the leaf index stops increasing.
        last_start = 0
        trees = 1
        for i in range(1, len(entries)):
            prev, cur = entries[i - 1], entries[i]
            if prev is None or cur is None or cur["leaf_index"] <= prev["leaf_index"]:
                trees += 1
                last_start = i
        report["trees_detected"] = trees

        candidate = entries[last_start:]
        reason = None
        tree = MerkleTree()
        for position, entry in enumerate(candidate):
            if entry is None:
                reason = "a stored result has no readable Merkle proof"
                break
            if entry["leaf_index"] != position:
                reason = (
                    f"the most recent tree is incomplete: expected leaf {position}, "
                    f"found leaf {entry['leaf_index']}"
                )
                break
            tree.append_leaf_hash(entry["leaf_hash"])
            root = tree.root_hash
            if entry["tree_size"] != position + 1 or entry["root_hash"] != root.hex():
                reason = f"leaf {position}: the stored root is not the root of the stored leaves"
                break
            if not MerkleTree.verify_proof(
                entry["leaf_hash"], entry["siblings"], entry["directions"], root
            ):
                reason = f"leaf {position}: the stored inclusion proof does not verify"
                break

        if reason is None:
            for position, entry in enumerate(candidate):
                storage.insert_merkle_leaf(
                    conn,
                    position,
                    entry["leaf_hash"].hex(),
                    entry["root_hash"],
                    None,
                    settlement_hash=entry["settlement_hash"],
                    origin="legacy",
                )
            report["adopted_leaves"] = len(candidate)
            report["rows_outside_tree"] = len(rows) - len(candidate)
        else:
            report["reason"] = reason

    storage.set_meta(conn, _LEGACY_IMPORT_KEY, json.dumps(report))
    if report["adopted_leaves"]:
        logger.warning(
            "Adopted %d leaf hash(es) of the most recent in-memory Merkle tree from stored "
            "settlement results",
            report["adopted_leaves"],
        )
    if report["reason"]:
        logger.warning(
            "Stored settlement results were not adopted into the tree: %s", report["reason"]
        )
    if report["rows_outside_tree"]:
        logger.warning(
            "%d stored settlement result(s) belong to earlier in-memory Merkle trees that "
            "cannot be rebuilt; their stored proofs verify only against the root stored "
            "with each of them",
            report["rows_outside_tree"],
        )
    return report


def _check_links(conn, legacy: dict) -> list[str]:
    """Check stored leaves and stored results against each other."""
    problems: list[str] = []
    rows = conn.execute(
        "SELECT l.leaf_index, l.leaf_hash, s.data FROM merkle_leaves l "
        "LEFT JOIN settlement_results s ON s.settlement_hash = l.settlement_hash "
        "WHERE l.settlement_hash IS NOT NULL ORDER BY l.leaf_index"
    ).fetchall()
    for row in rows:
        if row["data"] is None:
            problems.append(f"leaf {row['leaf_index']}: its settlement result is not stored")
            continue
        try:
            leaf = json.loads(row["data"])["proof"]["merkle_result"]["leaf"]
            matches = (
                leaf["leaf_index"] == row["leaf_index"] and leaf["leaf_hash"] == row["leaf_hash"]
            )
        except (KeyError, TypeError, ValueError):
            matches = False
        if not matches:
            problems.append(
                f"leaf {row['leaf_index']}: the stored settlement result names a different leaf"
            )

    unlinked = conn.execute(
        "SELECT COUNT(*) FROM settlement_results s WHERE NOT EXISTS "
        "(SELECT 1 FROM merkle_leaves l WHERE l.settlement_hash = s.settlement_hash)"
    ).fetchone()[0]
    expected = int(legacy.get("rows_outside_tree", 0))
    if unlinked > expected:
        problems.append(
            f"{unlinked} stored settlement result(s) have no leaf in the tree, "
            f"{expected} expected: leaves are missing from the end of the tree, or "
            "settlements were stored by a release that kept the tree in memory"
        )
    return problems


def restore_ledger() -> dict:
    """Make SQLite the source of truth for the Merkle tree and the recovery ledger.

    Called once at service startup, after ``storage.initialize_db()``. Rebuilds
    the tree from the stored leaves, in insertion order, and checks the result
    against what is stored. A mismatch is logged at ERROR and remembered: the
    stored leaves stay loaded for inspection, ``merkle_status()`` reports
    ``consistent: false``, and no further leaf is appended. The tree is never
    silently restarted at size 0.

    Returns the same dict as ``merkle_status()``.
    """
    global _merkle_tree, _durable, _legacy_report, _uncommitted

    with _persist_lock:
        tree = MerkleTree()
        with storage.write_transaction() as conn:
            legacy = _adopt_legacy_tree(conn)
            problems = _extend_from_rows(tree, storage.load_merkle_leaves(conn))
            problems += _check_links(conn, legacy)

        _merkle_tree = tree
        _legacy_report = legacy
        _uncommitted = False
        _ledger_problems.clear()
        _durable = True
        for problem in problems:
            _report_problem(problem)

        if problems:
            logger.error(
                "MERKLE LEDGER INCONSISTENT: %d problem(s) found; POST /settle is refused "
                "until this is resolved. The stored leaves were NOT discarded.",
                len(problems),
            )
        else:
            logger.info(
                "Merkle tree restored from storage: %d leaves, root=%s",
                tree.size,
                tree.root_hash.hex() if tree.size else "<empty>",
            )
        return _status_locked()


def detach_ledger() -> None:
    """Return to the in-memory mode with an empty tree. Stored data is untouched.

    Called when the service shuts down, so that a process which goes on to use
    the pipeline as a library (a test run, for one) does not keep writing to
    the service's database.
    """
    global _merkle_tree, _durable, _legacy_report, _uncommitted

    with _persist_lock:
        _durable = False
        _merkle_tree = MerkleTree()
        _legacy_report = None
        _uncommitted = False
        _ledger_problems.clear()


def _catch_up(conn) -> None:
    """Bring this process's tree up to date with the stored leaves.

    Another worker process sharing the database may have appended since this
    process last looked. Raises SettlementHardFail if the stored leaves do not
    continue this process's tree.
    """
    global _merkle_tree, _uncommitted

    if _uncommitted:
        tree = MerkleTree()
        problems = _extend_from_rows(tree, storage.load_merkle_leaves(conn))
        _merkle_tree = tree
        _uncommitted = False
    else:
        tree = _merkle_tree
        problems = []
        size = tree.size
        if size:
            row = conn.execute(
                "SELECT root_hash FROM merkle_leaves WHERE leaf_index = ?", (size - 1,)
            ).fetchone()
            stored_count = conn.execute("SELECT COUNT(*) FROM merkle_leaves").fetchone()[0]
            if row is None or stored_count < size:
                problems.append(
                    f"this process holds {size} leaves but storage holds {stored_count}"
                )
            elif row["root_hash"] != tree.root_hash.hex():
                problems.append(
                    f"the root stored with leaf {size - 1} is not the root this process "
                    "computed for it"
                )
        if not problems:
            problems = _extend_from_rows(tree, storage.load_merkle_leaves(conn, start=size))

    for problem in problems:
        _report_problem(problem)
    if problems:
        raise SettlementHardFail(
            "HARD FAIL: the stored Merkle tree is inconsistent — settlement cannot proceed. "
            + "; ".join(problems)
        )


def _append_durable(payload: bytes) -> tuple[int, bytes, list[bytes], list[str], bytes]:
    """Append one leaf to the stored tree and to this process's copy of it.

    The whole step runs inside one database write transaction: read any leaves
    other processes appended, append, insert the new row, commit. Two writers,
    whether threads or processes, therefore never use the same leaf index.
    """
    global _uncommitted

    with _persist_lock:
        if _ledger_problems:
            raise SettlementHardFail(
                "HARD FAIL: the stored Merkle tree is inconsistent — settlement cannot "
                "proceed. " + "; ".join(_ledger_problems)
            )
        try:
            with storage.write_transaction() as conn:
                _catch_up(conn)
                appended = _merkle_tree.append_and_prove(payload)
                _uncommitted = True
                leaf_index, leaf_hash, _siblings, _directions, root_hash = appended
                storage.insert_merkle_leaf(
                    conn, leaf_index, leaf_hash.hex(), root_hash.hex(), payload.decode("utf-8")
                )
            _uncommitted = False
        except SettlementHardFail:
            raise
        except Exception as exc:
            raise SettlementHardFail(
                f"HARD FAIL: Merkle Tree append failed — settlement cannot proceed. {exc}"
            ) from exc
        return appended


def _status_locked() -> dict:
    tree = _merkle_tree
    size = tree.size
    return {
        "tree_size": size,
        "root_hash": tree.root_hash.hex() if size > 0 else None,
        "persistent": _durable,
        "consistent": not _ledger_problems,
        "problems": list(_ledger_problems),
        "legacy": _legacy_report,
    }


def merkle_status() -> dict:
    """Size and root of the tree, and whether it agrees with what is stored.

    In the durable mode this first reads any leaves another worker process
    appended, so every worker reports the same tree.
    """
    with _persist_lock:
        if _durable and not _ledger_problems:
            try:
                with storage.write_transaction() as conn:
                    _catch_up(conn)
            except SettlementHardFail:
                pass  # recorded in _ledger_problems and reported below
        return _status_locked()


# ---------------------------------------------------------------------------
# Gatekeeper recovery ledger
# ---------------------------------------------------------------------------
# Completed settlements whose Merkle leaf is confirmed but whose mandate has
# not yet been released to the execution engine. In the durable mode this is
# the ``settlement_results`` table and nothing is kept in memory. Otherwise it
# is the dict below, which is lost with the process.

_confirmed_settlements: dict[str, SettlementResult] = {}
_confirmed_lock = threading.Lock()


def _stored_results(rows: list[dict]) -> list[SettlementResult]:
    results = []
    for row in rows:
        try:
            results.append(SettlementResult.model_validate(row))
        except ValueError:
            logger.exception("A stored settlement result could not be read; skipping it")
    return results


def _record_confirmed(result: SettlementResult) -> None:
    """Record a settlement whose Merkle leaf is confirmed."""
    if result.proof is None:
        return
    if _durable:
        storage.save_settlement_result(
            result.proof.settlement_hash,
            result.model_dump_json(),
            leaf_index=result.proof.merkle_result.leaf.leaf_index,
        )
        return
    with _confirmed_lock:
        _confirmed_settlements[result.proof.settlement_hash] = result


def mark_executed(settlement_hash: str) -> bool:
    """Mark a confirmed settlement as successfully executed.

    Called by the execution engine after the AP2 Mandate has been
    released.  Returns True if the settlement was found and marked. In the
    durable mode a settlement already marked failed stays failed and this
    returns False.
    """
    if _durable:
        return storage.mark_settlement_executed(settlement_hash)
    with _confirmed_lock:
        result = _confirmed_settlements.get(settlement_hash)
        if result is None:
            return False
        result.execution_status = ExecutionStatus.EXECUTED
        return True


def mark_failed(settlement_hash: str, error: str) -> bool:
    """Mark a confirmed settlement as failed during execution.

    Returns True if the settlement was found and marked. In the durable mode
    a settlement already marked executed stays executed and this returns False.
    """
    if _durable:
        return storage.mark_settlement_failed(settlement_hash, error)
    with _confirmed_lock:
        result = _confirmed_settlements.get(settlement_hash)
        if result is None:
            return False
        result.execution_status = ExecutionStatus.FAILED
        result.error = error
        return True


def get_pending_settlements() -> list[SettlementResult]:
    """Return all confirmed settlements that have not been marked executed.

    The Gatekeeper's recovery loop should periodically call this and
    re-emit the AP2 Mandate for each pending settlement.
    """
    if _durable:
        return _stored_results(storage.list_pending_settlement_results())
    with _confirmed_lock:
        return [
            r
            for r in _confirmed_settlements.values()
            if r.execution_status == ExecutionStatus.PENDING
        ]


def get_confirmed_settlement(settlement_hash: str) -> SettlementResult | None:
    """Look up a confirmed settlement by its settlement hash."""
    if _durable:
        stored = storage.get_settlement_result(settlement_hash)
        return SettlementResult.model_validate(stored) if stored is not None else None
    with _confirmed_lock:
        return _confirmed_settlements.get(settlement_hash)


def get_stale_settlements(threshold_seconds: float) -> list[SettlementResult]:
    """Return confirmed settlements that have been PENDING longer than *threshold_seconds*.

    Used by the heartbeat worker to detect settlements where the Merkle
    leaf was committed but execution never completed.
    """
    now = datetime.now(timezone.utc)
    if _durable:
        return [
            r
            for r in get_pending_settlements()
            if (now - r.completed_at).total_seconds() > threshold_seconds
        ]
    with _confirmed_lock:
        return [
            r
            for r in _confirmed_settlements.values()
            if r.execution_status == ExecutionStatus.PENDING
            and (now - r.completed_at).total_seconds() > threshold_seconds
        ]


class SettlementHardFail(Exception):
    """Raised when the pipeline must abort with no partial result."""


class IngestionLimitExceeded(ValueError):
    """Raised when inbound data exceeds configured size limits.

    Prevents "Context Bomb" attacks where a malicious agent floods the
    mediator with oversized payloads to drive up LLM costs or cause
    evaluation timeouts.
    """


# ---------------------------------------------------------------------------
# Ingestion validation (Context Bomb mitigation)
# ---------------------------------------------------------------------------


def _validate_ingestion(
    transcript: NegotiationTranscript,
    mandates: list[AP2Mandate],
) -> None:
    """Enforce size limits on transcript and mandate payloads.

    Raises IngestionLimitExceeded if any limit is breached.
    """
    if len(transcript.transcript_hash) > settings.max_transcript_hash_length:
        raise IngestionLimitExceeded(
            f"transcript_hash length {len(transcript.transcript_hash)} exceeds "
            f"limit of {settings.max_transcript_hash_length} characters"
        )

    if len(mandates) > settings.max_mandates_per_settlement:
        raise IngestionLimitExceeded(
            f"mandate count {len(mandates)} exceeds "
            f"limit of {settings.max_mandates_per_settlement}"
        )

    total_chars = 0
    for m in mandates:
        if len(m.description) > settings.max_mandate_description_length:
            raise IngestionLimitExceeded(
                f"mandate {m.mandate_id!r} description length "
                f"{len(m.description)} exceeds limit of "
                f"{settings.max_mandate_description_length}"
            )
        if len(m.conditions) > settings.max_conditions_per_mandate:
            raise IngestionLimitExceeded(
                f"mandate {m.mandate_id!r} has {len(m.conditions)} conditions, "
                f"exceeding limit of {settings.max_conditions_per_mandate}"
            )
        total_chars += len(m.description) + sum(len(c) for c in m.conditions)

    if total_chars > settings.max_mandate_payload_chars:
        raise IngestionLimitExceeded(
            f"total mandate payload size {total_chars} chars exceeds "
            f"limit of {settings.max_mandate_payload_chars}"
        )


# ---------------------------------------------------------------------------
# Stage 1 — LLM arbitration
# ---------------------------------------------------------------------------


def _call_arbitration_llm(request: ArbitrationRequest) -> ArbitrationVerdict:
    """Send the arbitration request to LiteLLM and parse the verdict."""
    mandates_json = json.dumps(
        [m.model_dump(mode="json") for m in request.mandates],
        indent=2,
    )
    user_prompt = build_arbitration_prompt(
        transcript_hash=request.transcript.transcript_hash,
        source_service=request.transcript.source_service,
        session_id=request.transcript.session_id,
        mandates_json=mandates_json,
        escrow_id=request.escrow_id,
    )

    t0 = time.monotonic()
    response = litellm.completion(
        model=settings.llm_model,
        messages=[
            {"role": "system", "content": ARBITRATION_SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        **temperature_kwargs(),
        max_tokens=settings.llm_max_tokens,
        timeout=settings.llm_timeout_seconds,
    )
    latency_ms = int((time.monotonic() - t0) * 1000)

    raw_text = response.choices[0].message.content.strip()
    prompt_tokens = response.usage.prompt_tokens if response.usage else 0
    completion_tokens = response.usage.completion_tokens if response.usage else 0

    if settings.audit_log_enabled:
        logger.info("Arbitration LLM response (%dms): %s", latency_ms, raw_text)

    # Strip markdown fences if present
    if raw_text.startswith("```"):
        raw_text = raw_text.split("\n", 1)[1] if "\n" in raw_text else raw_text[3:]
        if raw_text.endswith("```"):
            raw_text = raw_text[:-3]
        raw_text = raw_text.strip()

    parsed = json.loads(raw_text)

    decision_str = parsed.get("decision", "").upper()
    if decision_str not in ("APPROVED", "REJECTED"):
        raise ValueError(f"LLM returned unrecognized decision: {decision_str!r}")

    confidence = max(0.0, min(1.0, float(parsed.get("confidence", 0.0))))

    # Low confidence forces REJECTED regardless of LLM output
    if confidence < 0.5:
        decision_str = "REJECTED"

    return ArbitrationVerdict(
        decision=ArbitrationDecision(decision_str),
        confidence=confidence,
        reasoning=parsed.get("reasoning", "No reasoning provided"),
        factors=parsed.get("factors", []),
        mandate_compliance=parsed.get("mandate_compliance", {}),
        llm_model=settings.llm_model,
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        latency_ms=latency_ms,
    )


# ---------------------------------------------------------------------------
# Stage 2 — Attestation payload construction
# ---------------------------------------------------------------------------


def _build_attestation_payload(
    transcript: NegotiationTranscript,
    mandates: list[AP2Mandate],
    verdict: ArbitrationVerdict,
) -> PreDisputeAttestationPayload:
    """Construct the immutable Pre-Dispute Attestation Payload."""
    payload_hash = PreDisputeAttestationPayload.compute_hash(transcript, mandates, verdict)

    return PreDisputeAttestationPayload(
        transcript=transcript,
        mandates=mandates,
        verdict=verdict,
        payload_hash=payload_hash,
    )


# ---------------------------------------------------------------------------
# Stage 3 — RFC 3161 timestamping
# ---------------------------------------------------------------------------


def _request_timestamp(payload_hash_hex: str) -> TimestampToken:
    """Request an RFC 3161 timestamp for the attestation payload hash.

    Raises SettlementHardFail on timeout or TSA error.
    """
    tsa = RFC3161Client(
        tsa_url=settings.tsa_url,
        timeout_seconds=settings.tsa_timeout_seconds,
    )

    payload_hash_bytes = bytes.fromhex(payload_hash_hex)

    try:
        return tsa.request_timestamp(payload_hash_bytes)
    except TSATimeoutError as exc:
        raise SettlementHardFail(
            f"HARD FAIL: TSA server timed out — settlement cannot proceed. {exc}"
        ) from exc
    except TSAClientError as exc:
        raise SettlementHardFail(
            f"HARD FAIL: TSA request failed — settlement cannot proceed. {exc}"
        ) from exc


# ---------------------------------------------------------------------------
# Stage 4 — Merkle Tree append + verification
# ---------------------------------------------------------------------------


def _append_to_merkle_tree(timestamped_payload: bytes) -> MerkleAppendResult:
    """Append the timestamped payload to the Merkle Tree and verify the proof.

    The Merkle append and proof generation happen atomically under a lock.
    In the durable mode the leaf is also committed to storage before this
    returns, inside the same critical section.
    After the append, the proof is independently verified against the new
    root hash.  If verification fails, the settlement hard-fails.

    Raises SettlementHardFail if the proof does not verify.
    """
    data_hash = hashlib.sha256(timestamped_payload).hexdigest()

    if _durable:
        leaf_index, leaf_hash, siblings, directions, root_hash = _append_durable(
            timestamped_payload
        )
    else:
        try:
            leaf_index, leaf_hash, siblings, directions, root_hash = (
                _merkle_tree.append_and_prove(timestamped_payload)
            )
        except Exception as exc:
            raise SettlementHardFail(
                f"HARD FAIL: Merkle Tree append failed — settlement cannot proceed. {exc}"
            ) from exc
    # The size the proof was computed at. Reading the tree's size again here
    # could include leaves appended by other threads in the meantime.
    tree_size = leaf_index + 1

    verified = MerkleTree.verify_proof(leaf_hash, siblings, directions, root_hash)

    if not verified:
        raise SettlementHardFail(
            "HARD FAIL: Merkle Tree proof verification failed — "
            "the append was NOT mathematically successful. "
            f"leaf_index={leaf_index} root={root_hash.hex()}"
        )

    logger.info(
        "Merkle append verified: leaf=%d root=%s tree_size=%d",
        leaf_index,
        root_hash.hex(),
        tree_size,
    )

    return MerkleAppendResult(
        leaf=MerkleLeaf(
            leaf_index=leaf_index,
            leaf_hash=leaf_hash.hex(),
            data_hash=data_hash,
        ),
        proof=MerkleProof(
            leaf_index=leaf_index,
            leaf_hash=leaf_hash.hex(),
            siblings=[s.hex() for s in siblings],
            directions=directions,
            root_hash=root_hash.hex(),
            tree_size=tree_size,
        ),
        root_hash=root_hash.hex(),
        tree_size=tree_size,
        verified=True,
    )


# ---------------------------------------------------------------------------
# Stage 5 — Settlement proof assembly
# ---------------------------------------------------------------------------


def _assemble_proof(
    attestation: PreDisputeAttestationPayload,
    timestamp: TimestampToken,
    merkle_result: MerkleAppendResult,
) -> SettlementProof:
    """Assemble the final cryptographic proof tying all components together."""
    binding_input = (
        f"{attestation.payload_hash}:"
        f"{timestamp.message_hash}:"
        f"{merkle_result.root_hash}"
    )
    settlement_hash = hashlib.sha256(binding_input.encode("utf-8")).hexdigest()

    return SettlementProof(
        attestation_payload=attestation,
        timestamp=timestamp,
        merkle_result=merkle_result,
        settlement_hash=settlement_hash,
    )


# ---------------------------------------------------------------------------
# Main pipeline entry point
# ---------------------------------------------------------------------------


def settle(
    transcript: NegotiationTranscript,
    mandates: list[AP2Mandate],
    escrow_id: str | None = None,
    agent_identities: list[AgentIdentity] | None = None,
    currency_precision: CurrencyPrecision | None = None,
) -> SettlementResult:
    """Run the full SEC 17a-4 WORM-compliant settlement pipeline.

    Pipeline stages:
        1. ARBITRATION — Call LiteLLM with transcript hash + AP2 mandates
        2. ATTESTATION — If APPROVED, build the Pre-Dispute Attestation Payload
        3. TIMESTAMPING — Request an RFC 3161 timestamp from the TSA
        4. MERKLE_APPEND — Append timestamped payload to the Merkle Tree
        5. MERKLE_VERIFY — Verify the Merkle proof is mathematically correct
        6. COMPLETE — Assemble and return the full cryptographic proof

    Hard-fail semantics:
        - TSA timeout → settlement fails, no proof is returned
        - Merkle append failure → settlement fails, no proof is returned
        - Merkle verification failure → settlement fails, no proof is returned

    Returns:
        SettlementResult with success=True and a full SettlementProof,
        or success=False with error details and the stage where failure occurred.
    """
    started_at = datetime.now(timezone.utc)
    stage = SettlementStage.INGESTION

    logger.info(
        "Settlement pipeline started — transcript_hash=%s mandates=%d escrow=%s",
        transcript.transcript_hash[:16] + "...",
        len(mandates),
        escrow_id or "none",
    )

    # --- Stage 0: Ingestion validation (Context Bomb mitigation) ---
    try:
        _validate_ingestion(transcript, mandates)
    except IngestionLimitExceeded as exc:
        logger.warning("Ingestion rejected: %s", exc)
        return SettlementResult(
            success=False,
            error=f"Ingestion limit exceeded: {exc}",
            stage_reached=stage,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    request = ArbitrationRequest(
        transcript=transcript,
        mandates=mandates,
        escrow_id=escrow_id,
    )

    # --- Stage 1: Arbitration ---
    stage = SettlementStage.ARBITRATION
    try:
        verdict = _call_arbitration_llm(request)
    except json.JSONDecodeError as exc:
        logger.error("Arbitration LLM returned invalid JSON: %s", exc)
        return SettlementResult(
            success=False,
            error=f"Arbitration LLM returned invalid JSON: {exc}",
            stage_reached=stage,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )
    except Exception as exc:
        logger.error("Arbitration LLM call failed: %s", exc)
        return SettlementResult(
            success=False,
            error=f"Arbitration failed: {exc}",
            stage_reached=stage,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    logger.info(
        "Arbitration verdict: %s (confidence=%.2f)",
        verdict.decision.value,
        verdict.confidence,
    )

    # Gate: only APPROVED proceeds
    if verdict.decision != ArbitrationDecision.APPROVED:
        return SettlementResult(
            success=False,
            error=f"Arbitration REJECTED: {verdict.reasoning}",
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    # --- Stage 2: Build Attestation Payload ---
    stage = SettlementStage.ATTESTATION_BUILD
    try:
        attestation = _build_attestation_payload(transcript, mandates, verdict)
    except Exception as exc:
        logger.error("Attestation payload construction failed: %s", exc)
        return SettlementResult(
            success=False,
            error=f"Attestation construction failed: {exc}",
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    logger.info("Attestation payload built — hash=%s", attestation.payload_hash[:16] + "...")

    # --- Stage 3: RFC 3161 Timestamp ---
    stage = SettlementStage.TIMESTAMPING
    try:
        timestamp = _request_timestamp(attestation.payload_hash)
    except SettlementHardFail as exc:
        logger.error("Settlement hard-fail at timestamping: %s", exc)
        return SettlementResult(
            success=False,
            error=str(exc),
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    logger.info("RFC 3161 timestamp obtained from %s", timestamp.tsa_url)

    # --- Stage 4 + 5: Merkle Tree Append + Verify ---
    stage = SettlementStage.MERKLE_APPEND

    effective_identities = agent_identities or [
        AgentIdentity(agent_id="unknown-buyer", role="buyer"),
        AgentIdentity(agent_id="unknown-seller", role="seller"),
    ]
    effective_precision = currency_precision or CurrencyPrecision(
        currency_code="USD", decimal_places=2,
    )

    leaf_payload_hash = MerkleLeafPayload.compute_hash(
        agent_identities=effective_identities,
        currency_precision=effective_precision,
        attestation=attestation,
        timestamp=timestamp,
    )
    leaf_payload = MerkleLeafPayload(
        agent_identities=effective_identities,
        currency_precision=effective_precision,
        attestation=attestation,
        timestamp=timestamp,
        payload_hash=leaf_payload_hash,
    )
    leaf_payload_json = json.dumps(
        leaf_payload.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    )
    timestamped_payload_bytes = leaf_payload_json.encode("utf-8")

    try:
        merkle_result = _append_to_merkle_tree(timestamped_payload_bytes)
    except SettlementHardFail as exc:
        logger.error("Settlement hard-fail at Merkle append: %s", exc)
        return SettlementResult(
            success=False,
            error=str(exc),
            stage_reached=stage,
            arbitration_verdict=verdict,
            started_at=started_at,
            completed_at=datetime.now(timezone.utc),
        )

    stage = SettlementStage.MERKLE_VERIFY
    # Verification already happened inside _append_to_merkle_tree;
    # if we reach here, the proof is valid.

    # --- Stage 6: Assemble Final Proof ---
    stage = SettlementStage.COMPLETE
    proof = _assemble_proof(attestation, timestamp, merkle_result)

    logger.info(
        "Settlement complete — settlement_hash=%s merkle_root=%s tree_size=%d",
        proof.settlement_hash[:16] + "...",
        merkle_result.root_hash[:16] + "...",
        merkle_result.tree_size,
    )

    result = SettlementResult(
        success=True,
        proof=proof,
        stage_reached=stage,
        arbitration_verdict=verdict,
        execution_status=ExecutionStatus.PENDING,
        started_at=started_at,
        completed_at=datetime.now(timezone.utc),
    )

    _record_confirmed(result)

    return result
