"""Background heartbeat worker for Gatekeeper recovery.

Periodically scans the confirmed-settlements ledger for entries that have
been PENDING longer than a configurable threshold.  When stale settlements
are found and an execution callback URL is configured, the worker POSTs
each settlement to the callback.  A successful 2xx response causes the
settlement to be marked EXECUTED; failures are logged and retried on the
next tick.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone

import httpx

from a2a_settlement_mediator.config import settings
from a2a_settlement_mediator.settlement_pipeline import (
    get_stale_settlements,
    mark_executed,
)

logger = logging.getLogger(__name__)


class HeartbeatWorker:
    """Daemon thread that recovers stale PENDING settlements."""

    def __init__(
        self,
        interval: float | None = None,
        threshold: float | None = None,
        callback_url: str | None = None,
    ) -> None:
        self._interval = interval if interval is not None else settings.heartbeat_interval_seconds
        self._threshold = (
            threshold if threshold is not None else settings.stale_settlement_threshold_seconds
        )
        self._callback_url = (
            callback_url if callback_url is not None else settings.execution_callback_url
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._last_scan_at: datetime | None = None
        self._last_stale_count: int = 0

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def last_scan_at(self) -> datetime | None:
        return self._last_scan_at

    @property
    def last_stale_count(self) -> int:
        return self._last_stale_count

    def start(self) -> None:
        """Start the heartbeat background thread."""
        if self.running:
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="heartbeat")
        self._thread.start()
        logger.info(
            "Heartbeat worker started (interval=%.1fs, threshold=%.1fs, callback=%s)",
            self._interval,
            self._threshold,
            self._callback_url or "<none>",
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the worker to stop and wait up to *timeout* seconds."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None
        logger.info("Heartbeat worker stopped")

    def status(self) -> dict:
        """Return a snapshot of the worker's state."""
        return {
            "running": self.running,
            "interval_seconds": self._interval,
            "threshold_seconds": self._threshold,
            "callback_url": self._callback_url or None,
            "last_scan_at": self._last_scan_at.isoformat() if self._last_scan_at else None,
            "last_stale_count": self._last_stale_count,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                self._tick()
            except Exception:
                logger.exception("Heartbeat tick failed")
            self._stop_event.wait(timeout=self._interval)

    def _tick(self) -> None:
        stale = get_stale_settlements(self._threshold)
        self._last_scan_at = datetime.now(timezone.utc)
        self._last_stale_count = len(stale)

        if not stale:
            return

        logger.warning(
            "Heartbeat detected %d stale PENDING settlement(s)", len(stale),
        )

        if not self._callback_url:
            return

        for result in stale:
            settlement_hash = result.proof.settlement_hash  # type: ignore[union-attr]
            try:
                with httpx.Client(timeout=10.0) as client:
                    resp = client.post(
                        self._callback_url,
                        json=result.model_dump(mode="json"),
                    )
                if resp.is_success:
                    mark_executed(settlement_hash)
                    logger.info(
                        "Heartbeat auto-executed settlement %s (callback %d)",
                        settlement_hash[:16] + "...",
                        resp.status_code,
                    )
                else:
                    logger.warning(
                        "Execution callback returned %d for %s — will retry",
                        resp.status_code,
                        settlement_hash[:16] + "...",
                    )
            except httpx.HTTPError as exc:
                logger.warning(
                    "Execution callback failed for %s: %s — will retry",
                    settlement_hash[:16] + "...",
                    exc,
                )
