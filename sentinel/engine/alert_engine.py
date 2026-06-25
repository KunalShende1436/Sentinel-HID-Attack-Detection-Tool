"""
sentinel.engine.alert_engine
==============================
Central alert processing pipeline.

Responsibilities:
    1. **Receive** alerts from all detector modules via a thread-safe queue.
    2. **Score** — apply composite threat scoring (future: correlation).
    3. **Deduplicate** — suppress repeated alerts from the same source
       within a configurable cooldown window.
    4. **Dispatch** — log every alert as structured JSON and, when the
       threat score exceeds the snapshot threshold, trigger the
       forensic snapshot engine.
    5. **Rate-limit** — self-throttle to prevent alert storms from
       degrading system performance.

The engine runs in its own daemon thread, consuming from the shared
``Queue[Alert]`` that all detectors write to.
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from queue import Empty, Queue
from typing import Callable, Dict, List, Optional

from sentinel.config import ALERT_CFG, LOG_DIR, AlertConfig
from sentinel.core import Alert, Severity
from sentinel.forensics import capture_snapshot
from sentinel.response import try_kill_process

_log = logging.getLogger("sentinel.alert_engine")


# ── JSON log writer ──────────────────────────────────────────────
class _JsonLogWriter:
    """Append-only JSON-lines file for structured alert persistence."""

    def __init__(self, log_dir: Path) -> None:
        log_dir.mkdir(parents=True, exist_ok=True)
        self._path = log_dir / "alerts.jsonl"
        self._lock = threading.Lock()

    def write(self, alert: Alert) -> None:
        record = {
            "ts": alert.timestamp,
            "src": alert.source,
            "sev": int(alert.severity),
            "title": alert.title,
            "details": alert.details,
            "snapshot": alert.snapshot_requested,
        }
        line = json.dumps(record, default=str) + "\n"
        with self._lock:
            with open(self._path, "a", encoding="utf-8") as fh:
                fh.write(line)


# ── desktop notification (best-effort) ───────────────────────────
def _notify_desktop(alert: Alert) -> None:
    """
    Fire a Windows toast notification.  Falls back silently if
    the ``win10toast`` package is not installed.
    """
    try:
        # Use ctypes MessageBeep for a lightweight audible alert
        import ctypes
        MB_ICONEXCLAMATION = 0x00000030
        ctypes.windll.user32.MessageBeep(MB_ICONEXCLAMATION)  # type: ignore[union-attr]
    except Exception:
        pass

    try:
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
        toaster.show_toast(
            f"Sentinel [{alert.severity.name}]",
            alert.title,
            duration=5,
            threaded=True,
        )
    except ImportError:
        _log.debug("win10toast not installed — desktop notification skipped.")
    except Exception:
        _log.debug("Desktop notification failed.", exc_info=True)


# ── engine ───────────────────────────────────────────────────────
class AlertEngine:
    """
    Consumes alerts from the shared queue, applies dedup / rate
    limiting, persists to structured log, and triggers forensic
    snapshots when warranted.
    """

    def __init__(
        self,
        alert_queue: Queue[Alert],
        cfg: AlertConfig = ALERT_CFG,
        log_dir: Path = LOG_DIR,
        on_alert: Optional[Callable[[Alert], None]] = None,
    ) -> None:
        self._queue = alert_queue
        self._cfg = cfg
        self._log_writer = _JsonLogWriter(log_dir)
        self._on_alert = on_alert  # optional external callback

        # In-memory ring buffer for quick access by the web dashboard
        self._recent_alerts: deque[Alert] = deque(maxlen=500)

        # Dedup state: source → last-alert timestamp
        self._last_alert_ts: Dict[str, float] = defaultdict(float)

        # Rate-limiting state
        self._alert_timestamps: List[float] = []

        # Lifecycle
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── public API ───────────────────────────────────────────────
    def set_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register an external callback (e.g. WebSocket bridge)."""
        self._on_alert = callback

    def recent_alerts(self, limit: int = 100) -> List[Alert]:
        """Return the most recent alerts from the in-memory ring buffer."""
        alerts = list(self._recent_alerts)
        return alerts[-limit:] if limit < len(alerts) else alerts

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run, name="sentinel-alert-engine", daemon=True
        )
        self._thread.start()
        _log.info("Alert engine started.")

    def stop(self, timeout: float = 5.0) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        self._thread = None
        _log.info("Alert engine stopped.")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    # ── main loop ────────────────────────────────────────────────
    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                alert = self._queue.get(timeout=0.5)
            except Empty:
                continue

            if self._is_duplicate(alert):
                _log.debug("Suppressed duplicate alert from %s", alert.source)
                continue

            if self._is_rate_limited():
                _log.warning("Alert rate limit reached — throttling.")
                continue

            # Persist
            # Store in ring buffer
            self._recent_alerts.append(alert)

            # Persist to disk
            self._log_writer.write(alert)

            # AUTO-KILL: terminate malicious process on HIGH+ severity
            if int(alert.severity) >= int(Severity.HIGH):
                killed = try_kill_process(alert)
                alert.details["process_killed"] = killed

            # Forensic snapshot if severity warrants it
            if int(alert.severity) >= self._cfg.snapshot_threshold:
                alert.snapshot_requested = True
                _log.info("Triggering forensic snapshot for: %s", alert.title)
                snapshot_path = capture_snapshot(alert)
                if snapshot_path:
                    alert.details["snapshot_path"] = str(snapshot_path)

            # Desktop notification
            _notify_desktop(alert)

            # External callback (e.g. SIEM forwarding)
            if self._on_alert is not None:
                try:
                    self._on_alert(alert)
                except Exception:
                    _log.exception("External alert callback failed.")

            # Record timestamp for rate-limiting
            self._alert_timestamps.append(time.time())

    # ── deduplication ────────────────────────────────────────────
    def _is_duplicate(self, alert: Alert) -> bool:
        now = time.time()
        last = self._last_alert_ts.get(alert.source, 0.0)
        if now - last < self._cfg.dedup_window_s:
            return True
        self._last_alert_ts[alert.source] = now
        return False

    # ── rate limiting ────────────────────────────────────────────
    def _is_rate_limited(self) -> bool:
        now = time.time()
        # Prune old timestamps
        self._alert_timestamps = [
            ts for ts in self._alert_timestamps if now - ts < 60.0
        ]
        return len(self._alert_timestamps) >= self._cfg.max_alerts_per_minute
