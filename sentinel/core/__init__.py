"""
sentinel.core.base
===================
Abstract base classes that every detection module must implement.

Design goals:
    • Enforce a uniform start / stop / report lifecycle.
    • Thread-safe alert emission via a shared queue.
    • Clean shutdown with cooperative cancellation.
"""

from __future__ import annotations

import abc
import logging
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum, auto
from queue import Queue
from typing import Any, Dict, Optional


# ── Threat severity levels ───────────────────────────────────────
class Severity(IntEnum):
    """Ordered severity for alert prioritisation."""
    INFO = 0
    LOW = 25
    MEDIUM = 50
    HIGH = 75
    CRITICAL = 100


# ── Alert payload ────────────────────────────────────────────────
@dataclass
class Alert:
    """
    Immutable record emitted by any detection module when an
    anomaly is observed.

    Attributes:
        timestamp : Unix epoch (float) of the detection moment.
        source    : Canonical name of the emitting module.
        severity  : Threat score (0–100).
        title     : Human-readable one-liner.
        details   : Free-form evidence dictionary.
        snapshot  : Whether forensic snapshot was requested.
    """
    timestamp: float
    source: str
    severity: Severity
    title: str
    details: Dict[str, Any] = field(default_factory=dict)
    snapshot_requested: bool = False

    def __post_init__(self) -> None:
        # Defensive: clamp severity to valid range
        if not (0 <= int(self.severity) <= 100):
            raise ValueError(f"Severity must be 0–100, got {self.severity}")


# ── Abstract detector base ───────────────────────────────────────
class BaseDetector(abc.ABC):
    """
    Contract that every Sentinel detection module must honour.

    Subclasses implement ``_run_loop`` which is executed in a
    dedicated daemon thread.  The base class provides lifecycle
    management, logging, and a thread-safe alert queue.
    """

    def __init__(self, name: str, alert_queue: Queue[Alert]) -> None:
        self._name = name
        self._alert_queue = alert_queue
        self._logger = logging.getLogger(f"sentinel.{name}")
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ── public API ───────────────────────────────────────────────
    @property
    def name(self) -> str:
        return self._name

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        """Launch the detector in a background daemon thread."""
        if self.is_running:
            self._logger.warning("%s already running — ignoring start()", self._name)
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._safe_run,
            name=f"sentinel-{self._name}",
            daemon=True,
        )
        self._thread.start()
        self._logger.info("%s started.", self._name)

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the detector to stop and wait for thread exit."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            if self._thread.is_alive():
                self._logger.warning(
                    "%s did not terminate within %.1fs.", self._name, timeout
                )
            else:
                self._logger.info("%s stopped cleanly.", self._name)
        self._thread = None

    # ── internal helpers ─────────────────────────────────────────
    def _safe_run(self) -> None:
        """Wrapper that catches unhandled exceptions in the run loop."""
        try:
            self._run_loop()
        except Exception:
            self._logger.exception("Unhandled exception in %s — detector halted.", self._name)

    def _emit_alert(
        self,
        severity: Severity,
        title: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Thread-safe helper to push an alert onto the shared queue."""
        alert = Alert(
            timestamp=time.time(),
            source=self._name,
            severity=severity,
            title=title,
            details=details or {},
        )
        self._alert_queue.put_nowait(alert)
        self._logger.warning("ALERT [%s] %s — %s", severity.name, title, details)

    def _should_stop(self) -> bool:
        """Check the cooperative cancellation flag."""
        return self._stop_event.is_set()

    # ── abstract contract ────────────────────────────────────────
    @abc.abstractmethod
    def _run_loop(self) -> None:
        """
        Main detection loop.  Implementations MUST check
        ``self._should_stop()`` periodically and exit cleanly
        when it returns True.
        """
        ...
