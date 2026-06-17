"""
sentinel.orchestrator
======================
Top-level lifecycle manager that wires together every detection
module, the alert engine, and the forensic subsystem.

Usage::

    from sentinel.orchestrator import SentinelOrchestrator
    orch = SentinelOrchestrator()
    orch.start()          # non-blocking — all modules run in threads
    ...
    orch.stop()           # clean shutdown

The orchestrator owns the shared alert queue and ensures orderly
startup (engine first, then detectors) and shutdown (detectors
first, then engine).
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
from queue import Queue
from typing import Callable, List

from sentinel.core import Alert, BaseDetector
from sentinel.detectors.behavioral_analyzer import BehavioralAnalyzer
from sentinel.detectors.hardware_watcher import HardwareWatcher
from sentinel.detectors.process_sentinel import ProcessSentinel
from sentinel.engine import AlertEngine

_log = logging.getLogger("sentinel.orchestrator")


class SentinelOrchestrator:
    """
    Central coordinator for the Sentinel detection framework.

    Manages the lifecycle of:
        • HardwareWatcher
        • BehavioralAnalyzer
        • ProcessSentinel
        • AlertEngine (with forensic snapshot integration)
    """

    def __init__(self) -> None:
        self._alert_queue: Queue[Alert] = Queue(maxsize=500)
        self._detectors: List[BaseDetector] = []
        self._engine: AlertEngine = AlertEngine(alert_queue=self._alert_queue)
        self._running = False

        # Instantiate all detection modules
        self._detectors = [
            HardwareWatcher(alert_queue=self._alert_queue),
            BehavioralAnalyzer(alert_queue=self._alert_queue),
            ProcessSentinel(alert_queue=self._alert_queue),
        ]

    # ── public API ───────────────────────────────────────────────
    def start(self) -> None:
        """
        Start all Sentinel subsystems.
        Order: Alert Engine → Detectors (so alerts are never lost).
        """
        if self._running:
            _log.warning("Sentinel is already running.")
            return

        _log.info("=" * 60)
        _log.info("  SENTINEL v1.0.0 — HID Attack Detection Framework")
        _log.info("=" * 60)

        # 1. Alert engine first — ensures queue consumer is ready
        self._engine.start()

        # 2. Start each detector
        for detector in self._detectors:
            try:
                detector.start()
            except Exception:
                _log.exception("Failed to start detector: %s", detector.name)

        self._running = True
        _log.info("All modules started.  Sentinel is active.")

    def stop(self) -> None:
        """
        Graceful shutdown.
        Order: Detectors → Alert Engine (drain remaining alerts).
        """
        if not self._running:
            return

        _log.info("Initiating graceful shutdown...")

        # 1. Stop detectors (producers) first
        for detector in reversed(self._detectors):
            try:
                detector.stop(timeout=5.0)
            except Exception:
                _log.exception("Error stopping detector: %s", detector.name)

        # 2. Stop the alert engine (consumer)
        self._engine.stop(timeout=5.0)

        self._running = False
        _log.info("Sentinel stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    def wait(self) -> None:
        """
        Block the calling thread until interrupted (Ctrl+C) or
        until ``stop()`` is called from another thread.
        """
        stop_event = threading.Event()

        def _signal_handler(sig: int, frame: object) -> None:
            _log.info("Received signal %d — shutting down...", sig)
            stop_event.set()

        # Register signal handlers for graceful Ctrl+C handling
        signal.signal(signal.SIGINT, _signal_handler)
        signal.signal(signal.SIGTERM, _signal_handler)

        try:
            stop_event.wait()
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def status(self) -> dict:
        """Return a quick health-check dictionary."""
        return {
            "running": self._running,
            "engine": self._engine.is_running,
            "detectors": {
                d.name: d.is_running for d in self._detectors
            },
        }

    def set_alert_callback(self, callback: Callable[[Alert], None]) -> None:
        """Register an external callback on the alert engine (e.g. WebSocket bridge)."""
        self._engine.set_alert_callback(callback)

    def get_alert_history(self, limit: int = 100) -> List[Alert]:
        """Return recent alerts from the engine's in-memory buffer."""
        return self._engine.recent_alerts(limit)

    @property
    def engine(self) -> AlertEngine:
        """Access the alert engine instance (used by web server)."""
        return self._engine
