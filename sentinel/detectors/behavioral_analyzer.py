"""
sentinel.detectors.behavioral_analyzer
========================================
Low-level keyboard hook that analyses inter-keystroke timing to
detect injection attacks characterised by:

    1. **Impossible typing speed** — sustained WPM above human limits
       (~200 WPM ≈ 1 000 chars/min ≈ <60 ms average delta).
    2. **Robotic repeat patterns** — long runs of identical keystrokes
       that a human would not produce.
    3. **Burst injection** — sudden spike in keypress rate after a
       period of inactivity (HID payload deployment pattern).

The module uses ``pynput`` for a user-space keyboard hook, meaning
no administrator privileges are required.

Thread model:
    ``pynput.keyboard.Listener`` runs its own daemon thread.
    We bridge events into the detector's analysis via a bounded
    deque that is drained every analysis cycle.
"""

from __future__ import annotations

import collections
import statistics
import time
from queue import Queue
from typing import Deque, List, Optional

from sentinel.config import BA_CFG, BehavioralAnalyzerConfig
from sentinel.core import Alert, BaseDetector, Severity

# Lazy import — may not be present on headless / CI systems
try:
    from pynput.keyboard import Key, Listener as KbListener
except ImportError:
    KbListener = None  # type: ignore[assignment,misc]
    Key = None  # type: ignore[assignment,misc]


# ── internal data ────────────────────────────────────────────────
class _KeyEvent:
    """Lightweight keystroke record."""
    __slots__ = ("key_repr", "timestamp")

    def __init__(self, key_repr: str, timestamp: float) -> None:
        self.key_repr = key_repr
        self.timestamp = timestamp


# ── detector ─────────────────────────────────────────────────────
class BehavioralAnalyzer(BaseDetector):
    """
    Hooks keyboard input and performs real-time statistical analysis
    on inter-keystroke deltas to identify HID injection patterns.
    """

    def __init__(
        self,
        alert_queue: Queue[Alert],
        cfg: BehavioralAnalyzerConfig = BA_CFG,
    ) -> None:
        super().__init__(name="behavioral_analyzer", alert_queue=alert_queue)
        self._cfg = cfg

        # Bounded ring-buffer for recent keystrokes
        self._buffer: Deque[_KeyEvent] = collections.deque(
            maxlen=self._cfg.window_size * 2
        )
        self._listener: Optional[object] = None

    # ── lifecycle ────────────────────────────────────────────────
    def _run_loop(self) -> None:
        if KbListener is None:
            self._logger.error("pynput not available — behavioral analysis disabled.")
            return

        self._listener = KbListener(on_press=self._on_key_press)
        self._listener.start()  # type: ignore[union-attr]
        self._logger.info("Keyboard hook installed.")

        try:
            while not self._should_stop():
                time.sleep(0.5)  # analysis cadence
                self._analyse_window()
                self._prune_old_events()
        finally:
            if self._listener is not None:
                self._listener.stop()  # type: ignore[union-attr]
            self._logger.info("Keyboard hook removed.")

    # ── keyboard callback (runs on pynput thread) ────────────────
    def _on_key_press(self, key: object) -> None:
        """
        Called by pynput for every key-down event.
        We only store a minimal record — never the actual character
        for privacy reasons.  We store a *category* representation.
        """
        try:
            # Normalise: printable chars → "CHAR", special → their name
            if hasattr(key, "char") and getattr(key, "char", None) is not None:
                key_repr = "CHAR"
            else:
                key_repr = str(key)
        except Exception:
            key_repr = "UNKNOWN"

        self._buffer.append(_KeyEvent(key_repr=key_repr, timestamp=time.perf_counter()))

    # ── analysis engine ──────────────────────────────────────────
    def _analyse_window(self) -> None:
        """Run all heuristics against the current event buffer."""
        events = list(self._buffer)
        if len(events) < 2:
            return

        self._check_typing_speed(events)
        self._check_robotic_repeats(events)
        self._check_burst_injection(events)

    def _check_typing_speed(self, events: List[_KeyEvent]) -> None:
        """Flag if average inter-key delta implies superhuman WPM."""
        # Take the most recent ``window_size`` events
        window = events[-self._cfg.window_size:]
        if len(window) < self._cfg.window_size:
            return

        deltas_ms = [
            (window[i].timestamp - window[i - 1].timestamp) * 1000.0
            for i in range(1, len(window))
        ]

        avg_delta = statistics.mean(deltas_ms)
        if avg_delta <= 0:
            return  # clock anomaly guard

        # WPM estimate: assume average 5 chars per word
        chars_per_min = 60_000.0 / avg_delta
        est_wpm = chars_per_min / 5.0

        if avg_delta < self._cfg.min_human_delta_ms:
            self._emit_alert(
                severity=Severity.CRITICAL,
                title=f"Impossible typing speed detected — {est_wpm:.0f} WPM "
                      f"(avg delta {avg_delta:.1f} ms)",
                details={
                    "avg_delta_ms": round(avg_delta, 2),
                    "estimated_wpm": round(est_wpm, 1),
                    "window_size": len(window),
                    "min_delta_ms": round(min(deltas_ms), 2),
                    "max_delta_ms": round(max(deltas_ms), 2),
                },
            )
        elif est_wpm > self._cfg.max_human_wpm:
            self._emit_alert(
                severity=Severity.HIGH,
                title=f"Sustained superhuman typing — {est_wpm:.0f} WPM",
                details={
                    "avg_delta_ms": round(avg_delta, 2),
                    "estimated_wpm": round(est_wpm, 1),
                },
            )

    def _check_robotic_repeats(self, events: List[_KeyEvent]) -> None:
        """
        Detect long runs of identical key categories — a hallmark
        of payload injectors that spam 'a', Enter, or arrow keys.
        """
        if len(events) < self._cfg.repeat_threshold:
            return

        run_length = 1
        max_run = 1
        max_key = events[0].key_repr

        for i in range(1, len(events)):
            if events[i].key_repr == events[i - 1].key_repr:
                run_length += 1
                if run_length > max_run:
                    max_run = run_length
                    max_key = events[i].key_repr
            else:
                run_length = 1

        if max_run >= self._cfg.repeat_threshold:
            self._emit_alert(
                severity=Severity.HIGH,
                title=f"Robotic key repeat detected — '{max_key}' × {max_run}",
                details={
                    "key_category": max_key,
                    "consecutive_count": max_run,
                    "threshold": self._cfg.repeat_threshold,
                },
            )

    def _check_burst_injection(self, events: List[_KeyEvent]) -> None:
        """
        Detect a sudden burst of keystrokes after silence — typical
        of HID payloads that fire after a delay timer.

        Approach: split the window at the median timestamp and
        compare keystroke density in each half.
        """
        if len(events) < 10:
            return

        mid = len(events) // 2
        first_half = events[:mid]
        second_half = events[mid:]

        # Compute average rate (keystrokes / second) in each half
        def _rate(evts: List[_KeyEvent]) -> float:
            if len(evts) < 2:
                return 0.0
            span = evts[-1].timestamp - evts[0].timestamp
            return len(evts) / span if span > 0 else 0.0

        rate_1 = _rate(first_half)
        rate_2 = _rate(second_half)

        # If the second half is ≥5× faster than the first, flag it
        if rate_1 > 0 and rate_2 / rate_1 >= 5.0 and rate_2 > 30:
            self._emit_alert(
                severity=Severity.HIGH,
                title="Burst keystroke injection detected",
                details={
                    "rate_before_ks": round(rate_1, 1),
                    "rate_after_ks": round(rate_2, 1),
                    "ratio": round(rate_2 / rate_1, 1),
                },
            )

    # ── maintenance ──────────────────────────────────────────────
    def _prune_old_events(self) -> None:
        """Remove events older than ``history_ttl_s``."""
        cutoff = time.perf_counter() - self._cfg.history_ttl_s
        while self._buffer and self._buffer[0].timestamp < cutoff:
            self._buffer.popleft()
