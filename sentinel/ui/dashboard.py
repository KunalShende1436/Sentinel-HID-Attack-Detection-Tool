"""
sentinel.ui.dashboard
======================
Real-time tkinter GUI dashboard for the Sentinel framework.

Features:
    • Live alert feed with severity colour-coding
    • Module health-status indicators (green/red)
    • Start / Stop / Snapshot controls
    • Alert statistics (total, by severity)
    • Auto-kill status indicator
    • Dark-themed, lightweight — runs in the main thread while
      detectors run in daemon threads

The UI polls the orchestrator state every 500 ms via ``root.after()``
which keeps the GUI responsive without blocking.
"""

from __future__ import annotations

import datetime
import json
import logging
import threading
import time
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from pathlib import Path
from queue import Empty, Queue
from typing import Dict, List, Optional

from sentinel import __version__
from sentinel.config import BASE_DIR, LOG_DIR
from sentinel.core import Alert, Severity
from sentinel.orchestrator import SentinelOrchestrator

_log = logging.getLogger("sentinel.ui")

# ── colour palette (dark theme) ─────────────────────────────────
_BG         = "#1a1a2e"
_BG_CARD    = "#16213e"
_BG_INPUT   = "#0f3460"
_FG         = "#e0e0e0"
_FG_DIM     = "#888888"
_ACCENT     = "#00d4ff"
_GREEN      = "#00e676"
_YELLOW     = "#ffd600"
_ORANGE     = "#ff9100"
_RED        = "#ff1744"
_CRIMSON    = "#d50000"

_SEV_COLOURS: Dict[int, str] = {
    int(Severity.INFO):     _FG_DIM,
    int(Severity.LOW):      _GREEN,
    int(Severity.MEDIUM):   _YELLOW,
    int(Severity.HIGH):     _ORANGE,
    int(Severity.CRITICAL): _RED,
}


def _sev_colour(sev: int) -> str:
    """Return the hex colour for a given severity value."""
    if sev >= int(Severity.CRITICAL):
        return _RED
    if sev >= int(Severity.HIGH):
        return _ORANGE
    if sev >= int(Severity.MEDIUM):
        return _YELLOW
    if sev >= int(Severity.LOW):
        return _GREEN
    return _FG_DIM


def _ts_str(ts: float) -> str:
    """Format a Unix timestamp as HH:MM:SS."""
    return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")


# ── main dashboard class ────────────────────────────────────────
class SentinelDashboard:
    """Tkinter GUI for Sentinel — runs on the main thread."""

    def __init__(self) -> None:
        self._orch: Optional[SentinelOrchestrator] = None

        # Alert mirror queue: the alert engine pushes here via callback
        self._ui_queue: Queue[Alert] = Queue(maxsize=1000)
        self._alerts: List[Alert] = []
        self._stats = {"total": 0, "killed": 0, "snapshots": 0}
        self._sev_counts: Dict[str, int] = {
            "INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0,
        }

        # ── build root window ───────────────────────────────────
        self._root = tk.Tk()
        self._root.title(f"Sentinel v{__version__} — HID Attack Detection")
        self._root.configure(bg=_BG)
        self._root.geometry("1100x720")
        self._root.minsize(900, 600)

        # Try to set icon (non-critical)
        try:
            self._root.iconbitmap(default="")
        except Exception:
            pass

        self._build_ui()

        # Handle window close
        self._root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ════════════════════════════════════════════════════════════
    #  UI CONSTRUCTION
    # ════════════════════════════════════════════════════════════

    def _build_ui(self) -> None:
        # ── Title bar ────────────────────────────────────────────
        title_frame = tk.Frame(self._root, bg=_BG_CARD, pady=10, padx=15)
        title_frame.pack(fill=tk.X)

        tk.Label(
            title_frame, text="◆ SENTINEL", font=("Consolas", 20, "bold"),
            fg=_ACCENT, bg=_BG_CARD,
        ).pack(side=tk.LEFT)

        tk.Label(
            title_frame,
            text="HID Attack Detection & Response",
            font=("Segoe UI", 11), fg=_FG_DIM, bg=_BG_CARD,
        ).pack(side=tk.LEFT, padx=(15, 0))

        self._status_label = tk.Label(
            title_frame, text="● STOPPED", font=("Consolas", 12, "bold"),
            fg=_RED, bg=_BG_CARD,
        )
        self._status_label.pack(side=tk.RIGHT)

        # ── Control buttons ──────────────────────────────────────
        ctrl_frame = tk.Frame(self._root, bg=_BG, pady=8, padx=15)
        ctrl_frame.pack(fill=tk.X)

        btn_style = dict(
            font=("Segoe UI", 10, "bold"), width=14, relief=tk.FLAT,
            cursor="hand2", pady=5,
        )

        self._btn_start = tk.Button(
            ctrl_frame, text="▶  START", bg=_GREEN, fg="#000",
            command=self._on_start, **btn_style,
        )
        self._btn_start.pack(side=tk.LEFT, padx=(0, 8))

        self._btn_stop = tk.Button(
            ctrl_frame, text="■  STOP", bg=_RED, fg="#fff",
            command=self._on_stop, state=tk.DISABLED, **btn_style,
        )
        self._btn_stop.pack(side=tk.LEFT, padx=(0, 8))

        self._btn_snapshot = tk.Button(
            ctrl_frame, text="📸  SNAPSHOT", bg=_BG_INPUT, fg=_FG,
            command=self._on_manual_snapshot, state=tk.DISABLED, **btn_style,
        )
        self._btn_snapshot.pack(side=tk.LEFT, padx=(0, 8))

        self._btn_clear = tk.Button(
            ctrl_frame, text="🗑  CLEAR LOG", bg=_BG_INPUT, fg=_FG,
            command=self._on_clear_log, **btn_style,
        )
        self._btn_clear.pack(side=tk.LEFT)

        # ── Stats bar ────────────────────────────────────────────
        stats_frame = tk.Frame(self._root, bg=_BG_CARD, pady=8, padx=15)
        stats_frame.pack(fill=tk.X, pady=(5, 0))

        self._stat_labels: Dict[str, tk.Label] = {}
        stat_items = [
            ("Total", "total", _FG),
            ("INFO", "INFO", _FG_DIM),
            ("LOW", "LOW", _GREEN),
            ("MEDIUM", "MEDIUM", _YELLOW),
            ("HIGH", "HIGH", _ORANGE),
            ("CRITICAL", "CRITICAL", _RED),
            ("Killed", "killed", _CRIMSON),
            ("Snapshots", "snapshots", _ACCENT),
        ]
        for label_text, key, colour in stat_items:
            container = tk.Frame(stats_frame, bg=_BG_CARD)
            container.pack(side=tk.LEFT, padx=(0, 20))
            tk.Label(
                container, text=label_text, font=("Segoe UI", 9),
                fg=_FG_DIM, bg=_BG_CARD,
            ).pack()
            lbl = tk.Label(
                container, text="0", font=("Consolas", 14, "bold"),
                fg=colour, bg=_BG_CARD,
            )
            lbl.pack()
            self._stat_labels[key] = lbl

        # ── Module status indicators ─────────────────────────────
        mod_frame = tk.LabelFrame(
            self._root, text="  MODULE STATUS  ",
            font=("Segoe UI", 10, "bold"), fg=_ACCENT, bg=_BG,
            bd=1, relief=tk.GROOVE, padx=10, pady=8,
        )
        mod_frame.pack(fill=tk.X, padx=15, pady=(8, 0))

        self._mod_indicators: Dict[str, tk.Label] = {}
        modules = [
            ("hardware_watcher", "Hardware Watcher"),
            ("behavioral_analyzer", "Behavioral Analyzer"),
            ("process_sentinel", "Process Sentinel"),
            ("alert_engine", "Alert Engine"),
        ]
        for key, display_name in modules:
            row = tk.Frame(mod_frame, bg=_BG)
            row.pack(fill=tk.X, pady=2)
            indicator = tk.Label(
                row, text="●", font=("Consolas", 14),
                fg=_RED, bg=_BG, width=2,
            )
            indicator.pack(side=tk.LEFT)
            tk.Label(
                row, text=display_name, font=("Segoe UI", 10),
                fg=_FG, bg=_BG, anchor=tk.W,
            ).pack(side=tk.LEFT, padx=(5, 0))
            self._mod_indicators[key] = indicator

        # ── Alert feed (scrollable) ─────────────────────────────
        feed_frame = tk.LabelFrame(
            self._root, text="  LIVE ALERT FEED  ",
            font=("Segoe UI", 10, "bold"), fg=_ACCENT, bg=_BG,
            bd=1, relief=tk.GROOVE, padx=5, pady=5,
        )
        feed_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(8, 10))

        self._alert_text = scrolledtext.ScrolledText(
            feed_frame,
            font=("Consolas", 10),
            bg=_BG_CARD, fg=_FG,
            insertbackground=_FG,
            selectbackground=_BG_INPUT,
            relief=tk.FLAT,
            state=tk.DISABLED,
            wrap=tk.WORD,
            height=15,
        )
        self._alert_text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for severity colouring
        self._alert_text.tag_configure("INFO",     foreground=_FG_DIM)
        self._alert_text.tag_configure("LOW",      foreground=_GREEN)
        self._alert_text.tag_configure("MEDIUM",   foreground=_YELLOW)
        self._alert_text.tag_configure("HIGH",     foreground=_ORANGE)
        self._alert_text.tag_configure("CRITICAL", foreground=_RED, font=("Consolas", 10, "bold"))
        self._alert_text.tag_configure("KILLED",   foreground=_CRIMSON, font=("Consolas", 10, "bold"))
        self._alert_text.tag_configure("TIMESTAMP", foreground=_FG_DIM)
        self._alert_text.tag_configure("HEADER",   foreground=_ACCENT, font=("Consolas", 10, "bold"))

        # ── Footer ───────────────────────────────────────────────
        footer = tk.Frame(self._root, bg=_BG_CARD, pady=5, padx=15)
        footer.pack(fill=tk.X, side=tk.BOTTOM)
        tk.Label(
            footer,
            text=f"Sentinel v{__version__} │ Logs: {LOG_DIR} │ Snapshots: {BASE_DIR / 'snapshots'}",
            font=("Segoe UI", 8), fg=_FG_DIM, bg=_BG_CARD,
        ).pack(side=tk.LEFT)
        tk.Label(
            footer,
            text="Developed by Kunal S & Ayush K",
            font=("Segoe UI", 9, "bold"), fg=_ACCENT, bg=_BG_CARD,
        ).pack(side=tk.LEFT, expand=True)
        self._clock_label = tk.Label(
            footer, text="", font=("Consolas", 9), fg=_FG_DIM, bg=_BG_CARD,
        )
        self._clock_label.pack(side=tk.RIGHT)

    # ════════════════════════════════════════════════════════════
    #  EVENT HANDLERS
    # ════════════════════════════════════════════════════════════

    def _on_start(self) -> None:
        """Start the Sentinel orchestrator."""
        if self._orch is not None and self._orch.is_running:
            return

        self._orch = SentinelOrchestrator()
        # Register our UI callback on the alert engine
        self._orch._engine._on_alert = self._on_alert_callback

        self._orch.start()
        self._btn_start.configure(state=tk.DISABLED)
        self._btn_stop.configure(state=tk.NORMAL)
        self._btn_snapshot.configure(state=tk.NORMAL)
        self._status_label.configure(text="● ACTIVE", fg=_GREEN)

        self._append_feed(
            "SYSTEM", _ACCENT,
            "Sentinel started — all detection modules active.\n"
        )

        # Start the periodic UI refresh
        self._schedule_refresh()

    def _on_stop(self) -> None:
        """Stop the Sentinel orchestrator."""
        if self._orch is None:
            return

        self._append_feed("SYSTEM", _ORANGE, "Shutting down...\n")

        # Run stop in a thread to avoid freezing the UI
        def _stop_worker():
            if self._orch:
                self._orch.stop()

        threading.Thread(target=_stop_worker, daemon=True).start()

        self._btn_start.configure(state=tk.NORMAL)
        self._btn_stop.configure(state=tk.DISABLED)
        self._btn_snapshot.configure(state=tk.DISABLED)
        self._status_label.configure(text="● STOPPED", fg=_RED)

        self._append_feed("SYSTEM", _ORANGE, "Sentinel stopped.\n")

    def _on_manual_snapshot(self) -> None:
        """Take a manual forensic snapshot."""
        from sentinel.forensics import capture_snapshot
        from sentinel.core import Alert, Severity

        alert = Alert(
            timestamp=time.time(),
            source="manual_snapshot",
            severity=Severity.INFO,
            title="Manual forensic snapshot requested by operator",
        )
        self._append_feed("SYSTEM", _ACCENT, "Taking manual forensic snapshot...\n")

        def _snap_worker():
            path = capture_snapshot(alert)
            if path:
                self._ui_queue.put(Alert(
                    timestamp=time.time(), source="system",
                    severity=Severity.INFO,
                    title=f"Snapshot saved → {path.name}",
                    details={"snapshot_path": str(path)},
                ))

        threading.Thread(target=_snap_worker, daemon=True).start()

    def _on_clear_log(self) -> None:
        """Clear the alert feed."""
        self._alert_text.configure(state=tk.NORMAL)
        self._alert_text.delete("1.0", tk.END)
        self._alert_text.configure(state=tk.DISABLED)

    def _on_close(self) -> None:
        """Handle window close — stop Sentinel first."""
        if self._orch and self._orch.is_running:
            self._orch.stop()
        self._root.destroy()

    # ════════════════════════════════════════════════════════════
    #  ALERT CALLBACK (called from alert engine thread)
    # ════════════════════════════════════════════════════════════

    def _on_alert_callback(self, alert: Alert) -> None:
        """
        Called by the AlertEngine from its worker thread.
        We push to a thread-safe queue; the UI drains it via after().
        """
        try:
            self._ui_queue.put_nowait(alert)
        except Exception:
            pass  # queue full — drop alert for UI (still logged to file)

    # ════════════════════════════════════════════════════════════
    #  PERIODIC UI REFRESH (every 500 ms)
    # ════════════════════════════════════════════════════════════

    def _schedule_refresh(self) -> None:
        """Schedule the next UI poll cycle."""
        self._refresh_alerts()
        self._refresh_module_status()
        self._refresh_clock()

        # Reschedule if still running
        if self._orch and self._orch.is_running:
            self._root.after(500, self._schedule_refresh)
        else:
            # One final refresh
            self._refresh_module_status()

    def _refresh_alerts(self) -> None:
        """Drain the UI alert queue and render new alerts."""
        count = 0
        while count < 50:  # cap per cycle to avoid UI freeze
            try:
                alert = self._ui_queue.get_nowait()
            except Empty:
                break
            count += 1
            self._alerts.append(alert)
            self._render_alert(alert)
            self._update_stats(alert)

    def _render_alert(self, alert: Alert) -> None:
        """Append a single alert to the feed with colour tags."""
        sev_name = alert.severity.name if isinstance(alert.severity, Severity) else "INFO"
        ts = _ts_str(alert.timestamp)
        killed = alert.details.get("process_killed", False)
        pid = alert.details.get("pid", "")

        self._alert_text.configure(state=tk.NORMAL)

        # Timestamp
        self._alert_text.insert(tk.END, f"[{ts}] ", "TIMESTAMP")

        # Severity badge
        self._alert_text.insert(tk.END, f"[{sev_name:>8}] ", sev_name)

        # Title
        self._alert_text.insert(tk.END, f"{alert.title}", sev_name)

        # Kill indicator
        if killed:
            self._alert_text.insert(tk.END, f"  ⛔ PROCESS KILLED (PID {pid})", "KILLED")

        # Snapshot indicator
        if alert.snapshot_requested:
            self._alert_text.insert(tk.END, "  📸 SNAPSHOT", "HEADER")

        self._alert_text.insert(tk.END, "\n")

        # Details (compact JSON)
        if alert.details:
            detail_keys = {k: v for k, v in alert.details.items()
                          if k not in ("snapshot_path",)}
            if detail_keys:
                detail_str = json.dumps(detail_keys, indent=None, default=str)
                if len(detail_str) > 200:
                    detail_str = detail_str[:200] + "…"
                self._alert_text.insert(tk.END, f"         {detail_str}\n", "INFO")

        # Auto-scroll to bottom
        self._alert_text.see(tk.END)
        self._alert_text.configure(state=tk.DISABLED)

    def _update_stats(self, alert: Alert) -> None:
        """Update statistic counters."""
        self._stats["total"] += 1
        sev_name = alert.severity.name if isinstance(alert.severity, Severity) else "INFO"
        self._sev_counts[sev_name] = self._sev_counts.get(sev_name, 0) + 1

        if alert.details.get("process_killed"):
            self._stats["killed"] += 1
        if alert.snapshot_requested:
            self._stats["snapshots"] += 1

        # Update labels
        self._stat_labels["total"].configure(text=str(self._stats["total"]))
        self._stat_labels["killed"].configure(text=str(self._stats["killed"]))
        self._stat_labels["snapshots"].configure(text=str(self._stats["snapshots"]))
        for sev in ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            self._stat_labels[sev].configure(text=str(self._sev_counts.get(sev, 0)))

    def _refresh_module_status(self) -> None:
        """Update the green/red module status indicators."""
        if self._orch is None:
            for ind in self._mod_indicators.values():
                ind.configure(fg=_RED)
            return

        status = self._orch.status()
        detectors = status.get("detectors", {})

        # Engine
        engine_ok = status.get("engine", False)
        self._mod_indicators["alert_engine"].configure(
            fg=_GREEN if engine_ok else _RED
        )

        # Detectors
        for key in ("hardware_watcher", "behavioral_analyzer", "process_sentinel"):
            running = detectors.get(key, False)
            self._mod_indicators[key].configure(
                fg=_GREEN if running else _RED
            )

    def _refresh_clock(self) -> None:
        """Update the footer clock."""
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._clock_label.configure(text=now)

    # ════════════════════════════════════════════════════════════
    #  FEED HELPER
    # ════════════════════════════════════════════════════════════

    def _append_feed(self, tag: str, colour: str, text: str) -> None:
        """Append arbitrary text to the feed with a given colour."""
        # Create a dynamic tag if needed
        self._alert_text.tag_configure(tag, foreground=colour)
        self._alert_text.configure(state=tk.NORMAL)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._alert_text.insert(tk.END, f"[{ts}] ", "TIMESTAMP")
        self._alert_text.insert(tk.END, text, tag)
        self._alert_text.see(tk.END)
        self._alert_text.configure(state=tk.DISABLED)

    # ════════════════════════════════════════════════════════════
    #  PUBLIC ENTRY POINT
    # ════════════════════════════════════════════════════════════

    def run(self) -> None:
        """Launch the GUI event loop (blocks until window is closed)."""
        _log.info("Launching Sentinel Dashboard UI.")
        self._root.mainloop()
