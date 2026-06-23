"""
sentinel.detectors.process_sentinel
=====================================
Monitors process creation events to detect suspicious shell spawns
that are characteristic of HID payload execution.

Detection heuristics:
    1. **Shell from unexpected parent** — ``cmd.exe`` / ``powershell.exe``
       spawned by ``explorer.exe``, ``conhost.exe``, ``rundll32.exe``, etc.
    2. **Rapid shell chaining** — multiple shells created within a short
       window (common in staged payloads).
    3. **Script-host invocation** — ``wscript.exe`` / ``mshta.exe``
       launched with inline or remote arguments.

Implementation uses WMI's ``Win32_ProcessStartTrace`` event
subscription for near-real-time notification of new processes.
Falls back to periodic ``psutil`` polling when WMI is unavailable.
"""

from __future__ import annotations

import os
import time
from collections import deque
from queue import Queue
from typing import Deque, Optional, Tuple

from sentinel.config import PS_CFG, ProcessSentinelConfig
from sentinel.core import Alert, BaseDetector, Severity

# Lazy imports for Windows-only libraries
try:
    import wmi as wmi_mod
except ImportError:
    wmi_mod = None  # type: ignore[assignment]

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]


# ── helpers ──────────────────────────────────────────────────────
def _basename_lower(path: Optional[str]) -> str:
    """Extract lowercase basename from a full path (safe on None)."""
    if not path:
        return ""
    return os.path.basename(path).lower()


def _is_suspicious_command_line(cmdline: str) -> bool:
    """
    Basic heuristic: flag command lines that contain common payload
    indicators (encoded commands, download cradles, etc.).
    """
    lowered = cmdline.lower()
    indicators = (
        "-encodedcommand",
        "-enc ",
        "-e ",
        "invoke-webrequest",
        "invoke-expression",
        "iex(",
        "downloadstring",
        "downloadfile",
        "bitsadmin",
        "certutil",
        "regsvr32",
        "mshta",
        "hidden",
        "-windowstyle hidden",
        "-w hidden",
        "-nop",
        "-noprofile",
        "bypass",
    )
    return any(ind in lowered for ind in indicators)


# ── detector ─────────────────────────────────────────────────────
class ProcessSentinel(BaseDetector):
    """
    Watches for process-creation events and flags suspicious
    parent→child relationships indicative of HID payload execution.
    """

    def __init__(
        self,
        alert_queue: Queue[Alert],
        cfg: ProcessSentinelConfig = PS_CFG,
    ) -> None:
        super().__init__(name="process_sentinel", alert_queue=alert_queue)
        self._cfg = cfg

        # Track recent shell spawns for chaining detection
        self._recent_spawns: Deque[Tuple[float, str, str]] = deque(maxlen=50)

    # ── lifecycle ────────────────────────────────────────────────
    def _run_loop(self) -> None:
        if wmi_mod is not None:
            self._run_wmi_loop()
        elif psutil is not None:
            self._logger.warning("WMI unavailable — falling back to psutil polling.")
            self._run_psutil_loop()
        else:
            self._logger.error("Neither WMI nor psutil available — process monitoring disabled.")

    # ── WMI-based loop (preferred) ───────────────────────────────
    def _run_wmi_loop(self) -> None:
        """
        Subscribe to Win32_ProcessStartTrace via WMI.  Each event
        delivers PID + process name; we then resolve the parent via
        psutil for richer context.
        """
        try:
            import pythoncom
            pythoncom.CoInitialize()
        except ImportError:
            self._logger.debug("pythoncom not available for COM init.")
        except Exception:
            pass

        try:
            c = wmi_mod.WMI()  # type: ignore[union-attr]
        except Exception:
            self._logger.warning("Failed to connect to WMI — falling back to psutil.")
            if psutil is not None:
                self._run_psutil_loop()
            return

        self._logger.info("WMI process-start subscription active.")

        # Use polling with timeout so we can honour stop requests
        # Win32_ProcessStartTrace requires admin; fall back if denied.
        try:
            watcher = c.Win32_ProcessStartTrace.watch_for(
                delay_secs=int(self._cfg.poll_interval_s)
            )
        except Exception:
            self._logger.warning(
                "WMI ProcessStartTrace requires admin — falling back to psutil."
            )
            if psutil is not None:
                self._run_psutil_loop()
            return

        while not self._should_stop():
            try:
                event = watcher(timeout_ms=int(self._cfg.poll_interval_s * 1000))
            except wmi_mod.x_wmi_timed_out:  # type: ignore[union-attr]
                continue
            except Exception:
                self._logger.debug("WMI watcher timeout / error — retrying.")
                continue

            proc_name = _basename_lower(getattr(event, "ProcessName", ""))
            pid = getattr(event, "ProcessID", 0)
            self._evaluate_process(proc_name, pid)

    # ── psutil fallback loop ─────────────────────────────────────
    def _run_psutil_loop(self) -> None:
        """
        Periodically snapshot running processes and diff to find
        new ones.  Less precise than WMI but works everywhere psutil
        is installed.
        """
        known_pids: set = set()
        if psutil is not None:
            known_pids = {p.pid for p in psutil.process_iter(["pid"])}

        self._logger.info("psutil polling loop active (%d initial PIDs).", len(known_pids))

        while not self._should_stop():
            time.sleep(self._cfg.poll_interval_s)
            if psutil is None:
                continue

            current_pids = set()
            for proc in psutil.process_iter(["pid", "name"]):
                current_pids.add(proc.pid)
                if proc.pid not in known_pids:
                    proc_name = _basename_lower(proc.info.get("name", ""))
                    self._evaluate_process(proc_name, proc.pid)

            known_pids = current_pids

    # ── evaluation ───────────────────────────────────────────────
    def _evaluate_process(self, proc_name: str, pid: int) -> None:
        """Check a newly-created process against detection rules."""
        if proc_name not in {t.lower() for t in self._cfg.target_processes}:
            return

        parent_name, parent_pid, cmdline = self._resolve_parent(pid)
        now = time.time()

        # Track for chaining analysis
        self._recent_spawns.append((now, proc_name, parent_name))

        severity = Severity.MEDIUM
        reasons = []

        # Rule 1: Suspicious parent
        if parent_name in {p.lower() for p in self._cfg.suspicious_parents}:
            severity = max(severity, Severity.HIGH)
            reasons.append(f"spawned by suspicious parent '{parent_name}'")

        # Rule 2: Suspicious command-line content
        if cmdline and _is_suspicious_command_line(cmdline):
            severity = max(severity, Severity.CRITICAL)
            reasons.append("command line contains payload indicators")

        # Rule 3: Rapid shell chaining (≥3 shells in 5 seconds)
        recent_count = sum(
            1 for ts, _, _ in self._recent_spawns if now - ts < 5.0
        )
        if recent_count >= 3:
            severity = max(severity, Severity.HIGH)
            reasons.append(f"{recent_count} shells in <5 s (chaining)")

        if not reasons:
            reasons.append("target process created")

        self._emit_alert(
            severity=severity,
            title=f"Suspicious process: {proc_name} (PID {pid})",
            details={
                "process": proc_name,
                "pid": pid,
                "parent": parent_name,
                "parent_pid": parent_pid,
                "cmdline": cmdline[:500] if cmdline else "",
                "reasons": reasons,
            },
        )

    def _resolve_parent(self, pid: int) -> Tuple[str, int, str]:
        """
        Resolve the parent process name and command line for a given PID.
        Returns (parent_name, parent_pid, cmdline).
        """
        if psutil is None:
            return ("unknown", 0, "")

        try:
            proc = psutil.Process(pid)
            cmdline = " ".join(proc.cmdline()) if proc.cmdline() else ""
            parent = proc.parent()
            if parent is not None:
                return (_basename_lower(parent.name()), parent.pid, cmdline)
            return ("unknown", 0, cmdline)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return ("unknown", 0, "")
