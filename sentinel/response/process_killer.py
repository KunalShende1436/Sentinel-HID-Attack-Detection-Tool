"""
sentinel.response.process_killer
=================================
Automated response module that terminates malicious processes
when the Alert Engine determines the threat severity is HIGH
or CRITICAL.

Safety guardrails:
    • Only kills processes whose PID is explicitly cited in the alert details.
    • Never kills system-critical PIDs (PID 0, 4, csrss, lsass, etc.).
    • Logs every kill attempt with full context for audit trail.
    • Kill is best-effort — AccessDenied is logged, not raised.
"""

from __future__ import annotations

import logging
import os
from typing import FrozenSet

from sentinel.core import Alert, Severity

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

_log = logging.getLogger("sentinel.response.killer")

# Processes that must NEVER be killed regardless of alert severity
_PROTECTED_PROCESSES: FrozenSet[str] = frozenset({
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "winlogon.exe",
    "dwm.exe",
    "explorer.exe",    # killing explorer disrupts the whole desktop
    "taskhostw.exe",
    "runtimebroker.exe",
    "sentinel",        # never kill ourselves
})

# PIDs that are always off-limits
_PROTECTED_PIDS: FrozenSet[int] = frozenset({0, 4})


def try_kill_process(alert: Alert) -> bool:
    """
    Attempt to terminate the malicious process referenced in *alert*.

    Returns True if the process was successfully killed, False otherwise.
    Only acts when:
        1. Severity is HIGH (75) or CRITICAL (100).
        2. A valid ``pid`` is present in ``alert.details``.
        3. The process is not on the protected list.
    """
    if psutil is None:
        _log.warning("psutil not available — cannot kill process.")
        return False

    # Gate: only act on HIGH+ severity
    if int(alert.severity) < int(Severity.HIGH):
        return False

    pid = alert.details.get("pid")
    if not isinstance(pid, int) or pid <= 0:
        _log.debug("Alert has no valid PID — skipping kill.")
        return False

    # Safety: never kill protected PIDs
    if pid in _PROTECTED_PIDS:
        _log.warning("Refusing to kill protected PID %d.", pid)
        return False

    try:
        proc = psutil.Process(pid)
        proc_name = proc.name().lower()

        # Safety: never kill protected system processes
        if proc_name in _PROTECTED_PROCESSES:
            _log.warning(
                "Refusing to kill protected process '%s' (PID %d).", proc_name, pid
            )
            return False

        # Attempt graceful termination first, then force-kill
        _log.warning(
            "KILLING suspicious process '%s' (PID %d) — severity %s | %s",
            proc_name, pid, alert.severity.name, alert.title,
        )
        proc.terminate()

        # Wait up to 3 seconds for graceful exit
        try:
            proc.wait(timeout=3.0)
            _log.info("Process '%s' (PID %d) terminated gracefully.", proc_name, pid)
            return True
        except psutil.TimeoutExpired:
            # Force kill
            _log.warning("Process '%s' (PID %d) did not exit — sending SIGKILL.", proc_name, pid)
            proc.kill()
            proc.wait(timeout=2.0)
            _log.info("Process '%s' (PID %d) force-killed.", proc_name, pid)
            return True

    except psutil.NoSuchProcess:
        _log.info("Process PID %d already exited.", pid)
        return False
    except psutil.AccessDenied:
        _log.error(
            "ACCESS DENIED: Cannot kill PID %d — run Sentinel as admin for auto-kill.",
            pid,
        )
        return False
    except Exception:
        _log.exception("Unexpected error killing PID %d.", pid)
        return False
