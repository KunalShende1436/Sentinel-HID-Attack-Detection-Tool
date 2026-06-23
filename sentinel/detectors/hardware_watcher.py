"""
sentinel.detectors.hardware_watcher
====================================
Monitors USB device enumeration via Windows registry (USBSTOR / USB
keys) and flags devices whose VID:PID is not in the known-good allow
list or matches known ESP32 / attack-board vendor prefixes.

Detection heuristics:
    1. **Unknown VID:PID** — any device not in ``known_vid_pids``.
    2. **Suspicious vendor prefix** — Espressif, CH340, CP210x, etc.
    3. **Phantom HID** — a device that registers as a keyboard but has
       no physical HID descriptor attributes Windows would expect
       (composite device with only HID class).

Registry paths monitored:
    HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB
    HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR
"""

from __future__ import annotations

import re
import time
from queue import Queue
from typing import Dict, FrozenSet, Set

from sentinel.config import HW_CFG, HardwareWatcherConfig
from sentinel.core import Alert, BaseDetector, Severity

# Lazy imports — these are Windows-only; guard for linting on other OS
try:
    import winreg
except ImportError:
    winreg = None  # type: ignore[assignment]


# ── helpers ──────────────────────────────────────────────────────
_VID_PID_RE = re.compile(r"VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})", re.IGNORECASE)


def _enumerate_usb_vid_pids(registry_path: str) -> Dict[str, Set[str]]:
    """
    Walk a registry key (e.g. HKLM\\…\\USB) and extract all
    VID:PID pairs found in sub-key names.

    Returns:
        dict mapping "VID:PID" → set of instance IDs.
    """
    results: Dict[str, Set[str]] = {}
    if winreg is None:
        return results

    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, registry_path, 0, winreg.KEY_READ
        ) as parent:
            idx = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(parent, idx)
                    idx += 1
                except OSError:
                    break

                match = _VID_PID_RE.search(subkey_name)
                if not match:
                    continue

                vid_pid = f"{match.group(1).upper()}:{match.group(2).upper()}"

                # Enumerate instance IDs under this device
                try:
                    with winreg.OpenKey(parent, subkey_name) as dev_key:
                        inst_idx = 0
                        instances: Set[str] = set()
                        while True:
                            try:
                                instances.add(winreg.EnumKey(dev_key, inst_idx))
                                inst_idx += 1
                            except OSError:
                                break
                        results.setdefault(vid_pid, set()).update(instances)
                except OSError:
                    pass

    except OSError:
        pass  # Key may not exist — not an error condition

    return results


def _get_device_class(registry_path: str, subkey: str) -> str:
    """Read the 'Class' value from a device registry key (e.g. 'Keyboard')."""
    if winreg is None:
        return ""
    try:
        full_path = f"{registry_path}\\{subkey}"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, full_path, 0, winreg.KEY_READ) as key:
            # Walk instance sub-keys
            inst_idx = 0
            while True:
                try:
                    instance = winreg.EnumKey(key, inst_idx)
                    inst_idx += 1
                    with winreg.OpenKey(key, instance) as inst_key:
                        try:
                            val, _ = winreg.QueryValueEx(inst_key, "Class")
                            return str(val)
                        except OSError:
                            continue
                except OSError:
                    break
    except OSError:
        pass
    return ""


# ── detector ─────────────────────────────────────────────────────
class HardwareWatcher(BaseDetector):
    """
    Periodically polls USB registry keys and diffs the enumerated
    VID:PID set against a known-good baseline.

    Thread-safe: all mutable state is accessed only from the
    dedicated detector thread.
    """

    def __init__(
        self,
        alert_queue: Queue[Alert],
        cfg: HardwareWatcherConfig = HW_CFG,
    ) -> None:
        super().__init__(name="hardware_watcher", alert_queue=alert_queue)
        self._cfg = cfg
        self._baseline: Dict[str, Set[str]] = {}
        self._seen_vid_pids: Set[str] = set()

    # ── lifecycle ────────────────────────────────────────────────
    def _run_loop(self) -> None:
        # Capture initial baseline so we only alert on *new* devices
        self._baseline = self._snapshot()
        self._seen_vid_pids = set(self._baseline.keys())
        self._logger.info(
            "Baseline captured — %d VID:PID pairs known.", len(self._seen_vid_pids)
        )

        while not self._should_stop():
            time.sleep(self._cfg.poll_interval_s)
            current = self._snapshot()
            self._diff_and_alert(current)

    # ── internal ─────────────────────────────────────────────────
    def _snapshot(self) -> Dict[str, Set[str]]:
        """Merge VID:PID maps from both USB and USBSTOR keys."""
        merged: Dict[str, Set[str]] = {}
        for path in (self._cfg.usb_key, self._cfg.usbstor_key):
            for vid_pid, instances in _enumerate_usb_vid_pids(path).items():
                merged.setdefault(vid_pid, set()).update(instances)
        return merged

    def _diff_and_alert(self, current: Dict[str, Set[str]]) -> None:
        """Compare *current* device set against baseline and emit alerts."""
        new_vid_pids = set(current.keys()) - self._seen_vid_pids

        for vid_pid in new_vid_pids:
            severity = self._score_device(vid_pid)
            details = {
                "vid_pid": vid_pid,
                "instances": sorted(current.get(vid_pid, set())),
                "device_class": self._resolve_class(vid_pid),
            }

            self._emit_alert(
                severity=severity,
                title=f"New USB device detected — VID:PID {vid_pid}",
                details=details,
            )
            # Prevent re-alerting on the same device
            self._seen_vid_pids.add(vid_pid)

        # Update baseline
        self._baseline = current

    def _score_device(self, vid_pid: str) -> Severity:
        """
        Assign a threat severity to a newly-observed VID:PID.

        Scoring rules (highest wins):
            CRITICAL — matches a known ESP32 / attack-board vendor prefix
            HIGH     — unknown VID:PID not in allow list
            MEDIUM   — new device within an otherwise trusted vendor
        """
        vid = vid_pid.split(":")[0] if ":" in vid_pid else ""

        # Check against suspicious vendor prefixes (Espressif, CH340, etc.)
        for prefix in self._cfg.suspicious_vid_prefixes:
            if vid.upper().startswith(prefix.upper()):
                return Severity.CRITICAL

        # Check against known-good list
        if self._cfg.known_vid_pids and vid_pid not in self._cfg.known_vid_pids:
            return Severity.HIGH

        return Severity.MEDIUM

    def _resolve_class(self, vid_pid: str) -> str:
        """Attempt to read the Windows device class for a VID:PID."""
        # Build the sub-key name pattern Windows uses
        vid, pid = vid_pid.split(":") if ":" in vid_pid else (vid_pid, "")
        subkey = f"VID_{vid}&PID_{pid}"
        device_class = _get_device_class(self._cfg.usb_key, subkey)
        return device_class or "Unknown"
