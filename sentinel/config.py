"""
sentinel.config
===============
Centralised, immutable configuration for every Sentinel module.

All tuneable knobs live here so operators can adjust thresholds
without touching detection logic.  Values are deliberately
conservative — better a false-positive than a missed injection.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet


# ── paths ────────────────────────────────────────────────────────
BASE_DIR: Path = Path(os.environ.get("SENTINEL_BASE", Path.home() / ".sentinel"))
LOG_DIR: Path = BASE_DIR / "logs"
SNAPSHOT_DIR: Path = BASE_DIR / "snapshots"


@dataclass(frozen=True)
class HardwareWatcherConfig:
    """Thresholds for USB / HID device monitoring."""

    # Registry key that Windows populates on USB mass-storage insert
    usbstor_key: str = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
    usb_key: str = r"SYSTEM\CurrentControlSet\Enum\USB"

    # Poll interval in seconds (registry does not support push notifications)
    poll_interval_s: float = 2.0

    # Known-good VID:PID pairs (hex, upper-case).  Devices NOT in this
    # set are flagged as suspicious.  Populate from your asset inventory.
    known_vid_pids: FrozenSet[str] = field(default_factory=frozenset)

    # ESP32-based attack boards frequently use these Espressif VIDs
    # or clone common keyboard VIDs.  Flag on sight.
    suspicious_vid_prefixes: tuple[str, ...] = (
        "303A",   # Espressif Systems
        "1A86",   # QinHeng Electronics (CH340 — common on cheap dev boards)
        "10C4",   # Silicon Labs CP210x
    )


@dataclass(frozen=True)
class BehavioralAnalyzerConfig:
    """Thresholds for keystroke-anomaly detection."""

    # Minimum inter-key delta (ms) considered humanly possible
    min_human_delta_ms: float = 25.0

    # Maximum sustained words-per-minute before flagging
    max_human_wpm: int = 200

    # Sliding window size (keystrokes) for WPM calculation
    window_size: int = 50

    # Number of identical consecutive keystrokes to flag as "robotic repeat"
    repeat_threshold: int = 15

    # How long (seconds) to keep keystroke history before pruning
    history_ttl_s: float = 30.0


@dataclass(frozen=True)
class ProcessSentinelConfig:
    """Thresholds for process-creation monitoring."""

    # Shells to watch for
    target_processes: FrozenSet[str] = field(
        default_factory=lambda: frozenset({
            "cmd.exe",
            "powershell.exe",
            "pwsh.exe",
            "wscript.exe",
            "cscript.exe",
            "mshta.exe",
            "conhost.exe",
        })
    )

    # Parent images that should NOT be spawning shells
    suspicious_parents: FrozenSet[str] = field(
        default_factory=lambda: frozenset({
            "explorer.exe",
            "conhost.exe",
            "rundll32.exe",
            "dllhost.exe",
            "svchost.exe",      # only when not expected
        })
    )

    # WMI poll cadence (seconds)
    poll_interval_s: float = 1.0


@dataclass(frozen=True)
class ForensicConfig:
    """Settings for the forensic snapshot engine."""

    snapshot_dir: Path = SNAPSHOT_DIR

    # Maximum snapshot archive size (bytes) — 50 MB safety cap
    max_archive_bytes: int = 50 * 1024 * 1024

    # Registry hives to export on alert
    registry_hives: tuple[str, ...] = (
        r"HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR",
        r"HKLM\SYSTEM\CurrentControlSet\Enum\USB",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    )

    # Prefetch folder
    prefetch_dir: Path = Path(r"C:\Windows\Prefetch")

    # Temp folder (resolved per-user)
    temp_dir: Path = Path(os.environ.get("TEMP", r"C:\Temp"))

    # Max individual file size to include in snapshot (bytes) — 5 MB
    max_file_size: int = 5 * 1024 * 1024


@dataclass(frozen=True)
class AlertConfig:
    """Alert engine tunables."""

    # Threat-score threshold to trigger forensic snapshot (0–100)
    snapshot_threshold: int = 60

    # Cooldown between duplicate alerts for the same source (seconds)
    dedup_window_s: float = 30.0

    # Maximum alerts per minute before self-throttling
    max_alerts_per_minute: int = 20


# ── singleton instances (importable everywhere) ─────────────────
HW_CFG = HardwareWatcherConfig()
BA_CFG = BehavioralAnalyzerConfig()
PS_CFG = ProcessSentinelConfig()
FORENSIC_CFG = ForensicConfig()
ALERT_CFG = AlertConfig()
