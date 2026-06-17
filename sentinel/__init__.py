"""
Sentinel — Host-Side HID Attack Detection Framework
=====================================================

A modular, object-oriented Python framework designed to detect
unauthorized HID (Human Interface Device) injection attacks,
particularly those originating from ESP32-based attack hardware.

Modules:
    - hardware_watcher : USB registry and device enumeration monitoring
    - behavioral_analyzer : Keystroke timing and pattern anomaly detection
    - process_sentinel : Suspicious process creation monitoring
    - forensic_logic : Automated system-state snapshotting on alert
    - alert_engine : Threat scoring, deduplication, and dispatch
    - orchestrator : Lifecycle management for all watchers

Author : CFI TAE — Sentinel Project
License: MIT
"""

__version__ = "1.0.0"
__codename__ = "Sentinel"
