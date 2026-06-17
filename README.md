# Sentinel — HID Attack Detection Framework

```
███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
```

**Host-side detection system for unauthorized HID (Human Interface Device) injection attacks**, specifically targeting ESP32-based attack hardware like ZeroTrace.

Includes a **real-time web dashboard** with live alert feed, threat gauge, timeline chart, module health monitoring, and full forensic snapshot management.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        USB / HID Event                          │
└──────────────┬──────────────────────────────────────────────────┘
               │
    ┌──────────▼──────────┐
    │   Hardware Watcher  │  Registry (USBSTOR/USB) polling
    │   VID:PID analysis  │  ESP32 vendor prefix detection
    └──────────┬──────────┘
               │ Alert
    ┌──────────▼──────────┐
    │ Behavioral Analyzer │  Keystroke timing analysis
    │   WPM / burst / rep │  Inter-key delta statistics
    └──────────┬──────────┘
               │ Alert
    ┌──────────▼──────────┐
    │  Process Sentinel   │  WMI process creation events
    │   parent→child map  │  Shell-spawn heuristics
    └──────────┬──────────┘
               │ Alert
    ┌──────────▼──────────┐
    │    Alert Engine      │  Threat scoring + dedup + rate limit
    └──────┬───────┬──────┘
           │       │
    ┌──────▼──┐  ┌─▼───────────┐   ┌──────────────────┐
    │  Logs   │  │  Forensic   │   │  Web Dashboard    │
    │ (JSONL) │  │  Snapshot   │   │  (Flask+SocketIO) │
    └─────────┘  └──────┬──────┘   └────────┬─────────┘
                        │                   │
                 ┌──────▼───────────────────▼──┐
                 │   Snapshot Viewer / Browser  │
                 │   (REST API + WebSocket)     │
                 └─────────────────────────────┘
```

---

## Quick Start

### Prerequisites

- **Windows 10/11** (registry, WMI, and Prefetch paths are Windows-specific)
- **Python 3.10+**

### Installation

```powershell
cd "Sentinel Project"
pip install -r requirements.txt
```

### Run

```powershell
# Launch the Web Dashboard (opens browser at http://localhost:8452)
python -m sentinel --gui

# Web dashboard on a custom port
python -m sentinel --gui --port 9000

# Legacy tkinter dashboard
python -m sentinel --gui-legacy

# Terminal mode (foreground, Ctrl+C to stop)
python -m sentinel

# Health check
python -m sentinel --status

# Version
python -m sentinel --version
```

---

## Web Dashboard

The web dashboard is a premium cybersecurity command center built with Flask, Socket.IO, and vanilla HTML/CSS/JS. Launch it with `python -m sentinel --gui`.

### Features

| Feature | Description |
|---------|-------------|
| **Live Alert Feed** | Real-time colour-coded alerts (INFO → CRITICAL) with auto-scroll, kill/snapshot badges, and truncated JSON details |
| **Threat Gauge** | Animated SVG radial gauge showing the maximum severity from the last 60 seconds |
| **Alert Timeline** | Canvas-based 5-minute sliding-window chart with severity-coloured bars |
| **Module Health** | Green/red pulsing status pills for Hardware Watcher, Behavioral Analyzer, Process Sentinel, and Alert Engine |
| **Statistics** | Live counters — total alerts, critical, high, medium, low, killed processes, snapshots captured |
| **Snapshot Browser** | Browse, drill-down, and download forensic snapshot ZIPs directly from the dashboard |
| **Controls** | Start / Stop / Manual Snapshot / Clear Log / Export JSON buttons |
| **Toast Notifications** | Auto-dismissing browser notifications for HIGH+ severity events |
| **Dark Theme** | Glassmorphism panels, deep navy background, cyan accents, JetBrains Mono typography, micro-animations |
| **Responsive** | Breakpoints at 1200px, 768px, and 480px |

### Dashboard Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  ◆ SENTINEL   HID Attack Detection & Response   [● ACTIVE] [v1.0] │
├──────────┬──────────┬──────────┬──────────┬─────────────────────────┤
│ THREAT   │  TOTAL   │  HIGH+   │  KILLED  │     MODULE STATUS       │
│ LEVEL    │  ALERTS  │  ALERTS  │ PROCS    │ HW ● BA ● PS ● AE ●    │
│ [GAUGE]  │   142    │    7     │    3     │                         │
├──────────┴──────────┴──────────┴──────────┴─────────────────────────┤
│                    ALERT TIMELINE CHART (5 min)                     │
├─────────────────────────────────────┬───────────────────────────────┤
│       LIVE ALERT FEED               │     SNAPSHOT BROWSER          │
│  ┌──────────────────────┐           │  ┌─────────────────────────┐  │
│  │ 🔴 CRITICAL 21:30:05 │           │  │ 📸 2026-06-16_21:30:05 │  │
│  │ ESP32 device detected │           │  │    ▸ Processes (47)     │  │
│  │ [⚡ KILLED] [📸 SNAP] │           │  │    ▸ Network (12)       │  │
│  └──────────────────────┘           │  │    ▸ Registry (4)       │  │
│                                     │  │    ▸ Temp Files (8)     │  │
│                                     │  │    [⬇ Download ZIP]     │  │
├─────────────────────────────────────┴───────────────────────────────┤
│  [▶ START] [⏹ STOP] [📸 SNAPSHOT] [🗑 CLEAR] [⬇ EXPORT]           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## REST API Reference

The web dashboard exposes a local REST API on `http://localhost:8452`:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Serves the dashboard HTML |
| `/api/status` | GET | System health — `{running, engine, detectors: {name: bool}}` |
| `/api/alerts` | GET | Alert history — `?limit=100&offset=0` — paginated |
| `/api/alerts/stats` | GET | Aggregated stats — by severity, source, recent 5 min |
| `/api/snapshots` | GET | List all snapshot ZIPs with metadata |
| `/api/snapshots/<name>/contents` | GET | Parse ZIP and return structured JSON (processes, network, registry, temp, prefetch) |
| `/api/snapshots/<name>/download` | GET | Download the raw snapshot ZIP |
| `/api/snapshots/manual` | POST | Trigger a manual forensic snapshot |
| `/api/control/start` | POST | Start the orchestrator and all detectors |
| `/api/control/stop` | POST | Graceful shutdown |

**WebSocket events** (Socket.IO):
- `alert` — real-time alert objects as they are processed
- `status` — system health broadcast every 2 seconds

---

## Project Structure

```
sentinel/
├── __init__.py                  # Package metadata (__version__, __codename__)
├── __main__.py                  # CLI entry point (--gui, --gui-legacy, --port, --status)
├── config.py                    # Centralised configuration (all tunables)
├── orchestrator.py              # Lifecycle manager + alert callback bridge
├── core/
│   └── __init__.py              # BaseDetector, Alert, Severity
├── detectors/
│   ├── __init__.py
│   ├── hardware_watcher.py      # USB registry + VID:PID monitoring
│   ├── behavioral_analyzer.py   # Keystroke anomaly detection
│   └── process_sentinel.py      # Suspicious shell-spawn detection
├── engine/
│   ├── __init__.py
│   └── alert_engine.py          # Alert pipeline + in-memory ring buffer
├── forensics/
│   ├── __init__.py
│   ├── snapshot.py              # Automated system-state capture (ZIP archives)
│   └── snapshot_viewer.py       # ZIP reader/parser for dashboard browsing
├── response/
│   ├── __init__.py
│   └── process_killer.py        # Auto-terminate malicious processes
└── ui/
    ├── __init__.py
    ├── dashboard.py             # Legacy tkinter dashboard (--gui-legacy)
    ├── web_server.py            # Flask + Socket.IO web dashboard (--gui)
    └── static/
        ├── index.html           # Dashboard HTML
        ├── style.css            # Premium dark cybersecurity theme
        └── app.js               # Frontend logic, charts, WebSocket client
```

---

## Detection Modules

### 1. Hardware Watcher
- Polls `HKLM\SYSTEM\CurrentControlSet\Enum\USB` and `USBSTOR` registry keys
- Flags devices with unknown VID:PID pairs
- **CRITICAL** alert for Espressif (ESP32), CH340, CP210x vendor prefixes
- Maintains a baseline diff to alert only on *new* device insertions

### 2. Behavioral Analyzer
- Hooks keyboard via `pynput` (no admin required)
- Computes inter-keystroke deltas over a sliding window
- **Detects:**
  - Impossible typing speed (>200 WPM / <25ms avg delta)
  - Robotic key repeats (>=15 consecutive identical keys)
  - Burst injection (5x rate spike after silence)
- Privacy-preserving: stores key *categories*, never actual characters

### 3. Process Sentinel
- Subscribes to `Win32_ProcessStartTrace` via WMI (falls back to `psutil` polling)
- Monitors for `cmd.exe`, `powershell.exe`, `wscript.exe`, `mshta.exe`, etc.
- Flags suspicious parent-to-child relationships (e.g., `explorer.exe` -> `powershell.exe`)
- Detects rapid shell chaining (>=3 shells in <5s)
- Scans command lines for payload indicators (`-EncodedCommand`, download cradles, etc.)

### 4. Automated Response
- **Process Killer** — automatically terminates malicious processes on HIGH+ severity alerts
- Protected process list prevents killing system-critical processes (csrss, lsass, explorer, etc.)

### 5. Forensic Snapshot Engine
Triggered automatically when an alert exceeds the severity threshold (default: 60/100), or manually from the dashboard.

**Captures:**

| Artefact | Details |
|----------|---------|
| Alert Metadata | Source, severity, title, details, snapshot ID, notes |
| Registry | USBSTOR, USB enum, Run/RunOnce keys |
| Prefetch | Directory listing with timestamps |
| %TEMP% | Files modified in the last 5 minutes |
| Processes | Full process table with cmdline + parent PID |
| Network | Active TCP/UDP connections |

Artefacts are bundled into a timestamped `.zip` under `~/.sentinel/snapshots/`.

Each snapshot includes a UUID-based `snapshot_id` for referencing. Manual snapshots support optional `notes` for annotation.

**Snapshot Viewer** — browse and inspect snapshots directly from the web dashboard:
- Drill into processes, network connections, registry exports, temp files, and prefetch data
- Download snapshot ZIPs from the browser
- Metadata display: source module, severity, timestamp, archive size

---

## Configuration

All tunables are in `sentinel/config.py` as frozen dataclasses:

| Config Class | Key Settings |
|---|---|
| `HardwareWatcherConfig` | `poll_interval_s`, `known_vid_pids`, `suspicious_vid_prefixes` |
| `BehavioralAnalyzerConfig` | `min_human_delta_ms`, `max_human_wpm`, `window_size`, `repeat_threshold` |
| `ProcessSentinelConfig` | `target_processes`, `suspicious_parents`, `poll_interval_s` |
| `ForensicConfig` | `snapshot_dir`, `max_archive_bytes`, `registry_hives` |
| `AlertConfig` | `snapshot_threshold`, `dedup_window_s`, `max_alerts_per_minute` |

---

## Extending Sentinel

The framework is designed for modularity. To add a new detector:

1. Create a class in `sentinel/detectors/` that extends `BaseDetector`
2. Implement `_run_loop()` — check `self._should_stop()` periodically
3. Call `self._emit_alert(severity, title, details)` when anomalies are detected
4. Register it in `SentinelOrchestrator.__init__()` within the `_detectors` list

```python
class MyCustomDetector(BaseDetector):
    def _run_loop(self) -> None:
        while not self._should_stop():
            # Your detection logic here
            if anomaly_detected:
                self._emit_alert(Severity.HIGH, "Custom alert", {"key": "value"})
            time.sleep(1.0)
```

---

## Security Design Principles

- **Least privilege** — no admin required for keyboard hooks or process monitoring
- **Defensive coding** — all OS calls wrapped in try/except; malformed data never crashes the framework
- **Privacy first** — keystroke content is never stored; only timing metadata
- **Bounded resources** — queue sizes, archive caps, and rate limits prevent runaway resource consumption
- **Clean shutdown** — cooperative cancellation via `threading.Event`; no orphan threads
- **Local only** — web dashboard binds to `127.0.0.1`; not exposed to the network

---

## Output

- **Dashboard:** `http://localhost:8452` — real-time web UI with alerts, charts, snapshot browser
- **Logs:** `~/.sentinel/logs/sentinel.log` (human-readable) + `alerts.jsonl` (machine-parseable)
- **Snapshots:** `~/.sentinel/snapshots/snapshot_<source>_<timestamp>.zip`
- **Desktop:** Windows toast notification + audible beep on alert

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `pywin32` | Win32 API access (registry, services, events) |
| `wmi` | WMI queries for process & device enumeration |
| `pynput` | Low-level keyboard hook (no admin required) |
| `psutil` | Process inspection & system metrics |
| `flask` | Lightweight web server for dashboard UI |
| `flask-socketio` | WebSocket support for real-time alert streaming |
| `gevent` | Async transport for Flask-SocketIO |
| `gevent-websocket` | WebSocket handler for gevent |

---

*Built as a defence-in-depth countermeasure for the ZeroTrace ESP32 HID attack framework.*

*Developed by **Kunal S & Ayush K**.*

