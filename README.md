# Sentinel

Sentinel is a Windows-focused host monitoring framework for detecting suspicious HID activity, such as unauthorized USB or ESP32-based device behavior, and for surfacing those events through a local dashboard and forensic snapshot workflow.

## What it does

- Watches for new USB and storage device activity through Windows registry and WMI data.
- Analyzes keyboard behavior for abnormal input patterns.
- Monitors suspicious process creation and shell spawning.
- Raises alerts with severity scoring and optional automated response.
- Provides a Flask-based web dashboard for live monitoring and snapshot review.

## Requirements

- Python 3.10+
- Windows 10/11

Install dependencies with:

```powershell
python -m pip install -r requirements.txt
```

## Quick start

Run the application in terminal mode:

```powershell
python -m sentinel
```

Launch the web dashboard:

```powershell
python -m sentinel --gui
```

Launch the legacy tkinter dashboard:

```powershell
python -m sentinel --gui-legacy
```

Check the current system status:

```powershell
python -m sentinel --status
```

Show the version:

```powershell
python -m sentinel --version
```

## Project layout

```text
sentinel/
├── __main__.py
├── config.py
├── orchestrator.py
├── core/
├── detectors/
├── engine/
├── forensics/
├── response/
└── ui/
```

## Notes

- The Windows-specific integrations are guarded in the dependency file so the project can be installed more flexibly on non-Windows hosts.
- The web dashboard listens on port 8452 by default and can be changed with `--port`.
- Forensic snapshots are stored under the user’s Sentinel data directory and can be browsed from the dashboard.
