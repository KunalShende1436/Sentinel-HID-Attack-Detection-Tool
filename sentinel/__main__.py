#!/usr/bin/env python3
"""
sentinel.__main__
==================
CLI entry point for the Sentinel HID Attack Detection Framework.

Usage:
    python -m sentinel              # start all modules (terminal mode)
    python -m sentinel --gui        # launch web dashboard (opens browser)
    python -m sentinel --gui-legacy # launch legacy tkinter dashboard
    python -m sentinel --status     # print health check and exit
    python -m sentinel --version    # print version and exit

The process runs in the foreground and can be stopped with Ctrl+C.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from sentinel import __version__
from sentinel.config import BASE_DIR, LOG_DIR
from sentinel.orchestrator import SentinelOrchestrator


def _setup_logging() -> None:
    """Configure root logger: file + stderr."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "sentinel.log"

    fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)-8s %(name)s :: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler — rotate manually or via logrotate
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(fmt)

    # Console handler — INFO and above
    ch = logging.StreamHandler(sys.stderr)
    ch.setLevel(logging.INFO)
    ch.setFormatter(fmt)

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    root.addHandler(fh)
    root.addHandler(ch)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — Host-Side HID Attack Detection Framework",
    )
    parser.add_argument(
        "--version", action="store_true", help="Print version and exit."
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Start Sentinel briefly, print health-check JSON, and exit.",
    )
    parser.add_argument(
        "--gui", action="store_true",
        help="Launch the web-based dashboard (opens in browser).",
    )
    parser.add_argument(
        "--gui-legacy", action="store_true",
        help="Launch the legacy tkinter dashboard.",
    )
    parser.add_argument(
        "--port", type=int, default=8452,
        help="Port for the web dashboard (default: 8452).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()

    if args.version:
        print(f"Sentinel v{__version__}")
        return

    _setup_logging()
    log = logging.getLogger("sentinel.main")

    log.info("Base directory: %s", BASE_DIR)

    # ── Web dashboard mode ───────────────────────────────────────
    if args.gui:
        from sentinel.ui.web_server import SentinelWebDashboard
        dashboard = SentinelWebDashboard(port=args.port)
        dashboard.run()
        return

    # ── Legacy tkinter dashboard mode ────────────────────────────
    if args.gui_legacy:
        from sentinel.ui.dashboard import SentinelDashboard
        dashboard = SentinelDashboard()
        dashboard.run()
        return

    orch = SentinelOrchestrator()

    if args.status:
        orch.start()
        import time
        time.sleep(2)  # let modules initialize
        print(json.dumps(orch.status(), indent=2))
        orch.stop()
        return

    # Normal run — block until Ctrl+C
    orch.start()
    try:
        orch.wait()
    except SystemExit:
        orch.stop()


if __name__ == "__main__":
    main()
