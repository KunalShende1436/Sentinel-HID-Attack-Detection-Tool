"""
sentinel.ui.web_server
========================
Flask-based web dashboard for Sentinel with real-time WebSocket alerts.

Provides:
    • Static file serving for the HTML/CSS/JS dashboard
    • REST API for status, alerts, snapshots, and controls
    • WebSocket (Socket.IO) for real-time alert streaming
    • Periodic status broadcast every 2 seconds

Usage::

    from sentinel.ui.web_server import SentinelWebDashboard
    dashboard = SentinelWebDashboard(port=8452)
    dashboard.run()  # blocks — starts Flask + orchestrator
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import webbrowser
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from flask import Flask, jsonify, request, send_from_directory, send_file
from flask_socketio import SocketIO

from sentinel import __version__
from sentinel.config import LOG_DIR, SNAPSHOT_DIR
from sentinel.core import Alert, Severity
from sentinel.forensics import capture_snapshot
from sentinel.forensics.snapshot_viewer import SnapshotViewer
from sentinel.orchestrator import SentinelOrchestrator

_log = logging.getLogger("sentinel.ui.web")

# ── paths ────────────────────────────────────────────────────────
_STATIC_DIR = Path(__file__).parent / "static"


# ── alert serialiser ─────────────────────────────────────────────

def _alert_to_dict(alert: Alert) -> dict:
    """Convert an Alert dataclass to a JSON-serialisable dict."""
    sev_name_map = {0: "INFO", 25: "LOW", 50: "MEDIUM", 75: "HIGH", 100: "CRITICAL"}
    sev_val = int(alert.severity)
    sev_name = sev_name_map.get(sev_val, "UNKNOWN")

    return {
        "timestamp": alert.timestamp,
        "source": alert.source,
        "severity": sev_val,
        "severity_name": sev_name,
        "title": alert.title,
        "details": alert.details,
        "snapshot_requested": alert.snapshot_requested,
    }


# ── web dashboard class ─────────────────────────────────────────

class SentinelWebDashboard:
    """
    Web-based Sentinel dashboard.

    Wraps Flask + Socket.IO + SentinelOrchestrator into a single
    entry point.  The orchestrator is created and managed internally.
    """

    def __init__(self, port: int = 8452) -> None:
        self._port = port
        self._orch: Optional[SentinelOrchestrator] = None
        self._socketio: Optional[SocketIO] = None

        # Build Flask app
        self._app = Flask(
            __name__,
            static_folder=str(_STATIC_DIR),
            static_url_path="/static",
        )
        self._app.config["SECRET_KEY"] = os.urandom(24).hex()

        # Suppress Flask request logs (noisy)
        flask_log = logging.getLogger("werkzeug")
        flask_log.setLevel(logging.WARNING)

        # Socket.IO — use 'threading' mode for full compatibility with
        # the orchestrator's standard threading.Thread-based detectors.
        # gevent's monkey-patching breaks WMI, pynput, and registry polling.
        self._socketio = SocketIO(
            self._app,
            async_mode="threading",
            cors_allowed_origins="*",
            logger=False,
            engineio_logger=False,
        )

        self._register_routes()
        self._register_socket_events()

    # ── route registration ───────────────────────────────────────

    def _register_routes(self) -> None:
        app = self._app

        # ── dashboard page ───────────────────────────────────────
        @app.route("/")
        def index():
            return send_from_directory(str(_STATIC_DIR), "index.html")

        # ── system status ────────────────────────────────────────
        @app.route("/api/status")
        def api_status():
            if self._orch is None:
                return jsonify({"running": False, "engine": False, "detectors": {}})
            return jsonify(self._orch.status())

        # ── alerts ───────────────────────────────────────────────
        @app.route("/api/alerts")
        def api_alerts():
            limit = request.args.get("limit", 100, type=int)
            offset = request.args.get("offset", 0, type=int)

            if self._orch is None:
                return jsonify({"alerts": [], "total": 0})

            all_alerts = self._orch.get_alert_history(limit=500)
            # Convert to dicts
            alert_dicts = [_alert_to_dict(a) for a in reversed(all_alerts)]

            total = len(alert_dicts)
            paginated = alert_dicts[offset:offset + limit]
            return jsonify({"alerts": paginated, "total": total})

        @app.route("/api/alerts/stats")
        def api_alert_stats():
            if self._orch is None:
                return jsonify({
                    "total": 0,
                    "by_severity": {},
                    "by_source": {},
                    "recent_5min": 0,
                })

            all_alerts = self._orch.get_alert_history(limit=500)
            by_severity: dict = {}
            by_source: dict = {}
            cutoff = time.time() - 300
            recent = 0

            for a in all_alerts:
                sev_name = Severity(int(a.severity)).name
                by_severity[sev_name] = by_severity.get(sev_name, 0) + 1
                by_source[a.source] = by_source.get(a.source, 0) + 1
                if a.timestamp >= cutoff:
                    recent += 1

            return jsonify({
                "total": len(all_alerts),
                "by_severity": by_severity,
                "by_source": by_source,
                "recent_5min": recent,
            })

        # ── snapshots ────────────────────────────────────────────
        @app.route("/api/snapshots")
        def api_snapshots():
            snapshots = SnapshotViewer.list_snapshots()
            result = []
            for s in snapshots:
                result.append({
                    "name": s.name,
                    "timestamp": s.timestamp,
                    "size_bytes": s.size_bytes,
                    "source": s.source,
                    "severity": s.severity,
                    "snapshot_id": s.snapshot_id,
                })
            return jsonify({"snapshots": result})

        @app.route("/api/snapshots/<name>/contents")
        def api_snapshot_contents(name: str):
            snapshots = SnapshotViewer.list_snapshots()
            target = None
            for s in snapshots:
                if s.name == name:
                    target = s
                    break

            if target is None:
                return jsonify({"error": "Snapshot not found"}), 404

            contents = SnapshotViewer.read_snapshot(target.path)
            return jsonify({
                "alert_metadata": contents.alert_metadata,
                "processes": contents.processes,
                "network": contents.network,
                "registry": contents.registry,
                "temp_files": contents.temp_files,
                "prefetch": contents.prefetch,
            })

        @app.route("/api/snapshots/<name>/download")
        def api_snapshot_download(name: str):
            snapshots = SnapshotViewer.list_snapshots()
            target = None
            for s in snapshots:
                if s.name == name:
                    target = s
                    break

            if target is None:
                return jsonify({"error": "Snapshot not found"}), 404

            return send_file(
                str(target.path),
                as_attachment=True,
                download_name=name,
                mimetype="application/zip",
            )

        @app.route("/api/snapshots/manual", methods=["POST"])
        def api_manual_snapshot():
            # Create a synthetic alert for manual snapshots
            notes = ""
            if request.is_json:
                notes = request.json.get("notes", "")

            alert = Alert(
                timestamp=time.time(),
                source="manual_dashboard",
                severity=Severity.INFO,
                title="Manual snapshot triggered from web dashboard",
                details={"trigger": "web_dashboard", "notes": notes},
            )

            def _do_snapshot():
                path = capture_snapshot(alert, notes=notes)
                if path:
                    _log.info("Manual snapshot saved: %s", path)

            thread = threading.Thread(target=_do_snapshot, daemon=True)
            thread.start()
            thread.join(timeout=30)  # Wait up to 30s

            return jsonify({"success": True})

        @app.route("/api/snapshots/clear", methods=["POST"])
        def api_clear_snapshots():
            """Delete all forensic snapshot ZIP archives."""
            try:
                snapshot_dir = SNAPSHOT_DIR
                deleted = 0
                if snapshot_dir.is_dir():
                    for f in snapshot_dir.iterdir():
                        if f.is_file() and f.suffix == ".zip" and f.name.startswith("snapshot_"):
                            try:
                                f.unlink()
                                deleted += 1
                            except OSError as e:
                                _log.warning("Cannot delete snapshot %s: %s", f.name, e)
                _log.info("Cleared %d snapshot(s) from %s", deleted, snapshot_dir)
                return jsonify({"success": True, "deleted": deleted})
            except Exception as e:
                _log.exception("Error in /api/snapshots/clear")
                return jsonify({"success": False, "error": str(e)}), 500

        # ── controls ─────────────────────────────────────────────
        @app.route("/api/control/start", methods=["POST"])
        def api_start():
            try:
                if self._orch is None:
                    self._orch = SentinelOrchestrator()
                    self._orch.set_alert_callback(self._on_alert)

                if not self._orch.is_running:
                    # Start in a background thread so we don't block the HTTP response
                    def _do_start():
                        try:
                            self._orch.start()
                            _log.info("Orchestrator started via web dashboard.")
                        except Exception:
                            _log.exception("Failed to start orchestrator.")

                    t = threading.Thread(target=_do_start, daemon=True)
                    t.start()
                    t.join(timeout=10)
                    return jsonify({"success": True})

                return jsonify({"success": True, "message": "Already running"})
            except Exception as e:
                _log.exception("Error in /api/control/start")
                return jsonify({"success": False, "error": str(e)}), 500

        @app.route("/api/control/stop", methods=["POST"])
        def api_stop():
            try:
                if self._orch is not None and self._orch.is_running:
                    def _stop():
                        try:
                            self._orch.stop()
                            _log.info("Orchestrator stopped via web dashboard.")
                        except Exception:
                            _log.exception("Failed to stop orchestrator.")
                    thread = threading.Thread(target=_stop, daemon=True)
                    thread.start()
                    thread.join(timeout=10)
                return jsonify({"success": True})
            except Exception as e:
                _log.exception("Error in /api/control/stop")
                return jsonify({"success": False, "error": str(e)}), 500

    # ── Socket.IO events ─────────────────────────────────────────

    def _register_socket_events(self) -> None:
        sio = self._socketio

        @sio.on("connect")
        def on_connect():
            _log.debug("WebSocket client connected.")
            # Send initial status
            if self._orch:
                sio.emit("status", self._orch.status())

        @sio.on("disconnect")
        def on_disconnect():
            _log.debug("WebSocket client disconnected.")

    # ── alert callback (called from AlertEngine thread) ──────────

    def _on_alert(self, alert: Alert) -> None:
        """Bridge AlertEngine → WebSocket clients."""
        if self._socketio:
            try:
                self._socketio.emit("alert", _alert_to_dict(alert))
            except Exception:
                _log.debug("Failed to emit alert via WebSocket.", exc_info=True)

    # ── periodic status broadcast ────────────────────────────────

    def _status_broadcaster(self) -> None:
        """Broadcast system status to all WebSocket clients every 2 seconds."""
        while True:
            try:
                time.sleep(2)
                if self._orch and self._socketio:
                    self._socketio.emit("status", self._orch.status())
            except Exception:
                pass

    # ── public run ───────────────────────────────────────────────

    def run(self) -> None:
        """
        Start the web dashboard.  Blocks the calling thread.

        Creates the orchestrator, registers the alert callback,
        starts the status broadcaster, opens the browser, and
        launches the Flask-SocketIO server.
        """
        # Create orchestrator
        self._orch = SentinelOrchestrator()
        self._orch.set_alert_callback(self._on_alert)

        # Start status broadcaster
        broadcaster = threading.Thread(
            target=self._status_broadcaster,
            name="sentinel-status-broadcaster",
            daemon=True,
        )
        broadcaster.start()

        # Open browser after a short delay
        def _open_browser():
            time.sleep(1.5)
            url = f"http://localhost:{self._port}"
            _log.info("Opening dashboard: %s", url)
            webbrowser.open(url)

        threading.Thread(target=_open_browser, daemon=True).start()

        _log.info("Starting Sentinel Web Dashboard on port %d", self._port)
        print(f"\n  ◆ SENTINEL Web Dashboard")
        print(f"  ─────────────────────────")
        print(f"  Dashboard:  http://localhost:{self._port}")
        print(f"  Logs:       {LOG_DIR}")
        print(f"  Snapshots:  {SNAPSHOT_DIR}")
        print(f"  Press Ctrl+C to stop.\n")

        try:
            self._socketio.run(
                self._app,
                host="127.0.0.1",
                port=self._port,
                debug=False,
                use_reloader=False,
                log_output=False,
                allow_unsafe_werkzeug=True,
            )
        except KeyboardInterrupt:
            pass
        finally:
            if self._orch and self._orch.is_running:
                self._orch.stop()
