"""
sentinel.forensics.snapshot
============================
Automated system-state snapshotting triggered when the Alert Engine
determines a detection event exceeds the forensic threshold.

Captured artefacts:
    1. **Registry exports** — USBSTOR, USB enum, Run/RunOnce keys.
    2. **Prefetch files** — evidence of recently executed binaries.
    3. **%TEMP% directory listing** — dropped payloads / staging files.
    4. **Process table** — full snapshot of running processes at the
       moment of the alert.
    5. **Network connections** — active TCP/UDP sockets.

All artefacts are bundled into a single timestamped ZIP archive
under ``SENTINEL_BASE/snapshots/``.

Security notes:
    • No user-content (keystrokes, clipboard) is captured — privacy first.
    • Archives are capped at ``max_archive_bytes`` to prevent disk abuse.
    • Temp files larger than ``max_file_size`` are skipped.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import os
import subprocess
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.config import FORENSIC_CFG, ForensicConfig
from sentinel.core import Alert

try:
    import psutil
except ImportError:
    psutil = None  # type: ignore[assignment]

_log = logging.getLogger("sentinel.forensics")


# ── public API ───────────────────────────────────────────────────
def capture_snapshot(
    alert: Alert,
    cfg: ForensicConfig = FORENSIC_CFG,
    notes: str = "",
) -> Optional[Path]:
    """
    Create a forensic snapshot ZIP in response to *alert*.

    Args:
        alert: The triggering alert.
        cfg: Forensic configuration.
        notes: Optional user-provided notes (for manual snapshots).

    Returns:
        Path to the ZIP archive on success, ``None`` on failure.
    """
    snapshot_id = uuid.uuid4().hex[:12]
    ts = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    safe_source = "".join(c if c.isalnum() or c in "-_" else "_" for c in alert.source)
    archive_name = f"snapshot_{safe_source}_{ts}.zip"
    archive_path = cfg.snapshot_dir / archive_name

    # Ensure output directory exists
    try:
        cfg.snapshot_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        _log.exception("Cannot create snapshot directory %s", cfg.snapshot_dir)
        return None

    try:
        with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
            _add_alert_metadata(zf, alert, snapshot_id=snapshot_id, notes=notes)
            _add_registry_exports(zf, cfg)
            _add_prefetch_listing(zf, cfg)
            _add_temp_files(zf, cfg)
            _add_process_table(zf)
            _add_network_connections(zf)

        # Safety: enforce archive size cap
        if archive_path.stat().st_size > cfg.max_archive_bytes:
            _log.warning(
                "Snapshot %s exceeds %d bytes — removing.",
                archive_path,
                cfg.max_archive_bytes,
            )
            archive_path.unlink(missing_ok=True)
            return None

        _log.info("Forensic snapshot saved → %s", archive_path)
        return archive_path

    except Exception:
        _log.exception("Snapshot creation failed.")
        # Clean up partial archive
        if archive_path.exists():
            archive_path.unlink(missing_ok=True)
        return None


# ── internal artefact collectors ─────────────────────────────────

def _add_alert_metadata(
    zf: zipfile.ZipFile,
    alert: Alert,
    snapshot_id: str = "",
    notes: str = "",
) -> None:
    """Embed the triggering alert as JSON inside the archive."""
    meta = {
        "snapshot_id": snapshot_id,
        "timestamp": alert.timestamp,
        "source": alert.source,
        "severity": int(alert.severity),
        "title": alert.title,
        "details": alert.details,
        "notes": notes,
    }
    zf.writestr("alert_metadata.json", json.dumps(meta, indent=2, default=str))


def _add_registry_exports(zf: zipfile.ZipFile, cfg: ForensicConfig) -> None:
    """
    Export each configured registry hive via ``reg export``.
    Uses a subprocess with strict timeout to avoid hanging.
    """
    for hive in cfg.registry_hives:
        safe_name = hive.replace("\\", "_").replace("/", "_") + ".reg"
        try:
            result = subprocess.run(
                ["reg", "export", hive, "CON", "/y"],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0,
            )
            if result.returncode == 0 and result.stdout:
                zf.writestr(f"registry/{safe_name}", result.stdout)
            else:
                zf.writestr(
                    f"registry/{safe_name}.error",
                    f"reg export returned {result.returncode}\n{result.stderr}",
                )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            zf.writestr(f"registry/{safe_name}.error", str(exc))


def _add_prefetch_listing(zf: zipfile.ZipFile, cfg: ForensicConfig) -> None:
    """
    List (not copy — they require SYSTEM access) Prefetch files
    with timestamps.
    """
    entries: List[Dict[str, Any]] = []
    prefetch = cfg.prefetch_dir
    if prefetch.is_dir():
        try:
            for f in sorted(prefetch.iterdir()):
                try:
                    stat = f.stat()
                    entries.append({
                        "name": f.name,
                        "size": stat.st_size,
                        "modified": datetime.datetime.fromtimestamp(
                            stat.st_mtime
                        ).isoformat(),
                        "created": datetime.datetime.fromtimestamp(
                            stat.st_ctime
                        ).isoformat(),
                    })
                except OSError:
                    entries.append({"name": f.name, "error": "access denied"})
        except PermissionError:
            entries.append({"error": "Cannot list Prefetch directory"})
    else:
        entries.append({"error": f"{prefetch} does not exist or is not accessible"})

    zf.writestr("prefetch/listing.json", json.dumps(entries, indent=2))


def _add_temp_files(zf: zipfile.ZipFile, cfg: ForensicConfig) -> None:
    """
    Copy small files from %TEMP% into the snapshot.
    Only files created/modified in the last 5 minutes are included
    to keep the archive focused on the incident window.
    """
    cutoff = datetime.datetime.now().timestamp() - 300  # 5 minutes
    temp_dir = cfg.temp_dir
    included = 0

    if not temp_dir.is_dir():
        return

    try:
        for entry in temp_dir.iterdir():
            if not entry.is_file():
                continue
            try:
                stat = entry.stat()
            except OSError:
                continue

            if stat.st_mtime < cutoff:
                continue
            if stat.st_size > cfg.max_file_size:
                continue

            try:
                zf.write(entry, f"temp/{entry.name}")
                included += 1
            except (OSError, PermissionError):
                pass

            if included >= 200:  # hard cap on temp files
                break
    except PermissionError:
        pass


def _add_process_table(zf: zipfile.ZipFile) -> None:
    """Snapshot of all running processes with key metadata."""
    if psutil is None:
        zf.writestr("processes.json", '{"error": "psutil not available"}')
        return

    procs: List[Dict[str, Any]] = []
    for proc in psutil.process_iter(
        ["pid", "name", "ppid", "username", "cmdline", "create_time"]
    ):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info["name"],
                "ppid": info["ppid"],
                "user": info.get("username", ""),
                "cmdline": " ".join(info["cmdline"]) if info.get("cmdline") else "",
                "created": datetime.datetime.fromtimestamp(
                    info["create_time"]
                ).isoformat() if info.get("create_time") else "",
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    zf.writestr("processes.json", json.dumps(procs, indent=2))


def _add_network_connections(zf: zipfile.ZipFile) -> None:
    """Snapshot active network connections."""
    if psutil is None:
        zf.writestr("network.json", '{"error": "psutil not available"}')
        return

    conns: List[Dict[str, Any]] = []
    try:
        for conn in psutil.net_connections(kind="all"):
            conns.append({
                "fd": conn.fd,
                "family": str(conn.family),
                "type": str(conn.type),
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                "status": conn.status,
                "pid": conn.pid,
            })
    except (psutil.AccessDenied, OSError):
        conns.append({"error": "insufficient privileges"})

    zf.writestr("network.json", json.dumps(conns, indent=2))
