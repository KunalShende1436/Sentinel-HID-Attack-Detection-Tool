"""
sentinel.forensics.snapshot_viewer
===================================
Utility module for reading and parsing forensic snapshot ZIP archives.

Provides structured access to snapshot contents for the web dashboard,
allowing users to browse processes, network connections, registry exports,
temp files, and prefetch data without manually extracting archives.
"""

from __future__ import annotations

import json
import logging
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from sentinel.config import FORENSIC_CFG, ForensicConfig

_log = logging.getLogger("sentinel.forensics.viewer")


# ── data classes ─────────────────────────────────────────────────

@dataclass
class SnapshotMeta:
    """Metadata for a single snapshot archive."""
    name: str
    path: Path
    timestamp: float          # Unix epoch from filename or metadata
    size_bytes: int
    source: str = ""          # Alert source module
    severity: int = 0         # Alert severity at time of capture
    snapshot_id: str = ""     # UUID-based ID


@dataclass
class SnapshotContents:
    """Parsed contents of a snapshot ZIP archive."""
    alert_metadata: Dict[str, Any] = field(default_factory=dict)
    processes: List[Dict[str, Any]] = field(default_factory=list)
    network: List[Dict[str, Any]] = field(default_factory=list)
    registry: Dict[str, str] = field(default_factory=dict)
    temp_files: List[str] = field(default_factory=list)
    prefetch: List[Dict[str, Any]] = field(default_factory=list)


# ── timestamp parser ─────────────────────────────────────────────
_TS_PATTERN = re.compile(r"(\d{4})(\d{2})(\d{2})T(\d{2})(\d{2})(\d{2})Z")


def _parse_timestamp_from_name(name: str) -> float:
    """Extract Unix timestamp from snapshot filename like snapshot_hw_20260616T213005Z.zip."""
    match = _TS_PATTERN.search(name)
    if match:
        import datetime
        y, mo, d, h, mi, s = (int(g) for g in match.groups())
        try:
            dt = datetime.datetime(y, mo, d, h, mi, s)
            return dt.timestamp()
        except (ValueError, OverflowError):
            pass
    return 0.0


# ── public API ───────────────────────────────────────────────────

class SnapshotViewer:
    """Utility for listing and reading forensic snapshot ZIP archives."""

    @staticmethod
    def list_snapshots(
        snapshot_dir: Optional[Path] = None,
    ) -> List[SnapshotMeta]:
        """
        List all snapshot ZIPs in the configured directory.

        Returns a list of SnapshotMeta sorted by timestamp (newest first).
        """
        directory = snapshot_dir or FORENSIC_CFG.snapshot_dir
        if not directory.is_dir():
            return []

        snapshots: List[SnapshotMeta] = []

        try:
            for entry in directory.iterdir():
                if not entry.is_file() or not entry.suffix == ".zip":
                    continue
                if not entry.name.startswith("snapshot_"):
                    continue

                try:
                    stat = entry.stat()
                    ts = _parse_timestamp_from_name(entry.name)

                    # Try to extract source from filename: snapshot_<source>_<timestamp>.zip
                    parts = entry.stem.split("_", 2)  # ['snapshot', 'source', 'timestamp']
                    source = parts[1] if len(parts) >= 3 else ""

                    meta = SnapshotMeta(
                        name=entry.name,
                        path=entry,
                        timestamp=ts if ts > 0 else stat.st_mtime,
                        size_bytes=stat.st_size,
                        source=source,
                    )

                    # Try to peek at alert_metadata.json for severity/ID
                    try:
                        with zipfile.ZipFile(entry, "r") as zf:
                            if "alert_metadata.json" in zf.namelist():
                                raw = zf.read("alert_metadata.json")
                                alert_meta = json.loads(raw)
                                meta.severity = alert_meta.get("severity", 0)
                                meta.snapshot_id = alert_meta.get("snapshot_id", "")
                    except (zipfile.BadZipFile, json.JSONDecodeError, KeyError):
                        pass

                    snapshots.append(meta)

                except OSError:
                    _log.debug("Cannot stat snapshot file: %s", entry)
                    continue

        except PermissionError:
            _log.warning("Cannot list snapshot directory: %s", directory)

        # Sort newest first
        snapshots.sort(key=lambda s: s.timestamp, reverse=True)
        return snapshots

    @staticmethod
    def read_snapshot(zip_path: Path) -> SnapshotContents:
        """
        Read and parse a snapshot ZIP archive into structured data.

        Args:
            zip_path: Path to the snapshot ZIP file.

        Returns:
            SnapshotContents with all parsed artefacts.
        """
        contents = SnapshotContents()

        if not zip_path.is_file():
            _log.warning("Snapshot file not found: %s", zip_path)
            return contents

        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()

                # Alert metadata
                if "alert_metadata.json" in names:
                    try:
                        raw = zf.read("alert_metadata.json")
                        contents.alert_metadata = json.loads(raw)
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Processes
                if "processes.json" in names:
                    try:
                        raw = zf.read("processes.json")
                        data = json.loads(raw)
                        if isinstance(data, list):
                            contents.processes = data
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Network
                if "network.json" in names:
                    try:
                        raw = zf.read("network.json")
                        data = json.loads(raw)
                        if isinstance(data, list):
                            contents.network = data
                    except (json.JSONDecodeError, KeyError):
                        pass

                # Registry exports
                for name in names:
                    if name.startswith("registry/") and not name.endswith("/"):
                        try:
                            raw = zf.read(name)
                            # Store as string, truncate very large exports
                            text = raw.decode("utf-8", errors="replace")
                            if len(text) > 50_000:
                                text = text[:50_000] + "\n... [truncated]"
                            reg_key = name.replace("registry/", "")
                            contents.registry[reg_key] = text
                        except (KeyError, UnicodeDecodeError):
                            pass

                # Temp files (just names, not contents — privacy)
                for name in names:
                    if name.startswith("temp/") and not name.endswith("/"):
                        contents.temp_files.append(name.replace("temp/", ""))

                # Prefetch listing
                if "prefetch/listing.json" in names:
                    try:
                        raw = zf.read("prefetch/listing.json")
                        data = json.loads(raw)
                        if isinstance(data, list):
                            contents.prefetch = data
                    except (json.JSONDecodeError, KeyError):
                        pass

        except zipfile.BadZipFile:
            _log.warning("Corrupt snapshot archive: %s", zip_path)
        except Exception:
            _log.exception("Failed to read snapshot: %s", zip_path)

        return contents

    @staticmethod
    def get_snapshot_summary(zip_path: Path) -> dict:
        """
        Quick summary of a snapshot without fully parsing it.

        Returns a dict with counts and basic metadata.
        """
        summary: Dict[str, Any] = {
            "name": zip_path.name,
            "size_bytes": 0,
            "file_count": 0,
            "has_processes": False,
            "has_network": False,
            "has_registry": False,
            "has_temp": False,
            "has_prefetch": False,
        }

        if not zip_path.is_file():
            return summary

        try:
            summary["size_bytes"] = zip_path.stat().st_size
            with zipfile.ZipFile(zip_path, "r") as zf:
                names = zf.namelist()
                summary["file_count"] = len(names)
                summary["has_processes"] = "processes.json" in names
                summary["has_network"] = "network.json" in names
                summary["has_registry"] = any(n.startswith("registry/") for n in names)
                summary["has_temp"] = any(n.startswith("temp/") for n in names)
                summary["has_prefetch"] = "prefetch/listing.json" in names
        except (zipfile.BadZipFile, OSError):
            pass

        return summary
