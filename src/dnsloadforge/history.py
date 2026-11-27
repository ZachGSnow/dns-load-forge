"""Finished runs, kept across restarts.

The comparison table is the part of a session worth keeping: the same seeded
traffic sent to several filters, often on different days.  It lived only in
memory, so restarting the dashboard -- to change a flag, after a reboot -- emptied
it.  Each finished run is now appended to ``history.jsonl`` as one JSON line, and
the last ``limit`` runs are read back on start.

The file lives in ``$DNSLOADFORGE_DATA`` when that is set; in ``runs/`` inside a
source checkout, beside the record logs; otherwise in a per-user data directory,
because an installed package must not write into its own install location.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

__all__ = ["HISTORY_FILE", "HistoryStore", "default_data_dir"]

HISTORY_FILE = "history.jsonl"


def default_data_dir() -> Path:
    """Where the tool keeps what it produces: run history, by default."""
    override = os.environ.get("DNSLOADFORGE_DATA", "").strip()
    if override:
        return Path(override)
    checkout = Path(__file__).resolve().parent.parent.parent
    if (checkout / "lists").is_dir():
        return checkout / "runs"
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "dnsloadforge"


class HistoryStore:
    """Run summaries in a JSON Lines file.

    Reading skips any line it cannot parse, since a crash in the middle of a write
    leaves at most one.  Once the file holds four times ``limit`` runs it is
    rewritten to the last ``limit``, so it never grows without bound.  With no
    path the store keeps nothing, which is what ``--no-history`` and the tests use.
    """

    def __init__(self, path: str | Path | None, limit: int = 50) -> None:
        self.path = Path(path) if path else None
        self.limit = max(1, int(limit))
        self._lock = threading.Lock()
        self._lines = 0

    def load(self) -> list[dict]:
        """The last ``limit`` runs, oldest first."""
        if self.path is None:
            return []
        runs: list[dict] = []
        try:
            with self.path.open(encoding="utf-8") as handle:
                for line in handle:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(entry, dict) and "target" in entry:
                        runs.append(entry)
        except OSError:
            return []
        self._lines = len(runs)
        return runs[-self.limit :]

    def append(self, summary: dict) -> str:
        """Save one run.  Returns why it could not be saved, or ""."""
        if self.path is None:
            return ""
        with self._lock:
            try:
                self.path.parent.mkdir(parents=True, exist_ok=True)
                with self.path.open("a", encoding="utf-8") as handle:
                    handle.write(json.dumps(summary, separators=(",", ":"), default=str) + "\n")
                self._lines += 1
                if self._lines > 4 * self.limit:
                    self._compact()
            except OSError as exc:
                return f"could not save the run history to {self.path}: {exc}"
        return ""

    def _compact(self) -> None:
        runs = self.load()
        assert self.path is not None
        temporary = self.path.with_suffix(".jsonl.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            for run in runs:
                handle.write(json.dumps(run, separators=(",", ":"), default=str) + "\n")
        os.replace(temporary, self.path)
        self._lines = len(runs)

    def clear(self) -> str:
        """Forget every saved run.  Returns why it could not, or ""."""
        if self.path is None:
            return ""
        with self._lock:
            try:
                self.path.unlink(missing_ok=True)
            except OSError as exc:
                return f"could not clear the run history at {self.path}: {exc}"
            self._lines = 0
        return ""
