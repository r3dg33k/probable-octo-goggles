from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path


class ScanState:
    """Persistent scan state for save/resume."""

    VERSION = 2

    def __init__(self, output_dir: Path):
        self._output_dir = output_dir
        self._state_path = output_dir / "state.json"
        self._data: dict = {
            "version": self.VERSION,
            "urls": [],
            "scanned_urls": [],
            "timestamp": "",
            "metadata": {},
        }

    def load(self) -> bool:
        """Load state from disk. Returns True if state was found and loaded."""
        if not self._state_path.exists():
            return False
        try:
            raw = self._state_path.read_text(encoding="utf-8")
            self._data = json.loads(raw)
            return True
        except (json.JSONDecodeError, OSError):
            return False

    def save(self):
        """Atomically save state to disk."""
        self._data["timestamp"] = datetime.now(UTC).isoformat()
        self._output_dir.mkdir(parents=True, exist_ok=True)
        tmp = tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(self._output_dir),
            prefix=".state_tmp_",
            suffix=".json",
            delete=False,
        )
        try:
            json.dump(self._data, tmp, indent=2, default=str)
            tmp.close()
            os.replace(tmp.name, self._state_path)
        except Exception:
            os.unlink(tmp.name)
            raise

    def add_url(self, url: str):
        if url not in self._data["urls"]:
            self._data["urls"].append(url)

    def add_scanned(self, url: str):
        if url not in self._data["scanned_urls"]:
            self._data["scanned_urls"].append(url)

    @property
    def urls(self) -> list[str]:
        return self._data.get("urls", [])

    @property
    def scanned_urls(self) -> list[str]:
        return self._data.get("scanned_urls", [])

    @property
    def metadata(self) -> dict:
        return self._data.get("metadata", {})

    @metadata.setter
    def metadata(self, value: dict):
        self._data["metadata"] = value
