from __future__ import annotations

import csv
import json
import logging
import sys
from abc import ABC, abstractmethod
from pathlib import Path
from typing import TextIO

from colorama import Fore, Style
from colorama import init as colorama_init

from spartan.results import ScanResult

log = logging.getLogger(__name__)

colorama_init(autoreset=True)

_COLORS = {
    200: Fore.GREEN,
    201: Fore.GREEN,
    202: Fore.GREEN,
    204: Fore.GREEN,
    301: Fore.YELLOW,
    302: Fore.YELLOW,
    303: Fore.YELLOW,
    307: Fore.YELLOW,
    308: Fore.YELLOW,
    400: Fore.RED,
    401: Fore.BLUE,
    403: Fore.BLUE,
    404: Fore.RED,
    405: Fore.RED,
    500: Fore.MAGENTA,
    502: Fore.MAGENTA,
    503: Fore.MAGENTA,
}


class OutputSink(ABC):
    @abstractmethod
    def write_result(self, result: ScanResult) -> None: ...

    @abstractmethod
    def write_message(self, message: str, level: str = "info") -> None: ...

    @abstractmethod
    def close(self) -> None: ...


class ConsoleSink(OutputSink):
    """Color-aware console output."""

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self._verbose = verbose
        self._quiet = quiet

    def write_result(self, result: ScanResult) -> None:
        if self._quiet:
            return

        if not self._verbose and not result.is_interesting:
            return

        if result.error:
            self._print(Fore.RED, f"[!] {result.url} - {result.error}")
            return

        if result.is_friendly_404:
            if self._verbose:
                self._print(
                    Fore.RED,
                    f"[-] [Friendly 404][{result.content_length}b] - {result.url}",
                )
            return

        color = _COLORS.get(result.status_code or 0, Fore.RESET)
        tag = "[+]" if result.is_success else "[-]"
        sc = result.status_code or "???"
        self._print(
            color,
            f"{tag} [{sc}][{result.content_length}b] - {result.url}",
        )

    def write_message(self, message: str, level: str = "info") -> None:
        if self._quiet and level != "error":
            return
        color = {"info": Fore.CYAN, "warn": Fore.YELLOW, "error": Fore.RED}.get(
            level, Fore.RESET
        )
        self._print(color, message)

    def write_banner(self, text: str) -> None:
        if not self._quiet:
            self._print(Fore.CYAN, text)

    def _print(self, color: str, text: str) -> None:
        print(f"{color}{text}{Style.RESET_ALL}", file=sys.stderr)

    def close(self) -> None:
        pass


class JsonSink(OutputSink):
    """Buffered JSON array output."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._results: list[dict] = []

    def write_result(self, result: ScanResult) -> None:
        self._results.append(result.to_dict())

    def write_message(self, message: str, level: str = "info") -> None:
        pass

    def close(self) -> None:
        self._path.write_text(
            json.dumps(self._results, indent=2, default=str), encoding="utf-8"
        )


class JsonlSink(OutputSink):
    """Streaming JSONL output — one JSON object per line."""

    def __init__(self, path: str):
        self._path = Path(path)
        self._fh: TextIO | None = None

    def _ensure_open(self):
        if self._fh is None:
            self._fh = self._path.open("a", encoding="utf-8")

    def write_result(self, result: ScanResult) -> None:
        self._ensure_open()
        line = json.dumps(result.to_dict(), default=str)
        self._fh.write(line + "\n")
        self._fh.flush()

    def write_message(self, message: str, level: str = "info") -> None:
        pass

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()


class CsvSink(OutputSink):
    """Streaming CSV output."""

    FIELDS = [
        "url",
        "method",
        "status_code",
        "content_length",
        "content_type",
        "title",
        "redirect_url",
        "elapsed_ms",
        "detector",
        "error",
        "is_friendly_404",
    ]

    def __init__(self, path: str):
        self._path = Path(path)
        self._fh: TextIO | None = None
        self._writer: csv.DictWriter | None = None

    def _ensure_open(self):
        if self._fh is None:
            self._fh = self._path.open("a", newline="", encoding="utf-8")
            self._writer = csv.DictWriter(self._fh, fieldnames=self.FIELDS)
            self._writer.writeheader()
            self._fh.flush()

    def write_result(self, result: ScanResult) -> None:
        self._ensure_open()
        if self._writer is None:
            return
        row = {f: result.to_dict().get(f, "") for f in self.FIELDS}
        self._writer.writerow(row)
        self._fh.flush()

    def write_message(self, message: str, level: str = "info") -> None:
        pass

    def close(self) -> None:
        if self._fh is not None:
            self._fh.close()
