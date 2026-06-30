from __future__ import annotations

import hashlib
import logging
import os
import tempfile
import time
from pathlib import Path

from spartan.http_client import SessionFactory

log = logging.getLogger(__name__)

_DOWNLOADABLE_EXTENSIONS = {
    ".txt", ".stp", ".xlsx", ".xls", ".doc", ".docx",
    ".pdf", ".xml", ".config", ".conf", ".aspx", ".asp",
    ".webpart", ".csv",
}


def _sanitize_filename(name: str) -> str:
    """Remove path separators and null bytes from a filename."""
    name = name.replace("/", "_").replace("\\", "_").replace("\0", "")
    if not name or name in (".", ".."):
        name = f"download_{int(time.time())}"
    return name


def _is_interpreted_asp(content: bytes) -> bool:
    """Check if ASP/ASPX content has server-side script markers."""
    text = content.decode("utf-8", errors="replace")
    return "<%" in text and "%>" in text


class DownloadResult:
    """Metadata about a downloaded file."""

    def __init__(
        self,
        url: str,
        filename: str,
        size_bytes: int,
        sha256: str,
        skipped: bool = False,
        error: str | None = None,
    ):
        self.url = url
        self.filename = filename
        self.size_bytes = size_bytes
        self.sha256 = sha256
        self.skipped = skipped
        self.error = error

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "filename": self.filename,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "skipped": self.skipped,
            "error": self.error,
        }


class SafeDownloader:
    """Thread-safe downloader with path traversal protection, size limits,
    atomic writes, and SHA-256 hashing."""

    def __init__(
        self,
        session_factory: SessionFactory,
        output_dir: Path,
        max_size: int = 10 * 1024 * 1024,
        no_overwrite: bool = True,
        hash_downloads: bool = False,
    ):
        self._session_factory = session_factory
        self._output_dir = output_dir
        self._max_size = max_size
        self._no_overwrite = no_overwrite
        self._hash_downloads = hash_downloads

    def download(self, url: str) -> DownloadResult:
        """Download a single file safely. Returns result metadata."""
        ext = Path(url.split("?")[0]).suffix.lower()

        # Only download allowed extensions
        if ext not in _DOWNLOADABLE_EXTENSIONS:
            return DownloadResult(
                url=url,
                filename="",
                size_bytes=0,
                sha256="",
                skipped=True,
                error="Unsupported extension",
            )

        filename = _sanitize_filename(url.rsplit("/", 1)[-1].split("?")[0])
        dest = (self._output_dir / filename).resolve()

        # Path traversal check
        if not str(dest).startswith(str(self._output_dir.resolve())):
            return DownloadResult(
                url=url,
                filename=filename,
                size_bytes=0,
                sha256="",
                skipped=True,
                error="Path traversal detected",
            )

        if self._no_overwrite and dest.exists():
            return DownloadResult(
                url=url,
                filename=filename,
                size_bytes=dest.stat().st_size,
                sha256=_sha256_file(dest),
                skipped=True,
                error=None,
            )

        session = self._session_factory.get_session()

        try:
            # HEAD request for Content-Length pre-check
            head_resp = session.head(url, timeout=10)
            content_length = head_resp.headers.get("Content-Length")
            if content_length and int(content_length) > self._max_size:
                return DownloadResult(
                    url=url,
                    filename=filename,
                    size_bytes=int(content_length),
                    sha256="",
                    skipped=True,
                    error=f"Exceeds max size ({content_length}B > {self._max_size}B)",
                )

            # Stream GET
            resp = session.get(url, stream=True, timeout=30)

            if ext in (".asp", ".aspx"):
                # Peek at first chunk to check for interpreted ASP
                chunk = resp.raw.read(4096)
                if _is_interpreted_asp(chunk):
                    return DownloadResult(
                        url=url,
                        filename=filename,
                        size_bytes=0,
                        sha256="",
                        skipped=True,
                        error="Interpreted ASP/ASPX (contains <% %>)",
                    )
                resp.raw._from_content = chunk  # type: ignore[attr-defined]

            # Stream to temp file with size limit
            tmp = tempfile.NamedTemporaryFile(
                mode="wb",
                dir=str(self._output_dir),
                prefix=".download_tmp_",
                suffix=ext or ".bin",
                delete=False,
            )

            sha = hashlib.sha256()
            total = 0

            try:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        tmp.write(chunk)
                        if self._hash_downloads:
                            sha.update(chunk)
                        total += len(chunk)
                        if total > self._max_size:
                            tmp.close()
                            os.unlink(tmp.name)
                            return DownloadResult(
                                url=url,
                                filename=filename,
                                size_bytes=total,
                                sha256="",
                                skipped=True,
                                error=(
                                    f"Exceeded max size during download"
                                    f" ({total}B > {self._max_size}B)"
                                ),
                            )

                tmp.close()
                os.replace(tmp.name, dest)

            except Exception:
                tmp.close()
                if os.path.exists(tmp.name):
                    os.unlink(tmp.name)
                raise

            hex_digest = sha.hexdigest() if self._hash_downloads else ""

            return DownloadResult(
                url=url,
                filename=filename,
                size_bytes=total,
                sha256=hex_digest,
                skipped=False,
                error=None,
            )

        except Exception as e:
            return DownloadResult(
                url=url,
                filename=filename,
                size_bytes=0,
                sha256="",
                skipped=True,
                error=str(e),
            )


def _sha256_file(path: Path) -> str:
    """Compute SHA-256 of an existing file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()
