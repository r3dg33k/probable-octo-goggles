import tempfile
from pathlib import Path

import responses

from spartan.auth import NoAuthProvider
from spartan.downloader import DownloadResult, SafeDownloader
from spartan.http_client import SessionFactory


class TestDownloadResult:
    def test_defaults(self):
        d = DownloadResult(url="http://test/", filename="f", size_bytes=100, sha256="abc")
        assert d.url == "http://test/"
        assert d.skipped is False
        assert d.error is None

    def test_to_dict(self):
        d = DownloadResult(
            url="http://test/", filename="f.txt",
            size_bytes=100, sha256="abc", skipped=True,
        )
        dd = d.to_dict()
        assert dd["url"] == "http://test/"
        assert dd["skipped"] is True


class TestSafeDownloader:
    def _factory(self) -> SessionFactory:
        return SessionFactory(
            user_agent="test/1.0",
            timeout=30.0,
            connect_timeout=10.0,
            read_timeout=20.0,
            ignore_ssl=False,
            proxy=None,
            auth_provider=NoAuthProvider(),
        )

    def test_unsupported_extension(self):
        factory = self._factory()
        with tempfile.TemporaryDirectory() as tmp:
            dl = SafeDownloader(factory, Path(tmp))
            result = dl.download("http://test/file.xyz")
            assert result.skipped is True
            assert "Unsupported extension" in (result.error or "")

    def test_path_traversal_blocked(self):
        factory = self._factory()
        with tempfile.TemporaryDirectory() as tmp:
            dl = SafeDownloader(factory, Path(tmp))
            result = dl.download("http://test/../../etc/passwd")
            assert result.skipped is True

    def test_skipped_if_exists(self):
        factory = self._factory()
        with tempfile.TemporaryDirectory() as tmp:
            existing = Path(tmp) / "test.txt"
            existing.write_text("existing content")
            dl = SafeDownloader(factory, Path(tmp), no_overwrite=True)
            result = dl.download("http://test/test.txt")
            assert result.skipped is True

    def test_download_success(self):
        factory = self._factory()
        with tempfile.TemporaryDirectory() as tmp:
            url = "http://test/download.txt"
            with responses.RequestsMock() as rsps:
                rsps.add(responses.GET, url, body=b"hello world", status=200)
                rsps.add(responses.HEAD, url, body=b"", status=200)
                dl = SafeDownloader(factory, Path(tmp))
                result = dl.download(url)
            assert result.skipped is False
            assert result.size_bytes == len(b"hello world")
