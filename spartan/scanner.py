from __future__ import annotations

import importlib.resources
import logging
import random
import string
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from spartan.config import ScanConfig
from spartan.crawler import Crawler
from spartan.detectors import sharepoint
from spartan.downloader import SafeDownloader
from spartan.http_client import SessionFactory
from spartan.keyword_scanner import scan as keyword_scan
from spartan.output import OutputSink
from spartan.rate_limit import RateLimiter
from spartan.results import ScanResult
from spartan.scope import ScopeGuard
from spartan.state import ScanState

log = logging.getLogger(__name__)

_FRIENDLY_404_CHARS = string.ascii_letters + string.digits


def _random_path() -> str:
    """Generate a random non-existent path for friendly-404 baseline."""
    rand = "".join(random.choices(_FRIENDLY_404_CHARS, k=16))
    return f"/_spartan_404_check_{rand}.aspx"


def _load_wordlist(name: str) -> list[str]:
    """Load a wordlist from spartan.wordlists package."""
    try:
        wordlist_dir = importlib.resources.files("spartan.wordlists")
        text = wordlist_dir.joinpath(name).read_text(encoding="utf-8")
        return [line.strip() for line in text.splitlines() if line.strip()]
    except Exception as e:
        log.warning("Failed to load wordlist %s: %s", name, e)
        return []


def _build_path_url(base: str, path: str) -> str:
    """Join base URL with a relative path, ensuring exactly one slash between."""
    base = base.rstrip("/")
    path = path.lstrip("/")
    return f"{base}/{path}"


class Scanner:
    """Central orchestrator for all SPartan scan modules."""

    def __init__(
        self,
        config: ScanConfig,
        session_factory: SessionFactory,
        scope_guard: ScopeGuard,
        rate_limiter: RateLimiter | None,
        state: ScanState | None,
        sinks: list[OutputSink],
        stop_event: threading.Event | None = None,
    ):
        self._config = config
        self._session_factory = session_factory
        self._scope = scope_guard
        self._rate_limiter = rate_limiter
        self._state = state
        self._sinks = sinks
        self._stop = stop_event or threading.Event()

        # Friendly 404 baseline
        self._friendly_404_size: int = 0
        self._friendly_404_hash: str = ""

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    def run(self) -> int:
        """Execute all enabled scan modules. Returns total URLs checked."""
        total = 0

        if self._config.show_plan:
            self._emit_plan()

        if self._config.dry_run:
            self._message("Dry-run mode: no requests will be sent")
            return 0

        self._message(f"Starting scan of {self._config.url}")
        self._establish_friendly_404_baseline()

        if self._config.sharepoint:
            total += self._run_sharepoint()

        if self._config.frontpage:
            total += self._run_frontpage()

        if self._config.dir_bruteforce:
            total += self._run_dir_bruteforce()

        if self._config.sps:
            total += self._run_sps_discovery()

        if self._config.users:
            total += self._run_user_enum()

        if self._config.crawl:
            total += self._run_crawler()

        if self._config.keyword:
            total += self._run_keyword_scan()

        if self._config.putable:
            total += self._run_put_check()

        if self._config.download.enabled:
            total += self._run_downloads()

        self._message(f"Scan complete. {total} URLs checked.")
        return total

    # -----------------------------------------------------------------------
    # Friendly 404 baseline
    # -----------------------------------------------------------------------

    def _establish_friendly_404_baseline(self) -> None:
        """Send a GET to a random path and record body size for friendly-404 detection."""
        session = self._session_factory.get_session()
        dummy_url = _build_path_url(self._config.url, _random_path())
        try:
            resp = session.get(dummy_url, timeout=self._config.network.timeout)
            self._friendly_404_size = len(resp.content)
            self._friendly_404_hash = __import__("hashlib").md5(resp.content).hexdigest()
            log.debug(
                "Friendly 404 baseline: %dB hash=%s",
                self._friendly_404_size,
                self._friendly_404_hash,
            )
        except Exception as e:
            log.debug("Friendly 404 baseline failed: %s", e)

    def _check_friendly_404(self, result: ScanResult) -> bool:
        """Return True if this result looks like a friendly 404."""
        if result.status_code == 404:
            result.is_friendly_404 = True
            return True
        if (
            result.status_code == 200
            and self._friendly_404_size > 0
            and result.content_length == self._friendly_404_size
        ):
            result.is_friendly_404 = True
            return True
        return False

    # -----------------------------------------------------------------------
    # Module runners
    # -----------------------------------------------------------------------

    def _run_sharepoint(self) -> int:
        self._message("Running SharePoint path enumeration...")
        paths = _load_wordlist("sp_layouts.txt")
        paths += _load_wordlist("sp_forms.txt")
        paths += _load_wordlist("sp_catalogs.txt")

        if self._config.custom_wordlist:
            try:
                custom = Path(self._config.custom_wordlist).read_text().splitlines()
                paths += [p.strip() for p in custom if p.strip()]
            except Exception as e:
                log.warning("Custom wordlist load failed: %s", e)

        return self._check_paths(paths, detector="sharepoint_paths")

    def _run_frontpage(self) -> int:
        self._message("Running FrontPage path enumeration...")
        paths = _load_wordlist("front_bin.txt")
        paths += _load_wordlist("front_pvt.txt")
        paths += _load_wordlist("front_serv.txt")

        return self._check_paths(paths, detector="frontpage_paths")

    def _run_dir_bruteforce(self) -> int:
        self._message("Running directory brute-force...")
        paths = _load_wordlist("dir.txt")

        return self._check_paths(paths, detector="dir_bruteforce")

    def _run_sps_discovery(self) -> int:
        self._message("Discovering SOAP services...")
        count = 0
        for result in sharepoint.discover_soap_services(
            self._session_factory.get_session(),
            self._config.url,
            self._config.network.timeout,
        ):
            self._emit(result)
            count += 1
        return count

    def _run_user_enum(self) -> int:
        self._message("Enumerating SharePoint users...")
        count = 0
        for result in sharepoint.enumerate_users(
            self._session_factory.get_session(),
            self._config.url,
            self._config.network.timeout,
        ):
            self._emit(result)
            count += 1
        return count

    def _run_crawler(self) -> int:
        self._message("Crawling site...")
        crawler = Crawler(
            session_factory=self._session_factory,
            scope_guard=self._scope,
            timeout=self._config.network.timeout,
            max_urls=self._config.scope.max_urls,
            max_depth=self._config.scope.max_depth,
            on_result=self._emit,
            stop_event=self._stop,
        )
        urls = crawler.crawl([self._config.url])
        self._message(f"Crawler found {len(urls)} URLs")
        return len(urls)

    def _run_keyword_scan(self) -> int:
        self._message(f"Scanning for keyword: {self._config.keyword}")
        urls = []
        state_path = Path(self._config.output.output_dir) / "state.json"
        if state_path.exists():
            state = ScanState(Path(self._config.output.output_dir))
            if state.load():
                urls = state.urls
        if not urls:
            urls = [self._config.url]
        results = keyword_scan(
            session_factory=self._session_factory,
            urls=urls,
            keyword=self._config.keyword,
            timeout=self._config.network.timeout,
            on_result=self._emit,
        )
        return len(results)

    def _run_put_check(self) -> int:
        self._message("Checking for PUTable directories...")
        session = self._session_factory.get_session()
        count = 0
        for path in _load_wordlist("dir.txt"):
            url = _build_path_url(self._config.url, path)
            try:
                resp = session.options(url, timeout=self._config.network.timeout)
                allow = resp.headers.get("Allow", resp.headers.get("Public", ""))
                if "PUT" in allow.upper():
                    sr = ScanResult(
                        url=url,
                        method="OPTIONS",
                        status_code=resp.status_code,
                        content_length=len(resp.content),
                        detector="putable",
                    )
                    sr.evidence = {"allow_header": allow}
                    self._emit(sr)
                    count += 1
            except Exception as e:
                log.debug("PUT check failed for %s: %s", url, e)
        return count

    def _run_downloads(self) -> int:
        self._message("Downloading interesting files...")
        output_dir = Path(self._config.output.output_dir) / "downloads"
        output_dir.mkdir(parents=True, exist_ok=True)
        downloader = SafeDownloader(
            session_factory=self._session_factory,
            output_dir=output_dir,
            max_size=self._config.download.max_size,
            no_overwrite=self._config.download.no_overwrite,
            hash_downloads=self._config.download.hash_downloads,
        )
        count = 0
        for path in _load_wordlist("front_bin.txt") + _load_wordlist("dir.txt"):
            url = _build_path_url(self._config.url, path)
            dlr = downloader.download(url)
            if not dlr.skipped:
                self._message(f"Downloaded {dlr.filename} ({dlr.size_bytes}B)")
                count += 1
            if dlr.error:
                log.debug("Download error %s: %s", url, dlr.error)
        return count

    # -----------------------------------------------------------------------
    # Path checking (parallel)
    # -----------------------------------------------------------------------

    def _check_paths(self, paths: list[str], detector: str) -> int:
        """Check a list of paths in parallel using ThreadPoolExecutor."""
        count = 0
        urls = [_build_path_url(self._config.url, p) for p in paths]

        with ThreadPoolExecutor(max_workers=self._config.network.threads) as pool:
            fut_map = {}
            for url in urls:
                if self._stop.is_set():
                    break
                if self._state:
                    if url in self._state.scanned_urls:
                        continue
                    self._state.add_url(url)
                if self._rate_limiter:
                    self._rate_limiter.wait()
                fut = pool.submit(self._check_single_path, url, detector)
                fut_map[fut] = url

            for fut in as_completed(fut_map):
                if self._stop.is_set():
                    break
                result = fut.result()
                self._check_friendly_404(result)
                self._emit(result)
                count += 1
                if self._state:
                    self._state.add_scanned(result.url)

        return count

    def _check_single_path(self, url: str, detector: str) -> ScanResult:
        """Perform a single path check."""
        import hashlib
        import time as time_module

        session = self._session_factory.get_session()
        t0 = time_module.monotonic()

        result = ScanResult(url=url, detector=detector)
        try:
            resp = session.get(url, timeout=self._config.network.timeout)
            result.status_code = resp.status_code
            result.content_length = len(resp.content)
            result.content_type = resp.headers.get("Content-Type", "")
            result.elapsed_ms = (time_module.monotonic() - t0) * 1000
            result.response_hash = hashlib.md5(resp.content).hexdigest()
            result.redirect_url = resp.url if resp.url != url else ""
        except Exception as e:
            result.error = str(e)

        return result

    # -----------------------------------------------------------------------
    # Sink management
    # -----------------------------------------------------------------------

    def _emit(self, result: ScanResult) -> None:
        for sink in self._sinks:
            sink.write_result(result)

    def _message(self, text: str, level: str = "info") -> None:
        for sink in self._sinks:
            sink.write_message(text, level=level)

    def _emit_plan(self) -> None:
        """Print a plan of what the scanner will do."""
        c = self._config
        lines = [
            "=== Scan Plan ===",
            f"  Target: {c.url}",
            "  Modules:",
            f"    - SharePoint path enum: {c.sharepoint}",
            f"    - FrontPage path enum: {c.frontpage}",
            f"    - Directory brute-force: {c.dir_bruteforce}",
            f"    - SOAP discovery: {c.sps}",
            f"    - User enumeration: {c.users}",
            f"    - Crawl: {c.crawl}",
            f"    - PUT check: {c.putable}",
            f"    - Download: {c.download.enabled}",
            f"  Auth: {c.auth.mode}",
            f"  Threads: {c.network.threads}",
            f"  Rate limit: {c.network.rate_limit or 'unlimited'}",
            f"  Output dir: {c.output.output_dir}",
            f"  Dry-run: {c.dry_run}",
            f"  Resume: {c.resume}",
        ]
        for line in lines:
            self._message(line)

    def close(self) -> None:
        for sink in self._sinks:
            try:
                sink.close()
            except Exception as e:
                log.debug("Sink close error: %s", e)
