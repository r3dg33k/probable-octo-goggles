from __future__ import annotations

import logging
import threading
from collections import deque
from collections.abc import Callable

from spartan.http_client import SessionFactory
from spartan.results import ScanResult
from spartan.scope import ScopeGuard

log = logging.getLogger(__name__)


class Crawler:
    """BFS scope-aware web crawler."""

    def __init__(
        self,
        session_factory: SessionFactory,
        scope_guard: ScopeGuard,
        timeout: float,
        max_urls: int = 1000,
        max_depth: int = 0,
        on_result: Callable[[ScanResult], None] | None = None,
        stop_event: threading.Event | None = None,
    ):
        self._session_factory = session_factory
        self._scope = scope_guard
        self._timeout = timeout
        self._max_urls = max_urls
        self._max_depth = max_depth
        self._on_result = on_result
        self._stop = stop_event or threading.Event()

    def crawl(self, start_urls: list[str]) -> list[str]:
        """BFS crawl from start URLs, returning all found URLs."""
        found: list[str] = []
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque()

        for u in start_urls:
            if u not in visited:
                queue.append((u, 0))
                visited.add(u)

        session = self._session_factory.get_session()

        while queue and not self._stop.is_set():
            url, depth = queue.popleft()

            if len(found) >= self._max_urls:
                break

            if self._max_depth > 0 and depth >= self._max_depth:
                continue

            if not self._scope.is_allowed(url):
                continue

            try:
                resp = session.get(url, timeout=self._timeout)
                ct = resp.headers.get("Content-Type", "")

                # Skip binary or non-HTML content
                if "text/html" not in ct and "text/plain" not in ct:
                    continue

                sr = ScanResult(
                    url=url,
                    method="GET",
                    status_code=resp.status_code,
                    content_length=len(resp.content),
                    content_type=ct,
                    detector="crawler",
                )
                found.append(url)

                if self._on_result:
                    self._on_result(sr)

            except Exception as e:
                log.debug("Crawler error %s: %s", url, e)
                continue

            # Find links (simple HTML parsing)
            try:
                links = self._extract_links(resp.text, url)
            except Exception:
                continue

            for link in links:
                if link not in visited and self._scope.is_allowed(link):
                    visited.add(link)
                    queue.append((link, depth + 1))

        return found

    def _extract_links(self, html: str, base_url: str) -> list[str]:
        """Extract href links from HTML, resolving relative URLs."""
        import re

        links: list[str] = []
        from urllib.parse import urljoin

        for match in re.finditer(r'href=["\'](.*?)["\']', html, re.IGNORECASE):
            href = match.group(1).strip()
            if not href or href.startswith("#") or href.startswith("javascript:"):
                continue
            absolute = urljoin(base_url, href)
            if absolute.startswith(("http://", "https://")):
                links.append(absolute)

        return links
