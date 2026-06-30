from __future__ import annotations

import logging
from collections.abc import Callable

from spartan.http_client import SessionFactory
from spartan.results import ScanResult

log = logging.getLogger(__name__)


def scan(
    session_factory: SessionFactory,
    urls: list[str],
    keyword: str,
    timeout: float,
    on_result: Callable[[ScanResult], None] | None = None,
) -> list[ScanResult]:
    """Search a list of URLs for a keyword in the response body or URL."""
    results: list[ScanResult] = []
    session = session_factory.get_session()

    for url in urls:
        try:
            resp = session.get(url, timeout=timeout)
            content = resp.text

            sr = ScanResult(
                url=url,
                method="GET",
                status_code=resp.status_code,
                content_length=len(content),
                content_type=resp.headers.get("Content-Type", ""),
                detector="keyword_scanner",
            )

            if keyword in content or keyword in url:
                sr.evidence = {"keyword": keyword}

            results.append(sr)

            if on_result:
                on_result(sr)

        except Exception as e:
            log.debug("Keyword scan error %s: %s", url, e)

    return results
