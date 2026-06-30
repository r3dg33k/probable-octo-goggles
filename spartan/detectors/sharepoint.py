from __future__ import annotations

import hashlib
import logging
import time

import bs4
from requests import Session

from spartan.results import ScanResult

log = logging.getLogger(__name__)


def fingerprint(session: Session, url: str, timeout: float) -> ScanResult:
    """Check for SharePoint version indicators in response headers."""
    t0 = time.monotonic()
    result = ScanResult(url=url, detector="sharepoint_fingerprint")
    try:
        resp = session.get(url, timeout=timeout)
        result.status_code = resp.status_code
        result.content_length = len(resp.content)
        result.content_type = resp.headers.get("Content-Type", "")
        result.elapsed_ms = (time.monotonic() - t0) * 1000

        headers = {
            k.lower(): v
            for k, v in resp.headers.items()
        }

        evidence = {}
        if "microsoftsharepointteamservices" in headers:
            evidence["sharepoint_version"] = headers["microsoftsharepointteamservices"]
        if "x-aspnet-version" in headers:
            evidence["aspnet_version"] = headers["x-aspnet-version"]
        if "x-sharepointhealthscore" in headers:
            evidence["sharepoint_healthscore"] = headers["x-sharepointhealthscore"]

        if evidence:
            result.evidence = evidence

        result.response_hash = hashlib.md5(resp.content).hexdigest()

    except Exception as e:
        result.error = str(e)

    return result


def check_path(session: Session, url: str, timeout: float) -> ScanResult:
    """Check a single SharePoint path for availability."""
    t0 = time.monotonic()
    result = ScanResult(url=url, detector="sharepoint_paths")
    try:
        resp = session.get(url, timeout=timeout)
        result.status_code = resp.status_code
        result.content_length = len(resp.content)
        result.content_type = resp.headers.get("Content-Type", "")
        result.elapsed_ms = (time.monotonic() - t0) * 1000
        result.response_hash = hashlib.md5(resp.content).hexdigest()
    except Exception as e:
        result.error = str(e)

    return result


def discover_soap_services(
    session: Session, url: str, timeout: float
) -> list[ScanResult]:
    """Discover SOAP services by parsing spsdisco.aspx."""
    results: list[ScanResult] = []
    disco_url = url.rstrip("/") + "/_vti_bin/spsdisco.aspx"

    time.monotonic()
    try:
        resp = session.get(disco_url, timeout=timeout)
        if resp.status_code != 200:
            return results

        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        for disc in soup.find_all("discovery"):
            for contract in disc.find_all("contractref"):
                docref = contract.get("docref", "")
                if docref:
                    sr = ScanResult(
                        url=docref,
                        method="GET",
                        detector="sharepoint_soap",
                    )
                    sr.content_type = "text/xml"
                    sr.evidence = {"source": "spsdisco.aspx"}
                    results.append(sr)
    except Exception as e:
        log.debug("SOAP discovery failed for %s: %s", disco_url, e)

    return results


def enumerate_users(session: Session, url: str, timeout: float) -> list[ScanResult]:
    """Enumerate SharePoint users from people.aspx."""
    results: list[ScanResult] = []
    people_url = url.rstrip("/") + "/_layouts/people.aspx?MembershipGroupId=0"

    t0 = time.monotonic()
    try:
        resp = session.get(people_url, timeout=timeout)
        if resp.status_code != 200:
            return results

        soup = bs4.BeautifulSoup(resp.text, "html.parser")
        for input_tag in soup.find_all("input"):
            account = input_tag.get("account", "")
            if account:
                sr = ScanResult(
                    url=people_url,
                    method="GET",
                    detector="sharepoint_users",
                    status_code=200,
                    elapsed_ms=(time.monotonic() - t0) * 1000,
                )
                sr.evidence = {"account": account}
                results.append(sr)
    except Exception as e:
        log.debug("User enumeration failed: %s", e)

    return results
