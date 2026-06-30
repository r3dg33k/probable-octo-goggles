from __future__ import annotations

import hashlib
import logging
import time

from requests import Session

from spartan.results import ScanResult

log = logging.getLogger(__name__)


def fingerprint(session: Session, url: str, timeout: float) -> list[ScanResult]:
    """Check for FrontPage Server Extensions by probing binary paths."""
    results: list[ScanResult] = []

    linux_paths = [
        "_vti_bin/_vti_aut/author.exe",
        "_vti_bin/_vti_adm/admin.exe",
        "_vti_bin/shtml.exe",
    ]
    win_paths = [
        "_vti_bin/_vti_aut/author.dll",
        "_vti_bin/_vti_aut/dvwssr.dll",
        "_vti_bin/_vti_adm/admin.dll",
        "_vti_bin/shtml.dll",
    ]
    config_path = "_vti_inf.html"

    base = url.rstrip("/")

    for path in linux_paths:
        target = f"{base}/{path}"
        sr = _check_frontpage_path(session, target, timeout, "frontpage_fingerprint")
        if sr.status_code == 200:
            sr.evidence = {"frontpage_type": "linux"}
            results.append(sr)
            break

    for path in win_paths:
        target = f"{base}/{path}"
        sr = _check_frontpage_path(session, target, timeout, "frontpage_fingerprint")
        if sr.status_code == 200:
            sr.evidence = {"frontpage_type": "windows"}
            results.append(sr)
            break

    # Config file
    cfg_url = f"{base}/{config_path}"
    sr = _check_frontpage_path(session, cfg_url, timeout, "frontpage_fingerprint")
    if sr.status_code == 200:
        sr.evidence = {"config_found": True}
        results.append(sr)

    return results


def check_path(session: Session, url: str, timeout: float) -> ScanResult:
    """Check a single FrontPage path for availability."""
    t0 = time.monotonic()
    result = ScanResult(url=url, detector="frontpage_paths")
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


def _check_frontpage_path(
    session: Session, url: str, timeout: float, detector: str
) -> ScanResult:
    """Internal helper to probe a single path."""
    t0 = time.monotonic()
    result = ScanResult(url=url, detector=detector)
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


# ---------------------------------------------------------------------------
# Legacy stubs — preserved as TODO markers
# ---------------------------------------------------------------------------


def frontpage_fileup(url: str) -> None:
    """TODO: implement FrontPage file upload via RPC."""
    pass


def frontpage_folder_del(url: str) -> None:
    """TODO: implement FrontPage folder deletion via RPC."""
    pass


def frontpage_serv_enum(url: str) -> None:
    """TODO: implement FrontPage service enumeration."""
    pass


def frontpage_config_enum(url: str) -> None:
    """TODO: implement FrontPage configuration enumeration."""
    pass
