from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path
from urllib.parse import urlparse

from spartan.config import ScopeConfig

log = logging.getLogger(__name__)

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
]

_METADATA_IPS = {
    ipaddress.ip_address("169.254.169.254"),
    ipaddress.ip_address("fd00:ec2::254"),
}


class ScopeRule:
    """A single scope rule — auto-detected as domain, URL prefix, or CIDR."""

    def __init__(self, line: str):
        line = line.strip()
        self._deny = line.startswith("-")
        raw = line.lstrip("-").strip()

        # Try CIDR
        if "/" in raw:
            try:
                self._net = ipaddress.ip_network(raw, strict=False)
                self._type = "cidr"
                self._pattern = raw
                return
            except ValueError:
                pass

        # Try URL prefix
        if raw.startswith(("http://", "https://")):
            urlparse(raw)
            self._type = "prefix"
            self._pattern = raw.rstrip("/")
            return

        # Default: domain
        self._type = "domain"
        self._pattern = raw.lower().lstrip("*.")

    @property
    def is_deny(self) -> bool:
        return self._deny

    def matches(self, url: str) -> bool:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        if self._type == "domain":
            return host == self._pattern or host.endswith("." + self._pattern)
        if self._type == "prefix":
            return url.rstrip("/").startswith(self._pattern)
        if self._type == "cidr":
            try:
                addr = ipaddress.ip_address(socket.gethostbyname(host))
                return addr in self._net
            except (socket.gaierror, ValueError):
                return False
        return False


class ScopeGuard:
    """Validates that URLs are within the allowed scope."""

    def __init__(self, config: ScopeConfig, target_url: str):
        self._config = config
        self._target_url = target_url
        self._parsed = urlparse(target_url)
        self._target_host = self._parsed.hostname or ""
        self._target_scheme = self._parsed.scheme
        self._target_port = self._parsed.port or (
            443 if self._target_scheme == "https" else 80
        )
        self._rules: list[ScopeRule] = []
        self._loaded = False

    def _load_rules(self):
        if self._loaded:
            return
        self._loaded = True
        if self._config.scope_file:
            path = Path(self._config.scope_file)
            if path.exists():
                for line in path.read_text().splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._rules.append(ScopeRule(line))
                log.info("Loaded %d scope rules from %s", len(self._rules), path)

    def is_allowed(self, url: str) -> bool:
        """Check if a URL (redirect, crawled link) is within scope."""
        self._load_rules()

        # Parse the candidate URL
        try:
            parsed = urlparse(url)
        except Exception:
            return False
        host = parsed.hostname or ""
        scheme = parsed.scheme

        if not host:
            return False

        # Check file-based scope rules first
        for rule in self._rules:
            if rule.matches(url):
                return not rule.is_deny

        # Same-host enforcement
        if self._config.same_host_only:
            if host != self._target_host:
                log.debug("Scope: %s != target host %s", host, self._target_host)
                return False

        # Same-scheme enforcement
        if self._config.same_scheme:
            if scheme != self._target_scheme:
                log.debug("Scope: scheme %s != %s", scheme, self._target_scheme)
                return False

        # Private IP / metadata IP checks
        if self._config.deny_private_ip and not self._config.allow_private_ip:
            try:
                addr = ipaddress.ip_address(socket.gethostbyname(host))
                if addr in _METADATA_IPS:
                    log.warning("Scope: blocked metadata IP %s in %s", addr, url)
                    return False
                for net in _PRIVATE_NETS:
                    if addr in net:
                        log.warning("Scope: blocked private IP %s in %s", addr, url)
                        return False
            except (socket.gaierror, ValueError):
                log.debug("Scope: could not resolve %s, allowing", host)

        return True

    def is_same_host(self, url: str) -> bool:
        """Quick check if URL shares the same host as target."""
        try:
            parsed = urlparse(url)
            return (parsed.hostname or "").lower() == self._target_host.lower()
        except Exception:
            return False
