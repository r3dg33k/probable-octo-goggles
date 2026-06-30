from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

_RATE_RE = re.compile(r"^(\d+)/(\d*)([smh])$")


def parse_rate_limit(s: str | None) -> float | None:
    """Parse a rate-limit string like '5/s', '10/m', '100/h'.

    Returns the minimum seconds-between-requests, or None if unset.
    """
    if s is None:
        return None
    m = _RATE_RE.match(s)
    if not m:
        raise ValueError(f"Invalid rate-limit format: {s!r} (expected e.g. 5/s, 10/m)")
    count = int(m.group(1))
    period_mult = int(m.group(2)) if m.group(2) else 1
    unit = m.group(3)
    period_sec = {"s": period_mult, "m": period_mult * 60, "h": period_mult * 3600}[unit]
    return period_sec / count


def parse_size(s: str) -> int:
    """Parse a size string like '10MB', '500KB', '1GB' into bytes."""
    s = s.strip().upper()
    if s.endswith("GB"):
        return int(float(s[:-2]) * 1024**3)
    if s.endswith("MB"):
        return int(float(s[:-2]) * 1024**2)
    if s.endswith("KB"):
        return int(float(s[:-2]) * 1024)
    try:
        return int(s)
    except ValueError:
        raise ValueError(f"Invalid size: {s!r}")


@dataclass(frozen=True)
class AuthConfig:
    mode: str = "none"
    username: str | None = None
    password: str | None = None
    cookie_string: str | None = None
    bearer_token: str | None = None
    kerberos_mutual: str = "required"
    kerberos_delegate: bool = False


@dataclass(frozen=True)
class NetworkConfig:
    threads: int = 10
    timeout: float = 30.0
    connect_timeout: float = 10.0
    read_timeout: float = 20.0
    ignore_ssl: bool = False
    proxy: str | None = None
    rate_limit: str | None = None
    user_agent: str = "Mozilla/5.0 (compatible; SPartan/2.0; +https://github.com/sensepost/SPartan)"


@dataclass(frozen=True)
class ScopeConfig:
    same_host_only: bool = True
    same_scheme: bool = True
    follow_cross_domain_redirects: bool = False
    deny_private_ip: bool = True
    allow_private_ip: bool = False
    scope_file: str | None = None
    max_depth: int = 0
    max_urls: int = 1000


@dataclass(frozen=True)
class OutputConfig:
    output_dir: str = "."
    verbose: bool = False
    quiet: bool = False
    json_path: str | None = None
    jsonl_path: str | None = None
    csv_path: str | None = None


@dataclass(frozen=True)
class DownloadConfig:
    enabled: bool = False
    max_size: int = 10 * 1024 * 1024
    no_overwrite: bool = True
    hash_downloads: bool = False


@dataclass(frozen=True)
class RedactConfig:
    enabled: bool = False
    patterns_file: str | None = None


@dataclass(frozen=True)
class ScanConfig:
    # Target
    url: str = ""

    # Scan toggles
    frontpage: bool = False
    sharepoint: bool = False
    crawl: bool = False
    keyword: str | None = None
    sps: bool = False
    users: bool = False
    putable: bool = False
    dir_bruteforce: bool = False
    rpc: str | None = None

    # Sub-configs
    auth: AuthConfig = field(default_factory=AuthConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    download: DownloadConfig = field(default_factory=DownloadConfig)
    redact: RedactConfig = field(default_factory=RedactConfig)

    # State
    resume: bool = False
    dry_run: bool = False
    show_plan: bool = False

    # Extra
    custom_wordlist: str | None = None
    profile_name: str | None = None
    confirm_authorized: bool = False
    overwrite_downloads: bool = False

    # Derived (set after construction)
    output_dir_path: Path = field(default_factory=lambda: Path("."))

    def __post_init__(self):
        object.__setattr__(self, "output_dir_path", Path(self.output.output_dir))
