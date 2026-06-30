from __future__ import annotations

import logging
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3 import Retry

from spartan.auth import AuthProvider

log = logging.getLogger(__name__)

_REDACT_KEYS = {"authorization", "cookie", "password", "token", "api-key", "x-api-key"}


def _redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Return a copy of headers with sensitive values redacted."""
    result = {}
    for k, v in headers.items():
        if k.lower() in _REDACT_KEYS:
            result[k] = "[REDACTED]"
        else:
            result[k] = v
    return result


class SessionFactory:
    """Creates per-thread requests.Sessions with consistent settings.

    Each thread owns its own Session — this avoids NTLM/Kerberos
    connection-state cross-talk that would occur with a shared Session.
    """

    def __init__(
        self,
        user_agent: str,
        timeout: float,
        connect_timeout: float,
        read_timeout: float,
        ignore_ssl: bool,
        proxy: str | None,
        auth_provider: AuthProvider | None = None,
    ):
        self._user_agent = user_agent
        self._timeout = timeout
        self._connect_timeout = connect_timeout
        self._read_timeout = read_timeout
        self._ignore_ssl = ignore_ssl
        self._proxy = proxy
        self._auth_provider = auth_provider
        self._local = threading.local()

    def get_session(self) -> requests.Session:
        """Get or create a thread-local Session."""
        if not hasattr(self._local, "session"):
            self._local.session = self._build_session()
        return self._local.session

    def _build_session(self) -> requests.Session:
        session = requests.Session()
        session.headers["User-Agent"] = self._user_agent
        session.verify = not self._ignore_ssl

        # Timeout is set per-request; store for later use
        session.__spartan_timeout = (self._connect_timeout, self._read_timeout)  # type: ignore[attr-defined]

        # Proxy
        if self._proxy:
            session.proxies = {
                "http": self._proxy,
                "https": self._proxy,
            }

        # Retry adapter for safe methods
        retry = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Auth
        if self._auth_provider is not None:
            self._auth_provider.apply(session)

        return session

    def request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make a request with default timeouts applied."""
        session = self.get_session()
        timeout = kwargs.pop("timeout", None) or getattr(
            session, "__spartan_timeout", (10.0, 20.0)
        )
        return session.request(method, url, timeout=timeout, **kwargs)

    def get(self, url: str, **kwargs) -> requests.Response:
        return self.request("GET", url, **kwargs)

    def head(self, url: str, **kwargs) -> requests.Response:
        return self.request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> requests.Response:
        return self.request("OPTIONS", url, **kwargs)

    def post(self, url: str, data: str | None = None, **kwargs) -> requests.Response:
        return self.request("POST", url, data=data, **kwargs)

    def put(self, url: str, data: str | None = None, **kwargs) -> requests.Response:
        return self.request("PUT", url, data=data, **kwargs)

    def delete(self, url: str, **kwargs) -> requests.Response:
        return self.request("DELETE", url, **kwargs)
