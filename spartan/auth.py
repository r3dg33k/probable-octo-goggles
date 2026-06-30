from __future__ import annotations

import os
from abc import ABC, abstractmethod

from requests import Session
from requests.auth import AuthBase, HTTPBasicAuth
from requests_ntlm import HttpNtlmAuth


class AuthProvider(ABC):
    name: str = "none"

    @abstractmethod
    def apply(self, session: Session) -> None: ...

    @abstractmethod
    def validate(self) -> str | None: ...


class NoAuthProvider(AuthProvider):
    name = "none"

    def apply(self, session: Session) -> None:
        pass

    def validate(self) -> str | None:
        return None


class BasicAuthProvider(AuthProvider):
    name = "basic"

    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def apply(self, session: Session) -> None:
        session.auth = HTTPBasicAuth(self._username, self._password)

    def validate(self) -> str | None:
        if not self._username:
            return "Basic auth requires a username"
        if not self._password:
            return "Basic auth requires a password"
        return None


class NtlmAuthProvider(AuthProvider):
    name = "ntlm"

    def __init__(self, username: str, password: str):
        self._username = username
        self._password = password

    def apply(self, session: Session) -> None:
        session.auth = HttpNtlmAuth(self._username, self._password)

    def validate(self) -> str | None:
        if not self._username:
            return "NTLM auth requires username in DOMAIN\\user format"
        if not self._password:
            return "NTLM auth requires a password"
        return None


class CookieAuthProvider(AuthProvider):
    name = "cookie"

    def __init__(self, cookie_string: str):
        self._cookie_string = cookie_string

    def apply(self, session: Session) -> None:
        for pair in self._cookie_string.strip(";").split(";"):
            pair = pair.strip()
            if "=" in pair:
                key, val = pair.split("=", 1)
                session.cookies.set(key.strip(), val.strip())

    def validate(self) -> str | None:
        if not self._cookie_string:
            return "Cookie auth requires a --cookie string"
        return None


class BearerAuthProvider(AuthProvider):
    name = "bearer"

    def __init__(self, token: str):
        self._token = token

    def apply(self, session: Session) -> None:
        session.headers["Authorization"] = f"Bearer {self._token}"

    def validate(self) -> str | None:
        if not self._token:
            return "Bearer auth requires a --bearer-token"
        return None


class KerberosAuthProvider(AuthProvider):
    name = "kerberos"

    def __init__(
        self,
        mutual_auth: str = "required",
        delegate: bool = False,
    ):
        self._mutual = mutual_auth
        self._delegate = delegate
        self._auth: AuthBase | None = None

    def apply(self, session: Session) -> None:
        if self._auth is not None:
            session.auth = self._auth
            return
        try:
            from requests_kerberos import (  # type: ignore[import-untyped]
                DISABLED,
                OPTIONAL,
                REQUIRED,
                HTTPKerberosAuth,
            )
        except ImportError as exc:
            raise ImportError(
                "requests-kerberos is required for --auth kerberos. "
                "Install it with: pip install requests-kerberos"
            ) from exc

        mutual_map = {
            "required": REQUIRED,
            "optional": OPTIONAL,
            "disabled": DISABLED,
        }
        flag = mutual_map.get(self._mutual, REQUIRED)
        self._auth = HTTPKerberosAuth(
            mutual_authentication=flag,
            delegate=self._delegate,
        )
        session.auth = self._auth

    def validate(self) -> str | None:
        """Kerberos uses OS ticket cache; no creds to validate."""
        try:
            import requests_kerberos  # noqa: F401
        except ImportError:
            return (
                "requests-kerberos is not installed. "
                "Install it with: pip install requests-kerberos"
            )
        if "KRB5CCNAME" not in os.environ:
            return (
                "No Kerberos ticket cache found. "
                "Run 'kinit user@REALM' first."
            )
        return None


def create_auth_provider(config) -> AuthProvider:
    """Factory: build auth provider from ScanConfig AuthConfig."""
    ac = config.auth
    mode = ac.mode

    if mode == "none":
        return NoAuthProvider()
    if mode == "basic":
        if not ac.username:
            raise ValueError("--auth basic requires -l USER:PASS")
        return BasicAuthProvider(ac.username, ac.password or "")
    if mode == "ntlm":
        if not ac.username:
            raise ValueError("--auth ntlm requires -l DOMAIN\\USER:PASS")
        return NtlmAuthProvider(ac.username, ac.password or "")
    if mode == "cookie":
        if not ac.cookie_string:
            raise ValueError("--auth cookie requires --cookie STR")
        return CookieAuthProvider(ac.cookie_string)
    if mode == "bearer":
        if not ac.bearer_token:
            raise ValueError("--auth bearer requires --bearer-token TOKEN")
        return BearerAuthProvider(ac.bearer_token)
    if mode == "kerberos":
        return KerberosAuthProvider(
            mutual_auth=ac.kerberos_mutual,
            delegate=ac.kerberos_delegate,
        )

    raise ValueError(f"Unknown auth mode: {mode}")


# Short aliases for convenience
NoAuth = NoAuthProvider
BasicAuth = BasicAuthProvider
NtlmAuth = NtlmAuthProvider
CookieAuth = CookieAuthProvider
BearerAuth = BearerAuthProvider
KerberosAuth = KerberosAuthProvider
