from unittest.mock import MagicMock

from spartan.auth import (
    BasicAuthProvider,
    BearerAuthProvider,
    CookieAuthProvider,
    KerberosAuthProvider,
    NoAuthProvider,
    NtlmAuthProvider,
    create_auth_provider,
)
from spartan.config import AuthConfig, ScanConfig

# Short local aliases matching auth.py
NoAuth = NoAuthProvider
BasicAuth = BasicAuthProvider
NtlmAuth = NtlmAuthProvider
CookieAuth = CookieAuthProvider
BearerAuth = BearerAuthProvider
KerberosAuth = KerberosAuthProvider


class TestNoAuth:
    def test_apply_no_modify(self):
        session = MagicMock()
        session.auth = None
        NoAuth().apply(session)
        assert session.auth is None

    def test_validate(self):
        assert NoAuth().validate() is None


class TestBasicAuth:
    def test_apply_adds_auth(self):
        session = MagicMock()
        BasicAuth(username="user", password="pass").apply(session)
        assert session.auth is not None

    def test_validate(self):
        assert BasicAuth(username="u", password="p").validate() is None

    def test_validate_missing(self):
        msg = BasicAuth(username="", password="").validate()
        assert msg is not None

class TestNtlmAuth:
    def test_validate(self):
        assert NtlmAuth(username="u", password="p").validate() is None

    def test_validate_missing(self):
        msg = NtlmAuth(username="", password="").validate()
        assert msg is not None

class TestCookieAuth:
    def test_apply_adds_cookie(self):
        session = MagicMock()
        session.cookies = MagicMock()
        CookieAuth(cookie_string="foo=bar; baz=qux").apply(session)
        assert session.cookies.set.called

    def test_validate(self):
        assert CookieAuth(cookie_string="x=y").validate() is None
        assert CookieAuth(cookie_string="").validate() is not None


class TestBearerAuth:
    def test_apply_adds_header(self):
        session = MagicMock()
        session.headers = {}
        BearerAuth(token="mytoken123").apply(session)
        assert session.headers.get("Authorization") == "Bearer mytoken123"

    def test_validate(self):
        assert BearerAuth(token="tok").validate() is None
        assert BearerAuth(token="").validate() is not None


class TestKerberosAuth:
    def test_validate_no_krb5(self):
        auth = KerberosAuth()
        result = auth.validate()
        assert result is not None


class TestCreateAuthProvider:
    def _cfg(self, **kwargs) -> ScanConfig:
        return ScanConfig(auth=AuthConfig(**kwargs))

    def test_none(self):
        p = create_auth_provider(self._cfg(mode="none"))
        assert isinstance(p, NoAuthProvider)

    def test_basic(self):
        p = create_auth_provider(self._cfg(mode="basic", username="u", password="p"))
        assert isinstance(p, BasicAuthProvider)

    def test_ntlm(self):
        p = create_auth_provider(self._cfg(mode="ntlm", username="u", password="p"))
        assert isinstance(p, NtlmAuthProvider)

    def test_cookie(self):
        p = create_auth_provider(self._cfg(mode="cookie", cookie_string="a=b"))
        assert isinstance(p, CookieAuthProvider)

    def test_bearer(self):
        p = create_auth_provider(self._cfg(mode="bearer", bearer_token="tok"))
        assert isinstance(p, BearerAuthProvider)

    def test_kerberos(self):
        p = create_auth_provider(self._cfg(mode="kerberos"))
        assert isinstance(p, KerberosAuthProvider)

    def test_invalid(self):
        import pytest
        with pytest.raises(ValueError, match="Unknown auth mode"):
            create_auth_provider(self._cfg(mode="unknown"))
