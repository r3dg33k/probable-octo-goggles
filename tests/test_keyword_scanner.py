import responses
from requests import Session

from spartan.auth import NoAuthProvider
from spartan.http_client import SessionFactory
from spartan.keyword_scanner import scan


def _factory() -> SessionFactory:
    return SessionFactory(
        user_agent="test/1.0",
        timeout=30.0,
        connect_timeout=10.0,
        read_timeout=20.0,
        ignore_ssl=False,
        proxy=None,
        auth_provider=NoAuthProvider(),
    )


class TestKeywordScanner:
    def test_keyword_found_in_body(self):
        results = []
        factory = _factory()
        with responses.RequestsMock() as rsps:
            rsps.get("http://example.com/page", status=200, body="hello world secret")
            results = scan(factory, ["http://example.com/page"], "secret", 5.0)
        assert len(results) == 1
        assert results[0].evidence.get("keyword") == "secret"

    def test_keyword_found_in_url(self):
        results = []
        factory = _factory()
        with responses.RequestsMock() as rsps:
            rsps.get("http://example.com/admin", status=200, body="no match")
            results = scan(factory, ["http://example.com/admin"], "admin", 5.0)
        assert len(results) == 1
        assert results[0].evidence.get("keyword") == "admin"

    def test_keyword_not_found(self):
        results = []
        factory = _factory()
        with responses.RequestsMock() as rsps:
            rsps.get("http://example.com/page", status=200, body="hello world")
            results = scan(factory, ["http://example.com/page"], "secret", 5.0)
        assert len(results) == 1
        assert results[0].evidence == {}

    def test_multiple_urls(self):
        results = []
        factory = _factory()
        with responses.RequestsMock() as rsps:
            rsps.get("http://example.com/a", status=200, body="foo target bar")
            rsps.get("http://example.com/b", status=200, body="no match")
            results = scan(
                factory,
                ["http://example.com/a", "http://example.com/b"],
                "target",
                5.0,
            )
        assert len(results) == 2
        assert results[0].evidence.get("keyword") == "target"
        assert results[1].evidence == {}

    def test_connection_error_returns_result(self):
        results = []
        factory = _factory()
        with responses.RequestsMock() as rsps:
            rsps.get("http://example.com/page", body=ConnectionError("refused"))
            results = scan(factory, ["http://example.com/page"], "kw", 5.0)
        assert len(results) == 0
