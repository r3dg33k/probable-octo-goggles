import requests

from spartan.auth import NoAuthProvider
from spartan.http_client import SessionFactory


def _factory(**overrides) -> SessionFactory:
    kwargs = dict(
        user_agent="test/1.0",
        timeout=30.0,
        connect_timeout=10.0,
        read_timeout=20.0,
        ignore_ssl=False,
        proxy=None,
        auth_provider=NoAuthProvider(),
    )
    kwargs.update(overrides)
    return SessionFactory(**kwargs)


class TestSessionFactory:
    def test_get_session_returns_session(self):
        factory = _factory()
        session = factory.get_session()
        assert isinstance(session, requests.Session)

    def test_session_has_timeout(self):
        factory = _factory(timeout=15.0)
        session = factory.get_session()
        assert hasattr(session, "get")

    def test_thread_local_isolation(self):
        factory = _factory()
        s1 = factory.get_session()
        s2 = factory.get_session()
        assert s1 is s2

    def test_user_agent_header(self):
        factory = _factory(user_agent="TestAgent/1.0")
        session = factory.get_session()
        assert session.headers.get("User-Agent") == "TestAgent/1.0"

    def test_proxy_setup(self):
        factory = _factory(proxy="http://127.0.0.1:8080")
        session = factory.get_session()
        assert session.proxies.get("http") == "http://127.0.0.1:8080"
