from spartan.config import ScopeConfig
from spartan.scope import ScopeGuard


def _guard(**overrides) -> ScopeGuard:
    target = overrides.pop("target_url", "http://example.com")
    kwargs = dict(
        same_host_only=True,
        same_scheme=True,
        deny_private_ip=True,
        allow_private_ip=False,
        scope_file=None,
        max_depth=0,
        max_urls=1000,
    )
    kwargs.update(overrides)
    config = ScopeConfig(**kwargs)
    return ScopeGuard(config=config, target_url=target)


class TestScopeGuard:
    def test_default_allow_same_host(self):
        guard = _guard(same_host_only=True)
        assert guard.is_allowed("http://example.com/some/path") is True

    def test_deny_different_host(self):
        guard = _guard(same_host_only=True)
        assert guard.is_allowed("http://other.com/path") is False

    def test_allow_cross_domain_when_disabled(self):
        guard = _guard(same_host_only=False)
        assert guard.is_allowed("http://other.com/path") is True

    def test_block_private_ip_by_default(self):
        guard = _guard(same_host_only=False, deny_private_ip=True)
        assert guard.is_allowed("http://10.0.0.1/somepath") is False

    def test_block_metadata_ip(self):
        guard = _guard(same_host_only=False, deny_private_ip=True)
        assert guard.is_allowed("http://169.254.169.254/latest/meta-data") is False

    def test_allow_private_ip_when_permitted(self):
        guard = _guard(same_host_only=False, deny_private_ip=False)
        assert guard.is_allowed("http://10.0.0.1/path") is True

    def test_add_allowed_from_url(self):
        guard = _guard(same_host_only=True, target_url="https://example.com:8443")
        assert guard.is_allowed("https://example.com:8443/other") is True

    def test_scheme_mismatch(self):
        guard = _guard(same_host_only=True, same_scheme=True, target_url="https://example.com")
        assert guard.is_allowed("http://example.com/path") is False

    def test_scheme_flexible(self):
        guard = _guard(same_host_only=True, same_scheme=False)
        assert guard.is_allowed("http://example.com/path") is True

    def test_add_scope_file_not_found(self):
        guard = _guard(scope_file="nonexistent_file_xyz.txt")
        assert guard.is_allowed("http://other.com/path") is False
