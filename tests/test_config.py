from spartan.config import AuthConfig, parse_rate_limit, parse_size


class TestParseRateLimit:
    def test_per_second(self):
        assert parse_rate_limit("5/s") == 0.2

    def test_per_minute(self):
        val = parse_rate_limit("10/m")
        assert val is not None and abs(val - 6.0) < 0.01

    def test_per_hour(self):
        val = parse_rate_limit("100/h")
        assert val is not None and abs(val - 36.0) < 0.01

    def test_none(self):
        assert parse_rate_limit(None) is None

    def test_with_period_mult(self):
        val = parse_rate_limit("30/2m")
        assert val is not None and abs(val - 4.0) < 0.01

    def test_invalid(self):
        import pytest
        with pytest.raises(ValueError, match="Invalid rate-limit format"):
            parse_rate_limit("abc")


class TestParseSize:
    def test_mb(self):
        assert parse_size("5MB") == 5 * 1024 * 1024

    def test_kb(self):
        assert parse_size("500KB") == 500 * 1024

    def test_gb(self):
        assert parse_size("1GB") == 1024 ** 3

    def test_raw_int(self):
        assert parse_size("1234") == 1234

    def test_case_insensitive(self):
        assert parse_size("10mb") == 10 * 1024 * 1024

    def test_invalid(self):
        import pytest
        with pytest.raises(ValueError, match="Invalid size"):
            parse_size("xyz")


class TestAuthConfig:
    def test_defaults(self):
        c = AuthConfig()
        assert c.mode == "none"
        assert c.username is None
        assert c.password is None

    def test_frozen(self):
        c = AuthConfig(mode="basic", username="u", password="p")
        assert c.mode == "basic"
        assert c.username == "u"
        assert c.password == "p"
