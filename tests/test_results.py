from spartan.results import Finding, ScanResult


class TestScanResult:
    def test_defaults(self):
        r = ScanResult(url="http://test/")
        assert r.url == "http://test/"
        assert r.method == "GET"
        assert r.status_code is None
        assert r.content_length == 0
        assert r.detector == ""
        assert r.error is None

    def test_is_success_200(self):
        r = ScanResult(url="http://test/", status_code=200)
        assert r.is_success is True

    def test_is_success_friendly_404(self):
        r = ScanResult(url="http://test/", status_code=200, is_friendly_404=True)
        assert r.is_success is False

    def test_is_interesting_success(self):
        r = ScanResult(url="http://test/", status_code=200)
        assert r.is_interesting is True

    def test_is_interesting_redirect(self):
        r = ScanResult(url="http://test/", status_code=302, redirect_url="http://other/")
        assert r.is_interesting is True

    def test_is_interesting_redirect_no_url(self):
        r = ScanResult(url="http://test/", status_code=302, redirect_url="")
        assert r.is_interesting is False

    def test_is_interesting_auth_required(self):
        r = ScanResult(url="http://test/", status_code=401)
        assert r.is_interesting is True

    def test_is_interesting_forbidden(self):
        r = ScanResult(url="http://test/", status_code=403)
        assert r.is_interesting is True

    def test_is_interesting_server_error(self):
        r = ScanResult(url="http://test/", status_code=500)
        assert r.is_interesting is True

    def test_is_interesting_friendly_404(self):
        r = ScanResult(url="http://test/", status_code=200, is_friendly_404=True)
        assert r.is_interesting is False

    def test_is_interesting_404(self):
        r = ScanResult(url="http://test/", status_code=404)
        assert r.is_interesting is False

    def test_to_dict(self):
        r = ScanResult(
            url="http://test/",
            method="GET",
            status_code=200,
            content_length=100,
            content_type="text/html",
            detector="test",
            elapsed_ms=50.5,
        )
        d = r.to_dict()
        assert d["url"] == "http://test/"
        assert d["status_code"] == 200
        assert d["elapsed_ms"] == 50.5
        assert d["detector"] == "test"
        assert d["is_friendly_404"] is False


class TestFinding:
    def test_defaults(self):
        f = Finding()
        assert f.id == ""
        assert f.severity == "info"

    def test_to_dict(self):
        f = Finding(id="F-001", title="Test", severity="high", url="http://test/")
        d = f.to_dict()
        assert d["id"] == "F-001"
        assert d["title"] == "Test"
        assert d["severity"] == "high"
