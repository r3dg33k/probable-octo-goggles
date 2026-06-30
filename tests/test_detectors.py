import responses
from requests import Session

from spartan.detectors import frontpage, sharepoint


BASE = "http://example.com"
TIMEOUT = 5.0


class TestSharePointFingerprint:
    def test_detects_sharepoint_headers(self):
        with responses.RequestsMock() as rsps:
            rsps.get(
                BASE,
                status=200,
                body="<html/>",
                headers={
                    "MicrosoftSharePointTeamServices": "15.0.0.0",
                    "X-AspNet-Version": "4.0.30319",
                },
            )
            session = Session()
            result = sharepoint.fingerprint(session, BASE, TIMEOUT)

        assert result.status_code == 200
        assert result.evidence.get("sharepoint_version") == "15.0.0.0"
        assert result.evidence.get("aspnet_version") == "4.0.30319"
        assert result.detector == "sharepoint_fingerprint"

    def test_no_sharepoint_headers(self):
        with responses.RequestsMock() as rsps:
            rsps.get(BASE, status=200, body="<html/>", headers={"Server": "Apache"})
            session = Session()
            result = sharepoint.fingerprint(session, BASE, TIMEOUT)

        assert result.status_code == 200
        assert result.evidence == {}

    def test_connection_error(self):
        with responses.RequestsMock() as rsps:
            rsps.get(BASE, body=ConnectionError("refused"))
            session = Session()
            result = sharepoint.fingerprint(session, BASE, TIMEOUT)

        assert result.error is not None
        assert result.status_code is None


class TestSharePointCheckPath:
    def test_returns_200(self):
        with responses.RequestsMock() as rsps:
            rsps.get(f"{BASE}/_layouts/settings.aspx", status=200, body="ok")
            session = Session()
            result = sharepoint.check_path(
                session, f"{BASE}/_layouts/settings.aspx", TIMEOUT
            )

        assert result.status_code == 200
        assert result.content_length == 2
        assert result.detector == "sharepoint_paths"

    def test_returns_404(self):
        with responses.RequestsMock() as rsps:
            rsps.get(f"{BASE}/_layouts/nope.aspx", status=404)
            session = Session()
            result = sharepoint.check_path(
                session, f"{BASE}/_layouts/nope.aspx", TIMEOUT
            )

        assert result.status_code == 404


class TestSharePointDiscoverSoap:
    DISCO_XML = """<?xml version="1.0"?>
<discovery xmlns="http://schemas.xmlsoap.org/disco/">
  <contractRef docRef="http://example.com/_vti_bin/UserGroup.asmx?WSDL"/>
  <contractRef docRef="http://example.com/_vti_bin/Lists.asmx?WSDL"/>
</discovery>"""

    def test_discovers_services(self):
        with responses.RequestsMock() as rsps:
            rsps.get(
                f"{BASE}/_vti_bin/spsdisco.aspx",
                status=200,
                body=self.DISCO_XML,
                headers={"Content-Type": "text/xml"},
            )
            session = Session()
            results = sharepoint.discover_soap_services(session, BASE, TIMEOUT)

        assert len(results) == 2
        assert results[0].url.endswith("UserGroup.asmx?WSDL")
        assert results[1].url.endswith("Lists.asmx?WSDL")
        assert all(r.detector == "sharepoint_soap" for r in results)

    def test_non_200_returns_empty(self):
        with responses.RequestsMock() as rsps:
            rsps.get(f"{BASE}/_vti_bin/spsdisco.aspx", status=404)
            session = Session()
            results = sharepoint.discover_soap_services(session, BASE, TIMEOUT)

        assert results == []


class TestSharePointEnumerateUsers:
    USERS_HTML = """<html>
<body>
<input account="DOMAIN\\jdoe" />
<input account="DOMAIN\\asmith" />
</body>
</html>"""

    def test_returns_users(self):
        with responses.RequestsMock() as rsps:
            rsps.get(
                f"{BASE}/_layouts/people.aspx?MembershipGroupId=0",
                status=200,
                body=self.USERS_HTML,
            )
            session = Session()
            results = sharepoint.enumerate_users(session, BASE, TIMEOUT)

        assert len(results) == 2
        assert results[0].evidence["account"] == "DOMAIN\\jdoe"
        assert results[1].evidence["account"] == "DOMAIN\\asmith"
        assert all(r.detector == "sharepoint_users" for r in results)

    def test_non_200_returns_empty(self):
        with responses.RequestsMock() as rsps:
            rsps.get(
                f"{BASE}/_layouts/people.aspx?MembershipGroupId=0", status=403
            )
            session = Session()
            results = sharepoint.enumerate_users(session, BASE, TIMEOUT)

        assert results == []


class TestFrontPageFingerprint:
    def test_detects_linux(self):
        with responses.RequestsMock(
            assert_all_requests_are_fired=False
        ) as rsps:
            rsps.get(f"{BASE}/_vti_bin/_vti_aut/author.exe", status=200, body="FP")
            rsps.get(f"{BASE}/_vti_bin/_vti_adm/admin.exe", status=200, body="FP")
            rsps.get(f"{BASE}/_vti_bin/shtml.exe", status=200, body="FP")
            session = Session()
            results = frontpage.fingerprint(session, BASE, TIMEOUT)

        assert any(r.evidence.get("frontpage_type") == "linux" for r in results)

    def test_detects_windows(self):
        with responses.RequestsMock() as rsps:
            for p in [
                "_vti_bin/_vti_aut/author.exe",
                "_vti_bin/_vti_adm/admin.exe",
                "_vti_bin/shtml.exe",
            ]:
                rsps.get(f"{BASE}/{p}", status=404)
            rsps.get(f"{BASE}/_vti_bin/_vti_aut/author.dll", status=200, body="FP")
            session = Session()
            results = frontpage.fingerprint(session, BASE, TIMEOUT)

        assert any(r.evidence.get("frontpage_type") == "windows" for r in results)

    def test_no_frontpage(self):
        with responses.RequestsMock() as rsps:
            for path in [
                "_vti_bin/_vti_aut/author.exe",
                "_vti_bin/_vti_adm/admin.exe",
                "_vti_bin/shtml.exe",
                "_vti_bin/_vti_aut/author.dll",
                "_vti_bin/_vti_aut/dvwssr.dll",
                "_vti_bin/_vti_adm/admin.dll",
                "_vti_bin/shtml.dll",
                "_vti_inf.html",
            ]:
                rsps.get(f"{BASE}/{path}", status=404)
            session = Session()
            results = frontpage.fingerprint(session, BASE, TIMEOUT)

        assert results == []

    def test_detects_config_file(self):
        with responses.RequestsMock() as rsps:
            for path in [
                "_vti_bin/_vti_aut/author.exe",
                "_vti_bin/_vti_adm/admin.exe",
                "_vti_bin/shtml.exe",
                "_vti_bin/_vti_aut/author.dll",
                "_vti_bin/_vti_aut/dvwssr.dll",
                "_vti_bin/_vti_adm/admin.dll",
                "_vti_bin/shtml.dll",
            ]:
                rsps.get(f"{BASE}/{path}", status=404)
            rsps.get(f"{BASE}/_vti_inf.html", status=200, body="config")
            session = Session()
            results = frontpage.fingerprint(session, BASE, TIMEOUT)

        assert any(r.evidence.get("config_found") is True for r in results)


class TestFrontPageCheckPath:
    def test_returns_200(self):
        with responses.RequestsMock() as rsps:
            rsps.get(f"{BASE}/_vti_bin/shtml.dll", status=200, body="OK")
            session = Session()
            result = frontpage.check_path(
                session, f"{BASE}/_vti_bin/shtml.dll", TIMEOUT
            )

        assert result.status_code == 200
        assert result.detector == "frontpage_paths"

    def test_returns_404(self):
        with responses.RequestsMock() as rsps:
            rsps.get(f"{BASE}/_vti_bin/missing.dll", status=404)
            session = Session()
            result = frontpage.check_path(
                session, f"{BASE}/_vti_bin/missing.dll", TIMEOUT
            )

        assert result.status_code == 404
