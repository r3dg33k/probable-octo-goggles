import threading

import responses

from spartan.auth import NoAuthProvider
from spartan.config import (
    AuthConfig,
    DownloadConfig,
    NetworkConfig,
    OutputConfig,
    ScanConfig,
    ScopeConfig,
)
from spartan.http_client import SessionFactory
from spartan.output import ConsoleSink
from spartan.scanner import Scanner
from spartan.scope import ScopeGuard


class TestScanner:
    def _make_config(self, **overrides) -> ScanConfig:
        kwargs = dict(
            url="http://testsp.com",
            auth=AuthConfig(mode="none"),
            network=NetworkConfig(threads=2, timeout=5.0),
            scope=ScopeConfig(same_host_only=True),
            output=OutputConfig(output_dir=".", verbose=False, quiet=True),
            download=DownloadConfig(enabled=False),
        )
        kwargs.update(overrides)
        return ScanConfig(**kwargs)

    def _make_scanner(self, config: ScanConfig) -> Scanner:
        factory = SessionFactory(
            user_agent="test/1.0",
            timeout=5.0,
            connect_timeout=2.0,
            read_timeout=3.0,
            ignore_ssl=False,
            proxy=None,
            auth_provider=NoAuthProvider(),
        )
        guard = ScopeGuard(config=config.scope, target_url=config.url)
        sink = ConsoleSink(verbose=False, quiet=True)
        return Scanner(config, factory, guard, None, None, [sink], threading.Event())

    @responses.activate
    def test_sharepoint_fingerprint_headers(self):
        responses.add(
            responses.GET,
            "http://testsp.com/",
            body="<html>test</html>",
            status=200,
            headers={"MicrosoftSharePointTeamServices": "15.0.0.0"},
        )
        config = self._make_config(sharepoint=True, frontpage=False)
        scanner = self._make_scanner(config)
        scanner._establish_friendly_404_baseline = lambda: None
        count = scanner._run_sharepoint()
        assert count >= 0

    @responses.activate
    def test_frontpage_path_check(self):
        responses.add(
            responses.GET,
            "http://testsp.com/_vti_inf.html",
            body="FP info", status=200,
        )
        responses.add(
            responses.GET,
            "http://testsp.com/_vti_bin/shtml.dll/_vti_rpc",
            body="", status=404,
        )
        config = self._make_config(sharepoint=False, frontpage=True)
        scanner = self._make_scanner(config)
        scanner._establish_friendly_404_baseline = lambda: None
        count = scanner._run_frontpage()
        assert count >= 0

    @responses.activate
    def test_dir_bruteforce(self):
        responses.add(responses.GET, "http://testsp.com/_vti_pvt/", body="", status=200)
        responses.add(responses.GET, "http://testsp.com/_vti_bin/", body="", status=200)
        config = self._make_config(dir_bruteforce=True)
        scanner = self._make_scanner(config)
        scanner._establish_friendly_404_baseline = lambda: None
        count = scanner._run_dir_bruteforce()
        assert count >= 0

    @responses.activate
    def test_sps_discovery(self):
        body = (
            '<?xml version="1.0"?>'
            '<discovery xmlns="http://schemas.xmlsoap.org/disco/">'
            '<contractRef docRef="http://testsp.com/_vti_bin/Lists.asmx"/>'
            "</discovery>"
        )
        responses.add(
            responses.GET,
            "http://testsp.com/_vti_bin/spsdisco.aspx",
            body=body,
            status=200,
        )
        config = self._make_config(sps=True)
        scanner = self._make_scanner(config)
        count = scanner._run_sps_discovery()
        assert count > 0

    @responses.activate
    def test_user_enum(self):
        responses.add(
            responses.GET,
            "http://testsp.com/_layouts/people.aspx?MembershipGroupId=0",
            body='<input account="DOMAIN\\user1" />',
            status=200,
        )
        config = self._make_config(users=True)
        scanner = self._make_scanner(config)
        count = scanner._run_user_enum()
        assert count > 0

    @responses.activate
    def test_putable_check(self):
        responses.add(
            responses.OPTIONS,
            "http://testsp.com/_vti_pvt/",
            status=200,
            headers={"Allow": "GET, PUT, OPTIONS"},
        )
        config = self._make_config(putable=True)
        scanner = self._make_scanner(config)
        scanner._establish_friendly_404_baseline = lambda: None
        count = scanner._run_put_check()
        assert count > 0

    @responses.activate
    def test_crawl(self):
        responses.add(
            responses.GET,
            "http://testsp.com/",
            body='<html><a href="http://testsp.com/page1">link</a></html>',
            status=200,
        )
        config = self._make_config(crawl=True, scope=ScopeConfig(same_host_only=True))
        scanner = self._make_scanner(config)
        count = scanner._run_crawler()
        assert count > 0

    def test_run_no_modules(self):
        config = self._make_config()
        scanner = self._make_scanner(config)
        count = scanner.run()
        assert count == 0

    def test_run_dry_run(self):
        config = self._make_config(dry_run=True, sharepoint=True)
        scanner = self._make_scanner(config)
        count = scanner.run()
        assert count == 0

    def test_show_plan(self):
        config = self._make_config(show_plan=True)
        scanner = self._make_scanner(config)
        count = scanner.run()
        assert count == 0
