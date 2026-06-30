from spartan.cli import create_parser


class TestCLI:
    def test_parser_created(self):
        parser = create_parser()
        assert parser is not None
        assert parser.prog == "spartan"

    def test_default_values(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "http://example.com"])
        assert args.url == "http://example.com"
        assert args.threads == 10
        assert args.timeout == 30.0
        assert args.connect_timeout == 10.0
        assert args.read_timeout == 20.0
        assert args.auth_mode == "none"
        assert args.frontpage is False
        assert args.sharepoint is False
        assert args.crawl is False
        assert args.verbose is False
        assert args.quiet is False
        assert args.dry_run is False
        assert args.show_plan is False
        assert args.resume is False
        assert args.authorized is False
        assert args.ignore_ssl is False

    def test_frontpage_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "http://test", "-f"])
        assert args.frontpage is True

    def test_sharepoint_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "http://test", "-s"])
        assert args.sharepoint is True

    def test_verbose_flag(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "http://test", "-v"])
        assert args.verbose is True

    def test_auth_modes(self):
        parser = create_parser()
        for mode in ("ntlm", "cookie", "basic", "bearer", "kerberos", "none"):
            args = parser.parse_args(["-u", "http://test", "--auth", mode])
            assert args.auth_mode == mode

    def test_rate_limit(self):
        parser = create_parser()
        args = parser.parse_args(["-u", "http://test", "--rate-limit", "5/s"])
        assert args.rate_limit == "5/s"

    def test_all_combined_flags(self):
        parser = create_parser()
        argv = [
            "-u", "http://target", "-f", "-s", "-c", "-D", "-v",
            "--auth", "ntlm", "-l", "DOMAIN\\user:pass",
            "--rate-limit", "10/s", "--proxy", "http://proxy:8080",
            "--output-dir", "./output", "--json", "out.json",
            "--show-plan", "-A",
        ]
        args = parser.parse_args(argv)
        assert args.url == "http://target"
        assert args.frontpage is True
        assert args.sharepoint is True
        assert args.crawl is True
        assert args.dir_bruteforce is True
        assert args.verbose is True
        assert args.auth_mode == "ntlm"
        assert args.login == "DOMAIN\\user:pass"
        assert args.rate_limit == "10/s"
        assert args.proxy == "http://proxy:8080"
        assert args.output_dir == "./output"
        assert args.json_path == "out.json"
        assert args.show_plan is True
        assert args.authorized is True
