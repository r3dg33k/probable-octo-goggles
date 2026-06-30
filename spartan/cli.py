import argparse

BANNER = """
============================================
  SPartan v{version}
  SharePoint & FrontPage Security Scanner
============================================
"""


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spartan",
        usage="spartan -u <URL> [options]",
        description="SharePoint & FrontPage security scanner",
        add_help=False,
    )

    # --- Target ---
    parser.add_argument("-u", dest="url", metavar="URL",
                        help="Target URL (http://... or https://...)")

    # --- Scan Modules ---
    parser.add_argument("-f", dest="frontpage", action="store_true",
                        help="FrontPage scan (fingerprint + _vti paths)")
    parser.add_argument("-s", dest="sharepoint", action="store_true",
                        help="SharePoint scan (fingerprint + layouts/forms/catalogs)")
    parser.add_argument("--sps", dest="sps", action="store_true",
                        help="Discover SOAP services")
    parser.add_argument("--users", dest="users", action="store_true",
                        help="Enumerate SharePoint users")
    parser.add_argument("-c", dest="crawl", action="store_true",
                        help="Crawl site for links (BFS)")
    parser.add_argument("-D", dest="dir_bruteforce", action="store_true",
                        help="Directory brute-force (dir.txt + custom wordlist)")
    parser.add_argument("-k", dest="keyword", metavar="KEYWORD",
                        help="Search found pages for keyword")
    parser.add_argument("-d", dest="download", action="store_true",
                        help="Download interesting files")
    parser.add_argument("-p", dest="putable", action="store_true",
                        help="Find PUTable directories (OPTIONS check)")
    parser.add_argument("-r", dest="rpc", metavar="QUERY",
                        help="(STUB) FrontPage RPC query")

    # --- Authentication ---
    parser.add_argument("--auth", dest="auth_mode",
                        choices=["ntlm", "cookie", "basic", "bearer", "kerberos", "none"],
                        default="none", help="Authentication mode")
    parser.add_argument("-l", dest="login", metavar="USER:PASS",
                        help="Credentials (NTLM: DOMAIN\\USER:PASS, Basic: USER:PASS)")
    parser.add_argument("--cookie", dest="cookie_string", metavar="STR",
                        help='Cookie string e.g. "key=value; key=val"')
    parser.add_argument("--bearer", dest="bearer_token", metavar="TOKEN",
                        help="Bearer token (for --auth bearer)")

    # --- Network ---
    parser.add_argument("-t", dest="threads", type=int, default=10,
                        help="Thread count (default: 10)")
    parser.add_argument("--timeout", dest="timeout", type=float, default=30.0,
                        help="Overall request timeout in seconds (default: 30)")
    parser.add_argument("--connect-timeout", dest="connect_timeout",
                        type=float, default=10.0,
                        help="Connection timeout in seconds (default: 10)")
    parser.add_argument("--read-timeout", dest="read_timeout",
                        type=float, default=20.0,
                        help="Read timeout in seconds (default: 20)")
    parser.add_argument("--rate-limit", dest="rate_limit", metavar="N/s",
                        help="Requests per second e.g. 5/s, 10/m, 100/h")
    parser.add_argument("--proxy", dest="proxy", metavar="URL",
                        help="Proxy URL e.g. http://127.0.0.1:8080")
    parser.add_argument("-i", dest="ignore_ssl", action="store_true",
                        help="Ignore SSL verification")

    # --- Scope & Safety ---
    parser.add_argument("--no-follow-cross-domain", dest="no_follow_cross_domain",
                        action="store_true", help="Don't follow links to other domains")
    parser.add_argument("--deny-private-ip", dest="deny_private_ip",
                        action="store_true", help="Block requests to RFC1918 addresses")
    parser.add_argument("--allow-private-ip", dest="allow_private_ip",
                        action="store_true",
                        help="Override --deny-private-ip for internal targets")
    parser.add_argument("--scope-file", dest="scope_file", metavar="FILE",
                        help="Load scope rules (domain | URL prefix | CIDR)")
    parser.add_argument("--max-depth", dest="max_depth", type=int,
                        help="Max crawl depth")
    parser.add_argument("--max-urls", dest="max_urls", type=int, default=1000,
                        help="Max URLs to fetch during crawl (default: 1000)")

    # --- Output ---
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Verbose: show all responses including filtered")
    parser.add_argument("-q", "--quiet", dest="quiet", action="store_true",
                        help="Suppress non-result output")
    parser.add_argument("--output-dir", dest="output_dir", default=".",
                        help="Base output directory (default: ./)")
    parser.add_argument("--json", dest="json_path", metavar="FILE",
                        help="JSON output path")
    parser.add_argument("--jsonl", dest="jsonl_path", metavar="FILE",
                        help="JSONL output path")
    parser.add_argument("--csv", dest="csv_path", metavar="FILE",
                        help="CSV output path")
    parser.add_argument("--sqlite", dest="sqlite_path", metavar="FILE",
                        help="SQLite output path")

    # --- Download ---
    parser.add_argument("--max-download-size", dest="max_download_size",
                        metavar="SIZE", default="10MB",
                        help="Max file size e.g. 10MB, 500KB (default: 10MB)")
    parser.add_argument("--no-download-overwrite", dest="no_download_overwrite",
                        action="store_true", help="Skip download if file exists")
    parser.add_argument("--hash-downloads", dest="hash_downloads",
                        action="store_true",
                        help="Record SHA-256 of downloaded files")

    # --- Redaction ---
    parser.add_argument("--redact-secrets", dest="redact_secrets",
                        action="store_true",
                        help="Enable secret redaction in output/evidence")
    parser.add_argument("--redact-patterns", dest="redact_patterns",
                        metavar="FILE", help="Custom regex patterns file")

    # --- State & Plan ---
    parser.add_argument("--resume", dest="resume", action="store_true",
                        help="Auto-detect and resume previous session")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true",
                        help="Show what would be scanned, don't execute")
    parser.add_argument("--show-plan", dest="show_plan", action="store_true",
                        help="Print task plan before executing")

    # --- Helpers ---
    parser.add_argument("--profile", dest="profile_name", metavar="NAME",
                        help="Load JSON profile from profiles/NAME.json")
    parser.add_argument("--custom-wordlist", dest="custom_wordlist",
                        metavar="FILE",
                        help="Add custom paths to all enumeration scans")
    parser.add_argument("-A", "--authorized", dest="authorized",
                        action="store_true",
                        help="Confirm authorized testing")
    parser.add_argument("-h", "--help", dest="help", action="store_true",
                        help="Show this help message and exit")

    return parser
