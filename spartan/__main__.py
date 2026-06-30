from __future__ import annotations

import sys
import threading
from pathlib import Path

from spartan import __version__
from spartan.auth import create_auth_provider
from spartan.cli import BANNER, create_parser
from spartan.config import (
    AuthConfig,
    DownloadConfig,
    NetworkConfig,
    OutputConfig,
    RedactConfig,
    ScanConfig,
    ScopeConfig,
    parse_rate_limit,
    parse_size,
)
from spartan.http_client import SessionFactory
from spartan.output import ConsoleSink, CsvSink, JsonlSink, JsonSink
from spartan.rate_limit import RateLimiter
from spartan.scanner import Scanner
from spartan.scope import ScopeGuard
from spartan.state import ScanState


def _build_config(args) -> ScanConfig:
    """Convert parsed argparse.Namespace into ScanConfig."""
    parse_rate_limit(args.rate_limit)
    max_dl_size = parse_size(args.max_download_size) if args.download else 0

    return ScanConfig(
        url=args.url,
        frontpage=args.frontpage,
        sharepoint=args.sharepoint,
        crawl=args.crawl,
        keyword=args.keyword,
        sps=args.sps,
        users=args.users,
        putable=args.putable,
        dir_bruteforce=args.dir_bruteforce,
        rpc=args.rpc,
        auth=AuthConfig(
            mode=args.auth_mode,
            cookie_string=args.cookie_string,
            bearer_token=args.bearer_token,
        ),
        network=NetworkConfig(
            threads=args.threads or 10,
            timeout=args.timeout or 30.0,
            connect_timeout=args.connect_timeout or 10.0,
            read_timeout=args.read_timeout or 20.0,
            ignore_ssl=args.ignore_ssl,
            proxy=args.proxy,
            rate_limit=args.rate_limit,
        ),
        scope=ScopeConfig(
            same_host_only=bool(args.no_follow_cross_domain),
            same_scheme=True,
            deny_private_ip=args.deny_private_ip or not args.allow_private_ip,
            allow_private_ip=args.allow_private_ip,
            scope_file=args.scope_file,
            max_depth=args.max_depth or 0,
            max_urls=args.max_urls or 1000,
        ),
        output=OutputConfig(
            output_dir=args.output_dir or ".",
            verbose=args.verbose,
            quiet=args.quiet,
            json_path=args.json_path,
            jsonl_path=args.jsonl_path,
            csv_path=args.csv_path,
        ),
        download=DownloadConfig(
            enabled=bool(args.download),
            max_size=max_dl_size or 10 * 1024 * 1024,
            no_overwrite=args.no_download_overwrite,
            hash_downloads=args.hash_downloads,
        ),
        redact=RedactConfig(
            enabled=args.redact_secrets,
            patterns_file=args.redact_patterns,
        ),
        resume=args.resume,
        dry_run=args.dry_run,
        show_plan=args.show_plan,
        custom_wordlist=args.custom_wordlist,
        profile_name=args.profile_name,
        confirm_authorized=args.authorized,
        overwrite_downloads=not args.no_download_overwrite,
    )


def _build_sinks(config: ScanConfig) -> list:
    sinks = [ConsoleSink(verbose=config.output.verbose, quiet=config.output.quiet)]

    if config.output.json_path:
        sinks.append(JsonSink(config.output.json_path))
    if config.output.jsonl_path:
        sinks.append(JsonlSink(config.output.jsonl_path))
    if config.output.csv_path:
        sinks.append(CsvSink(config.output.csv_path))

    return sinks


def main():
    parser = create_parser()

    if len(sys.argv) == 1:
        print(BANNER.format(version=__version__))
        parser.print_help()
        sys.exit(0)

    args = parser.parse_args()

    if getattr(args, "help", False):
        print(BANNER.format(version=__version__))
        parser.print_help()
        sys.exit(0)

    if not args.url:
        print("[!] No target URL specified. Use -u <URL>.")
        print(BANNER.format(version=__version__))
        parser.print_help()
        sys.exit(1)

    config = _build_config(args)
    sinks = _build_sinks(config)
    stop_event = threading.Event()

    # Confirm authorization
    if not config.confirm_authorized:
        sinks[0].write_message(
            "Use -A/--authorized to confirm you are authorized to test this target.",
            level="warn",
        )

    # State for resume
    state = None
    state_dir = Path(config.output.output_dir)
    if config.resume:
        state = ScanState(state_dir)
        if state.load():
            sinks[0].write_message(
                f"Resuming from {len(state.scanned_urls)} already-scanned URLs",
            )

    # Auth provider
    try:
        login = getattr(args, "login", None)
        if login and config.auth.mode in ("basic", "ntlm"):
            if "\\" in login:
                parts = login.split("\\", 1)
                domain_user = parts[0]
                user_pass = parts[1].split(":", 1)
                config.auth.username = f"{domain_user}\\{user_pass[0]}"
                if len(user_pass) > 1:
                    config.auth.password = user_pass[1]
            elif ":" in login:
                user, pwd = login.split(":", 1)
                config.auth.username = user
                config.auth.password = pwd
            else:
                config.auth.username = login
        auth_provider = create_auth_provider(config)
    except Exception as e:
        sinks[0].write_message(f"Auth setup failed: {e}", level="error")
        sys.exit(1)

    # Session factory
    session_factory = SessionFactory(
        user_agent=config.network.user_agent,
        timeout=config.network.timeout,
        connect_timeout=config.network.connect_timeout,
        read_timeout=config.network.read_timeout,
        ignore_ssl=config.network.ignore_ssl,
        proxy=config.network.proxy,
        auth_provider=auth_provider,
    )

    # Scope guard
    scope_guard = ScopeGuard(config=config.scope, target_url=config.url)

    # Rate limiter
    rate_limiter = None
    base_delay = parse_rate_limit(config.network.rate_limit)
    if base_delay is not None:
        rate_limiter = RateLimiter(base_delay_sec=base_delay)

    # Scanner
    scanner = Scanner(
        config=config,
        session_factory=session_factory,
        scope_guard=scope_guard,
        rate_limiter=rate_limiter,
        state=state,
        sinks=sinks,
        stop_event=stop_event,
    )

    try:
        total = scanner.run()
    except KeyboardInterrupt:
        sinks[0].write_message("Interrupted by user", level="warn")
        stop_event.set()
        total = 0
    finally:
        scanner.close()

    if total > 0:
        sinks[0].write_message(f"Done. {total} URLs checked.")

    sys.exit(0)


if __name__ == "__main__":
    main()
