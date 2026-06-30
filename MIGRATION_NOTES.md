# Migration Notes: SPartan Python 2 → Python 3

## Overview

This is a full rewrite of SPartan from Python 2 (`SPartan.py`) to Python 3.10+
modular architecture. The original `SPartan.py` is preserved as a reference
and is kept untouched.

## Architectural Changes

| Area | Python 2 (original) | Python 3 (refactor) |
|------|---------------------|---------------------|
| Entry point | `python SPartan.py -u <URL>` | `python -m spartan -u <URL>` |
| Structure | Single monolithic file | Modular: `cli.py`, `config.py`, `auth.py`, `http_client.py`, `scanner.py`, `detectors/`, `output/`, etc. |
| Auth | Inline NTLM/Cookie/Basic | Provider pattern: `NoAuth`, `Basic`, `NTLM`, `Cookie`, `Bearer`, `Kerberos` |
| HTTP | Direct `requests.get()` | `SessionFactory` with thread-local sessions, retry policy, timeouts |
| Results | `print()` everywhere | `ScanResult`/`Finding` dataclasses, structured output sinks |
| Output | Print-only | `ConsoleSink`, `JsonSink`, `JsonlSink`, `CsvSink` |
| State | None | `ScanState` with JSON save/load for resume |
| Scope | No scope enforcement | `ScopeGuard` with host/scheme/private-IP/scope-file rules |
| Wordlists | External file loading | `importlib.resources` bundled wordlists |
| Rate limiting | None | `RateLimiter` with adaptive backoff |
| Detectors | Inline in `SPartan.py` | Separate `detectors/sharepoint.py` and `detectors/frontpage.py` |
| Friendly 404 | Inline logic | `Scanner._establish_friendly_404_baseline()` + `_check_friendly_404()` |
| Config | Hard-coded defaults | Frozen `dataclass` config objects (`ScanConfig`, `AuthConfig`, etc.) |

## New Features Added

- `-D` / `--dir-bruteforce` — directory enumeration
- `--connect-timeout` / `--read-timeout` — separate connect/read timeouts
- `-q` / `--quiet` — suppress non-result output
- `--json` / `--jsonl` / `--csv` — structured output formats
- `--output-dir` — specify output directory
- `--resume` — save/restore scan state
- `--dry-run` / `--show-plan` — preview without executing
- `--proxy` — HTTP proxy support
- `--rate-limit` — requests per second limiting
- `--max-depth` / `--max-urls` — crawl constraints
- `--scope-file` — custom scope rules
- `--custom-wordlist` — custom wordlist for enumeration
- `--auth` — explicit auth mode selection (none/basic/ntlm/cookie/bearer/kerberos)
- `--bearer` — bearer token auth
- `-A` / `--authorized` — confirm authorization
- `--max-download-size` — size limit for downloads
- `--no-download-overwrite` / `--hash-downloads` — download management
- `--redact-secrets` — redact secrets from output

## Kerberos

- Uses `requests-kerberos` with the OS ticket cache
- No Kerberos passwords are stored by the tool
- Run `kinit user@REALM` before scanning

## Scope Safety

By default, the scanner:
- Stays on the same host as the target URL
- Blocks RFC1918 private IPs (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Blocks cloud metadata IPs (169.254.169.254, fd00:ec2::254)
- Blocks out-of-scope redirects
- Respects `--scope-file` rules

## Destructive Features

The following RPC operations from the original are preserved as
disabled stubs and are NOT implemented:
- `frontpage_fileup` — FrontPage RPC file upload
- `frontpage_folder_del` — FrontPage RPC folder deletion
- `frontpage_serv_enum` — FrontPage service enumeration
- `frontpage_config_enum` — FrontPage configuration enumeration

## Legacy Files Preserved

- `SPartan.py` — Original Python 2 script (reference only, kept untouched)
- `front_services.txt` — Legacy empty wordlist (preserved as-is)

## Testing

```bash
python -m pytest
python -m ruff check .
```

## Credits

Original SPartan by Keiran Dennie / SensePost
https://github.com/sensepost/SPartan
