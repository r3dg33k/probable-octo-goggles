# SPartan v2

**SharePoint & FrontPage Security Scanner**

Originally created by [Keiran Dennie](https://sensepost.com) for [SensePost](https://github.com/sensepost/SPartan). This is a Python 3.10+ refactor preserving the original CLI behavior with improved architecture.

## Installation

```bash
pip install -r requirements.txt
```

Required: `requests`, `requests-ntlm`, `requests-kerberos`, `beautifulsoup4`, `colorama`

## Quick Start

```bash
# Basic SharePoint scan
python -m spartan -u https://target.com -s

# Basic FrontPage scan
python -m spartan -u http://target.com -f

# Full scan: SharePoint + FrontPage + crawl + directory brute-force
python -m spartan -u https://sharepoint.internal -s -f -c -D -v

# Authenticated scan (NTLM)
python -m spartan -u https://sharepoint.internal -s --auth ntlm -l "DOMAIN\user:pass"

# Scan with keyword search and JSON output
python -m spartan -u https://target.com -s -c -k "password" --json results.json

# Dry-run to see what would be scanned
python -m spartan -u https://target.com -s -f -D --dry-run --show-plan
```

## Usage

```
spartan -u <URL> [options]
```

### Target

| Flag | Description |
|------|-------------|
| `-u <URL>` | Target URL (http://... or https://...) |

### Scan Modules

| Flag | Description |
|------|-------------|
| `-f` | FrontPage scan (fingerprint + _vti paths) |
| `-s` | SharePoint scan (fingerprint + layouts/forms/catalogs) |
| `-c` | Crawl site for links (BFS) |
| `-D` | Directory brute-force (dir.txt + custom wordlist) |
| `-k <KEYWORD>` | Search found pages for keyword |
| `-d` | Download interesting files |
| `-p` | Find PUTable directories (OPTIONS check) |
| `--sps` | Discover SOAP services |
| `--users` | Enumerate SharePoint users |
| `-r <QUERY>` | (STUB) FrontPage RPC query |

### Authentication

| Flag | Description |
|------|-------------|
| `--auth <MODE>` | Auth mode: `none`, `basic`, `ntlm`, `cookie`, `bearer`, `kerberos` (default: `none`) |
| `-l <USER:PASS>` | Credentials format: `DOMAIN\USER:PASS` (NTLM), `USER:PASS` (Basic) |
| `--cookie <STR>` | Cookie string e.g. `"key=value; key=val"` |
| `--bearer <TOKEN>` | Bearer token (for `--auth bearer`) |

### Network

| Flag | Description |
|------|-------------|
| `-t <N>` | Thread count (default: 10) |
| `--timeout <SEC>` | Overall request timeout (default: 30) |
| `--connect-timeout <SEC>` | Connection timeout (default: 10) |
| `--read-timeout <SEC>` | Read timeout (default: 20) |
| `--rate-limit <N/s>` | Rate limit e.g. `5/s`, `10/m`, `100/h` |
| `--proxy <URL>` | Proxy URL e.g. `http://127.0.0.1:8080` |
| `-i` | Ignore SSL verification |

### Scope & Safety

| Flag | Description |
|------|-------------|
| `--no-follow-cross-domain` | Don't follow links to other domains |
| `--deny-private-ip` | Block requests to RFC1918 addresses |
| `--allow-private-ip` | Override --deny-private-ip for internal targets |
| `--scope-file <FILE>` | Load scope rules (domain\|URL prefix\|CIDR) |
| `--max-depth <N>` | Max crawl depth |
| `--max-urls <N>` | Max URLs to fetch during crawl (default: 1000) |

### Output

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show all responses including filtered |
| `-q`, `--quiet` | Suppress non-result output |
| `--output-dir <DIR>` | Base output directory (default: `./`) |
| `--json <FILE>` | JSON output path |
| `--jsonl <FILE>` | JSONL output path |
| `--csv <FILE>` | CSV output path |
| `--sqlite <FILE>` | SQLite output path |

### Download

| Flag | Description |
|------|-------------|
| `--max-download-size <SIZE>` | Max file size e.g. `10MB`, `500KB` (default: `10MB`) |
| `--no-download-overwrite` | Skip download if file exists |
| `--hash-downloads` | Record SHA-256 of downloaded files |

### State & Plan

| Flag | Description |
|------|-------------|
| `--resume` | Auto-detect and resume previous session |
| `--dry-run` | Show what would be scanned, don't execute |
| `--show-plan` | Print task plan before executing |

### Other

| Flag | Description |
|------|-------------|
| `--custom-wordlist <FILE>` | Add custom paths to all enumeration scans |
| `--profile <NAME>` | Load JSON profile from `profiles/<NAME>.json` |
| `-A`, `--authorized` | Confirm authorized testing |
| `-h`, `--help` | Show help message |

## License

SPartan by SensePost is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](http://creativecommons.org/licenses/by-sa/4.0/).

Original project: [https://github.com/sensepost/SPartan](https://github.com/sensepost/SPartan)
