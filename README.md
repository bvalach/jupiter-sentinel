# Sentinel

Portable multi-agent security sentinel for personal servers and workstations.

This public prototype is intentionally generic:
- no personal paths
- no site-specific logic
- no production database dependency
- no API-key requirement for the model CLIs

The intended setup is local OAuth/session login for Claude Code and Codex.

## Architecture

```text
cron ──→ scanner/scan.sh        (deterministic host evidence, structured summary)
          │
          ├──→ Claude           (threat intel against recent advisories/news)
          │
          ├──→ Codex            (forensic posture review from captured evidence)
          │
          └──→ Claude           (merge, prioritize, report)
                    ↓
               local history + optional notification
```

## Design Principles

- The scanner is the only phase that touches the host directly.
- Models read audit artifacts, not the live machine.
- History is local JSONL by default, so the prototype stays portable.
- Every AI phase can fail independently without collapsing the whole run.
- OAuth-backed CLIs are assumed; API keys are optional and not required.

## What It Scans

| Signal | Default source |
|--------|----------------|
| Pending OS package updates | `apt` on Linux, `brew outdated` on macOS when available |
| Local CVE hints | `debsecan` on Debian/Ubuntu when installed |
| Listening services | `ss` or `lsof` |
| Recent failed logins | `journalctl` / `auth.log` when available |
| File integrity drift | SHA-256 checksum baseline |
| Docker posture | `docker images`, `docker ps`, `docker inspect` |
| SUID/SGID binaries | `find` |
| World-writable files in sensitive paths | `find` |
| Root-owned processes | `ps aux` |
| Firewall evidence | `nft` or `iptables` when available |
| SSH baseline | `sshd -T` or relevant config lines |
| Cron visibility | `crontab -l` and `/etc/cron*` |
| Repo secret heuristics | deterministic regex scan over configured project paths |
| Recent external threats | Claude with `WebSearch` / `WebFetch` |
| Internal posture review | Codex over the captured artifacts |

## Setup

### Prerequisites

```bash
# Python 3
# Claude Code CLI authenticated locally
# Codex CLI authenticated locally

# Optional Linux helper
sudo apt install debsecan

# Optional host tools
# docker
# nftables / iptables
# Homebrew (macOS package visibility)
```

### Configure

```bash
cp env.example .env
# Edit .env for your machine
```

### Make executable

```bash
chmod +x run-audit.sh scanner/scan.sh lib/notify.sh
```

### Cron

```bash
crontab -e
0 6 * * * /absolute/path/to/run-audit.sh >> /tmp/sentinel.log 2>&1
```

## Usage

```bash
./run-audit.sh
./run-audit.sh --scan-only
./run-audit.sh --skip-scan
```

## History Search

```bash
python3 lib/store.py search "ssh password authentication"
python3 lib/store.py search "docker privileged mount" --host workstation-01
```

## Directory Structure

```text
sentinel/
├── .gitignore
├── LICENSE
├── env.example
├── run-audit.sh
├── scanner/
│   └── scan.sh
├── prompts/
│   ├── threat-intel.md
│   ├── forensic-audit.md
│   └── merge-report.md
├── lib/
│   ├── build_scan_summary.py
│   ├── store.py
│   ├── notify.sh
│   └── requirements.txt
├── schema/
│   └── finding.schema.json
├── daily/
│   └── YYYYMMDD/
│       ├── raw/
│       ├── scan-summary.json
│       ├── opus-findings.json
│       ├── codex-findings.json
│       ├── summary.json
│       └── report.md
└── history/
    └── summaries.jsonl
```

## Configuration Notes

- `PROJECT_PATHS` is a comma-separated list of directories to inspect for manifests, `.env` files, and secret-like patterns.
- `CHECKSUM_FILES` is a colon-separated list of tracked files.
- `SUID_SCAN_PATHS` and `WORLD_WRITABLE_PATHS` are colon-separated path lists.
- `RUN_NETWORK_AUDITS=false` by default to keep the public prototype deterministic and portable.
- Notification is optional and disabled by default.

## Notes

- This repository intentionally contains no personal defaults or site-specific logic.
- The scanner may show blind spots when a command is unavailable or lacks privileges. Those blind spots are preserved in `scan-summary.json`.
- Threat intel and forensic phases are expected to run through locally authenticated CLI sessions.
- If a model phase fails because OAuth expired or a CLI is unavailable, Sentinel degrades gracefully and keeps the scan artifacts.
