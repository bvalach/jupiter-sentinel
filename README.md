<div align="center">

```
  ___  ____  _  _  ____  ____  _  _  ____  __   
 / __)( ___)( \( )(_  _)(_  _)( \( )( ___)(  )  
 \__ \ )__)  )  (   )(   _)(_  )  (  )__)  )(__ 
 (___/(____)(_)\_) (__) (____)(_)\_)(____)(____) 
```

**Multi-agent security sentinel for personal servers and workstations.**

*One cron job. Three AI analysts. Zero API keys required.*

`scanner` **>>** `Claude (threat intel)` **>>** `Codex (forensics)` **>>** `Claude (report)` **>>** `history`

---

[MIT License](LICENSE) / Linux & macOS / Python 3 / Claude Code + Codex CLI

</div>

---

## How it works

Sentinel runs a **deterministic scanner** that collects host evidence, then hands that evidence to **two AI analysts** that can't touch your machine directly. A final AI pass merges everything into a prioritized operator briefing.

```
                         +------------------+
                         |    cron / manual  |
                         +--------+---------+
                                  |
                    +-------------v--------------+
                    |   Phase 1: Scanner (bash)  |
                    |   Deterministic evidence    |
                    |   collection from the host  |
                    +-------------+--------------+
                                  |
                          scan-summary.json
                                  |
                  +---------------+---------------+
                  |                               |
     +------------v-----------+    +--------------v-----------+
     | Phase 2: Claude Opus   |    | Phase 3: Codex o3        |
     | Threat intelligence    |    | Forensic posture review  |
     | WebSearch + WebFetch   |    | Internal config analysis |
     +------------+-----------+    +--------------+-----------+
                  |                               |
         opus-findings.json             codex-findings.json
                  |                               |
                  +---------------+---------------+
                                  |
                   +--------------v--------------+
                   | Phase 4: Claude Sonnet      |
                   | Merge, deduplicate,         |
                   | prioritize, write report    |
                   +--------------+--------------+
                                  |
                     report.md + summary.json
                                  |
                  +---------------+---------------+
                  |                               |
        +---------v---------+         +-----------v----------+
        | Phase 5: History  |         | Phase 6: Notify      |
        | Local JSONL store |         | Telegram (optional)  |
        +-------------------+         +----------------------+
```

## Design principles

| Principle | Why |
|-----------|-----|
| **Scanner = only host contact** | AI phases read artifacts, never the live machine |
| **Graceful degradation** | Each AI phase can fail independently without collapsing the run |
| **No API keys needed** | Uses locally authenticated CLI sessions (OAuth/session login) |
| **Portable by default** | Local JSONL history, no database, no site-specific logic |
| **Structured output** | JSON schema for all findings, machine-readable summaries |

## What it scans

<details>
<summary><strong>15 signal categories</strong> (click to expand)</summary>

| Signal | Source |
|--------|--------|
| Pending OS updates | `apt` / `brew outdated` |
| Local CVE hints | `debsecan` (Debian/Ubuntu) |
| Listening services | `ss` / `lsof` |
| Failed logins | `journalctl` / `auth.log` |
| File integrity drift | SHA-256 checksum baseline |
| Docker posture | `docker images` / `ps` / `inspect` |
| SUID/SGID binaries | `find` |
| World-writable files | `find` on sensitive paths |
| Root-owned processes | `ps aux` |
| Firewall rules | `nft` / `iptables` |
| SSH baseline | `sshd -T` or config inspection |
| Cron jobs | `crontab -l` + `/etc/cron*` |
| Secret heuristics | Regex scan over project paths |
| External threats | Claude + `WebSearch` / `WebFetch` |
| Internal posture | Codex forensic analysis |

</details>

## Quick start

```bash
# 1. Clone
git clone https://github.com/YOUR_USER/jupiter-sentinel-generic.git
cd jupiter-sentinel-generic

# 2. Configure
cp env.example .env
$EDITOR .env                  # adjust for your machine

# 3. Make executable
chmod +x run-audit.sh scanner/scan.sh lib/notify.sh

# 4. Run
./run-audit.sh
```

### Prerequisites

- **Python 3**
- **Claude Code CLI** — authenticated locally via OAuth/session
- **Codex CLI** — authenticated locally via OAuth/session
- Optional: `debsecan` (Linux CVE hints), Docker, `nftables`/`iptables`, Homebrew (macOS)

### Schedule it

```bash
crontab -e
# Daily at 06:00
0 6 * * * /absolute/path/to/run-audit.sh >> /tmp/sentinel.log 2>&1
```

## Usage

```bash
./run-audit.sh              # Full pipeline: scan + AI analysis + report
./run-audit.sh --scan-only  # Just the deterministic scanner
./run-audit.sh --skip-scan  # Reuse existing scan, run AI phases only
```

### Search history

```bash
python3 lib/store.py search "ssh password authentication"
python3 lib/store.py search "docker privileged mount" --host workstation-01
```

## Project structure

```
sentinel/
├── run-audit.sh                 # Orchestrator: runs all phases sequentially
├── scanner/
│   └── scan.sh                  # Phase 1: deterministic host evidence collector
├── prompts/
│   ├── threat-intel.md          # Phase 2 prompt: Claude threat intelligence
│   ├── forensic-audit.md        # Phase 3 prompt: Codex forensic review
│   └── merge-report.md          # Phase 4 prompt: Claude merge & report
├── lib/
│   ├── build_scan_summary.py    # Builds structured JSON from raw scan artifacts
│   ├── store.py                 # JSONL history: store & search
│   ├── notify.sh                # Optional Telegram notification
│   └── requirements.txt
├── schema/
│   └── finding.schema.json      # JSON Schema for all findings
├── daily/                       # Output: one folder per day
│   └── YYYYMMDD/
│       ├── raw/                 #   Raw scan artifacts
│       ├── scan-summary.json    #   Structured scanner output
│       ├── opus-findings.json   #   Claude threat intel findings
│       ├── codex-findings.json  #   Codex forensic findings
│       ├── summary.json         #   Merged machine-readable summary
│       └── report.md            #   Human-readable operator briefing
├── history/
│   └── summaries.jsonl          # Append-only audit history
├── env.example                  # Template configuration
├── AGENTS.md                    # AI agent roles and coordination
└── LICENSE                      # MIT
```

## Configuration

All settings live in `.env` (copied from `env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `AUDIT_DIR` | Output directory for daily audits | `daily` |
| `HOSTNAME_LABEL` | Host label in reports | `hostname -s` |
| `CLAUDE_MODEL_INTEL` | Model for threat intel phase | `opus` |
| `CLAUDE_MODEL_MERGE` | Model for merge/report phase | `sonnet` |
| `CODEX_MODEL` | Model for forensic phase | `o3` |
| `ENABLE_THREAT_INTEL` | Toggle Phase 2 | `true` |
| `ENABLE_FORENSIC_AUDIT` | Toggle Phase 3 | `true` |
| `ENABLE_MERGE_REPORT` | Toggle Phase 4 | `true` |
| `PROJECT_PATHS` | Comma-separated dirs for secret scanning | *(empty)* |
| `CHECKSUM_FILES` | Colon-separated files for integrity checks | `/etc/passwd:/etc/group:...` |
| `RUN_NETWORK_AUDITS` | Enable network-level audits | `false` |
| `ENABLE_NOTIFICATIONS` | Telegram alerts | `false` |

## How it degrades

Sentinel is built to keep working when things break:

- **CLI not installed?** Phase writes a `degraded` stub, pipeline continues.
- **OAuth expired?** Same: stub + graceful skip.
- **Scanner tool missing?** Blind spot recorded in `scan-summary.json`, not silently ignored.
- **No findings?** Report says "ALL CLEAR" in 5 lines.
- **Yesterday's data missing?** Delta comparison skipped, no crash.

---

<div align="center">

*Built for operators who want to sleep well.*

</div>
