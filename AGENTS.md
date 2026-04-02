# AGENTS.md — Sentinel Agent Coordination

How the AI agents collaborate inside Sentinel.

---

## Overview

Sentinel is a **multi-agent security pipeline** where a deterministic scanner collects host evidence and three AI agents analyze it from different angles. No agent touches the live machine. All agents work on structured artifacts.

```
Scanner (bash)  ──>  Analyst 1 (Claude)  ──>  Analyst 2 (Codex)  ──>  Synthesizer (Claude)
  [evidence]          [threats]                [forensics]              [report]
```

---

## Agent roster

### Phase 1 — Scanner (deterministic, no AI)

| | |
|---|---|
| **What** | Bash script that collects raw host evidence |
| **File** | `scanner/scan.sh` + `lib/build_scan_summary.py` |
| **Touches host** | Yes — the only component that does |
| **Output** | `raw/*` artifacts + `scan-summary.json` |

The scanner is the **trust boundary**. Everything downstream reads artifacts, not the machine. If a tool is missing or a command lacks privileges, the blind spot is explicitly recorded in `scan-summary.json` rather than silently ignored.

---

### Phase 2 — Threat Intelligence Analyst (Claude)

| | |
|---|---|
| **Model** | Claude Opus (configurable via `CLAUDE_MODEL_INTEL`) |
| **Prompt** | `prompts/threat-intel.md` |
| **Input** | `scan-summary.json`, web (via `WebSearch` + `WebFetch`) |
| **Output** | `opus-findings.json` |
| **Allowed tools** | `Bash(readonly:true)`, `WebSearch`, `WebFetch`, `Read`, `Write` |
| **Max turns** | 12 (configurable via `MAX_TURNS_INTEL`) |

**Role:** Answer one question — *which recent external threats are relevant to this specific machine today?*

Workflow:
1. Read `scan-summary.json` to understand what's installed, exposed, and running.
2. Search the web for CVEs, vendor advisories, and supply-chain incidents from the last 72 hours that connect to the local evidence.
3. Classify each threat as `direct`, `indirect`, or `contextual` based on how tightly it maps to the host.
4. Write structured findings. Maximum 8 findings. No generic CVE roundups.

**Key constraint:** The analyst cannot access the live host. It reads scan artifacts and searches the web, nothing more.

---

### Phase 3 — Forensic Posture Analyst (Codex)

| | |
|---|---|
| **Model** | Codex o3 (configurable via `CODEX_MODEL`) |
| **Prompt** | `prompts/forensic-audit.md` |
| **Input** | `scan-summary.json`, `opus-findings.json`, `raw/*` artifacts |
| **Output** | `codex-findings.json` |
| **Mode** | `--full-auto` |

**Role:** Internal posture review — look at the configuration, permissions, and exposure from the inside.

Workflow:
1. Read `scan-summary.json` for the baseline.
2. Read `opus-findings.json` to avoid duplicating threat intel.
3. Dig into raw artifacts (`open-ports.txt`, `suid-sgid.txt`, `docker-inspect.json`, etc.) when needed.
4. Compare with yesterday's `summary.json` if available to detect drift.
5. Write structured findings. Maximum 10 findings. Never output actual secret values.

**Key constraint:** Reads artifacts only. No web access, no host access. Focuses on what the scanner saw, not what an external adversary might see.

---

### Phase 4 — Report Synthesizer (Claude)

| | |
|---|---|
| **Model** | Claude Sonnet (configurable via `CLAUDE_MODEL_MERGE`) |
| **Prompt** | `prompts/merge-report.md` |
| **Input** | `scan-summary.json`, `opus-findings.json`, `codex-findings.json`, yesterday's output |
| **Output** | `report.md` + `summary.json` |
| **Allowed tools** | `Read`, `Write` |
| **Max turns** | 8 (configurable via `MAX_TURNS_MERGE`) |

**Role:** Merge, deduplicate, prioritize, and produce a one-page operator briefing.

Workflow:
1. Merge scanner baseline + Claude findings + Codex findings.
2. Deduplicate: same issue reported by multiple sources gets one entry with the best phrasing.
3. Assign traffic-light priority: red (action today), amber (action this week), green (monitor).
4. Write `report.md` (human-readable, max 1 page) and `summary.json` (machine-readable).

**Key constraint:** No re-analysis. Only synthesizes what earlier phases produced.

---

## Agent coordination model

```
              Scanner
                |
                | scan-summary.json
                |
          +-----+-----+
          |           |
       Claude       Codex
     (Phase 2)    (Phase 3)
          |           |
          | opus-     | codex-
          | findings  | findings
          |           |
          +-----+-----+
                |
              Claude
            (Phase 4)
                |
         report + summary
                |
          +-----+-----+
          |           |
        History    Notify
       (JSONL)   (Telegram)
```

**Sequential by design.** Phase 3 reads Phase 2 output to avoid duplication. Phase 4 reads both. This isn't parallelizable without accepting redundant findings.

---

## Finding schema

All agents write findings using the same JSON Schema (`schema/finding.schema.json`):

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | `OPUS-NNN`, `CDX-NNN`, or `SCAN-NNN` |
| `severity` | enum | `critical` / `high` / `medium` / `low` / `info` |
| `category` | enum | `cve`, `supply-chain`, `permissions`, `docker`, `ssh`, etc. |
| `title` | string | Short description (max 120 chars) |
| `package_or_system` | string? | Affected component |
| `cve_id` | string? | CVE identifier if applicable |
| `description` | string | What was found |
| `evidence` | string? | File path, line number, or summarized output |
| `recommendation` | string | Specific actionable fix |
| `source_url` | string? | Reference URL |
| `requires_action` | boolean | Whether operator intervention is needed |

---

## Degradation behavior

Each agent phase is **independently failable**:

| Failure | What happens |
|---------|-------------|
| CLI not found | Phase writes a `degraded` stub JSON, pipeline continues |
| OAuth/session expired | Same: stub + skip |
| Agent exits with error | Same: stub + skip |
| Agent completes but writes nothing | Stub created, flagged as `degraded` |
| Yesterday's data missing | Delta comparison skipped gracefully |

The orchestrator (`run-audit.sh`) tracks every phase outcome in `phase-status.tsv` so you can audit what ran and what didn't.

---

## Security boundaries

1. **The scanner is the only component with host access.** All AI phases operate in a sandbox of artifacts.
2. **Agents never see secret values.** The scanner redacts; the forensic analyst is instructed to reference file paths and line numbers, never values.
3. **No outbound writes except to the audit directory.** Claude and Codex are restricted to `Read` + `Write` within the audit folder.
4. **Web access is limited to Phase 2** (threat intel). Phase 3 and Phase 4 have no web access.

---

## Customization

To change agent behavior, edit the corresponding prompt in `prompts/`:

| File | Controls |
|------|----------|
| `prompts/threat-intel.md` | What Phase 2 searches for and how it classifies threats |
| `prompts/forensic-audit.md` | What Phase 3 inspects and its finding categories |
| `prompts/merge-report.md` | Report format, priority definitions, summary structure |

Model selection, turn limits, and phase toggles are configured in `.env`.
