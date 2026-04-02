#!/usr/bin/env bash
# ============================================================
# Sentinel — Daily Security Audit Orchestrator
# Scanner (deterministic) -> Claude (threat intel) -> Codex (forensic)
# -> Claude (merge/report) -> local history -> optional notification
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export SENTINEL_HOME="$SCRIPT_DIR"
ENV_FILE="${SCRIPT_DIR}/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "[sentinel] ERROR: .env not found."
  echo "[sentinel] Copy env.example to .env and adjust the values for your machine."
  exit 1
fi

set -a
source "$ENV_FILE"
set +a

resolve_path() {
  local raw_path="$1"
  if [ -z "$raw_path" ]; then
    return 0
  fi
  if [[ "$raw_path" = /* ]]; then
    printf '%s\n' "$raw_path"
  else
    printf '%s/%s\n' "$SCRIPT_DIR" "$raw_path"
  fi
}

python_date() {
  local fmt="$1"
  local offset_days="${2:-0}"
  python3 -c "from datetime import datetime, timedelta; print((datetime.now() + timedelta(days=${offset_days})).strftime('${fmt}'))"
}

require_var() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[sentinel] ERROR: Missing required setting: ${name}"
    exit 1
  fi
}

write_findings_stub() {
  local output_file="$1"
  local analyst="$2"
  local reason="$3"
  python3 - "$output_file" "$TODAY_ISO" "$analyst" "$reason" <<'PY'
import json
import sys

output_file, date_iso, analyst, reason = sys.argv[1:5]
payload = {
    "date": date_iso,
    "analyst": analyst,
    "status": "degraded",
    "reason": reason,
    "findings": [],
}
if analyst == "opus":
    payload["external_threats"] = []
with open(output_file, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, indent=2)
    fh.write("\n")
PY
}

record_phase() {
  local phase="$1"
  local status="$2"
  local note="${3:-}"
  printf '%s\t%s\t%s\n' "$phase" "$status" "${note//$'\t'/ }" >> "$PHASE_STATUS_FILE"
}

can_run_binary() {
  command -v "$1" >/dev/null 2>&1
}

require_var "AUDIT_DIR"

AUDIT_DIR="$(resolve_path "${AUDIT_DIR}")"
HISTORY_FILE="$(resolve_path "${HISTORY_FILE:-history/summaries.jsonl}")"
HOSTNAME_LABEL="${HOSTNAME_LABEL:-$(hostname -s 2>/dev/null || uname -n)}"
CLAUDE_CLI="${CLAUDE_CLI:-claude}"
CODEX_CLI="${CODEX_CLI:-codex}"
CLAUDE_MODEL_INTEL="${CLAUDE_MODEL_INTEL:-opus}"
CLAUDE_MODEL_MERGE="${CLAUDE_MODEL_MERGE:-sonnet}"
CODEX_MODEL="${CODEX_MODEL:-o3}"
MAX_TURNS_INTEL="${MAX_TURNS_INTEL:-12}"
MAX_TURNS_MERGE="${MAX_TURNS_MERGE:-8}"
ENABLE_THREAT_INTEL="${ENABLE_THREAT_INTEL:-true}"
ENABLE_FORENSIC_AUDIT="${ENABLE_FORENSIC_AUDIT:-true}"
ENABLE_MERGE_REPORT="${ENABLE_MERGE_REPORT:-true}"
ENABLE_NOTIFICATIONS="${ENABLE_NOTIFICATIONS:-false}"

export AUDIT_DIR HISTORY_FILE HOSTNAME_LABEL

mkdir -p "$AUDIT_DIR" "$(dirname "$HISTORY_FILE")"

TODAY="$(python_date '%Y%m%d' 0)"
TODAY_ISO="$(python_date '%Y-%m-%d' 0)"
YESTERDAY="$(python_date '%Y%m%d' -1)"
YESTERDAY_ISO="$(python_date '%Y-%m-%d' -1)"
OUT="${AUDIT_DIR}/${TODAY}"
PHASE_STATUS_FILE="${OUT}/phase-status.tsv"

SCAN_ONLY=false
SKIP_SCAN=false
for arg in "$@"; do
  case "$arg" in
    --scan-only) SCAN_ONLY=true ;;
    --skip-scan) SKIP_SCAN=true ;;
    *) echo "[sentinel] WARNING: unknown argument ignored: $arg" ;;
  esac
done

mkdir -p "$OUT"
printf 'phase\tstatus\tnote\n' > "$PHASE_STATUS_FILE"

echo "============================================"
echo " Sentinel — ${HOSTNAME_LABEL} — ${TODAY_ISO}"
echo "============================================"

if [ "$SKIP_SCAN" = false ]; then
  echo ""
  echo "[Phase 1] Running deterministic scanner..."
  if bash "${SCRIPT_DIR}/scanner/scan.sh"; then
    record_phase "scanner" "ok" "scan completed"
  else
    record_phase "scanner" "failed" "scanner exited with error"
    echo "[sentinel] ERROR: scanner failed."
    exit 1
  fi
else
  record_phase "scanner" "skipped" "reusing existing artifacts"
fi

if [ "$SCAN_ONLY" = true ]; then
  echo "[sentinel] Scan-only mode. Stopping."
  exit 0
fi

if [ ! -f "${OUT}/scan-summary.json" ]; then
  echo "[sentinel] ERROR: ${OUT}/scan-summary.json not found."
  exit 1
fi

PROMPT_INTEL="$(cat "${SCRIPT_DIR}/prompts/threat-intel.md")"
PROMPT_INTEL="${PROMPT_INTEL//\{\{AUDIT_DIR\}\}/${AUDIT_DIR}}"
PROMPT_INTEL="${PROMPT_INTEL//\{\{TODAY\}\}/${TODAY}}"
PROMPT_INTEL="${PROMPT_INTEL//\{\{HOSTNAME_LABEL\}\}/${HOSTNAME_LABEL}}"

PROMPT_FORENSIC="$(cat "${SCRIPT_DIR}/prompts/forensic-audit.md")"
PROMPT_FORENSIC="${PROMPT_FORENSIC//\{\{AUDIT_DIR\}\}/${AUDIT_DIR}}"
PROMPT_FORENSIC="${PROMPT_FORENSIC//\{\{TODAY\}\}/${TODAY}}"
PROMPT_FORENSIC="${PROMPT_FORENSIC//\{\{HOSTNAME_LABEL\}\}/${HOSTNAME_LABEL}}"
PROMPT_FORENSIC="${PROMPT_FORENSIC//\{\{YESTERDAY\}\}/${YESTERDAY}}"

PROMPT_MERGE="$(cat "${SCRIPT_DIR}/prompts/merge-report.md")"
PROMPT_MERGE="${PROMPT_MERGE//\{\{AUDIT_DIR\}\}/${AUDIT_DIR}}"
PROMPT_MERGE="${PROMPT_MERGE//\{\{TODAY\}\}/${TODAY}}"
PROMPT_MERGE="${PROMPT_MERGE//\{\{YESTERDAY\}\}/${YESTERDAY}}"
PROMPT_MERGE="${PROMPT_MERGE//\{\{HOSTNAME_LABEL\}\}/${HOSTNAME_LABEL}}"
PROMPT_MERGE="${PROMPT_MERGE//\{\{TODAY_ISO\}\}/${TODAY_ISO}}"
PROMPT_MERGE="${PROMPT_MERGE//\{\{YESTERDAY_ISO\}\}/${YESTERDAY_ISO}}"

echo ""
echo "[Phase 2] Threat intelligence..."
if [ "$ENABLE_THREAT_INTEL" != "true" ]; then
  write_findings_stub "${OUT}/opus-findings.json" "opus" "phase disabled by configuration"
  record_phase "threat-intel" "skipped" "disabled"
elif ! can_run_binary "$CLAUDE_CLI"; then
  write_findings_stub "${OUT}/opus-findings.json" "opus" "claude cli not available"
  record_phase "threat-intel" "skipped" "claude cli missing"
else
  if "${CLAUDE_CLI}" -p "${PROMPT_INTEL}" \
    --allowedTools "Bash(readonly:true),WebSearch,WebFetch,Read,Write" \
    --model "${CLAUDE_MODEL_INTEL}" \
    --max-turns "${MAX_TURNS_INTEL}" \
    > >(tee "${OUT}/opus-phase.log") 2>&1; then
    if [ -s "${OUT}/opus-findings.json" ]; then
      record_phase "threat-intel" "ok" "findings created"
    else
      write_findings_stub "${OUT}/opus-findings.json" "opus" "command completed without writing findings"
      record_phase "threat-intel" "degraded" "missing findings output"
    fi
  else
    write_findings_stub "${OUT}/opus-findings.json" "opus" "command failed, likely oauth/session issue or tool restriction"
    record_phase "threat-intel" "failed" "claude phase error"
  fi
fi

echo ""
echo "[Phase 3] Forensic audit..."
if [ "$ENABLE_FORENSIC_AUDIT" != "true" ]; then
  write_findings_stub "${OUT}/codex-findings.json" "codex" "phase disabled by configuration"
  record_phase "forensic-audit" "skipped" "disabled"
elif ! can_run_binary "$CODEX_CLI"; then
  write_findings_stub "${OUT}/codex-findings.json" "codex" "codex cli not available"
  record_phase "forensic-audit" "skipped" "codex cli missing"
else
  if "${CODEX_CLI}" --model "${CODEX_MODEL}" --full-auto "${PROMPT_FORENSIC}" \
    > >(tee "${OUT}/codex-phase.log") 2>&1; then
    if [ -s "${OUT}/codex-findings.json" ]; then
      record_phase "forensic-audit" "ok" "findings created"
    else
      write_findings_stub "${OUT}/codex-findings.json" "codex" "command completed without writing findings"
      record_phase "forensic-audit" "degraded" "missing findings output"
    fi
  else
    write_findings_stub "${OUT}/codex-findings.json" "codex" "command failed, likely oauth/session issue or sandbox restriction"
    record_phase "forensic-audit" "failed" "codex phase error"
  fi
fi

echo ""
echo "[Phase 4] Merge and report..."
if [ "$ENABLE_MERGE_REPORT" != "true" ]; then
  record_phase "merge-report" "skipped" "disabled"
elif ! can_run_binary "$CLAUDE_CLI"; then
  record_phase "merge-report" "skipped" "claude cli missing"
else
  if "${CLAUDE_CLI}" -p "${PROMPT_MERGE}" \
    --allowedTools "Read,Write" \
    --model "${CLAUDE_MODEL_MERGE}" \
    --max-turns "${MAX_TURNS_MERGE}" \
    > >(tee "${OUT}/merge-phase.log") 2>&1; then
    if [ -s "${OUT}/summary.json" ] && [ -s "${OUT}/report.md" ]; then
      record_phase "merge-report" "ok" "report created"
    else
      record_phase "merge-report" "degraded" "missing report or summary output"
    fi
  else
    record_phase "merge-report" "failed" "claude merge phase error"
  fi
fi

echo ""
echo "[Phase 5] Storing local history..."
if [ -f "${OUT}/summary.json" ]; then
  if python3 "${SCRIPT_DIR}/lib/store.py" store "${OUT}/summary.json"; then
    record_phase "history-store" "ok" "summary stored"
  else
    record_phase "history-store" "failed" "summary store failed"
    echo "[sentinel] WARNING: local history store failed."
  fi
else
  record_phase "history-store" "skipped" "no summary generated"
fi

echo ""
echo "[Phase 6] Notification..."
if [ "$ENABLE_NOTIFICATIONS" != "true" ]; then
  record_phase "notify" "skipped" "disabled"
elif [ -f "${OUT}/report.md" ]; then
  if bash "${SCRIPT_DIR}/lib/notify.sh" "${OUT}/report.md"; then
    record_phase "notify" "ok" "notification sent"
  else
    record_phase "notify" "failed" "notification failed"
    echo "[sentinel] WARNING: notification failed."
  fi
else
  record_phase "notify" "skipped" "no report generated"
fi

echo ""
echo "[sentinel] Output directory: ${OUT}"
echo "[sentinel] Phase status: ${PHASE_STATUS_FILE}"
echo "============================================"
echo " Sentinel complete — $(date -Iseconds 2>/dev/null || date)"
echo "============================================"
