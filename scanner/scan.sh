#!/usr/bin/env bash
# ============================================================
# Sentinel — Phase 1: Deterministic scanner
# Collects local evidence and writes structured summaries.
# Models read the summary and audit artifacts, not the live host.
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

if [ ! -f "$ENV_FILE" ]; then
  echo "[sentinel] ERROR: .env not found."
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
    printf '%s/%s\n' "$ROOT_DIR" "$raw_path"
  fi
}

python_date() {
  local fmt="$1"
  local offset_days="${2:-0}"
  python3 -c "from datetime import datetime, timedelta; print((datetime.now() + timedelta(days=${offset_days})).strftime('${fmt}'))"
}

record_status() {
  local check="$1"
  local status="$2"
  local artifact="$3"
  local note="${4:-}"
  printf '%s\t%s\t%s\t%s\n' "$check" "$status" "$artifact" "${note//$'\t'/ }" >> "$STATUS_FILE"
}

run_capture() {
  local check="$1"
  local artifact="$2"
  shift 2
  mkdir -p "$(dirname "$artifact")"
  if "$@" >"$artifact" 2>"${artifact}.stderr"; then
    record_status "$check" "ok" "$artifact"
  else
    local exit_code=$?
    record_status "$check" "error:${exit_code}" "$artifact" "see ${artifact}.stderr"
  fi
}

run_capture_allow_exit_codes() {
  local check="$1"
  local artifact="$2"
  local allowed_codes="$3"
  shift 3
  mkdir -p "$(dirname "$artifact")"
  set +e
  "$@" >"$artifact" 2>"${artifact}.stderr"
  local exit_code=$?
  set -e
  if [[ ",${allowed_codes}," == *",${exit_code},"* ]]; then
    record_status "$check" "ok" "$artifact"
  else
    record_status "$check" "error:${exit_code}" "$artifact" "see ${artifact}.stderr"
  fi
}

record_skip() {
  local check="$1"
  local artifact="$2"
  local note="$3"
  record_status "$check" "skipped" "$artifact" "$note"
}

AUDIT_DIR="$(resolve_path "${AUDIT_DIR}")"
TODAY="$(python_date '%Y%m%d' 0)"
TODAY_ISO="$(python_date '%Y-%m-%d' 0)"
OUT="${AUDIT_DIR}/${TODAY}"
RAW_DIR="${OUT}/raw"
STATUS_FILE="${OUT}/command-status.tsv"
OS_NAME="$(uname -s | tr '[:upper:]' '[:lower:]')"

HOSTNAME_LABEL="${HOSTNAME_LABEL:-$(hostname -s 2>/dev/null || uname -n)}"
RUN_NETWORK_AUDITS="${RUN_NETWORK_AUDITS:-false}"
DEBIAN_SUITE="${DEBIAN_SUITE:-auto}"
CHECKSUM_FILES="${CHECKSUM_FILES:-/etc/passwd:/etc/group:/etc/sudoers:/etc/ssh/sshd_config}"
SUID_SCAN_PATHS="${SUID_SCAN_PATHS:-/}"
WORLD_WRITABLE_PATHS="${WORLD_WRITABLE_PATHS:-/etc:/usr/local:/opt}"

mkdir -p "$RAW_DIR"
printf 'check\tstatus\tartifact\tnote\n' > "$STATUS_FILE"

echo "[sentinel] Phase 1: scanning ${HOSTNAME_LABEL} — ${TODAY_ISO}"

printf '%s\n' "${HOSTNAME_LABEL}" > "${RAW_DIR}/hostname.txt"
printf '%s\n' "${OS_NAME}" > "${RAW_DIR}/os-family.txt"

run_capture "system.uname" "${RAW_DIR}/uname.txt" uname -a
run_capture "system.identity" "${RAW_DIR}/id.txt" id

PROJECT_PATHS_RESOLVED=""
IFS=',' read -r -a PROJECT_PATH_ARRAY <<< "${PROJECT_PATHS:-}"
for raw_project in "${PROJECT_PATH_ARRAY[@]}"; do
  [ -z "$raw_project" ] && continue
  resolved_project="$(resolve_path "$raw_project")"
  if [ -z "$PROJECT_PATHS_RESOLVED" ]; then
    PROJECT_PATHS_RESOLVED="$resolved_project"
  else
    PROJECT_PATHS_RESOLVED="${PROJECT_PATHS_RESOLVED},${resolved_project}"
  fi
done
printf '%s\n' "${PROJECT_PATHS_RESOLVED}" > "${RAW_DIR}/project-paths.txt"

if [ "$OS_NAME" = "linux" ] && command -v apt >/dev/null 2>&1; then
  run_capture "packages.apt_upgradable" "${RAW_DIR}/apt-upgradable.txt" bash -lc "apt list --upgradable 2>&1"
else
  record_skip "packages.apt_upgradable" "${RAW_DIR}/apt-upgradable.txt" "apt not available on this host"
fi

if [ "$OS_NAME" = "linux" ]; then
  if [ "$DEBIAN_SUITE" = "auto" ] && command -v lsb_release >/dev/null 2>&1; then
    DEBIAN_SUITE="$(lsb_release -cs)"
  fi
  if command -v debsecan >/dev/null 2>&1; then
    run_capture "packages.debsecan" "${RAW_DIR}/debsecan.txt" debsecan --suite "${DEBIAN_SUITE}"
  else
    record_skip "packages.debsecan" "${RAW_DIR}/debsecan.txt" "debsecan not installed"
  fi
elif [ "$OS_NAME" = "darwin" ] && command -v brew >/dev/null 2>&1; then
  run_capture "packages.brew_outdated" "${RAW_DIR}/brew-outdated.json" brew outdated --json=v2
else
  record_skip "packages.generic" "${RAW_DIR}/packages.txt" "no package scanner configured for this host"
fi

if command -v ss >/dev/null 2>&1; then
  run_capture "network.listeners" "${RAW_DIR}/open-ports.txt" ss -lntupH
elif command -v lsof >/dev/null 2>&1; then
  run_capture "network.listeners" "${RAW_DIR}/open-ports.txt" lsof -nP -iTCP -sTCP:LISTEN
else
  record_skip "network.listeners" "${RAW_DIR}/open-ports.txt" "neither ss nor lsof is available"
fi

if [ "$OS_NAME" = "linux" ] && command -v journalctl >/dev/null 2>&1; then
  run_capture "auth.failed_logins" "${RAW_DIR}/failed-logins.txt" bash -lc \
    "journalctl --since '24 hours ago' --no-pager 2>/dev/null | grep -iE 'failed password|invalid user|authentication failure|refused connect' || true"
elif [ "$OS_NAME" = "linux" ] && [ -f /var/log/auth.log ]; then
  run_capture "auth.failed_logins" "${RAW_DIR}/failed-logins.txt" bash -lc \
    "grep -iE 'failed password|invalid user|authentication failure|refused connect' /var/log/auth.log | tail -200 || true"
else
  record_skip "auth.failed_logins" "${RAW_DIR}/failed-logins.txt" "no supported auth log source"
fi

CHECKSUM_CMD=""
if command -v sha256sum >/dev/null 2>&1; then
  CHECKSUM_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  CHECKSUM_CMD="shasum -a 256"
fi

if [ -n "$CHECKSUM_CMD" ]; then
  > "${RAW_DIR}/checksum-targets.txt"
  IFS=':' read -r -a CHECKSUM_ARRAY <<< "$CHECKSUM_FILES"
  for target in "${CHECKSUM_ARRAY[@]}"; do
    [ -e "$target" ] && printf '%s\n' "$target" >> "${RAW_DIR}/checksum-targets.txt"
  done
  if [ -s "${RAW_DIR}/checksum-targets.txt" ]; then
    run_capture "integrity.checksums" "${RAW_DIR}/checksums.txt" bash -lc \
      "${CHECKSUM_CMD} \$(cat '${RAW_DIR}/checksum-targets.txt') 2>&1"
    YESTERDAY_DIR="${AUDIT_DIR}/$(python_date '%Y%m%d' -1)"
    if [ -f "${YESTERDAY_DIR}/raw/checksums.txt" ]; then
      run_capture_allow_exit_codes "integrity.diff" "${RAW_DIR}/integrity-diff.txt" "0,1" \
        diff "${YESTERDAY_DIR}/raw/checksums.txt" "${RAW_DIR}/checksums.txt"
    else
      record_skip "integrity.diff" "${RAW_DIR}/integrity-diff.txt" "no checksum baseline from yesterday"
    fi
  else
    record_skip "integrity.checksums" "${RAW_DIR}/checksums.txt" "no checksum targets exist on this host"
    record_skip "integrity.diff" "${RAW_DIR}/integrity-diff.txt" "no checksum baseline from yesterday"
  fi
else
  record_skip "integrity.checksums" "${RAW_DIR}/checksums.txt" "no sha256 utility available"
fi

if command -v docker >/dev/null 2>&1; then
  run_capture "docker.images" "${RAW_DIR}/docker-images.jsonl" docker images --format '{{json .}}'
  run_capture "docker.ps" "${RAW_DIR}/docker-ps.jsonl" docker ps -a --format '{{json .}}'
  container_ids="$(docker ps -aq 2>/dev/null || true)"
  if [ -n "$container_ids" ]; then
    run_capture "docker.inspect" "${RAW_DIR}/docker-inspect.json" docker inspect ${container_ids}
  else
    record_skip "docker.inspect" "${RAW_DIR}/docker-inspect.json" "no containers found"
  fi
else
  record_skip "docker.images" "${RAW_DIR}/docker-images.jsonl" "docker not installed"
  record_skip "docker.ps" "${RAW_DIR}/docker-ps.jsonl" "docker not installed"
  record_skip "docker.inspect" "${RAW_DIR}/docker-inspect.json" "docker not installed"
fi

if [ "$RUN_NETWORK_AUDITS" = "true" ] && command -v npm >/dev/null 2>&1; then
  record_status "projects.npm_audit" "skipped" "${RAW_DIR}/npm-audit.txt" "site-specific network audit left to local adaptation"
else
  record_skip "projects.npm_audit" "${RAW_DIR}/npm-audit.txt" "disabled by default for deterministic public prototype"
fi

if [ "$RUN_NETWORK_AUDITS" = "true" ] && command -v pip-audit >/dev/null 2>&1; then
  record_status "projects.pip_audit" "skipped" "${RAW_DIR}/pip-audit.txt" "site-specific network audit left to local adaptation"
else
  record_skip "projects.pip_audit" "${RAW_DIR}/pip-audit.txt" "disabled by default for deterministic public prototype"
fi

run_capture "filesystem.suid_sgid" "${RAW_DIR}/suid-sgid.txt" bash -lc \
  "find ${SUID_SCAN_PATHS//:/ } -xdev -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null | sort"
run_capture "processes.root" "${RAW_DIR}/root-processes.txt" bash -lc "ps aux 2>/dev/null | awk '\$1 == \"root\" || NR == 1'"
run_capture "filesystem.world_writable" "${RAW_DIR}/world-writable.txt" bash -lc \
  "find ${WORLD_WRITABLE_PATHS//:/ } -xdev -type f -perm -0002 2>/dev/null | sort"

if command -v nft >/dev/null 2>&1; then
  run_capture "network.firewall" "${RAW_DIR}/firewall.txt" nft list ruleset
elif command -v iptables >/dev/null 2>&1; then
  run_capture "network.firewall" "${RAW_DIR}/firewall.txt" iptables -L -n
else
  record_skip "network.firewall" "${RAW_DIR}/firewall.txt" "no supported firewall command detected"
fi

if command -v sshd >/dev/null 2>&1; then
  run_capture "ssh.effective" "${RAW_DIR}/sshd-effective.txt" sshd -T
elif [ -f /etc/ssh/sshd_config ]; then
  run_capture "ssh.config" "${RAW_DIR}/sshd-config.txt" grep -iE \
    '^(PermitRootLogin|PasswordAuthentication|MaxAuthTries|X11Forwarding|AllowTcpForwarding)' /etc/ssh/sshd_config
else
  record_skip "ssh.effective" "${RAW_DIR}/sshd-effective.txt" "no sshd data source available"
fi

if command -v crontab >/dev/null 2>&1; then
  run_capture_allow_exit_codes "cron.user" "${RAW_DIR}/crontab-user.txt" "0,1" crontab -l
else
  record_skip "cron.user" "${RAW_DIR}/crontab-user.txt" "crontab not installed"
fi

if [ -d /etc ]; then
  run_capture "cron.system" "${RAW_DIR}/cron-system.txt" bash -lc \
    "find /etc -maxdepth 2 \\( -path '/etc/crontab' -o -path '/etc/cron.d/*' -o -path '/etc/cron.daily/*' -o -path '/etc/cron.weekly/*' -o -path '/etc/cron.monthly/*' \\) -type f -print 2>/dev/null | sort"
else
  record_skip "cron.system" "${RAW_DIR}/cron-system.txt" "system cron directories not present"
fi

echo "[sentinel] Building scan summary..."
python3 "${ROOT_DIR}/lib/build_scan_summary.py" "${OUT}"

echo "[sentinel] Phase 1 complete. Output: ${OUT}"
