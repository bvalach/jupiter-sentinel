#!/usr/bin/env bash
# ============================================================
# Sentinel — Telegram notification
# Sends the report as plain text to avoid markdown escaping issues.
# ============================================================
set -euo pipefail

REPORT="${1:?Usage: notify.sh /path/to/report.md}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/../.env"

if [ -z "${TELEGRAM_BOT_TOKEN:-}" ] || [ -z "${TELEGRAM_CHAT_ID:-}" ]; then
  echo "[notify] Telegram not configured. Skipping."
  exit 0
fi

CONTENT="$(cat "$REPORT")"
MAX_LEN=3900

if [ ${#CONTENT} -le $MAX_LEN ]; then
  curl -fsS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
    -d chat_id="${TELEGRAM_CHAT_ID}" \
    -d text="${CONTENT}" > /dev/null
else
  PART=1
  while [ ${#CONTENT} -gt 0 ]; do
    CHUNK="${CONTENT:0:$MAX_LEN}"
    CONTENT="${CONTENT:$MAX_LEN}"
    curl -fsS -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
      -d chat_id="${TELEGRAM_CHAT_ID}" \
      -d text="(${PART}) ${CHUNK}" > /dev/null
    PART=$((PART + 1))
    sleep 1
  done
fi

echo "[notify] Report sent to Telegram."
