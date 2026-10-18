#!/usr/bin/env bash
# Hit the demo app's /health once a second and log status, key fingerprint,
# and revision, so a rollout's failed requests can be counted.
# Usage: demo/load.sh <service-url> <seconds> <out-file>
set -u
URL="$1"
SECONDS_TOTAL="$2"
OUT="$3"
end=$(( $(date +%s) + SECONDS_TOTAL ))
while [ "$(date +%s)" -lt "$end" ]; do
  body=$(curl -s -m 10 -w ' %{http_code}' "$URL/health" | tr -d '\n')
  printf '%s %s\n' "$(date +%s)" "$body" >> "$OUT"
  sleep 1
done
