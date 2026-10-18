#!/usr/bin/env bash
# Measure how fast each cut-off method stops a token stolen before its key
# was disabled. Runs the three methods one after another on a throwaway
# service account and writes one event log per method.
# Usage: demo/cutoff-runs.sh <project-id> <throwaway-sa-email> <out-dir>
set -u
PROJECT="$1"
SA="$2"
OUT="$3"
CHECK="https://cloudresourcemanager.googleapis.com/v1/projects/$PROJECT"
mkdir -p "$OUT"
for method in disable-sa remove-roles; do  # deny policies need a Google Cloud organization
  echo "=== $method $(date -u +%H:%M:%S)"
  vg cutoff --project "$PROJECT" --service-account "$SA" --method "$method" \
    --check-url "$CHECK" --interval 10 --stable 3 --max-minutes 20 \
    --out "$OUT/cutoff-$method.jsonl" | grep -E '"event": "(summary|cutoff_applied|cutoff_undone|never_minted)"'
done
echo "=== done $(date -u +%H:%M:%S)"
