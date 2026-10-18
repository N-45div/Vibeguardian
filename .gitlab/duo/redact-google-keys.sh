#!/usr/bin/env bash
# Runs before any Duo flow in this project starts (setup_script in
# agent-config.yml), so no agent ever reads a Google API key.
#
# 1. If the flow was started by a pipeline event, check out that pipeline's
#    branch (the flow's own checkout is the default branch).
# 2. Replace every Google API key in tracked files with a placeholder that
#    names its fingerprint: VIBEGUARDIAN_REDACTED_<12 hex>.
# 3. List each replacement in .vibeguardian/redactions.txt as
#    "<file>:<line> sha256:<12 hex>".
#
# It prints fingerprints only. If anything goes wrong it exits non-zero, so
# the flow does not start with secrets in its checkout (fail closed).
set -euo pipefail

# Classic keys ("AIza" + 35) and authorization keys ("AQ." + 50, ending in
# A, Q, g or w). A key must not touch another key character on either side
# (ERE has no lookaround, so match the edges).
KEY_RE='(AIza[0-9A-Za-z_-]{35}|AQ\.[0-9A-Za-z_-]{49}[AQgw])'
EDGE='[^0-9A-Za-z_-]'
BOUNDED_RE="(^|${EDGE})${KEY_RE}(${EDGE}|\$)"
out_dir=".vibeguardian"
out="$out_dir/redactions.txt"
mkdir -p "$out_dir"
: > "$out"

# 1. Pipeline-triggered flows: the goal is the pipeline event JSON.
ref=$(printf '%s' "${DUO_WORKFLOW_GOAL:-}" | grep -o '"ref":"[^"]*"' | head -n 1 | cut -d'"' -f4 || true)
if [ -n "$ref" ] && [ "$ref" != "$(git rev-parse --abbrev-ref HEAD)" ]; then
  if git fetch --quiet origin "$ref" 2>/dev/null; then
    git checkout --quiet --detach FETCH_HEAD
    echo "VibeGuardian: checked out pipeline branch $ref"
  else
    echo "VibeGuardian: could not fetch $ref; redacting the current checkout"
  fi
fi
printf '%s\n' "${ref:-$(git rev-parse --abbrev-ref HEAD)}" > "$out_dir/ref.txt"

# 2 and 3. Redact.
files=$(git grep -lIE "$BOUNDED_RE" -- . || true)
count=0
for file in $files; do
  keys=$( (grep -oE "$BOUNDED_RE" "$file" || true) | grep -oE "$KEY_RE" | sort -u || true)
  for key in $keys; do
    hex=$(printf '%s' "$key" | sha256sum | cut -c1-12)
    placeholder="VIBEGUARDIAN_REDACTED_${hex}"
    literal=$(printf '%s' "$key" | sed 's/\./\\./g')  # the "." in AQ. keys is literal
    sed -i -E "s/(^|${EDGE})${literal}(${EDGE}|\$)/\1${placeholder}\2/g" "$file"
    for line in $(grep -n "$placeholder" "$file" | cut -d: -f1); do
      printf '%s:%s sha256:%s\n' "$file" "$line" "$hex" >> "$out"
      count=$((count + 1))
    done
  done
done

# Verify nothing slipped through before handing over to the agent.
if git grep -qIE "$BOUNDED_RE" -- .; then
  echo "VibeGuardian: a Google API key is still present after redaction; refusing to start" >&2
  exit 1
fi
echo "VibeGuardian: redacted $count Google API key occurrence(s); details in $out"
