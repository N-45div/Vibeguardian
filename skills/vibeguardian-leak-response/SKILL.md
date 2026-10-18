---
name: vibeguardian-leak-response
description: Respond to a leaked Google Cloud API key without breaking production and without ever reading the key. Use when secret detection flags a Google API key (AIza...) in a commit, merge request, or pull request, or when someone reports that a key leaked.
---

# Leaked Google API key response

A leaked key is only handled when Google rejects it. Deleting it from the
code, or even deleting it in the console, is not proof: tokens and caches
can keep it working. Follow these steps in order.

## Hard rules

- Never read, print, paste, or reconstruct a key value. Work with
  fingerprints only (`sha256:` plus 12 hex characters). If a file shows a
  placeholder like `VIBEGUARDIAN_REDACTED_<hex>`, that placeholder stands for
  the key: leave the value alone and fix the code around it.
- Do not fetch the leaking file from the repository API or from git history.
- Never claim a key is dead unless the proof step says so.
- Roll out the replacement before retiring the old key. If any health check
  fails, stop: the old key stays, and a human decides.

## Steps

1. **Retire** (needs a Google identity with API Keys, Secret Manager and
   Cloud Run rights; in CI use keyless Workload Identity Federation):

   ```bash
   vg respond --project "$GCP_PROJECT_ID" --incident incident.json
   ```

   For each leaked key it finds its owner, every Secret Manager secret that
   holds it and every Cloud Run service that reads those secrets, creates a
   replacement with the same restrictions, rolls each service onto it, checks
   each service now serves the replacement's fingerprint, and only then
   deletes the old key. On any failure it rolls back.

2. **Prove**, from a job with no cloud identity:

   ```bash
   vg prove-leaks --incident incident.json --proof proof.json
   ```

   It recovers the leaked values from the repository itself and probes Google
   until the old key is rejected 12 times in a row. Its `state` is one of
   `proven_dead`, `rejected_not_yet_proven`, `alive`, `unknown`.

3. **Gate**:

   ```bash
   vg gate --incident incident.json --proof proof.json
   ```

   Fails while a leaked key is still in the current code or is not proven
   dead. A key that is only in history and proven dead passes: no history
   rewrite is needed.

4. **Write the incident** from `incident.json` and `proof.json` only: what
   leaked (fingerprint, file, line, commit), the outcome, a timeline, which
   services were rolled and their health, and the proof. If retirement
   failed, say so in the title and list what a human must do.

5. **Fix the code** in a merge request or pull request: remove the key and
   read it from the environment or Secret Manager instead (better: move the
   service to keyless identity). Link the incident and close it on merge.

## Platforms

- **GitLab:** `.gitlab-ci.yml` runs GitLab secret detection, then
  respond / prove / gate. The `flows/leak-incident.yml` Duo flow does steps 4
  and 5 when the pipeline fails, and `.gitlab/duo/redact-google-keys.sh` runs
  before any agent starts so no agent sees a key.
- **GitHub:** run the same three `vg` commands in a GitHub Actions workflow
  with OIDC to Google, feeding it a gitleaks or secret scanning report in the
  same format.
