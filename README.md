# VibeGuardian

Retires leaked Google Cloud keys and proves them dead.

When a key leaks, GitLab finds it. VibeGuardian rolls out a replacement,
retires the old key, and keeps testing the old key until Google itself
rejects it. Every incident ends with a measured **time-to-dead**.

> Status: in active development for the GitLab Transcend "Life After Code"
> hackathon (October 2026).

## Why "proves them dead"

Deleting a Google API key does not stop it working straight away. Independent
tests in May 2026 saw deleted keys keep working for 8 to 23 minutes, with
results that differ by region. A record that says "deleted" is not proof.
VibeGuardian treats Google's own response as the only proof: an incident
closes when the old key is rejected, repeatedly, from more than one place.

## Rules the code follows

- A secret value never enters logs, issues, merge requests, or the AI
  agent's context. Only a fingerprint (`sha256:` plus 12 hex characters) does.
- The replacement is rolled out and health-checked before the old key is
  retired. If any check fails, the old key stays and a human is called in.
- The agent that does the work never marks it done. Google's answer does.

## License

MIT. See [LICENSE](LICENSE).
