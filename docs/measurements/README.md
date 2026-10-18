# Measurements

Every number VibeGuardian quotes comes from a run recorded here. Raw event
logs are in [`raw/`](raw/). They hold key fingerprints and resource names,
never key values.

Runs up to 2026-10-15 probe from one place: a laptop in India, or a GitLab
runner. From 2026-10-16 the CI prover also asks from four other regions (see
"Proving a key dead from several places").

## Deleted API keys

How: `vg time-to-dead`. Create a key restricted to the Gemini API, wait until
Google accepts it, optionally use it (warm-up), delete it, then probe with a
read-only `models.list` call until Google rejects it on N probes in a row.
Dead means Google answered `400 API_KEY_INVALID`.

| Date (UTC) | Run | Warm-up calls | Rejected at first probe | Came back alive after delete | Rejected for good from | Probes after delete |
|---|---|---|---|---|---|---|
| 2026-10-11 | [cold](raw/2026-10-11-api-key-cold.jsonl) | 0 | yes (0 s) | no | 0 s | 6 over 66 s |
| 2026-10-11 | [warm](raw/2026-10-11-api-key-warm.jsonl) | 40 over ~3 min | yes (0 s) | **yes, at 25 s (HTTP 200)** | 34 s | 28 over 221 s |

What this shows so far:

- A deleted key was rejected immediately, then **accepted again 25 seconds
  later** after it had been in use. One rejection is not proof that a key is
  dead.
- We did not reproduce the 8 to 23 minute windows reported in May 2026 from
  other regions. Two runs from one place are not enough to say either way.

## Retiring a live key with no downtime

How: the demo app (`demo/app`) runs on Cloud Run and reads its Gemini key
from Secret Manager. We treat that key as leaked and run `vg retire`, while
`demo/load.sh` calls the app's `/health` once a second. Then `vg prove`
probes the old key until Google rejects it 12 times in a row.

| Date (UTC) | Run | Leak to retired | Requests while it ran | Failed | Old key proof |
|---|---|---|---|---|---|
| 2026-10-11 | [retire](raw/2026-10-11-retire-live.jsonl), [incident](raw/2026-10-11-incident-live.json), [load](raw/2026-10-11-retire-load.log), [prove](raw/2026-10-11-prove-live.jsonl) | 52 s | 124 over 248 s, from 12 s before the incident to after the proof | **0** | dead on 12 of 12 probes, 0 flaps |

Timeline of that run (seconds after the key was identified):

| t | Step |
|---|---|
| 0 | Leaked value looked up: key `9749a1b9…` (`sha256:88e943394b81`) |
| 9 | Found its holder (`gemini-api-key` v1) and consumer (Cloud Run `vg-demo`) |
| 15 | Replacement created with the same restrictions (`sha256:aae006dfde32`) |
| 27 | Google accepts the replacement |
| 31 | Secret version 2 added |
| 40 | First request served by the new revision with the new key |
| 48 | `/health` confirms the new revision serves the new fingerprint |
| 51 | Old key deleted |
| 52 | Old secret version disabled |

The traffic switched to the new key about 10 seconds before the old key was
deleted, which is the order that keeps users from seeing errors.

The load log's lines put the status code on the line after the body. The
script that wrote it was fixed afterwards. That edit was made while the
script was still running, which stopped it with a syntax error after the
logged window; the 124 requests above are everything it recorded.

## Hands-off in GitLab CI: push a leak, touch nothing

How: push a commit that hardcodes the demo app's live Gemini key on a branch
(`leak-drill/5`, pipeline 2935774351). Nobody touches anything after the push.

| Step | Who | Result |
|---|---|---|
| Secret detection | GitLab's scanner | flagged `demo/app/main.py:31` |
| Retire | `leak-respond`, as the `vg-retirer` identity (no stored key) | **retired in 23.3 s**: replacement live at 9.2 s, Cloud Run healthy on the new fingerprint at 20.4 s, old key deleted at 22.9 s |
| Prove | `leak-prove`, **no cloud identity at all** | Google rejected the old key **12 of 12** times, 0 flaps, 57.5 s watched |
| Gate | `leak-gate` | red: the dead key is still in the code |
| Write-up and fix | GitLab Duo flow, started by the red pipeline | incident updated and fix MR opened about 2 minutes later |
| Users | `demo/load.sh`, one request a second | **315 requests, 315 OK**; traffic moved to the new key 4 s before the old key was deleted |

Raw: [incident](raw/2026-10-11-ci-drill5-incident.json), [respond log](raw/2026-10-11-ci-drill5-respond.jsonl),
[proof](raw/2026-10-11-ci-drill5-proof.json), [prove log](raw/2026-10-11-ci-drill5-prove.jsonl),
[load](raw/2026-10-11-ci-drill5-load.log).

Earlier drills found bugs and failed safe, which is what they are for:

- Drill 1: the CI identity could not get a token (a quota-project header is
  only valid for user logins). Nothing changed; the key stayed untouched.
- Drill 2: Google rejected the replacement's display name (over 63
  characters). The failure was recorded and nothing changed.
- Drill 3: the retire identity could not read the app's container image, so
  Cloud Run could not build the new revision. VibeGuardian rolled back: it
  disabled the new secret version, deleted the replacement key, and left the
  old key alone. The prover independently reported the key **not** dead, and
  the Duo flow's incident said so in its title. Users saw nothing: 924 of 924
  requests over the 25 minutes around the drill returned 200.

## Who used a key while it was public

Google counts every API call made with an API key, per key
(`credential_id = apikey:<uid>` on the Cloud Monitoring metric
`serviceruntime.googleapis.com/api/request_count`) and per Google region that
served it. `vg exposure` reads those counts from the leak commit to the moment
the key was deleted, and flags successful calls from regions where none of the
key's services run. In CI the `leak-exposure` job does this as `vg-watcher`,
an identity that can only read Cloud Monitoring. Counts come in one-minute
buckets, so the window's edges are rounded to the minute.

How fast calls show up: three calls from the laptop appeared after **63 s**
(polled every 30 s: nothing at 2 s or 33 s, all three at 63 s). Google
documents up to 30 minutes, so a report written sooner says it is partial and
when to check again. Raw: [log](raw/2026-10-15-metric-delay.log).

| Drill | Key public for | Calls from its service's region (us-central1) | Calls from anywhere else | Raw |
|---|---|---|---|---|
| 5, read afterwards | 80 s | 224 | **0** | [report](raw/2026-10-11-ci-drill5-exposure.json) |
| 7, in CI; the laptop played an outsider and called the key 5 times right after the push | 83 s | 0 | **5, all from asia-southeast1: flagged** | [report](raw/2026-10-15-ci-drill7-exposure.json), [incident](raw/2026-10-15-ci-drill7-incident.json), [proof](raw/2026-10-15-ci-drill7-proof.json) |
| 8, same as 7, on 2026-10-16 | 84 s | 0 | **5, all from asia-southeast1: flagged**; the complete counts 30 minutes later were the same | [report](raw/2026-10-16-ci-drill8-exposure.json), [complete](raw/2026-10-16-ci-drill8-exposure-complete.json), [incident](raw/2026-10-16-ci-drill8-incident.json), [proof](raw/2026-10-16-ci-drill8-proof.json) |

In drill 7 the key was retired in 25.8 s and Google rejected it 12 of 12
times. The Duo flow quoted the exposure report in the incident, said the
counts were partial, and listed the 5 calls under "Needs a human". Re-checked
after the 30-minute delay, the complete counts were the same: 5 calls, all from
asia-southeast1 ([complete report](raw/2026-10-15-ci-drill7-exposure-complete.json)).

The region is where Google served the call, which is near the caller, not the
caller's exact location. Treat it as a lead, not proof.

Drill 7 also found a bug, and it failed safe. The fix merge request's branch
still carried the leak in its history, so its pipelines ran the responder
again. Google still finds a deleted key for 30 days (it can be undeleted), so
the responder minted a replacement each time, found no consumers, and left two
unused live keys behind. Nothing serving users changed. The responder now
reads the key's `deleteTime` first and stops with `already_deleted`; rerun
against the same key, it made no new key. The two extra keys were deleted.
Raw: [one of those runs](raw/2026-10-15-fixer-branch-incident.json).

Drill 8 checked the fix in CI. Its fix branch's pipeline ran the responder on
the deleted key again, which stopped at once with `already_deleted`
("Google already deleted this key at 10:48:32"), and the project still had
exactly one key: the live replacement. Raw:
[the fix branch's run](raw/2026-10-16-ci-drill8-fix-branch-incident.json).

### Use, checks, and VibeGuardian's own probes (rules changed 2026-10-17)

Drill 11 found a false alarm. Its key was held for approval, so it stayed
live while VibeGuardian's prover, and the fix branch's pipelines, probed it
from the vantage regions. Counted afterwards, those 107 calls looked like
"used elsewhere". Google's counts record each call's method, and every one of
them was `ListModels`, the read-only call the probes make. Drill 13 then
showed the opposite gap: its outsider tried to generate content, Google
refused (the demo project's Gemini credit is used up), and the check, which
counted only successful calls, said nobody else used the key.

The rules now:

- **used_elsewhere**: any call from outside the key's service regions other
  than listing models, successful or refused. Google files a call under the
  key's id only once it has recognised the key, so a refused call still came
  from someone holding it.
- **checked_elsewhere**: no use, but model-list calls came from elsewhere
  before VibeGuardian began probing (the prover starts when the responder
  finishes). Someone found the key and tried it, as key scanners do.
- Model-list calls from elsewhere after probing began are reported as
  "likely VibeGuardian's own probes" and do not count. After a person
  approves a held retirement, every model-list call in the window counts as
  possibly ours, because the prover already checked the key during the hold.

Rerun on the recorded drills:

| Drill | Before | After |
|---|---|---|
| 7, 8 (outsider listed models 5 times, before any probe) | used_elsewhere | **checked_elsewhere**, 5 checks from asia-southeast1 |
| 11 (held, then approved) | used_elsewhere, 107 calls (false alarm) | no_use_elsewhere; 107 model-list calls reported as likely VibeGuardian's probes |
| 13 (outsider tried to generate content 5 times, all refused) | no_use_elsewhere (missed) | **used_elsewhere**, 5 calls from asia-southeast1, 0 succeeded |
| 10, 12 | no_use_elsewhere | no_use_elsewhere |

Raw: complete reports for drills
[10](raw/2026-10-17-ci-drill10-exposure-complete.json),
[11](raw/2026-10-17-ci-drill11-exposure-complete.json),
[12](raw/2026-10-17-ci-drill12-exposure-complete.json),
[13](raw/2026-10-17-ci-drill13-exposure-complete.json), and drill 13's
[incident](raw/2026-10-17-ci-drill13-incident.json).

## Incidents in GitLab Observability

The `leak-telemetry` job sends every incident to the project group's GitLab
Observability (OTLP over HTTP, no cloud identity): one trace per leaked key,
with a span for each retire step and one for the proof, exposure counts as
metrics, and each verdict as a log. Fingerprints and resource names only.
GitLab also exports each pipeline's own traces, metrics and logs.

| Run | What was sent | Result |
|---|---|---|
| Drill 7, sent afterwards from the laptop | 10 spans, exposure metrics, 2 logs | accepted; the trace showed in Observe > Traces with the steps in order (incident 26.1 s, proof 57.5 s) |
| Drill 8, from the `leak-telemetry` CI job | 10 spans, exposure metrics, 2 logs | accepted (HTTP 200 for traces, metrics and logs). Raw: [job output](raw/2026-10-16-ci-drill8-telemetry.log) |

In drill 8 the key was retired in 21.4 s (service rolled at 19.0 s) and Google
rejected it 12 of 12 times, with 0 flaps.

## Proving a key dead from several places

The prover asks Google from the CI runner and through `vg-vantage`, a private
Cloud Run service that CI builds, scans (GitLab Container Scanning) and
deploys to europe-west1, asia-northeast1, australia-southeast1 and
southamerica-east1. A key counts as proven dead only when every vantage that
answered saw Google reject it 12 times in a row. The prover's identity,
`vg-prover`, can only call those services. The services run as `vg-vantage`,
which has no roles, and refuse a caller without a Google sign-in (HTTP 403)
and anything that is not a Google API key (HTTP 400); both were checked on
all four after the first deploy.

Drill 9 (2026-10-16): retired in 22.9 s (service rolled at 20.4 s), then
proven dead from all 5 vantage points, 12 of 12 rejections each, 0 flaps,
60 of 60 overall, in 73.2 s. The Duo flow put a row per vantage in the
incident. Raw: [incident](raw/2026-10-16-ci-drill9-incident.json),
[proof](raw/2026-10-16-ci-drill9-proof.json),
[probe log](raw/2026-10-16-ci-drill9-prove.jsonl).

Where Google actually served those calls, from Cloud Monitoring's region for
the rejected requests. A second run sent 1, 2, 4 and 8 probes through the
four vantages so the totals decode uniquely:

| Vantage | Google served the call in |
|---|---|
| europe-west1 | europe-west1 |
| asia-northeast1 (Tokyo) | asia-east1 |
| australia-southeast1 (Sydney) | asia-east1 |
| southamerica-east1 (São Paulo) | us-east4 |
| GitLab runner | us-east4 (11 of 12), us-south1 (1) |
| Laptop in India (earlier runs) | asia-southeast1 |

So for the Gemini API, five vantage points reached **three** Google serving
regions: Tokyo and Sydney share asia-east1, and São Paulo is served from the
same region as the runner. Raw: [region map](raw/2026-10-16-vantage-region-map.log).

Drill 9's first push found a bug of ours, not Google's: that day's CI change
gave `container_scanning` the template's own rules, so on any branch it
needed a build job that did not exist, and GitLab created no pipeline at all.
The leaked key sat on the drill branch unretired. The fix set the job's rules
directly; a dry run of pipeline creation then passed for a branch and for
main. The drill branch was deleted and the drill rerun as `drill-9b-vantage`,
which retired that same key.

### The vantage image, scanned

GitLab Container Scanning (Trivy) scans every vantage image before it is
deployed. Three base images were tried, one pipeline each:

| Base image | Findings | Critical | High |
|---|---|---|---|
| `python:3.12-slim` (Debian 13) | 166 | 0 | 44 |
| `gcr.io/distroless/python3-debian12:nonroot` | 291 | 2 | 61 |
| `cgr.dev/chainguard/python:latest` (Wolfi) | **0** | 0 | 0 |

Distroless was worse, not better: its Python comes from Debian 12's own
packages, which carry more known issues than the official image's Python.
The Chainguard image is the one deployed. Its 0 is a real scan, not an empty
one: Trivy detected the Wolfi OS and listed 30 packages in its software bill
of materials. All four vantages passed the same checks after each redeploy
(403 without sign-in, 400 for anything but a key, and Google's verdict on a
dead key). Raw: [scan counts](raw/2026-10-16-vantage-image-scans.log).

## Rehearsal drills: the policy, the approval gate, a tighter replacement

`.vibeguardian.toml` says what may happen without a person: retire on its own
when at most `max_services` services use the key and none is `protected`;
otherwise stop with `needs_approval`, change nothing, and wait for someone to
run the manual `leak-approve` job. CI reads the policy from the default
branch, so a push cannot loosen it. When a leaked key works on every API, its
replacement is limited to the APIs the key actually called in the last 30
days, from Google's own counts.

Three drills on 2026-10-17, one after another. Times are seconds after GitLab
created the drill's push pipeline.

| Drill | Path | Key deleted | Proven dead (5 vantages) | Pipeline done | Incident opened | Fix MR opened |
|---|---|---|---|---|---|---|
| 10 | automatic | 76.4 s | 191.2 s, 60 of 60, 0 flaps | 234.7 s | 294.1 s (#7) | 395.0 s (!7) |
| 11 | held for approval, then approved | 457.1 s (59.5 s after the approval) | 635.1 s (237.5 s after), 72 of 75, **2 flaps** | 677.2 s | 220.5 s, while held (#8) | 252.0 s (!8) |
| 12 | unrestricted key, limited replacement | 80.2 s | 192.4 s, 60 of 60, 0 flaps | 240.9 s | 314.0 s (#9) | 360.6 s (!9) |

Drill 11. With `vg-demo` marked protected, `leak-respond` stopped at
"approval_needed" before changing anything. The prover's short check found
the key ALIVE from all five vantages (27 of 27 accepted), the gate said
"needs_approval, NOT PROVEN DEAD", and the Duo flow titled the incident "held
for approval: key STILL WORKS". Divij approved in chat and the `leak-approve`
job was started from his browser session, 397.6 s after the push; GitLab
recorded ndivij2004 as the user who ran it, and the incident says "Approved
by ndivij2004" with the policy's reason. The approved prove and gate jobs ran
on their own after it, and the flow rewrote the incident to "retired and
proven dead". The policy change was reverted on main afterwards.

Drill 12. The live key's restrictions were removed just before the drill, so
the leaked key worked on every API. Its replacement was created limited to
`generativelanguage.googleapis.com`, the only API Google counted it calling;
the app was healthy on it, and that limit is the live key's state now.

Raw: [timings](raw/2026-10-17-rehearsal-timings.jsonl);
drill 10 [incident](raw/2026-10-17-ci-drill10-incident.json), [proof](raw/2026-10-17-ci-drill10-proof.json);
drill 11 [held incident](raw/2026-10-17-ci-drill11-held-incident.json), [held proof](raw/2026-10-17-ci-drill11-held-proof.json),
[approved incident](raw/2026-10-17-ci-drill11-approved-incident.json), [approved proof](raw/2026-10-17-ci-drill11-approved-proof.json),
[probe log](raw/2026-10-17-ci-drill11-approved-prove.jsonl);
drill 12 [incident](raw/2026-10-17-ci-drill12-incident.json), [proof](raw/2026-10-17-ci-drill12-proof.json).

### A deleted key that worked again in Europe

In drill 11, after the key was deleted, the CI runner's probes were all
rejected from the first one (39.2 s after deletion) and reached 12 in a row
at 96.2 s. A prover asking only from the runner would have called the key
dead there. From europe-west1, Google rejected it 7 times, then **answered
HTTP 200 with real data at 78.5 s and again at 111.4 s after deletion**,
15 s after the runner's streak was complete, before rejecting it for good
from 117.0 s. From southamerica-east1 the first probe, at 39.2 s, also got
HTTP 200. The proof waited for every vantage, so it held its verdict until
Europe's own 12 in a row, at 177.9 s after deletion. This is the regional
behaviour that made us ask from several places.

## Authorization keys ("AQ.")

Google's newer API key format is `AQ.` plus 50 URL-safe characters (53 in
all), bound to a service account; Google calls these authorization keys, and
Google AI Studio has issued only these since mid-2026. Until 2026-10-18
VibeGuardian recognised only the classic `AIza` + 35 format, so a leaked
authorization key would have gone unanswered. Now its detector, the
redaction before the Duo agent, the companion and the vantages know both,
and a replacement stays bound to the same service account.

What Google answers for one (2026-10-18, from the laptop). A Gemini-only
authorization key was created in the demo project, bound to a service account
with no roles, then deleted:

| When | Answer |
|---|---|
| Live, 6 probes | HTTP 200 every time |
| Deleted, probed every 5 s for 3 minutes | **HTTP 401 `ACCESS_TOKEN_TYPE_UNSUPPORTED`, "API key not valid"**, from the first probe at 1.4 s, every time; never accepted again |

A classic key's death is HTTP 400 `API_KEY_INVALID`, so the prover now also
counts that 401 as dead, but only with the "API key not valid" message: a
live key can get a 401 with other messages. Raw: [probe log](raw/2026-10-18-aq-key-deleted.jsonl).

Drill 14 put the demo app on an authorization key and leaked it:

- GitLab's own secret detection caught it (rule `GCPVertexExpressModeKey`).
- The first responder run failed safely: creating a key bound to a service
  account needs `iam.serviceAccountApiKeyBindings.create`, which `vg-retirer`
  lacked. Nothing changed, and the prover reported the key still alive from
  all five vantages. The fix is a custom role with only the three key-binding
  permissions, granted to `vg-retirer` on that one service account.
- The fix branch's pipeline then retired the key: a replacement bound to the
  same account, the app rolled onto it and healthy, the old key deleted in
  22.8 s. **Proven dead from all five vantages, 60 of 60**, every rejection
  the new 401.
- It also exposed a race. The fixer pushed two commits 15 s apart, and both
  pipelines' responders worked on the same live key; the second found no
  consumers (the first had already moved the secret) and minted a replacement
  nothing used. The responders now share one GitLab `resource_group`, so they
  run one at a time and the second finds the key already deleted. The extra
  key was deleted.

Raw: [first run](raw/2026-10-18-ci-drill14-incident-first.json),
[retirement](raw/2026-10-18-ci-drill14-incident-fix-a.json),
[the racing run](raw/2026-10-18-ci-drill14-incident-fix-b-race.json),
[proof](raw/2026-10-18-ci-drill14-proof.json), [probe log](raw/2026-10-18-ci-drill14-prove.jsonl).

## Retiring a leaked service-account key

How: `demo/bootstrap_sa.py` creates a throwaway account (`vg-leaky-app`, read-only
project metadata) with a key stored in Secret Manager. Treat that key as
leaked: start `vg prove-sa` first (it mints its own canary token, standing in
for one an attacker already holds), then run `vg retire-sa`.

| Date (UTC) | Retired in | What it did | Proof (no cloud identity) |
|---|---|---|---|
| 2026-10-15 | **27 s** | replacement account with the same roles, new key live at 22 s, stored as secret version 2; old key, old version, and old account disabled | canary refused (401) and the leaked key unable to mint, **3 of 3** each |

Raw: [retire](raw/2026-10-15-sa-retire.jsonl), [prove](raw/2026-10-15-sa-prove.jsonl),
[incident](raw/2026-10-15-sa-incident.json).

In this run the canary was first refused 0.6 s after the key was disabled
and about 1.8 s before the account was disabled. The control runs below show
that disabling the key alone does not stop a token, so we read this as the
two steps landing too close together to separate, not as a key-only cut-off.

## Disabled service-account keys

How: `vg token-survival`. Create a key for a throwaway service account that
can only read project metadata, mint an access token with it (the token an
attacker would hold), disable the key, then probe two things: can the key
still mint tokens, and does the already-minted token still work.

The token is probed with a read-only `GET` on the project's own metadata
every ~32 s. Alive means Google answered 200; dead means 401.

| Date (UTC) | Run | Key stops minting tokens | Stolen token still works until | Calls that succeeded with the stolen token after the disable |
|---|---|---|---|---|
| 2026-10-11 | [run](raw/2026-10-11-sa-token-survival.jsonl) | immediately (0 s) | **59.6 min** (first 401 at 60.2 min) | **109 of 112** |

What this shows:

- Disabling a leaked service-account key stops new tokens straight away, but
  does nothing to a token minted before the disable. That token kept working
  for about an hour, until it expired on its own. This matches Google's
  documentation; it is not a bug that will be patched.
- So "the key is disabled" is not the end of an attacker's access. Ending it
  needs a second step that acts on the identity, not the key.

## Cutting off a token that was already stolen

How: `vg cutoff` (runner: `demo/cutoff-runs.sh`). Same setup as above: mint a
token with a fresh key, disable the key, then apply one cut-off method and
probe with the stolen token until Google refuses it (401 or 403) three times
in a row. Every method is undone afterwards.

| Date (UTC) | Method | Stolen token refused after | Raw |
|---|---|---|---|
| 2026-10-14 | Disable the key only (baseline, run above) | 59.6 min | [log](raw/2026-10-11-sa-token-survival.jsonl) |
| 2026-10-14 | Remove the account's roles on the project | **93.5 s** | [log](raw/2026-10-14-cutoff-remove-roles.jsonl) |
| 2026-10-14 | Disable the whole service account | **11.7 s** | [log](raw/2026-10-14-cutoff-disable-sa.jsonl) |
| — | IAM deny policy | not possible here | needs a Google Cloud organization; Deny Admin cannot be granted on a project |

Repeat and control runs (2026-10-15):

| Run | What was disabled | Stolen token | Raw |
|---|---|---|---|
| Key only, repeated | the key | worked for **59.7 min** (210 of 213 calls OK), refused at 60.0 min when it expired | [log](raw/2026-10-15-sa-token-survival.jsonl) |
| Key, then the account 60 s later | the key, then the account | **worked through all 60 s** after the key was disabled (9 of 9 calls OK), then **refused on the first probe** after the account was disabled (401) | [log](raw/2026-10-15-cutoff-gap.jsonl) |

So the account, not the key, is what ends a stolen token's access, and it does
so almost at once.

What this shows:

- Disabling the service account ends an attacker's access about 300 times
  faster than waiting for the stolen token to expire.
- It also stops the app if the app uses the same account, so VibeGuardian
  must move the app to a new identity first, then disable the leaked one.
- Deny policies, the cleanest option on paper, are out of reach for projects
  without an organization, which is most indie projects.
