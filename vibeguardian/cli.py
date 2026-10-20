"""Command line for VibeGuardian.

Secrets are read from environment variables named on the command line, never
from arguments, so they cannot land in shell history or CI job logs.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from vibeguardian import probe as probe_mod
from vibeguardian.experiment import time_to_dead
from vibeguardian.gcp import session
from vibeguardian.gcp.apikeys import ApiKeys
from vibeguardian.secret import fingerprint


def _secret_from_env(var: str) -> str:
    value = os.environ.get(var, "")
    if not value:
        sys.exit(f"environment variable {var} is empty or unset")
    return value


def cmd_probe(args: argparse.Namespace) -> int:
    key = _secret_from_env(args.key_env)
    result = probe_mod.probe(key, args.endpoint)
    print(json.dumps({"fingerprint": fingerprint(key), **result.as_dict()}))
    return 0 if result.verdict != probe_mod.Verdict.UNKNOWN else 2


def cmd_check_key(args: argparse.Namespace) -> int:
    from vibeguardian.checkkey import check_key

    key = _secret_from_env(args.key_env)
    keys = None
    if args.project:
        try:
            keys = ApiKeys(session(quota_project=args.project))
        except Exception as err:  # noqa: BLE001 - no Google login: still report liveness
            print(json.dumps({"note": f"no Google login ({type(err).__name__}); liveness only"}), file=sys.stderr)
    report = check_key(key, probe=lambda value: probe_mod.probe(value, args.endpoint), keys=keys)
    print(json.dumps(report))
    return 0


def cmd_lookup(args: argparse.Namespace) -> int:
    key = _secret_from_env(args.key_env)
    api = ApiKeys(session(quota_project=args.project))
    print(json.dumps({"fingerprint": fingerprint(key), "key": api.lookup(key)}))
    return 0


def cmd_time_to_dead(args: argparse.Namespace) -> int:
    api = ApiKeys(session(quota_project=args.project))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as log:

        def on_event(event: dict) -> None:
            event = {"ts": round(time.time(), 3), **event}
            log.write(json.dumps(event) + "\n")
            log.flush()
            if event.get("event") != "probe" or args.verbose:
                print(json.dumps(event), flush=True)

        result = time_to_dead(
            api,
            args.project,
            lambda key: probe_mod.probe(key, args.endpoint),
            label=f"vg-ttd-{time.strftime('%Y%m%d-%H%M%S')}",
            interval=args.interval,
            stable=args.stable,
            max_seconds=args.max_minutes * 60,
            warmup=args.warmup,
            on_event=on_event,
        )
    return 0 if result.reached else 1


def cmd_token_survival(args: argparse.Namespace) -> int:
    from vibeguardian import tokens
    from vibeguardian.experiment import token_survival
    from vibeguardian.gcp.iam import ServiceAccountKeys

    keys = ServiceAccountKeys(session(quota_project=args.project))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as log:

        def on_event(event: dict) -> None:
            event = {"ts": round(time.time(), 3), **event}
            log.write(json.dumps(event) + "\n")
            log.flush()
            if event.get("event") != "probe" or args.verbose:
                print(json.dumps(event), flush=True)

        summary = token_survival(
            keys,
            args.service_account,
            probe_mint=tokens.probe_mint,
            mint=tokens.mint,
            probe_token=lambda token: tokens.probe_token(token, args.check_url),
            interval=args.interval,
            stable=args.stable,
            max_seconds=args.max_minutes * 60,
            on_event=on_event,
        )
    return 0 if summary.get("reached") else 1


def cmd_exposure(args: argparse.Namespace) -> int:
    import subprocess
    from datetime import datetime, timedelta

    from vibeguardian.exposure import check_record, usage_by_region

    def parse(text: str) -> datetime:
        return datetime.fromisoformat(text.strip().replace("Z", "+00:00"))

    def since_for(leak: dict | None) -> datetime | None:
        """When the key became public: --since, else the leak commit's time, else the pipeline commit's."""
        if args.since:
            return parse(args.since)
        if leak and leak.get("commit"):
            shown = subprocess.run(["git", "show", "-s", "--format=%cI", leak["commit"]],
                                   capture_output=True, text=True, check=False)
            if shown.returncode == 0 and shown.stdout.strip():
                return parse(shown.stdout)
        timestamp = os.environ.get("CI_COMMIT_TIMESTAMP")
        return parse(timestamp) if timestamp else None

    record = json.loads(Path(args.incident).read_text(encoding="utf-8"))
    http = session(quota_project=args.project)
    try:
        reports = check_record(
            record,
            lambda uid, start, end, began: usage_by_region(http, args.project, uid, start, end, began),
            since_for,
            also_regions=set(args.also_region or []),
            settle=timedelta(seconds=args.settle),
        )
    except ValueError as err:
        sys.exit(f"{err} (give --since: when the key leaked)")
    result = {"reports": reports}
    if args.out:
        Path(args.out).write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps(result))
    return 0


def cmd_keys(args: argparse.Namespace) -> int:
    from vibeguardian.inventory import inventory

    http = session(quota_project=args.project)
    print(json.dumps(inventory(ApiKeys(http), http, args.project, days=args.days)))
    return 0


def cmd_telemetry(args: argparse.Namespace) -> int:
    import requests

    from vibeguardian.telemetry import build, export

    def load(path: str | None) -> dict | None:
        return json.loads(Path(path).read_text(encoding="utf-8")) if path and Path(path).exists() else None

    endpoint = args.endpoint or os.environ.get("VG_OTLP_ENDPOINT")
    record = load(args.incident)
    if not endpoint or record is None:
        print(json.dumps({"sent": {}, "skipped": "no OTLP endpoint" if not endpoint else "no incident record"}))
        return 0
    bodies = build(record, load(args.proof), load(args.exposure))
    sent = export(requests.Session(), endpoint, bodies, token=os.environ.get("GITLAB_OBSERVABILITY_TOKEN"))
    spans = len(bodies["traces"]["resourceSpans"][0]["scopeSpans"][0]["spans"]) if bodies["traces"] else 0
    print(json.dumps({"sent": sent, "spans": spans}))
    return 0 if all(200 <= code < 300 for code in sent.values()) else 1


def cmd_deploy_vantage(args: argparse.Namespace) -> int:
    from vibeguardian.gcp.cloudrun import CloudRun, is_ready

    run = CloudRun(session(quota_project=args.project))
    runtime = args.service_account or f"vg-vantage@{args.project}.iam.gserviceaccount.com"
    ok = True
    for region in args.region:
        service = run.deploy(args.project, region, "vg-vantage", args.image, service_account=runtime,
                             invokers=args.invoker, env={"VANTAGE_REGION": region})
        ready = is_ready(service)
        ok = ok and ready
        print(json.dumps({"region": region, "url": service.get("uri"), "ready": ready,
                          "revision": service.get("latestReadyRevision")}))
    return 0 if ok else 1


def cmd_scan_staged(args: argparse.Namespace) -> int:
    from vibeguardian.hook import report, staged_keys

    keys = staged_keys(args.repo)
    if not keys:
        return 0
    verdicts = None
    if args.check:
        verdicts = {}
        for k in keys:
            if k.provider is None and k.fingerprint not in verdicts:  # only Google keys can be checked here
                r = probe_mod.probe(k.value)
                verdicts[k.fingerprint] = {"alive": "LIVE: Google accepts it", "dead": "dead: Google rejects it"}.get(
                    r.verdict.value, "unknown: Google did not say")
    print(report(keys, verdicts), file=sys.stderr)
    return 1


def cmd_install_hook(args: argparse.Namespace) -> int:
    from vibeguardian.hook import install_hook

    try:
        path = install_hook(args.repo, force=args.force)
    except FileExistsError as err:
        sys.exit(str(err))
    print(f"installed {path}: commits that add a Google API key will be stopped")
    return 0


def _key_file_from_env(var: str) -> dict:
    from vibeguardian.sa_retire import parse_key_file

    info = parse_key_file(_secret_from_env(var))
    if not info:
        sys.exit(f"{var} does not hold a service-account key file")
    return info


def cmd_retire_sa(args: argparse.Namespace) -> int:
    from vibeguardian import tokens
    from vibeguardian.gcp.cloudrun import CloudRun
    from vibeguardian.gcp.iam import ProjectRoles, ServiceAccountKeys, ServiceAccounts
    from vibeguardian.gcp.secretmanager import SecretManager
    from vibeguardian.health import http_health
    from vibeguardian.retire import ALREADY_DELETED, RETIRED
    from vibeguardian.sa_retire import retire_service_account_key

    info = _key_file_from_env(args.key_file_env)
    http = session(quota_project=args.project)
    health = http_health(args.health_path)
    log, on_event = _event_log(args.out, args.verbose)
    with log:
        incident = retire_service_account_key(
            info, args.project, accounts=ServiceAccounts(http), keys=ServiceAccountKeys(http),
            roles=ProjectRoles(http), secrets=SecretManager(http), run=CloudRun(http),
            probe_mint=tokens.probe_mint, check_health=lambda service: health(service, ""), on_event=on_event,
        )
    if args.incident:
        Path(args.incident).write_text(json.dumps(incident.as_dict(), indent=2), encoding="utf-8")
    return 0 if incident.outcome in (RETIRED, ALREADY_DELETED) else 1


def cmd_prove_sa(args: argparse.Namespace) -> int:
    from vibeguardian import tokens
    from vibeguardian.sa_retire import prove_service_account_key

    info = _key_file_from_env(args.key_file_env)
    log, on_event = _event_log(args.out, args.verbose)
    with log:
        verdict = prove_service_account_key(
            info, mint=tokens.mint, probe_mint=tokens.probe_mint,
            probe_access=lambda token: tokens.probe_access(token, args.check_url),
            stable=args.stable, interval=args.interval, max_seconds=args.max_minutes * 60, on_event=on_event,
        )
    return 0 if verdict["dead"] else 1


def cmd_cutoff(args: argparse.Namespace) -> int:
    import uuid

    from vibeguardian import tokens
    from vibeguardian.experiment import access_cutoff
    from vibeguardian.gcp.iam import DenyPolicies, ProjectRoles, ServiceAccountKeys, ServiceAccounts, principal_for

    http = session(quota_project=args.project)
    email = args.service_account
    member = f"serviceAccount:{email}"
    if args.method == "remove-roles":
        roles = ProjectRoles(http)
        apply = lambda: roles.remove_member(args.project, member)  # noqa: E731
        undo = lambda removed: roles.restore_member(args.project, member, removed)  # noqa: E731
    elif args.method == "deny":
        deny = DenyPolicies(http)
        policy_id = f"vg-cutoff-{uuid.uuid4().hex[:8]}"
        apply = lambda: deny.deny(args.project, policy_id, principal_for(email), args.deny_permission) or policy_id  # noqa: E731
        undo = lambda pid: deny.remove(args.project, pid)  # noqa: E731
    else:
        accounts = ServiceAccounts(http)
        apply = lambda: accounts.disable(email)  # noqa: E731
        undo = lambda _: accounts.enable(email)  # noqa: E731

    log, on_event = _event_log(args.out, args.verbose)
    with log:
        summary = access_cutoff(
            ServiceAccountKeys(http), email, method=args.method, apply_cutoff=apply, undo_cutoff=undo,
            probe_mint=tokens.probe_mint, mint=tokens.mint,
            probe_access=lambda token: tokens.probe_access(token, args.check_url),
            interval=args.interval, stable=args.stable, max_seconds=args.max_minutes * 60,
            gap_seconds=args.gap_seconds, on_event=on_event,
        )
    return 0 if summary.get("reached") else 1


def _event_log(path: str, verbose: bool):
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    log = out.open("a", encoding="utf-8")

    def on_event(event: dict) -> None:
        event = {"ts": round(time.time(), 3), **event}
        log.write(json.dumps(event) + "\n")
        log.flush()
        if event.get("event") != "probe" or verbose:
            print(json.dumps(event), flush=True)

    return log, on_event


def cmd_retire(args: argparse.Namespace) -> int:
    from vibeguardian.gcp.cloudrun import CloudRun
    from vibeguardian.gcp.secretmanager import SecretManager
    from vibeguardian.health import http_health
    from vibeguardian.retire import ALREADY_DELETED, RETIRED, retire

    leaked = _secret_from_env(args.key_env)
    http = session(quota_project=args.project)
    log, on_event = _event_log(args.out, args.verbose)
    with log:
        incident = retire(
            leaked,
            args.project,
            keys=ApiKeys(http),
            secrets=SecretManager(http),
            run=CloudRun(http),
            check_key=lambda key: probe_mod.probe(key, args.endpoint),
            check_health=http_health(args.health_path),
            dry_run=args.dry_run,
            on_event=on_event,
        )
    if args.incident:
        Path(args.incident).write_text(json.dumps(incident.as_dict(), indent=2), encoding="utf-8")
    return 0 if incident.outcome in (RETIRED, ALREADY_DELETED, "dry_run") else 1


def cmd_prove(args: argparse.Namespace) -> int:
    key = _secret_from_env(args.key_env)
    log, on_event = _event_log(args.out, args.verbose)
    started = time.time()
    with log:
        result = probe_mod.watch(
            lambda: probe_mod.probe(key, args.endpoint),
            until=probe_mod.Verdict.DEAD,
            stable=args.stable,
            interval=args.interval,
            max_seconds=args.max_minutes * 60,
            on_probe=lambda r: on_event({"event": "probe", "fingerprint": fingerprint(key), **r.as_dict()}),
        )
        verdict = {
            "event": "verdict",
            "fingerprint": fingerprint(key),
            "dead": result.reached,
            "probes": result.probes,
            "flaps": result.flaps,
            "seconds_watched": round(time.time() - started, 1),
            "first_dead_at": result.first_at,
            "stable_dead_at": result.stable_at,
        }
        on_event(verdict)
    return 0 if result.reached else 1


def cmd_ci_auth(args: argparse.Namespace) -> int:
    from vibeguardian.ci import write_credentials

    path = write_credentials(args.service_account, args.out, args.token_env)
    print(f"export GOOGLE_APPLICATION_CREDENTIALS={path}")
    return 0


def cmd_respond(args: argparse.Namespace) -> int:
    from vibeguardian import pipeline
    from vibeguardian.gcp.cloudrun import CloudRun
    from vibeguardian.gcp.secretmanager import SecretManager
    from vibeguardian.health import http_health
    from vibeguardian.policy import load as load_policy
    from vibeguardian.retire import retire

    policy = load_policy(args.policy)
    leaks = pipeline.read_leaks(args.report)
    if not any(leak.kind == "google_api_key" for leak in leaks):
        pipeline.write_json(args.incident, pipeline.respond(leaks, lambda leak: {}))
        print(f"{len(leaks)} finding(s), none of them a Google API key")
        return 0
    http = session(quota_project=args.project)
    log, on_event = _event_log(args.out, args.verbose)

    def retire_one(leak):
        incident = retire(
            leak.value,
            args.project,
            keys=ApiKeys(http),
            secrets=SecretManager(http),
            run=CloudRun(http),
            check_key=lambda key: probe_mod.probe(key, args.endpoint),
            check_health=http_health(args.health_path),
            label=f"VibeGuardian replacement, leak at {leak.commit[:8]}",
            approval=policy.approval_reason,
            approved_by=args.approved_by,
            limit_replacement=lambda old_key: _limit_to_used_apis(http, args.project, old_key, policy, on_event),
            on_event=on_event,
        )
        return incident.as_dict()

    with log:
        pipeline.write_json(args.incident, pipeline.respond(leaks, retire_one))
    return 0


def _limit_to_used_apis(http, project: str, old_key: str, policy, on_event) -> dict | None:
    """The replacement's restrictions under the policy, or None to keep the old key's.

    A failure here never blocks the retirement: the replacement then keeps the
    old key's restrictions, and the incident says why.
    """
    from datetime import datetime, timedelta, timezone

    from vibeguardian.exposure import apis_used, key_uid
    from vibeguardian.retire import used_api_restrictions

    if not policy.limit_to_used_apis:
        return None
    try:
        now = datetime.now(timezone.utc)
        used = apis_used(http, project, key_uid(old_key), now - timedelta(days=policy.used_days), now)
        return used_api_restrictions(ApiKeys(http).get(old_key), used)
    except Exception as err:  # noqa: BLE001 - keep retiring; record why the limit was skipped
        on_event({"event": "limit_skipped", "at": round(time.time(), 3), "reason": f"{type(err).__name__}: {err}"})
        return None


def cmd_prove_leaks(args: argparse.Namespace) -> int:
    from vibeguardian import pipeline

    leaks = pipeline.read_leaks(args.report)
    incident = pipeline.read_json(args.incident)
    failed = {
        r["leak"]["fingerprint"]
        for r in incident.get("responses", [])
        if r.get("incident", {}).get("outcome") in ("aborted", "error", "needs_approval")
    }
    def local(key: str) -> probe_mod.ProbeResult:
        return probe_mod.probe(key, args.endpoint)

    check = local
    if args.vantage:
        from vibeguardian.vantage import id_token, parse_vantages, vantage_check

        vantages = parse_vantages(args.vantage)
        if args.vantage_identity:
            def minter(url: str):
                return lambda: id_token(session(), args.vantage_identity, url)

            tokens = {name: minter(url) for name, url in vantages.items()}
        elif os.environ.get("VG_VANTAGE_TOKEN"):
            tokens = dict.fromkeys(vantages, os.environ["VG_VANTAGE_TOKEN"])
        else:
            sys.exit("--vantage needs --vantage-identity (or VG_VANTAGE_TOKEN) to call the vantage services")
        check = {"runner": local, **{name: vantage_check(url, tokens[name]) for name, url in vantages.items()}}
    log, on_event = _event_log(args.out, args.verbose)
    with log:
        proof = pipeline.prove(
            leaks,
            check,
            stable=args.stable,
            interval=args.interval,
            max_seconds=args.max_minutes * 60,
            responder_failed=failed,
            on_probe=lambda e: on_event({"event": "probe", **e}),
        )
    pipeline.write_json(args.proof, proof)
    for fp, verdict in proof["keys"].items():
        print(f"{fp}: {verdict['state'].upper()} after {verdict['probes']} probes "
              f"({verdict['rejected']} rejected, {verdict['accepted']} accepted), "
              f"{verdict['flaps']} flaps, {verdict['seconds_watched']} s, {verdict['watch']} watch")
        for name, one in verdict.get("vantages", {}).items():
            print(f"  from {name}: {one['state']}, {one['rejected']} of {one['probes']} rejected, {one['flaps']} flaps")
        if verdict.get("unreachable"):
            print(f"  no answer from: {', '.join(verdict['unreachable'])}")
    return 0 if all(v["dead"] for v in proof["keys"].values()) else 1


def cmd_gate(args: argparse.Namespace) -> int:
    from vibeguardian import pipeline
    from vibeguardian.leaks import files_containing

    leaks = pipeline.read_leaks(args.report)
    present = {leak.fingerprint: files_containing(leak.value) for leak in leaks if leak.value}
    ok, lines = pipeline.gate(
        [leak.public() for leak in leaks],
        pipeline.read_json(args.incident),
        pipeline.read_json(args.proof),
        present,
    )
    print("\n".join(lines))
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vg", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("probe", help="ask Google whether a key is still accepted")
    p.add_argument("--key-env", required=True, help="env var holding the key")
    p.add_argument("--endpoint", default=probe_mod.DEFAULT_ENDPOINT)
    p.set_defaults(func=cmd_probe)

    p = sub.add_parser("check-key", help="is this key live, whose is it, how old, how restricted")
    p.add_argument("--key-env", required=True, help="env var holding the key")
    p.add_argument("--project", help="project to bill lookups to; omit for a liveness-only check")
    p.add_argument("--endpoint", default=probe_mod.DEFAULT_ENDPOINT)
    p.set_defaults(func=cmd_check_key)

    p = sub.add_parser("lookup", help="find the key resource for a key value")
    p.add_argument("--key-env", required=True)
    p.add_argument("--project", required=True, help="project to bill the lookup to")
    p.set_defaults(func=cmd_lookup)

    p = sub.add_parser("time-to-dead", help="measure how long a deleted key keeps working")
    p.add_argument("--project", required=True)
    p.add_argument("--out", default=".vg/time-to-dead.jsonl")
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--stable", type=int, default=6)
    p.add_argument("--max-minutes", type=float, default=40.0)
    p.add_argument("--warmup", type=int, default=0, help="calls with the key before deleting it")
    p.add_argument("--endpoint", default=probe_mod.DEFAULT_ENDPOINT)
    p.add_argument("--verbose", action="store_true", help="print every probe")
    p.set_defaults(func=cmd_time_to_dead)

    p = sub.add_parser(
        "token-survival",
        help="disable a service-account key; time when minting stops and when a stolen token stops",
    )
    p.add_argument("--project", required=True)
    p.add_argument("--service-account", required=True, help="email of a throwaway service account")
    p.add_argument("--check-url", required=True, help="GET this with the stolen token to test it")
    p.add_argument("--out", default=".vg/token-survival.jsonl")
    p.add_argument("--interval", type=float, default=30.0)
    p.add_argument("--stable", type=int, default=3)
    p.add_argument("--max-minutes", type=float, default=70.0)
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_token_survival)

    p = sub.add_parser("retire", help="roll out a replacement for a leaked key, then delete it")
    p.add_argument("--key-env", required=True, help="env var holding the leaked key")
    p.add_argument("--project", required=True, help="project whose secrets and services to roll")
    p.add_argument("--health-path", default="/health")
    p.add_argument("--endpoint", default=probe_mod.DEFAULT_ENDPOINT)
    p.add_argument("--dry-run", action="store_true", help="only report what would change")
    p.add_argument("--out", default=".vg/retire.jsonl")
    p.add_argument("--incident", help="write the incident record here as JSON")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_retire)

    p = sub.add_parser("prove", help="probe a retired key until Google rejects it N times in a row")
    p.add_argument("--key-env", required=True)
    p.add_argument("--stable", type=int, default=12)
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--max-minutes", type=float, default=30.0)
    p.add_argument("--endpoint", default=probe_mod.DEFAULT_ENDPOINT)
    p.add_argument("--out", default=".vg/prove.jsonl")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_prove)

    p = sub.add_parser("exposure", help="did anyone outside your services use a retired key while it leaked?")
    p.add_argument("--incident", required=True, help="record written by vg retire or vg respond")
    p.add_argument("--project", required=True)
    p.add_argument("--since", help="when the key leaked (ISO 8601); defaults to the leak commit's time")
    p.add_argument("--settle", type=float, default=0.0,
                   help="wait this many seconds after the key was deleted, so the last calls reach Monitoring")
    p.add_argument("--also-region", action="append", help="another region where the key is legitimately used")
    p.add_argument("--out", help="write the report here as JSON")
    p.set_defaults(func=cmd_exposure)

    p = sub.add_parser("keys", help="every API key in a project: age, limits, recent calls, and what is risky")
    p.add_argument("--project", required=True)
    p.add_argument("--days", type=int, default=7, help="count calls over this many days")
    p.set_defaults(func=cmd_keys)

    p = sub.add_parser("telemetry", help="send incidents to an OpenTelemetry endpoint, such as GitLab Observability")
    p.add_argument("--incident", required=True, help="record written by vg retire or vg respond")
    p.add_argument("--proof", help="proof written by vg prove-leaks")
    p.add_argument("--exposure", help="report written by vg exposure")
    p.add_argument("--endpoint", help="OTLP/HTTP base URL; defaults to VG_OTLP_ENDPOINT")
    p.set_defaults(func=cmd_telemetry)

    p = sub.add_parser("deploy-vantage", help="deploy the prover's vantage service, private, to several regions")
    p.add_argument("--project", required=True)
    p.add_argument("--image", required=True)
    p.add_argument("--region", action="append", required=True)
    p.add_argument("--invoker", action="append", required=True, help="IAM member allowed to call it")
    p.add_argument("--service-account", help="runtime identity; defaults to vg-vantage, which has no roles")
    p.set_defaults(func=cmd_deploy_vantage)

    p = sub.add_parser("scan-staged", help="stop a commit that adds an API key (a pre-commit hook)")
    p.add_argument("--repo", default=".")
    p.add_argument("--check", action="store_true", help="also ask Google whether each Google key is live")
    p.set_defaults(func=cmd_scan_staged)

    p = sub.add_parser("install-hook", help="install vg scan-staged as this repository's pre-commit hook")
    p.add_argument("--repo", default=".")
    p.add_argument("--force", action="store_true", help="replace an existing pre-commit hook")
    p.set_defaults(func=cmd_install_hook)

    p = sub.add_parser("retire-sa", help="retire a leaked service-account key and cut off its tokens")
    p.add_argument("--key-file-env", required=True, help="env var holding the leaked key file (JSON)")
    p.add_argument("--project", required=True)
    p.add_argument("--health-path", default="/health")
    p.add_argument("--out", default=".vg/retire-sa.jsonl")
    p.add_argument("--incident", help="write the incident record here as JSON")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_retire_sa)

    p = sub.add_parser("prove-sa", help="mint a canary now, then prove the canary and the key are both dead")
    p.add_argument("--key-file-env", required=True)
    p.add_argument("--check-url", required=True, help="GET this with the canary: 200 = still has access")
    p.add_argument("--stable", type=int, default=3)
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--max-minutes", type=float, default=25.0)
    p.add_argument("--out", default=".vg/prove-sa.jsonl")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_prove_sa)

    p = sub.add_parser("cutoff", help="time how fast a method stops a token stolen before its key was disabled")
    p.add_argument("--project", required=True)
    p.add_argument("--service-account", required=True, help="email of a throwaway service account")
    p.add_argument("--method", required=True, choices=["remove-roles", "deny", "disable-sa"])
    p.add_argument("--check-url", required=True, help="GET this with the stolen token: 200 = still has access")
    p.add_argument("--deny-permission", action="append",
                   default=["cloudresourcemanager.googleapis.com/projects.get"])
    p.add_argument("--out", default=".vg/cutoff.jsonl")
    p.add_argument("--interval", type=float, default=10.0)
    p.add_argument("--stable", type=int, default=3)
    p.add_argument("--max-minutes", type=float, default=20.0)
    p.add_argument("--gap-seconds", type=float, default=0.0,
                   help="probe this long after disabling the key, before applying the method")
    p.add_argument("--verbose", action="store_true")
    p.set_defaults(func=cmd_cutoff)

    p = sub.add_parser("ci-auth", help="turn this CI job's ID token into Google credentials")
    p.add_argument("--service-account", required=True)
    p.add_argument("--out", default=".gcp.creds.json")
    p.add_argument("--token-env", default="GCP_ID_TOKEN")
    p.set_defaults(func=cmd_ci_auth)

    report = "gl-secret-detection-report.json"
    p = sub.add_parser("respond", help="retire every leaked Google API key in a secret detection report")
    p.add_argument("--report", default=report)
    p.add_argument("--project", required=True)
    p.add_argument("--incident", default="incident.json")
    p.add_argument("--health-path", default="/health")
    p.add_argument("--endpoint", default=probe_mod.DEFAULT_ENDPOINT)
    p.add_argument("--out", default="respond.jsonl")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--policy", default=".vibeguardian.toml", help="what may happen without a person")
    p.add_argument("--approved-by", help="who approved a retirement the policy holds back")
    p.set_defaults(func=cmd_respond)

    p = sub.add_parser("prove-leaks", help="prove every leaked Google API key in a report is dead")
    p.add_argument("--report", default=report)
    p.add_argument("--proof", default="proof.json")
    p.add_argument("--incident", default="incident.json", help="only sets how long to watch each key")
    p.add_argument("--stable", type=int, default=12)
    p.add_argument("--interval", type=float, default=5.0)
    p.add_argument("--max-minutes", type=float, default=20.0)
    p.add_argument("--endpoint", default=probe_mod.DEFAULT_ENDPOINT)
    p.add_argument("--out", default="prove.jsonl")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--vantage", action="append", help="also ask Google from REGION=https://vantage-url")
    p.add_argument("--vantage-identity", help="service account whose ID token the vantage services accept")
    p.set_defaults(func=cmd_prove_leaks)

    p = sub.add_parser("gate", help="fail while leaked secrets remain in the code; print the outcome")
    p.add_argument("--report", default=report)
    p.add_argument("--incident", default="incident.json")
    p.add_argument("--proof", default="proof.json")
    p.set_defaults(func=cmd_gate)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
