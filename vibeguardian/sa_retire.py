"""Retire a leaked service-account key, and cut off tokens already minted from it.

Disabling only the key leaves every token minted from it working for up to an
hour (measured: 59.6 min). Disabling the whole account cuts those tokens off
in seconds (measured: 11.7 s), but it would also stop anything still using the
account. So the order is:

  1. find every secret that holds the key and every service that reads it
  2. create a replacement account with the same project roles, and a key for it
  3. roll each consumer onto the replacement and check it is healthy
  4. disable the leaked key, then the leaked account

If the leaked account is also the runtime identity of a Cloud Run service,
step 4 disables only the key and asks a human: disabling the account would
take that service down.

Proof is separate (``prove_service_account_key``) and owns its own canary: a
token it mints from the leaked key before the cut-off, standing in for any
token an attacker already holds.
"""

from __future__ import annotations

import json
import secrets as random_secrets
import time
from typing import Any, Callable

from vibeguardian.gcp.cloudrun import is_ready, secret_id, version_number
from vibeguardian.probe import ProbeResult, Verdict, watch
from vibeguardian.retire import ABORTED, ALREADY_DELETED, RETIRED, Incident
from vibeguardian.secret import fingerprint

KEY_ONLY = "key_disabled_account_in_use"


def parse_key_file(text: str) -> dict[str, Any] | None:
    """A service-account key file, or None if ``text`` is not one."""
    try:
        info = json.loads(text)
    except (ValueError, TypeError):
        return None
    needed = ("type", "client_email", "private_key_id", "private_key")
    if not isinstance(info, dict) or any(k not in info for k in needed) or info["type"] != "service_account":
        return None
    return info


def holds_key(key_id: str) -> Callable[[str], bool]:
    """Matches a secret value that is a key file for ``key_id``."""
    def match(value: str) -> bool:
        info = parse_key_file(value)
        return bool(info) and info["private_key_id"] == key_id
    return match


def replacement_id(email: str) -> str:
    """A new account id: the old one's name, trimmed, plus a short suffix (max 30 chars)."""
    name = email.split("@", 1)[0][:23].rstrip("-")
    return f"{name}-r{random_secrets.token_hex(2)}"


def retire_service_account_key(
    info: dict[str, Any],
    project: str,
    *,
    accounts: Any,
    keys: Any,
    roles: Any,
    secrets: Any,
    run: Any,
    probe_mint: Callable[[dict[str, Any]], ProbeResult],
    check_health: Callable[[dict[str, Any]], tuple[bool, str]],
    on_event: Callable[[dict[str, Any]], None] = lambda _: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> Incident:
    account, key_id = info["client_email"], info["private_key_id"]
    incident = Incident(leaked_fingerprint=fingerprint(info["private_key"]), started_at=clock())
    incident.old_key = f"projects/-/serviceAccounts/{account}/keys/{key_id}"

    def log(event: str, **data: Any) -> None:
        entry = {"event": event, "at": round(clock(), 3), **data}
        incident.timeline.append(entry)
        on_event(entry)

    def finish(outcome: str, reason: str | None = None) -> Incident:
        incident.outcome, incident.reason, incident.finished_at = outcome, reason, clock()
        log("finished", outcome=outcome, reason=reason)
        return incident

    log("identified", account=account, key_id=key_id)
    # A key retired earlier must not get a second replacement account.
    old_key, old_account = keys.get(incident.old_key), accounts.get(account)
    if old_key is None or old_key.get("disabled") or old_account is None or old_account.get("disabled"):
        state = ("key deleted" if old_key is None else "key disabled" if old_key.get("disabled")
                 else "account deleted" if old_account is None else "account disabled")
        return finish(ALREADY_DELETED, f"Google reports this credential already off: {state}")
    holders = secrets.find_holders_matching(project, holds_key(key_id))
    uses = [use for h in holders for use in run.consumers_of(project, h.secret)]
    runtime = [s["name"] for s in run.list_services(project)
               if s.get("template", {}).get("serviceAccount") == account]
    incident.secrets = [{"secret": h.secret, "old_version": h.version} for h in holders]
    log("consumers_found", secrets=[h.secret for h in holders], services=sorted({u.service for u in uses}),
        runtime_identity_of=runtime)

    # Replacement identity with the same project roles, and a key for it.
    new_account = accounts.create(project, replacement_id(account), f"Replacement for {account.split('@')[0]}")
    copied = roles.copy_member(project, f"serviceAccount:{account}", f"serviceAccount:{new_account}")
    log("replacement_account_created", account=new_account, roles=copied)
    new_key_name, new_info = keys.create(new_account)
    incident.new_key = new_key_name
    incident.new_fingerprint = fingerprint(new_info["private_key"])
    ready = watch(lambda: probe_mint(new_info), until=Verdict.ALIVE, stable=1, interval=5.0, max_seconds=300.0,
                  sleep=sleep, clock=clock)
    if not ready.reached:
        _undo_replacement(new_account, new_key_name, accounts, keys, log)
        return finish(ABORTED, "the replacement key never worked")
    log("replacement_key_live", key=new_key_name)

    new_versions: dict[str, str] = {}
    rolled: list[tuple[str, str, str]] = []
    try:
        for holder in holders:
            new_versions[holder.secret] = secrets.add_version(holder.secret, json.dumps(new_info))
            log("secret_version_added", secret=holder.secret, version=new_versions[holder.secret])
        for use in uses:
            holder = next(h for h in holders if secret_id(h.secret) == secret_id(use.secret))
            service = run.pin_secret(use.service, holder.secret, version_number(new_versions[holder.secret]))
            rolled.append((use.service, holder.secret, version_number(holder.version)))
            healthy, detail = check_health(service) if is_ready(service) else (False, "new revision is not ready")
            incident.services.append({"service": use.service, "revision": service.get("latestReadyRevision"),
                                      "healthy": healthy, "detail": detail})
            log("service_rolled", service=use.service, healthy=healthy, detail=detail)
            if not healthy:
                raise RuntimeError(f"{use.service} unhealthy on the replacement: {detail}")
    except Exception as err:  # noqa: BLE001 - every failure takes the same safe path
        for service, secret, old_version in reversed(rolled):
            run.pin_secret(service, secret, old_version)
            log("rolled_back", service=service)
        for secret, version in new_versions.items():
            secrets.add_version(secret, json.dumps(info))  # keep "latest" working
            secrets.disable_version(version)
            log("replacement_version_disabled", version=version)
        _undo_replacement(new_account, new_key_name, accounts, keys, log)
        return finish(ABORTED, str(err))

    # Cut off: the key, then the whole account unless something runs as it.
    keys.disable(incident.old_key)
    log("old_key_disabled", key=incident.old_key)
    for holder in holders:
        secrets.disable_version(holder.version)
        log("old_version_disabled", version=holder.version)
    if runtime:
        return finish(KEY_ONLY, f"{account} is the runtime identity of {', '.join(runtime)}; disabling it "
                      "would stop those services, so only the key was disabled. Tokens minted from the key "
                      "keep working until they expire (up to an hour). A human should move those services.")
    accounts.disable(account)
    log("old_account_disabled", account=account)
    return finish(RETIRED)


def _undo_replacement(new_account, new_key_name, accounts, keys, log) -> None:
    for action, call in (("replacement_key_deleted", lambda: keys.delete(new_key_name)),
                         ("replacement_account_deleted", lambda: accounts.delete(new_account))):
        try:
            call()
            log(action)
        except Exception as err:  # noqa: BLE001
            log(f"{action}_failed", error=type(err).__name__)


def prove_service_account_key(
    info: dict[str, Any],
    *,
    mint: Callable[[dict[str, Any]], str | None],
    probe_mint: Callable[[dict[str, Any]], ProbeResult],
    probe_access: Callable[[str], ProbeResult],
    stable: int = 3,
    interval: float = 10.0,
    max_seconds: float = 1500.0,
    canary_attempts: int = 6,
    on_event: Callable[[dict[str, Any]], None] = lambda _: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Mint a canary token now, then watch until the canary is refused AND the
    key can no longer mint, ``stable`` times in a row each. Start this before
    the cut-off: the canary stands in for tokens an attacker already holds.

    A brand-new key can take about a minute before it mints, so minting the
    canary is retried ``canary_attempts`` times before concluding it cannot."""
    canary = None
    for attempt in range(canary_attempts):
        canary = mint(info)
        if canary or attempt == canary_attempts - 1:
            break
        sleep(interval)
    on_event({"event": "canary", "minted": bool(canary)})
    started = clock()
    deadline = started + max_seconds
    streak = {"mint": 0, "canary": 0}
    first_dead: dict[str, float | None] = {"mint": None, "canary": None if canary else started}
    if not canary:
        streak["canary"] = stable  # nothing to watch: the key was already unable to mint
    probes = 0
    while clock() < deadline and (streak["mint"] < stable or streak["canary"] < stable):
        checks = [("mint", lambda: probe_mint(info))]
        if canary and streak["canary"] < stable:
            checks.append(("canary", lambda: probe_access(canary)))
        for name, check in checks:
            if streak[name] >= stable:
                continue
            result = check()
            probes += 1
            on_event({"event": "probe", "target": name, **result.as_dict()})
            if result.verdict == Verdict.DEAD:
                streak[name] += 1
                if first_dead[name] is None:
                    first_dead[name] = result.at
            elif result.verdict == Verdict.ALIVE:
                streak[name], first_dead[name] = 0, None
        if streak["mint"] < stable or streak["canary"] < stable:
            sleep(interval)
    dead = streak["mint"] >= stable and streak["canary"] >= stable
    verdict = {
        "event": "verdict",
        "dead": dead,
        "canary_minted": bool(canary),
        "seconds_until_key_cannot_mint": None if first_dead["mint"] is None else round(first_dead["mint"] - started, 1),
        "seconds_until_canary_refused": None if first_dead["canary"] is None else round(first_dead["canary"] - started, 1),
        "probes": probes,
    }
    on_event(verdict)
    return verdict
