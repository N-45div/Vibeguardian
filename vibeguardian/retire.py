"""Retire a leaked Google API key without breaking the services that use it.

Order is fixed: roll out the replacement, check every consumer is healthy on
it, and only then delete the old key. If anything fails, everything rolled so
far goes back to the old version, the replacement is deleted, the old key is
left alone, and the incident is handed to a human.

Proving the old key is dead is deliberately NOT done here. A separate job
does that, so the code that retired the key never grades its own work.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from vibeguardian.gcp.cloudrun import is_ready, secret_id, version_number
from vibeguardian.probe import ProbeResult, Verdict, watch
from vibeguardian.secret import fingerprint

RETIRED = "retired"
ABORTED = "aborted"
NOT_OURS = "not_ours"
ALREADY_DELETED = "already_deleted"
NEEDS_APPROVAL = "needs_approval"
DRY_RUN = "dry_run"


@dataclass
class Incident:
    leaked_fingerprint: str
    outcome: str = ""
    old_key: str | None = None
    new_key: str | None = None
    new_fingerprint: str | None = None
    secrets: list[dict[str, str]] = field(default_factory=list)
    services: list[dict[str, Any]] = field(default_factory=list)
    reason: str | None = None
    approved_by: str | None = None
    replacement_restrictions: dict[str, Any] | None = None
    started_at: float = 0.0
    finished_at: float = 0.0
    timeline: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items()}


HealthCheck = Callable[[dict[str, Any], str], tuple[bool, str]]


def retire(
    leaked: str,
    project: str,
    *,
    keys: Any,
    secrets: Any,
    run: Any,
    check_key: Callable[[str], ProbeResult],
    check_health: HealthCheck,
    dry_run: bool = False,
    health_attempts: int = 10,
    health_interval: float = 6.0,
    label: str = "rotated by VibeGuardian",
    approval: Callable[[list[str]], str | None] = lambda services: None,
    approved_by: str | None = None,
    limit_replacement: Callable[[str], dict[str, Any] | None] = lambda old_key: None,
    on_event: Callable[[dict[str, Any]], None] = lambda _: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> Incident:
    incident = Incident(leaked_fingerprint=fingerprint(leaked), started_at=clock())

    def log(event: str, **data: Any) -> None:
        entry = {"event": event, "at": round(clock(), 3), **data}
        incident.timeline.append(entry)
        on_event(entry)

    def finish(outcome: str, reason: str | None = None) -> Incident:
        incident.outcome, incident.reason, incident.finished_at = outcome, reason, clock()
        log("finished", outcome=outcome, reason=reason)
        return incident

    # 1. Which key is this, and who uses it?
    try:
        incident.old_key = keys.lookup(leaked)
    except LookupError:
        return finish(NOT_OURS, "Google does not know this key in any project we can see")
    log("identified", key=incident.old_key)
    # Google still finds a deleted key for 30 days (it can be undeleted). A
    # leak seen again, say on a branch that carries it in history, must not
    # mint a replacement that nothing will ever use.
    deleted_at = keys.get(incident.old_key).get("deleteTime")
    if deleted_at:
        return finish(ALREADY_DELETED, f"Google already deleted this key at {deleted_at}")

    holders = secrets.find_holders(project, incident.leaked_fingerprint)
    uses = [use for holder in holders for use in run.consumers_of(project, holder.secret)]
    incident.secrets = [{"secret": h.secret, "old_version": h.version} for h in holders]
    services = sorted({use.service for use in uses})
    log("consumers_found", secrets=[h.secret for h in holders], services=services)

    # The policy decides whether a person must approve before anything changes.
    needs_person = approval(services)
    if needs_person and not approved_by:
        log("approval_needed", reason=needs_person)
        return finish(NEEDS_APPROVAL, needs_person)
    if approved_by:
        incident.approved_by = approved_by
        log("approved", by=approved_by, policy_reason=needs_person)
    if dry_run:
        return finish(DRY_RUN)

    # 2. Mint the replacement and wait until Google accepts it.
    incident.replacement_restrictions = limit_replacement(incident.old_key)
    replacement = keys.clone(incident.old_key, label, restrictions=incident.replacement_restrictions)
    incident.new_key = replacement["name"]
    new_value = keys.key_string(incident.new_key)
    incident.new_fingerprint = fingerprint(new_value)
    log("replacement_created", key=incident.new_key, fingerprint=incident.new_fingerprint,
        limited_to=[t["service"] for t in (incident.replacement_restrictions or {}).get("apiTargets", [])] or None)
    ready = watch(
        lambda: check_key(new_value), until=Verdict.ALIVE, stable=2, interval=5.0, max_seconds=300.0,
        sleep=sleep, clock=clock,
    )
    if not ready.reached:
        keys.delete(incident.new_key)
        log("replacement_deleted")
        return finish(ABORTED, "Google never accepted the replacement key")
    log("replacement_live")

    # 3. Roll every consumer onto the replacement, checking health as we go.
    new_versions: dict[str, str] = {}
    rolled: list[tuple[str, str, str]] = []  # (service, secret, old version number)
    try:
        for holder in holders:
            new_versions[holder.secret] = secrets.add_version(holder.secret, new_value)
            log("secret_version_added", secret=holder.secret, version=new_versions[holder.secret])
        for use in uses:
            holder = next(h for h in holders if secret_id(h.secret) == secret_id(use.secret))
            service = run.pin_secret(use.service, holder.secret, version_number(new_versions[holder.secret]))
            rolled.append((use.service, holder.secret, version_number(holder.version)))
            healthy, detail = _healthy(service, incident.new_fingerprint, check_health,
                                       health_attempts, health_interval, sleep)
            incident.services.append({"service": use.service, "revision": service.get("latestReadyRevision"),
                                      "healthy": healthy, "detail": detail})
            log("service_rolled", service=use.service, healthy=healthy, detail=detail)
            if not healthy:
                raise _Unhealthy(f"{use.service} unhealthy on the replacement: {detail}")
    except Exception as err:  # noqa: BLE001 - every failure takes the same safe path
        _roll_back(rolled, new_versions, incident.new_key, leaked, keys, secrets, run, log)
        return finish(ABORTED, str(err))

    # 4. Only now retire the old key and the versions that held it.
    keys.delete(incident.old_key)
    log("old_key_deleted", key=incident.old_key)
    for holder in holders:
        secrets.disable_version(holder.version)
        log("old_version_disabled", version=holder.version)
    return finish(RETIRED)


def used_api_restrictions(key: dict[str, Any], used: dict[str, int]) -> dict[str, Any] | None:
    """Restrictions for the replacement of a key that works on every API.

    Limits it to the APIs the key actually called. Returns None, which keeps
    the old restrictions, when the key is already restricted or no calls were
    seen (there is nothing to limit it to). If the limit turns out too tight,
    the health check after roll-out fails and the retirement rolls back.
    """
    restrictions = key.get("restrictions") or {}
    already = restrictions.get("apiTargets") or any(k.endswith("KeyRestrictions") for k in restrictions)
    if already or not used:
        return None
    return {"apiTargets": [{"service": service} for service in sorted(used)]}


class _Unhealthy(RuntimeError):
    pass


def _healthy(service: dict[str, Any], expected_fp: str, check: HealthCheck,
             attempts: int, interval: float, sleep: Callable[[float], None]) -> tuple[bool, str]:
    if not is_ready(service):
        return False, "new revision is not ready"
    detail = "no attempts"
    for attempt in range(attempts):
        ok, detail = check(service, expected_fp)
        if ok:
            return True, detail
        if attempt < attempts - 1:
            sleep(interval)
    return False, detail


def _roll_back(rolled, new_versions, new_key, old_value, keys, secrets, run, log) -> None:
    for service, secret, old_version in reversed(rolled):
        try:
            run.pin_secret(service, secret, old_version)
            log("rolled_back", service=service, version=old_version)
        except Exception as err:  # noqa: BLE001
            log("roll_back_failed", service=service, error=str(err))
    for secret, version in new_versions.items():
        # Put the old value back on top first: consumers that read "latest"
        # would otherwise hit the disabled replacement on their next start.
        try:
            restored = secrets.add_version(secret, old_value)
            log("old_value_restored_as_latest", secret=secret, version=restored)
        except Exception as err:  # noqa: BLE001
            log("restore_failed", secret=secret, error=str(err))
        try:
            secrets.disable_version(version)
            log("replacement_version_disabled", version=version)
        except Exception as err:  # noqa: BLE001
            log("disable_failed", version=version, error=str(err))
    try:
        keys.delete(new_key)
        log("replacement_deleted", key=new_key)
    except Exception as err:  # noqa: BLE001
        log("replacement_delete_failed", error=str(err))
