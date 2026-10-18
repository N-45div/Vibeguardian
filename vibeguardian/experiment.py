"""Measure how long a deleted Google API key keeps working.

This is the experiment behind VibeGuardian's headline number. It creates a
throwaway key restricted to one cheap read-only API, waits until Google
accepts it, deletes it, and probes until Google rejects it consistently.
The throwaway key is always deleted, even if a step fails.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass
from typing import Any, Callable

from vibeguardian.probe import ProbeResult, Verdict, watch
from vibeguardian.secret import fingerprint

GEMINI_ONLY = {"apiTargets": [{"service": "generativelanguage.googleapis.com"}]}


@dataclass
class TimeToDead:
    key_name: str
    key_fingerprint: str
    created_at: float
    alive_at: float | None
    lookup_matched: bool | None
    deleted_at: float | None
    first_dead_at: float | None
    stable_dead_at: float | None
    reached: bool
    flaps: int
    probes_after_delete: int

    @property
    def seconds_to_first_dead(self) -> float | None:
        if self.deleted_at is None or self.first_dead_at is None:
            return None
        return round(self.first_dead_at - self.deleted_at, 1)

    @property
    def seconds_to_stable_dead(self) -> float | None:
        if self.deleted_at is None or self.stable_dead_at is None:
            return None
        return round(self.stable_dead_at - self.deleted_at, 1)

    def as_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["seconds_to_first_dead"] = self.seconds_to_first_dead
        out["seconds_to_stable_dead"] = self.seconds_to_stable_dead
        return out


def time_to_dead(
    api: Any,
    project: str,
    check: Callable[[str], ProbeResult],
    *,
    label: str,
    interval: float = 10.0,
    stable: int = 6,
    max_seconds: float = 2400.0,
    warmup: int = 0,
    warmup_interval: float = 2.0,
    on_event: Callable[[dict[str, Any]], None] = lambda _: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> TimeToDead:
    created = api.create(project, label, GEMINI_ONLY)
    name = created["name"]
    deleted = False
    try:
        key = api.key_string(name)
        result = TimeToDead(
            key_name=name,
            key_fingerprint=fingerprint(key),
            created_at=clock(),
            alive_at=None,
            lookup_matched=None,
            deleted_at=None,
            first_dead_at=None,
            stable_dead_at=None,
            reached=False,
            flaps=0,
            probes_after_delete=0,
        )
        on_event({"event": "created", "key": name, "fingerprint": result.key_fingerprint})

        def emit(phase: str) -> Callable[[ProbeResult], None]:
            return lambda r: on_event({"event": "probe", "phase": phase, **r.as_dict()})

        alive = watch(
            lambda: check(key),
            until=Verdict.ALIVE,
            stable=1,
            interval=5.0,
            max_seconds=300.0,
            on_probe=emit("before_delete"),
            sleep=sleep,
            clock=clock,
        )
        if not alive.reached:
            on_event({"event": "never_alive"})
            return result
        result.alive_at = alive.first_at

        # Use the key the way an app (or an attacker) would before deleting it,
        # so any cache of "this key is valid" has a chance to fill.
        for _ in range(warmup):
            emit("warmup")(check(key))
            sleep(warmup_interval)

        result.lookup_matched = api.lookup(key) == name
        on_event({"event": "lookup", "matched": result.lookup_matched})

        api.delete(name)
        deleted = True
        result.deleted_at = clock()
        on_event({"event": "deleted", "at": round(result.deleted_at, 3)})

        dead = watch(
            lambda: check(key),
            until=Verdict.DEAD,
            stable=stable,
            interval=interval,
            max_seconds=max_seconds,
            on_probe=emit("after_delete"),
            sleep=sleep,
            clock=clock,
        )
        result.reached = dead.reached
        result.first_dead_at = dead.first_at
        result.stable_dead_at = dead.stable_at
        result.flaps = dead.flaps
        result.probes_after_delete = dead.probes
        on_event({"event": "summary", **result.as_dict()})
        return result
    finally:
        if not deleted:
            api.delete(name)
            on_event({"event": "cleanup_deleted", "key": name})


def access_cutoff(
    keys: Any,
    email: str,
    *,
    method: str,
    apply_cutoff: Callable[[], Any],
    undo_cutoff: Callable[[Any], None],
    probe_mint: Callable[[dict[str, Any]], ProbeResult],
    mint: Callable[[dict[str, Any]], str | None],
    probe_access: Callable[[str], ProbeResult],
    interval: float = 10.0,
    stable: int = 3,
    max_seconds: float = 1200.0,
    gap_seconds: float = 0.0,
    on_event: Callable[[dict[str, Any]], None] = lambda _: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Time how long one cut-off method takes to stop a token stolen before
    the key was disabled. Always undoes the method and deletes the key.

    ``gap_seconds`` waits (probing) between disabling the key and applying the
    method, to separate the effect of each step."""
    name, info = keys.create(email)
    on_event({"event": "created", "method": method, "key": name, "fingerprint": fingerprint(info["private_key"])})
    undo_state: Any = None
    applied = False
    try:
        ready = watch(lambda: probe_mint(info), until=Verdict.ALIVE, stable=1, interval=5.0, max_seconds=300.0,
                      sleep=sleep, clock=clock)
        token = _mint_with_retry(mint, info, sleep) if ready.reached else None
        if not token:
            on_event({"event": "never_minted"})
            return {"method": method, "reached": False}
        before = probe_access(token)
        on_event({"event": "probe", "phase": "before", **before.as_dict()})
        keys.disable(name)
        key_disabled_at = clock()
        on_event({"event": "key_disabled", "at": round(key_disabled_at, 3)})
        gap_alive = 0
        while clock() - key_disabled_at < gap_seconds:
            sleep(interval)
            r = probe_access(token)
            gap_alive += r.verdict == Verdict.ALIVE
            on_event({"event": "probe", "phase": "key_disabled_only", **r.as_dict()})
        undo_state = apply_cutoff()
        applied = True
        cut_at = clock()
        on_event({"event": "cutoff_applied", "method": method, "at": round(cut_at, 3)})
        result = watch(
            lambda: probe_access(token), until=Verdict.DEAD, stable=stable, interval=interval,
            max_seconds=max_seconds,
            on_probe=lambda r: on_event({"event": "probe", "phase": "after_cutoff", **r.as_dict()}),
            sleep=sleep, clock=clock,
        )
        summary = {
            "method": method,
            "reached": result.reached,
            "token_had_access_before": before.verdict == Verdict.ALIVE,
            "seconds_until_stolen_token_cut": None if result.first_at is None else round(result.first_at - cut_at, 1),
            "gap_seconds": gap_seconds,
            "token_alive_probes_during_gap": gap_alive,
            "flaps": result.flaps,
            "probes": result.probes,
        }
        on_event({"event": "summary", **summary})
        return summary
    finally:
        if applied:
            undo_cutoff(undo_state)
            on_event({"event": "cutoff_undone", "method": method})
        keys.delete(name)
        on_event({"event": "cleanup_deleted", "key": name})


def _mint_with_retry(mint, info, sleep, attempts: int = 6, interval: float = 10.0):
    """A brand-new key can mint once and then fail for a while: retry."""
    for attempt in range(attempts):
        token = mint(info)
        if token or attempt == attempts - 1:
            return token
        sleep(interval)
    return None


class _Stream:
    """Tracks one probe stream until it is seen DEAD ``stable`` times in a row."""

    def __init__(self, stable: int):
        self.stable = stable
        self.streak = 0
        self.first_dead_at: float | None = None
        self.stable_dead_at: float | None = None

    def add(self, result: ProbeResult) -> None:
        if self.stable_dead_at is not None:
            return
        if result.verdict == Verdict.DEAD:
            self.streak += 1
            if self.first_dead_at is None:
                self.first_dead_at = result.at
            if self.streak >= self.stable:
                self.stable_dead_at = result.at
        elif result.verdict == Verdict.ALIVE:
            self.streak = 0
            self.first_dead_at = None


def token_survival(
    keys: Any,
    email: str,
    *,
    probe_mint: Callable[[dict[str, Any]], ProbeResult],
    mint: Callable[[dict[str, Any]], str | None],
    probe_token: Callable[[str], ProbeResult],
    interval: float = 30.0,
    stable: int = 3,
    max_seconds: float = 4200.0,
    on_event: Callable[[dict[str, Any]], None] = lambda _: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Disable a fresh service-account key and time two things separately:
    when the key stops minting tokens, and when a token minted before the
    disable stops working. The key is always deleted at the end."""
    name, info = keys.create(email)
    on_event({"event": "created", "key": name, "fingerprint": fingerprint(info["private_key"])})
    try:
        ready = watch(
            lambda: probe_mint(info), until=Verdict.ALIVE, stable=1, interval=5.0, max_seconds=300.0,
            sleep=sleep, clock=clock,
        )
        if not ready.reached:
            on_event({"event": "never_minted"})
            return {"reached": False}
        token = _mint_with_retry(mint, info, sleep)
        if not token:
            on_event({"event": "never_minted"})
            return {"reached": False}
        before = probe_token(token)
        on_event({"event": "probe", "phase": "token_before_disable", **before.as_dict()})

        keys.disable(name)
        disabled_at = clock()
        on_event({"event": "disabled", "at": round(disabled_at, 3)})

        minting, stolen = _Stream(stable), _Stream(stable)
        deadline = disabled_at + max_seconds
        while stolen.stable_dead_at is None and clock() < deadline:
            if minting.stable_dead_at is None:
                m = probe_mint(info)
                minting.add(m)
                on_event({"event": "probe", "phase": "mint_after_disable", **m.as_dict()})
            t = probe_token(token)
            stolen.add(t)
            on_event({"event": "probe", "phase": "token_after_disable", **t.as_dict()})
            if stolen.stable_dead_at is None:
                sleep(interval)

        def since(at: float | None) -> float | None:
            return None if at is None else round(at - disabled_at, 1)

        summary = {
            "reached": stolen.stable_dead_at is not None,
            "seconds_until_key_stops_minting": since(minting.first_dead_at),
            "seconds_until_stolen_token_stops": since(stolen.first_dead_at),
            "token_alive_before_disable": before.verdict == Verdict.ALIVE,
        }
        on_event({"event": "summary", **summary})
        return summary
    finally:
        keys.delete(name)
        on_event({"event": "cleanup_deleted", "key": name})
