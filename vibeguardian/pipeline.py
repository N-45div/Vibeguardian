"""The three CI steps of a leak response: respond, prove, gate.

respond  runs as the narrow ``vg-retirer`` identity and retires each leaked
         Google API key it can find in the secret detection report.
prove    recovers the leaked values from the repository on its own and asks
         Google whether they still work, from the CI runner and, through the
         vantage services, from other regions. Its only identity, vg-prover,
         can call those services and nothing else.
gate     fails the pipeline while leaked keys remain in the code, so the
         branch stays red until the fix lands, and reports what happened.

Only fingerprints and resource names are written to the job artifacts.
"""

from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable

from vibeguardian.leaks import Leak, read_leaks
from vibeguardian.probe import ProbeResult, Verdict, watch
from vibeguardian.secret import redact


def respond(
    leaks: list[Leak],
    retire_one: Callable[[Leak], dict[str, Any]],
) -> dict[str, Any]:
    responses = []
    for leak in leaks:
        if leak.kind != "google_api_key":
            continue
        try:
            incident = retire_one(leak)
        except Exception as err:  # noqa: BLE001 - record it; the prover still runs
            incident = {"outcome": "error", "reason": redact(f"{type(err).__name__}: {err}", leak.value or "")}
        responses.append({"leak": leak.public(), "incident": incident})
    return {
        "pipeline_id": os.environ.get("CI_PIPELINE_ID"),
        "commit": os.environ.get("CI_COMMIT_SHA"),
        "leaks": [leak.public() for leak in leaks],
        "responses": responses,
    }


def _watch_one(
    value: str,
    fp: str | None,
    check: Callable[[str], ProbeResult],
    *,
    stable: int,
    interval: float,
    max_seconds: float,
    watch_label: str,
    on_probe: Callable[[dict[str, Any]], None],
    sleep: Callable[[float], None],
    clock: Callable[[], float],
) -> dict[str, Any]:
    """Watch one key from one vantage point until Google rejects it ``stable`` times in a row."""
    seen = {Verdict.ALIVE: 0, Verdict.DEAD: 0, Verdict.UNKNOWN: 0}

    def record(r: ProbeResult) -> None:
        seen[r.verdict] += 1
        on_probe({"fingerprint": fp, **r.as_dict()})

    started = clock()
    result = watch(lambda: check(value), until=Verdict.DEAD, stable=stable, interval=interval,
                   max_seconds=max_seconds, on_probe=record, sleep=sleep, clock=clock)
    if result.reached:
        state = "proven_dead"
    elif seen[Verdict.ALIVE]:
        state = "alive"
    elif seen[Verdict.DEAD]:
        state = "rejected_not_yet_proven"
    else:
        state = "unknown"
    return {
        "dead": result.reached,
        "state": state,
        "accepted": seen[Verdict.ALIVE],
        "rejected": seen[Verdict.DEAD],
        "watch": watch_label,
        "probes": result.probes,
        "flaps": result.flaps,
        "seconds_watched": round(clock() - started, 1),
        "first_dead_at": result.first_at,
        "stable_dead_at": result.stable_at,
    }


def _combine(per_vantage: dict[str, dict[str, Any]], watch_label: str) -> dict[str, Any]:
    """One verdict from several vantage points: dead only if every one that answered proved it.

    A vantage that never got an answer from Google (all UNKNOWN, such as an
    unreachable relay) is listed as unreachable; it cannot prove or disprove.
    """
    answered = {n: v for n, v in per_vantage.items() if v["state"] != "unknown"}
    dead = bool(answered) and all(v["dead"] for v in answered.values())
    if dead:
        state = "proven_dead"
    elif any(v["accepted"] for v in answered.values()):
        state = "alive"
    elif answered:
        state = "rejected_not_yet_proven"
    else:
        state = "unknown"
    firsts = [v["first_dead_at"] for v in answered.values() if v["first_dead_at"]]
    stables = [v["stable_dead_at"] for v in answered.values() if v["stable_dead_at"]]
    return {
        "dead": dead,
        "state": state,
        "accepted": sum(v["accepted"] for v in per_vantage.values()),
        "rejected": sum(v["rejected"] for v in per_vantage.values()),
        "watch": watch_label,
        "probes": sum(v["probes"] for v in per_vantage.values()),
        "flaps": sum(v["flaps"] for v in per_vantage.values()),
        "seconds_watched": max(v["seconds_watched"] for v in per_vantage.values()),
        "first_dead_at": min(firsts) if firsts else None,
        "stable_dead_at": max(stables) if dead and stables else None,
        "unreachable": sorted(n for n in per_vantage if n not in answered),
        "vantages": per_vantage,
    }


def prove(
    leaks: list[Leak],
    check: Callable[[str], ProbeResult] | dict[str, Callable[[str], ProbeResult]],
    *,
    stable: int = 12,
    interval: float = 5.0,
    max_seconds: float = 1200.0,
    responder_failed: set[str] | None = None,
    unretired_seconds: float = 30.0,
    on_probe: Callable[[dict[str, Any]], None] = lambda _: None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Probe every leaked Google key until Google rejects it ``stable`` times in a row.

    ``check`` is one probe, or a probe per vantage point (``{"europe-west1":
    ...}``). With several, every vantage watches in parallel, and the key is
    proven dead only when each one that got an answer from Google proved it.

    ``responder_failed`` only sets how long to watch: a key whose retirement
    the responder reports as failed gets a short check instead of the full
    watch. Every other key, including one Google no longer recognises, gets
    the full watch. The verdict always comes from Google, never from the
    responder.
    """
    verdicts = {}
    failed = responder_failed or set()
    lock = threading.Lock()

    def locked(event: dict[str, Any]) -> None:
        with lock:
            on_probe(event)

    for leak in leaks:
        if leak.kind != "google_api_key" or not leak.value:
            continue
        expect_dead = leak.fingerprint not in failed
        options = {
            "stable": stable,
            "interval": interval,
            "max_seconds": max_seconds if expect_dead else unretired_seconds,
            "watch_label": "full" if expect_dead else "short (responder reported a failure)",
            "sleep": sleep,
            "clock": clock,
        }
        if not isinstance(check, dict):
            verdicts[leak.fingerprint] = _watch_one(leak.value, leak.fingerprint, check, on_probe=on_probe,
                                                    **options)
            continue
        with ThreadPoolExecutor(max_workers=len(check)) as pool:
            futures = {
                name: pool.submit(
                    _watch_one, leak.value, leak.fingerprint, probe_fn,
                    on_probe=lambda e, name=name: locked({**e, "vantage": name}), **options,
                )
                for name, probe_fn in check.items()
            }
            per_vantage = {name: future.result() for name, future in futures.items()}
        verdicts[leak.fingerprint] = _combine(per_vantage, options["watch_label"])
    return {"stable_required": stable, "keys": verdicts}


def gate(
    leaks: list[dict[str, Any]],
    incident: dict[str, Any],
    proof: dict[str, Any],
    present: dict[str, list[str]],
) -> tuple[bool, list[str]]:
    """Return (pipeline may pass, report lines).

    ``leaks`` are the public views of the findings, ``present`` maps a
    fingerprint to the files at HEAD that still contain that value.

    - A value still in the current code keeps the pipeline red.
    - A value only in history passes, but only if Google rejected it on every
      probe of a full watch: a dead key in history is harmless, so no history
      rewrite is needed.
    - Anything not proven dead keeps the pipeline red.
    """
    if not leaks:
        return True, ["No leaked secrets found in this push."]
    outcomes = {r["leak"]["fingerprint"]: r["incident"].get("outcome") for r in incident.get("responses", [])}
    lines, ok = [], True
    for leak in leaks:
        where = f"{leak['file']}:{leak['line']} ({leak['commit'][:8]})"
        if leak["kind"] != "google_api_key":
            lines.append(f"UNSUPPORTED {leak['rule']} at {where}: needs a human")
            ok = False
            continue
        fp = leak["fingerprint"]
        dead = bool(proof.get("keys", {}).get(fp, {}).get("dead"))
        files = present.get(fp, [])
        outcome = outcomes.get(fp, "no response from the responder")
        state = "PROVEN DEAD" if dead else "NOT PROVEN DEAD"
        if files:
            lines.append(f"{fp} at {where}: {outcome}, {state}, STILL IN THE CODE ({', '.join(files)})")
            ok = False
        elif dead:
            lines.append(f"{fp} at {where}: {outcome}, {state}, only in history: no rewrite needed")
        else:
            lines.append(f"{fp} at {where}: {outcome}, {state}, only in history but still treat it as live")
            ok = False
    if not ok:
        lines.append("This pipeline stays red until every leaked key is out of the code and proven dead.")
    return ok, lines


def write_json(path: str, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")


def read_json(path: str) -> dict[str, Any]:
    p = Path(path)
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}


__all__ = ["respond", "prove", "gate", "read_leaks", "write_json", "read_json"]
