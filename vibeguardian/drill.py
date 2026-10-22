"""A live drill, with Gemini as the judge.

One throwaway Gemini-only key: wait until Gemini answers with it, use it a few
times, delete it, then keep asking Google from several places, in rounds, until
every place that answers has refused the deleted key ``stable`` rounds in a
row. A round is two calls made at the same time: the read-only model list, and
one five-token question to Gemini. Either call answering means the deleted key
still worked there; both refusing is a refusal; anything else (a timeout, a
5xx) proves nothing and neither extends nor breaks a streak.

The key's value exists only in a local variable here. The record that ``save``
receives, and that a page shows, carries its fingerprint and resource name only.
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from vibeguardian.probe import GEMINI_MODEL, GEMINI_PROMPT, GeminiAnswer, Verdict, ask_gemini, probe
from vibeguardian.secret import fingerprint

PREFIX = "vg-live-"
RESTRICTIONS = {"apiTargets": [{"service": "generativelanguage.googleapis.com"}]}


@dataclass(frozen=True)
class Place:
    name: str  # the region the calls leave from
    label: str  # what a person reads: "Belgium"
    round: Callable[[str], dict[str, Any]]  # key -> {"list": {...}, "ask": {..., "answer"}}


def local_round(key: str) -> dict[str, Any]:
    """One round from this machine: list models and ask Gemini at the same time."""
    with ThreadPoolExecutor(max_workers=2) as pool:
        listing = pool.submit(probe, key)
        asked = pool.submit(ask_gemini, key)
        return {"list": listing.result().as_dict(), "ask": asked.result().as_dict()}


def combine(result: dict[str, Any]) -> str:
    """One verdict for a round: alive if either call worked, dead if both refused, else unknown."""
    verdicts = {(result.get(part) or {}).get("verdict") for part in ("list", "ask")}
    if Verdict.ALIVE.value in verdicts:
        return Verdict.ALIVE.value
    if verdicts == {Verdict.DEAD.value}:
        return Verdict.DEAD.value
    return Verdict.UNKNOWN.value


def _parallel(calls: list[Callable[[], Any]]) -> list[Any]:
    with ThreadPoolExecutor(max_workers=max(1, len(calls))) as pool:
        return [f.result() for f in [pool.submit(call) for call in calls]]


def sweep(keys: Any, project: str, *, older_than: float = 600.0, clock: Callable[[], float] = time.time) -> list[str]:
    """Delete live-drill keys left behind by a drill that died part-way. Touches no other key."""
    removed = []
    for key in keys.list_keys(project):
        if not str(key.get("displayName", "")).startswith(PREFIX):
            continue
        created = key.get("createTime")
        try:
            age = clock() - datetime.fromisoformat(str(created).replace("Z", "+00:00")).timestamp()
        except ValueError:
            continue
        if age > older_than:
            keys.delete(key["name"])
            removed.append(key["name"])
    return removed


def run_drill(
    drill_id: str,
    *,
    project: str,
    keys: Any,
    places: list[Place],
    save: Callable[[dict[str, Any]], None],
    ask: Callable[[str], GeminiAnswer] = ask_gemini,
    clock: Callable[[], float] = time.time,
    sleep: Callable[[float], None] = time.sleep,
    parallel: Callable[[list[Callable[[], Any]]], list[Any]] = _parallel,
    stable: int = 12,
    interval: float = 4.0,
    accept_timeout: float = 120.0,
    warm_uses: int = 5,
    max_prove_seconds: float = 360.0,
    unreachable_after: float = 60.0,
) -> dict[str, Any]:
    record: dict[str, Any] = {
        "id": drill_id, "status": "running", "started_at": round(clock(), 3), "model": GEMINI_MODEL,
        "prompt": GEMINI_PROMPT, "stable": stable, "fingerprint": None, "key": None, "steps": [],
        "deleted_at": None, "places": {p.name: {"label": p.label, "rounds": [], "streak": 0, "state": "waiting",
                                                "proven_at": None, "answered_after_delete": []} for p in places},
        "verdict": None,
    }

    def step(name: str, **fields: Any) -> None:
        record["steps"].append({"step": name, "at": round(clock(), 3), **fields})
        save(record)

    def finish(state: str, message: str, **fields: Any) -> dict[str, Any]:
        record["status"] = "done" if state != "failed" else "failed"
        record["verdict"] = {"state": state, "message": message, **fields}
        save(record)
        return record

    name = None
    secret = None
    deleted = False
    try:
        created = keys.create(project, f"{PREFIX}{drill_id}", RESTRICTIONS)
        name = created["name"]
        secret = keys.key_string(name)
        record["fingerprint"] = fingerprint(secret)
        record["key"] = name
        step("created", fingerprint=record["fingerprint"])

        began = clock()
        while True:
            answer = ask(secret)
            if answer.result.verdict == Verdict.ALIVE:
                step("accepted", answer=answer.answer, after_s=round(clock() - began, 1))
                break
            if clock() - began > accept_timeout:
                return finish("failed", "Google never accepted the new key, so there was nothing to prove.")
            sleep(5.0)
        for _ in range(warm_uses):
            answer = ask(secret)
            step("used", verdict=answer.result.verdict.value, answer=answer.answer)
            sleep(1.0)

        keys.delete(name)
        deleted = True
        record["deleted_at"] = round(clock(), 3)
        step("deleted")
        for place in record["places"].values():
            place["state"] = "proving"

        deadline = record["deleted_at"] + max_prove_seconds
        last_answer = {p.name: record["deleted_at"] for p in places}
        while True:
            proving = [p for p in places if record["places"][p.name]["state"] == "proving"]
            if not proving:
                break
            results = parallel([lambda p=p: _safe_round(p, secret) for p in proving])
            now = clock()
            t = round(now - record["deleted_at"], 1)
            for p, result in zip(proving, results):
                place = record["places"][p.name]
                verdict = combine(result)
                place["rounds"].append(_round_entry(t, verdict, result))
                if verdict == Verdict.DEAD.value:
                    place["streak"] += 1
                    last_answer[p.name] = now
                    if place["streak"] >= stable:
                        place["state"] = "proven_dead"
                        place["proven_at"] = t
                elif verdict == Verdict.ALIVE.value:
                    place["streak"] = 0
                    last_answer[p.name] = now
                    place["answered_after_delete"].append({
                        "t": t, "answer": (result.get("ask") or {}).get("answer"),
                        "how": "+".join(part for part in ("ask", "list")
                                        if (result.get(part) or {}).get("verdict") == Verdict.ALIVE.value)})
                elif now - last_answer[p.name] > unreachable_after:
                    place["state"] = "unreachable"
            save(record)
            if now + interval > deadline:
                break
            sleep(interval)

        revivals = [{"place": p.name, "label": record["places"][p.name]["label"], **a}
                    for p in places for a in record["places"][p.name]["answered_after_delete"]]
        states = {p.name: record["places"][p.name]["state"] for p in places}
        answering = [n for n, s in states.items() if s != "unreachable"]
        if answering and all(states[n] == "proven_dead" for n in answering):
            seconds = max(record["places"][n]["proven_at"] for n in answering)
            return finish("proven_dead", f"Proven dead from {len(answering)} of {len(places)} places "
                          f"{seconds:.1f} s after deletion.", seconds=seconds, revivals=revivals,
                          unreachable=[n for n, s in states.items() if s == "unreachable"])
        return finish("not_proven", "Not every place refused the deleted key in time.", revivals=revivals,
                      still_answering=[n for n, s in states.items() if s == "proving"],
                      unreachable=[n for n, s in states.items() if s == "unreachable"])
    except Exception as err:  # noqa: BLE001 - any failure ends the drill; the key must still go
        return finish("failed", f"The drill stopped: {type(err).__name__}.")
    finally:
        if name and not deleted:
            try:
                keys.delete(name)
            except Exception:  # noqa: BLE001 - the sweeper removes it on the next drill
                pass
        secret = None  # noqa: F841 - drop the only reference to the value


def _safe_round(place: Place, key: str) -> dict[str, Any]:
    try:
        return place.round(key)
    except Exception:  # noqa: BLE001 - a place that fails proves nothing this round
        return {"list": {"verdict": "unknown", "reason": "PLACE_ERROR"},
                "ask": {"verdict": "unknown", "reason": "PLACE_ERROR"}}


def _round_entry(t: float, verdict: str, result: dict[str, Any]) -> dict[str, Any]:
    listing, asked = result.get("list") or {}, result.get("ask") or {}
    return {"t": t, "verdict": verdict,
            "list": [listing.get("verdict"), listing.get("http_status"), listing.get("reason")],
            "ask": [asked.get("verdict"), asked.get("http_status"), asked.get("reason")],
            "answer": asked.get("answer")}
