import json

import pytest

from vibeguardian.drill import PREFIX, Place, combine, run_drill, sweep
from vibeguardian.probe import GeminiAnswer, ProbeResult, Verdict

KEY = "AIza" + "D" * 35  # built at runtime so no key-shaped literal sits in the source


class FakeKeys:
    def __init__(self, fail_delete=False):
        self.deleted = []
        self.fail_delete = fail_delete

    def create(self, project, display_name, restrictions):
        self.display_name, self.restrictions = display_name, restrictions
        return {"name": f"projects/9/locations/global/keys/{display_name}"}

    def key_string(self, name):
        return KEY

    def delete(self, name):
        if self.fail_delete:
            raise RuntimeError("delete failed")
        self.deleted.append(name)


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def sleep(self, seconds):
        self.t += seconds


def answer(verdict, text=None):
    return GeminiAnswer(ProbeResult(verdict, 200 if verdict == Verdict.ALIVE else 400, None, 10, 0), text)


def scripted(verdicts):
    """A place whose rounds return these (list, ask) verdict pairs, then keep refusing."""
    rounds = iter(verdicts)

    def round_(key):
        assert key == KEY
        lv, av = next(rounds, ("dead", "dead"))
        return {"list": {"verdict": lv, "http_status": 400}, "ask": {"verdict": av, "http_status": 400,
                                                                  "answer": "ALIVE" if av == "alive" else None}}
    return round_


def run(places, *, ask=None, keys=None, **kwargs):
    clock = Clock()
    saved = []
    ask = ask or (lambda key: answer(Verdict.ALIVE, "ALIVE"))
    record = run_drill("d1", project="p", keys=keys or FakeKeys(), places=places, save=lambda r: saved.append(json.dumps(r)),
                       ask=ask, clock=clock, sleep=clock.sleep, parallel=lambda calls: [c() for c in calls],
                       stable=3, interval=4.0, **kwargs)
    return record, saved


def test_combine():
    assert combine({"list": {"verdict": "dead"}, "ask": {"verdict": "dead"}}) == "dead"
    assert combine({"list": {"verdict": "dead"}, "ask": {"verdict": "alive"}}) == "alive"
    assert combine({"list": {"verdict": "alive"}, "ask": {"verdict": "unknown"}}) == "alive"
    assert combine({"list": {"verdict": "dead"}, "ask": {"verdict": "unknown"}}) == "unknown"
    assert combine({}) == "unknown"


def test_a_clean_drill_is_proven_dead_and_the_key_never_reaches_a_record():
    keys = FakeKeys()
    record, saved = run([Place("us-central1", "Iowa", scripted([])), Place("europe-west1", "Belgium", scripted([]))],
                        keys=keys)
    assert record["status"] == "done" and record["verdict"]["state"] == "proven_dead"
    assert [s["step"] for s in record["steps"]] == ["created", "accepted"] + ["used"] * 5 + ["deleted"]
    assert keys.display_name == PREFIX + "d1" and keys.deleted == [record["key"]]
    assert keys.restrictions == {"apiTargets": [{"service": "generativelanguage.googleapis.com"}]}
    assert all(KEY not in s for s in saved)
    assert all(p["state"] == "proven_dead" and len(p["rounds"]) == 3 for p in record["places"].values())


def test_a_place_that_answers_after_deletion_is_recorded_and_its_streak_restarts():
    belgium = scripted([("dead", "dead"), ("alive", "alive"), ("dead", "dead")])
    record, _ = run([Place("europe-west1", "Belgium", belgium)])
    place = record["places"]["europe-west1"]
    assert place["answered_after_delete"] == [{"t": 4.0, "answer": "ALIVE", "how": "ask+list"}]
    assert len(place["rounds"]) == 5  # dead, alive, then three refusals in a row
    assert record["verdict"]["state"] == "proven_dead"
    assert record["verdict"]["revivals"][0]["label"] == "Belgium"


def test_timeouts_neither_count_nor_break_a_streak():
    record, _ = run([Place("asia-northeast1", "Tokyo", scripted([("dead", "dead"), ("dead", "unknown"), ("dead", "dead")]))])
    place = record["places"]["asia-northeast1"]
    assert [r["verdict"] for r in place["rounds"]] == ["dead", "unknown", "dead", "dead"]
    assert place["state"] == "proven_dead"


def test_a_place_that_never_answers_is_unreachable_and_left_out_of_the_proof():
    silent = scripted([("unknown", "unknown")] * 100)
    record, _ = run([Place("us-central1", "Iowa", scripted([])), Place("australia-southeast1", "Sydney", silent)],
                    unreachable_after=20)
    assert record["places"]["australia-southeast1"]["state"] == "unreachable"
    assert record["verdict"]["state"] == "proven_dead" and record["verdict"]["unreachable"] == ["australia-southeast1"]


def test_a_place_that_keeps_answering_is_not_proven():
    alive = scripted([("alive", "dead")] * 200)
    record, _ = run([Place("europe-west1", "Belgium", alive)], max_prove_seconds=40)
    assert record["verdict"]["state"] == "not_proven"
    assert record["verdict"]["still_answering"] == ["europe-west1"]


def test_a_key_google_never_accepts_fails_and_is_still_deleted():
    keys = FakeKeys()
    record, _ = run([Place("us-central1", "Iowa", scripted([]))], keys=keys, ask=lambda key: answer(Verdict.UNKNOWN),
                    accept_timeout=20)
    assert record["status"] == "failed" and record["verdict"]["state"] == "failed"
    assert keys.deleted == [record["key"]]


def test_a_place_that_raises_proves_nothing_that_round():
    def broken(key):
        raise ConnectionError("down")

    record, _ = run([Place("us-central1", "Iowa", scripted([])), Place("southamerica-east1", "São Paulo", broken)],
                    unreachable_after=12)
    assert record["places"]["southamerica-east1"]["rounds"][0]["verdict"] == "unknown"
    assert record["verdict"]["state"] == "proven_dead"


def test_a_failed_delete_ends_the_drill_as_failed():
    record, _ = run([Place("us-central1", "Iowa", scripted([]))], keys=FakeKeys(fail_delete=True))
    assert record["status"] == "failed" and "RuntimeError" in record["verdict"]["message"]


class SweepKeys(FakeKeys):
    def list_keys(self, project):
        return [
            {"name": "k/old", "displayName": PREFIX + "x", "createTime": "2026-10-22T10:00:00Z"},
            {"name": "k/new", "displayName": PREFIX + "y", "createTime": "2026-10-22T10:59:00Z"},
            {"name": "k/app", "displayName": "gemini-demo", "createTime": "2026-10-01T00:00:00Z"},
        ]


def test_sweep_removes_only_old_live_drill_keys():
    keys = SweepKeys()
    from datetime import datetime, timezone
    now = datetime(2026, 10, 22, 11, 0, tzinfo=timezone.utc).timestamp()
    assert sweep(keys, "p", older_than=600, clock=lambda: now) == ["k/old"]
    assert keys.deleted == ["k/old"]


@pytest.mark.parametrize("bad", [None, "not a time"])
def test_sweep_skips_keys_with_no_readable_time(bad):
    class K(FakeKeys):
        def list_keys(self, project):
            return [{"name": "k/x", "displayName": PREFIX + "x", "createTime": bad}]

    keys = K()
    assert sweep(keys, "p", clock=lambda: 2e9) == [] and keys.deleted == []
