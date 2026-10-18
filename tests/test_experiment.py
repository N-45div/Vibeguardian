import pytest

from vibeguardian.experiment import time_to_dead
from vibeguardian.probe import ProbeResult, Verdict

NAME = "projects/1/locations/global/keys/k1"


class FakeKeys:
    def __init__(self, lookup_name=NAME, fail_lookup=False):
        self.lookup_name = lookup_name
        self.fail_lookup = fail_lookup
        self.deleted = []

    def create(self, project, label, restrictions):
        return {"name": NAME}

    def key_string(self, name):
        return "the-secret"

    def lookup(self, key):
        if self.fail_lookup:
            raise RuntimeError("lookup broke")
        return self.lookup_name

    def delete(self, name):
        self.deleted.append(name)


def scripted(verdicts, clock):
    sequence = iter(verdicts)

    def check(key):
        assert key == "the-secret"
        return ProbeResult(next(sequence), 400, None, 5, clock["t"])

    return check


def run(api, verdicts, **kwargs):
    clock = {"t": 0.0}
    events = []

    def sleep(seconds):
        clock["t"] += seconds

    result = time_to_dead(
        api,
        "proj",
        scripted(verdicts, clock),
        label="t",
        sleep=sleep,
        clock=lambda: clock["t"],
        on_event=events.append,
        **kwargs,
    )
    return result, events


def test_measures_time_from_delete_to_stable_dead():
    api = FakeKeys()
    result, events = run(
        api,
        [Verdict.ALIVE, Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD],
        interval=10,
        stable=2,
    )
    assert result.reached
    assert result.lookup_matched
    assert result.seconds_to_first_dead == 10.0
    assert result.seconds_to_stable_dead == 20.0
    assert api.deleted == [NAME]


def test_events_never_contain_the_secret():
    _, events = run(FakeKeys(), [Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD], interval=10, stable=2)
    assert "the-secret" not in repr(events)


def test_warmup_uses_the_key_before_deleting_it():
    api = FakeKeys()
    verdicts = [Verdict.ALIVE] + [Verdict.ALIVE] * 3 + [Verdict.DEAD, Verdict.DEAD]
    result, events = run(api, verdicts, interval=10, stable=2, warmup=3)
    phases = [e["phase"] for e in events if e["event"] == "probe"]
    assert phases == ["before_delete", "warmup", "warmup", "warmup", "after_delete", "after_delete"]
    assert result.reached


def test_key_is_deleted_even_when_a_step_fails():
    api = FakeKeys(fail_lookup=True)
    with pytest.raises(RuntimeError):
        run(api, [Verdict.ALIVE], interval=10, stable=2)
    assert api.deleted == [NAME]


def test_key_that_never_works_is_still_cleaned_up():
    api = FakeKeys()
    result, _ = run(api, [Verdict.UNKNOWN] * 100, interval=10, stable=2)
    assert result.alive_at is None
    assert api.deleted == [NAME]
