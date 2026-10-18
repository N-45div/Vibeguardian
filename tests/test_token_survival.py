import pytest

from vibeguardian.experiment import token_survival
from vibeguardian.probe import ProbeResult, Verdict

# Deliberately not shaped like a real key, so secret scanners do not flag the fixture.
INFO = {"private_key": "fake-key-material-for-tests", "private_key_id": "kid", "client_email": "a@b"}


class FakeSaKeys:
    def __init__(self):
        self.disabled = []
        self.deleted = []

    def create(self, email):
        return "projects/-/serviceAccounts/a@b/keys/kid", dict(INFO)

    def disable(self, name):
        self.disabled.append(name)

    def delete(self, name):
        self.deleted.append(name)


def run(token_verdicts, mint_verdicts, **kwargs):
    clock = {"t": 0.0}
    keys = FakeSaKeys()
    tokens = iter(token_verdicts)
    mints = iter(mint_verdicts)
    events = []

    def result(v):
        return ProbeResult(v, None, None, 1, clock["t"])

    summary = token_survival(
        keys,
        "a@b",
        probe_mint=lambda info: result(next(mints)),
        mint=lambda info: "stolen-token",
        probe_token=lambda token: result(next(tokens)),
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
        clock=lambda: clock["t"],
        on_event=events.append,
        **kwargs,
    )
    return summary, keys, events


def test_times_key_and_stolen_token_separately():
    # mint: first ALIVE is the readiness check, then dies right after disable.
    mints = [Verdict.ALIVE] + [Verdict.DEAD] * 10
    # token: alive before disable, alive for 3 rounds after, then dead.
    tokens = [Verdict.ALIVE, Verdict.ALIVE, Verdict.ALIVE, Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD]
    summary, keys, events = run(tokens, mints, interval=60, stable=2)
    assert summary["reached"]
    assert summary["seconds_until_key_stops_minting"] == 0.0
    assert summary["seconds_until_stolen_token_stops"] == 180.0
    assert keys.disabled and keys.deleted


def test_private_key_never_appears_in_events():
    mints = [Verdict.ALIVE] + [Verdict.DEAD] * 5
    tokens = [Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD]
    _, _, events = run(tokens, mints, interval=60, stable=2)
    assert "fake-key-material-for-tests" not in repr(events)
    assert "stolen-token" not in repr(events)


def test_key_is_deleted_if_anything_fails():
    def boom(token):
        raise RuntimeError("probe broke")

    keys = FakeSaKeys()
    with pytest.raises(RuntimeError):
        token_survival(
            keys,
            "a@b",
            probe_mint=lambda info: ProbeResult(Verdict.ALIVE, None, None, 1, 0.0),
            mint=lambda info: "t",
            probe_token=boom,
            sleep=lambda s: None,
        )
    assert keys.deleted
