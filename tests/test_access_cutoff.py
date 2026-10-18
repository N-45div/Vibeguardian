import pytest

from vibeguardian.experiment import access_cutoff
from vibeguardian.probe import ProbeResult, Verdict

INFO = {"private_key": "fake-key-material-for-tests", "private_key_id": "kid", "client_email": "a@b"}


class Keys:
    def __init__(self):
        self.log = []

    def create(self, email):
        self.log.append("create")
        return "projects/-/serviceAccounts/a@b/keys/kid", dict(INFO)

    def disable(self, name):
        self.log.append("disable")

    def delete(self, name):
        self.log.append("delete")


def run(access, keys=None, fail_probe=False, **kw):
    clock = {"t": 0.0}
    keys = keys or Keys()
    seq = iter(access)

    def probe_access(token):
        if fail_probe:
            raise RuntimeError("probe broke")
        return ProbeResult(next(seq), 200, None, 1, clock["t"])

    def apply():
        keys.log.append("apply")
        return "undo-token"

    def undo(state):
        keys.log.append(f"undo:{state}")

    summary = access_cutoff(
        keys, "a@b", method="test", apply_cutoff=apply, undo_cutoff=undo,
        probe_mint=lambda info: ProbeResult(Verdict.ALIVE, None, None, 1, clock["t"]),
        mint=lambda info: "stolen", probe_access=probe_access,
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"], **kw,
    )
    return summary, keys


def test_times_the_cut_from_when_the_method_was_applied():
    summary, keys = run([Verdict.ALIVE, Verdict.ALIVE, Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD],
                        interval=10, stable=2)
    assert summary["reached"]
    assert summary["seconds_until_stolen_token_cut"] == 20.0
    assert keys.log == ["create", "disable", "apply", "undo:undo-token", "delete"]


def test_undo_and_delete_happen_even_when_a_probe_fails():
    keys = Keys()
    with pytest.raises(RuntimeError):
        run([], keys=keys, fail_probe=True)
    assert keys.log == ["create", "delete"]  # nothing applied yet, so nothing to undo
