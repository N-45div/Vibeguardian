import json

from vibeguardian.leaks import Leak
from vibeguardian.pipeline import gate, prove, respond
from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.secret import fingerprint

KEY = "AIza" + "C" * 35
GOOGLE = Leak("google_api_key", "gcp-api-key", "app.py", 4, "abcdef1234", KEY)
OTHER = Leak("unsupported", "aws-access-token", "infra.tf", 9, "abcdef1234", None)


def test_respond_retires_only_google_keys_and_never_records_values():
    calls = []
    incident = respond([GOOGLE, OTHER], lambda leak: calls.append(leak) or {"outcome": "retired"})
    assert calls == [GOOGLE]
    assert len(incident["leaks"]) == 2
    assert KEY not in json.dumps(incident)


def test_respond_records_a_crash_without_the_secret():
    def boom(leak):
        raise RuntimeError(f"could not use {leak.value}")

    incident = respond([GOOGLE], boom)
    record = incident["responses"][0]["incident"]
    assert record["outcome"] == "error"
    assert KEY not in json.dumps(incident)
    assert fingerprint(KEY) in record["reason"]


def test_prove_requires_a_stable_run_of_rejections():
    clock = {"t": 0.0}
    sequence = iter([Verdict.DEAD, Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD, Verdict.DEAD])

    def check(value):
        assert value == KEY
        return ProbeResult(next(sequence), 400, None, 1, clock["t"])

    proof = prove(
        [GOOGLE, OTHER], check, stable=3, interval=5,
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"],
    )
    verdict = proof["keys"][fingerprint(KEY)]
    assert verdict["dead"] and verdict["flaps"] == 1 and verdict["probes"] == 5
    assert KEY not in json.dumps(proof)


def test_prove_gives_unretired_keys_only_a_short_check():
    clock = {"t": 0.0}

    def check(value):
        return ProbeResult(Verdict.ALIVE, 200, None, 1, clock["t"])

    proof = prove(
        [GOOGLE], check, stable=3, interval=5, max_seconds=1200, responder_failed={fingerprint(KEY)}, unretired_seconds=20,
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"],
    )
    verdict = proof["keys"][fingerprint(KEY)]
    assert not verdict["dead"]
    assert verdict["state"] == "alive"
    assert verdict["seconds_watched"] <= 20
    assert verdict["watch"].startswith("short")


def test_prove_labels_rejections_that_are_not_yet_a_full_proof():
    clock = {"t": 0.0}

    def check(value):
        return ProbeResult(Verdict.DEAD, 400, None, 1, clock["t"])

    proof = prove(
        [GOOGLE], check, stable=12, interval=5, responder_failed={fingerprint(KEY)}, unretired_seconds=20,
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"],
    )
    verdict = proof["keys"][fingerprint(KEY)]
    assert verdict["state"] == "rejected_not_yet_proven"
    assert verdict["accepted"] == 0


RETIRED = {"responses": [{"leak": GOOGLE.public(), "incident": {"outcome": "retired"}}]}
DEAD = {"keys": {fingerprint(KEY): {"dead": True}}}


def test_gate_passes_clean_pushes():
    ok, lines = gate([], {}, {}, {})
    assert ok
    assert "No leaked secrets" in lines[0]


def test_gate_stays_red_while_the_key_is_in_the_current_code():
    ok, lines = gate([GOOGLE.public()], RETIRED, DEAD, {fingerprint(KEY): ["app.py"]})
    assert not ok
    assert "STILL IN THE CODE (app.py)" in lines[0]


def test_gate_passes_a_dead_key_left_only_in_history():
    ok, lines = gate([GOOGLE.public()], RETIRED, DEAD, {fingerprint(KEY): []})
    assert ok
    assert "only in history: no rewrite needed" in lines[0]


def test_gate_stays_red_for_a_key_in_history_that_is_not_proven_dead():
    ok, lines = gate([GOOGLE.public()], {}, {"keys": {}}, {fingerprint(KEY): []})
    assert not ok
    assert "no response from the responder" in lines[0]


def test_gate_stays_red_for_unsupported_secret_types():
    ok, lines = gate([OTHER.public()], {}, {}, {})
    assert not ok
    assert lines[0].startswith("UNSUPPORTED aws-access-token")
