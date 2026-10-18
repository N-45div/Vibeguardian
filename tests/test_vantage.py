import pytest
import requests

from fakes import FakeHttp, FakeResponse
from vibeguardian.leaks import Leak
from vibeguardian.pipeline import prove
from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.secret import fingerprint
from vibeguardian.vantage import IAM_CREDENTIALS, id_token, parse_vantages, vantage_check

KEY = "AIza" + "Z" * 35  # built at runtime so no key-shaped literal sits in the source
URL = "https://vg-vantage-9.europe-west1.run.app"


def leak():
    return Leak("google_api_key", "GCP API key", "app.py", 3, "c1", KEY)


def answer(verdict, fp=None, status=400, reason="API_KEY_INVALID"):
    return FakeResponse(200, {"region": "europe-west1", "fingerprint": fp or fingerprint(KEY),
                              "verdict": verdict, "http_status": status, "reason": reason, "latency_ms": 90})


def test_parse_vantages():
    assert parse_vantages([f"europe-west1={URL}/"]) == {"europe-west1": URL}
    with pytest.raises(ValueError):
        parse_vantages(["europe-west1"])
    with pytest.raises(ValueError):
        parse_vantages(["x=http://insecure"])


def test_id_token_is_minted_for_the_audience():
    http = FakeHttp({("POST", f"{IAM_CREDENTIALS}/projects/-/serviceAccounts/p@x:generateIdToken"):
                     FakeResponse(200, {"token": "tok"})})
    assert id_token(http, "p@x", URL) == "tok"
    assert http.calls[0][2]["json"] == {"audience": URL, "includeEmail": True}


def test_vantage_check_passes_the_key_in_the_body_with_the_token():
    http = FakeHttp({("POST", f"{URL}/probe"): answer("dead")})
    result = vantage_check(URL, "tok", session=http)(KEY)
    assert result.verdict == Verdict.DEAD and result.reason == "API_KEY_INVALID"
    _, _, call = http.calls[0]
    assert call["json"] == {"key": KEY}
    assert call["headers"] == {"Authorization": "Bearer tok"}


@pytest.mark.parametrize("response, reason", [
    (FakeResponse(403, {}), "VANTAGE_HTTP_403"),
    (FakeResponse(200, {"oops": 1}), "VANTAGE_BAD_ANSWER"),
    (answer("dead", fp="sha256:000000000000"), "VANTAGE_WRONG_KEY"),
])
def test_anything_but_a_clear_answer_about_this_key_is_unknown(response, reason):
    result = vantage_check(URL, "tok", session=FakeHttp({("POST", f"{URL}/probe"): response}))(KEY)
    assert result.verdict == Verdict.UNKNOWN and result.reason == reason


def test_a_token_that_cannot_be_minted_makes_the_vantage_unknown_and_is_tried_once():
    tries = []

    def fail():
        tries.append(1)
        raise RuntimeError("no permission")

    check = vantage_check(URL, fail, session=FakeHttp({}))
    assert [check(KEY).reason for _ in range(2)] == ["VANTAGE_NO_TOKEN"] * 2
    assert tries == [1]


def test_the_token_is_minted_lazily_on_the_first_probe():
    tries = []
    http = FakeHttp({("POST", f"{URL}/probe"): answer("dead")})
    check = vantage_check(URL, lambda: tries.append(1) or "tok", session=http)
    assert tries == []
    check(KEY)
    check(KEY)
    assert tries == [1]


def test_an_unreachable_vantage_is_unknown():
    class Down:
        def post(self, *a, **k):
            raise requests.ConnectionError("down")

    assert vantage_check(URL, "tok", session=Down())(KEY).reason == "VANTAGE_UNREACHABLE"


def probe_seq(*verdicts):
    queue = list(verdicts)

    def check(_key):
        v = queue.pop(0) if len(queue) > 1 else queue[0]
        return ProbeResult(v, 400 if v == Verdict.DEAD else 200, None, 1, 0.0)

    return check


def run(checks, **kw):
    return prove([leak()], checks, stable=3, interval=0, max_seconds=1, sleep=lambda s: None, **kw)


def test_dead_only_when_every_answering_vantage_proved_it():
    proof = run({
        "runner": probe_seq(Verdict.DEAD),
        "europe-west1": probe_seq(Verdict.ALIVE, Verdict.DEAD),
        "asia-northeast1": probe_seq(Verdict.UNKNOWN),
    })["keys"][fingerprint(KEY)]
    assert proof["dead"] is True and proof["state"] == "proven_dead"
    assert proof["unreachable"] == ["asia-northeast1"]
    assert proof["vantages"]["europe-west1"]["flaps"] == 0 and proof["vantages"]["europe-west1"]["accepted"] == 1
    assert proof["rejected"] == 6


def test_one_vantage_where_the_key_still_works_means_alive():
    proof = run({"runner": probe_seq(Verdict.DEAD), "europe-west1": probe_seq(Verdict.ALIVE)})["keys"][fingerprint(KEY)]
    assert proof["dead"] is False and proof["state"] == "alive"
    assert proof["vantages"]["europe-west1"]["state"] == "alive"


def test_every_probe_event_names_its_vantage():
    events = []
    run({"runner": probe_seq(Verdict.DEAD), "europe-west1": probe_seq(Verdict.DEAD)}, on_probe=events.append)
    assert {e["vantage"] for e in events} == {"runner", "europe-west1"}
    assert len(events) == 6
