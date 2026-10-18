import json
import re

from fakes import FakeHttp, FakeResponse
from vibeguardian.telemetry import ERROR, OK, WARN, build, export

T0 = 1792091411.0
RECORD = {
    "pipeline_id": "2952447335",
    "commit": "af530d6e",
    "leaks": [],
    "responses": [{
        "leak": {"fingerprint": "sha256:4ccada543d71", "file": "demo/app/main.py", "line": 31, "commit": "af530d6e"},
        "incident": {
            "leaked_fingerprint": "sha256:4ccada543d71",
            "outcome": "retired",
            "old_key": "projects/9/locations/global/keys/old",
            "new_key": "projects/9/locations/global/keys/new",
            "new_fingerprint": "sha256:030f2157953f",
            "reason": None,
            "started_at": T0,
            "finished_at": T0 + 26.0,
            "timeline": [
                {"event": "identified", "at": T0, "key": "projects/9/locations/global/keys/old"},
                {"event": "replacement_live", "at": T0 + 14.1},
                {"event": "service_rolled", "at": T0 + 23.4, "service": "svc", "healthy": True},
                {"event": "old_key_deleted", "at": T0 + 25.8},
                {"event": "finished", "at": T0 + 26.0, "outcome": "retired"},
            ],
        },
    }],
}
PROOF = {"keys": {"sha256:4ccada543d71": {
    "dead": True, "state": "proven_dead", "accepted": 0, "rejected": 12, "probes": 12, "flaps": 0,
    "seconds_watched": 57.5, "stable_dead_at": T0 + 90.0,
}}}
EXPOSURE = {"reports": [{
    "fingerprint": "sha256:4ccada543d71", "expected_regions": ["us-central1"], "complete": True,
    "by_region": {"asia-southeast1": {"ok": 5, "error": 0}}, "verdict": "used_elsewhere",
    "summary": "5 successful call(s) with this key came from asia-southeast1",
}]}
ENV = {"CI_COMMIT_SHA": "abc", "CI_PROJECT_ID": "87473841", "CI_PROJECT_NAME": "vibeguardian",
       "CI_COMMIT_REF_NAME": "drill-7"}


def attrs(item):
    return {a["key"]: next(iter(a["value"].values())) for a in item["attributes"]}


def test_one_trace_per_leak_with_a_span_per_step_and_the_proof():
    bodies = build(RECORD, PROOF, EXPOSURE, env=ENV, now=T0 + 3600)
    spans = bodies["traces"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    assert [s["name"] for s in spans] == ["leak incident", "identified", "replacement_live", "service_rolled",
                                          "old_key_deleted", "prove"]
    root = spans[0]
    assert len(root["traceId"]) == 32 and len(root["spanId"]) == 16
    assert all(s["traceId"] == root["traceId"] for s in spans)
    assert all(s["parentSpanId"] == root["spanId"] for s in spans[1:])
    assert root["status"]["code"] == OK
    assert attrs(root)["vibeguardian.outcome"] == "retired"
    rolled = spans[3]
    assert int(rolled["endTimeUnixNano"]) - int(rolled["startTimeUnixNano"]) == int(9.3e9)
    prove = spans[-1]
    assert attrs(prove)["vibeguardian.rejected"] == "12"
    assert prove["endTimeUnixNano"] == str(int((T0 + 90.0) * 1e9))
    resource = attrs(bodies["traces"]["resourceSpans"][0]["resource"])
    assert resource["service.name"] == "vibeguardian" and resource["gitlab.project.id"] == "87473841"


def test_exposure_becomes_metrics_and_a_warning_log():
    bodies = build(RECORD, PROOF, EXPOSURE, env=ENV, now=T0 + 3600)
    metrics = bodies["metrics"]["resourceMetrics"][0]["scopeMetrics"][0]["metrics"]
    by_name = {}
    for m in metrics:
        by_name.setdefault(m["name"], []).extend(m["gauge"]["dataPoints"])
    assert by_name["vibeguardian.retire.duration"][0]["asDouble"] == 26.0
    calls = [attrs(p) | {"n": p["asInt"]} for p in by_name["vibeguardian.exposure.calls"]]
    assert {"cloud.region": "asia-southeast1", "vibeguardian.result": "ok", "n": "5"}.items() <= calls[0].items()
    assert calls[0]["vibeguardian.expected_region"] is False
    logs = bodies["logs"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"]
    assert [log["severityNumber"] for log in logs] == [9, WARN]
    assert "asia-southeast1" in logs[1]["body"]["stringValue"]


def test_a_failed_retire_marks_the_trace_as_an_error_and_nothing_secret_is_sent():
    record = json.loads(json.dumps(RECORD))
    record["responses"][0]["incident"].update(outcome="aborted", reason="Google never accepted the replacement key")
    bodies = build(record, env=ENV, now=T0 + 60)
    root = bodies["traces"]["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
    assert root["status"]["code"] == ERROR
    assert bodies["logs"]["resourceLogs"][0]["scopeLogs"][0]["logRecords"][0]["severityNumber"] == WARN
    assert not re.search(r"AIza[0-9A-Za-z_-]{35}", json.dumps(bodies))


def test_no_leaks_sends_nothing_and_export_posts_each_signal():
    assert build({"responses": []}, env=ENV) == {"traces": None, "metrics": None, "logs": None}
    url = "https://1.otel.example:14318"
    http = FakeHttp({("POST", f"{url}/v1/{s}"): FakeResponse(200, {}) for s in ("traces", "metrics", "logs")})
    sent = export(http, url + "/", build(RECORD, PROOF, EXPOSURE, env=ENV), token="t")
    assert sent == {"traces": 200, "metrics": 200, "logs": 200}
    assert http.calls[0][2]["headers"]["Authorization"] == "Bearer t"


def test_each_vantage_gets_its_own_span_under_the_proof():
    proof = json.loads(json.dumps(PROOF))
    proof["keys"]["sha256:4ccada543d71"]["vantages"] = {
        "runner": {"dead": True, "state": "proven_dead", "rejected": 12, "accepted": 0, "flaps": 0,
                   "seconds_watched": 57.0, "stable_dead_at": T0 + 89.0},
        "europe-west1": {"dead": True, "state": "proven_dead", "rejected": 12, "accepted": 1, "flaps": 1,
                         "seconds_watched": 60.0, "stable_dead_at": T0 + 90.0},
    }
    spans = build(RECORD, proof, env=ENV, now=T0 + 3600)["traces"]["resourceSpans"][0]["scopeSpans"][0]["spans"]
    prove_span = next(s for s in spans if s["name"] == "prove")
    regional = [s for s in spans if s["name"].startswith("prove from ")]
    assert [s["name"] for s in regional] == ["prove from runner", "prove from europe-west1"]
    assert all(s["parentSpanId"] == prove_span["spanId"] for s in regional)
    assert attrs(regional[1])["cloud.region"] == "europe-west1"
    assert attrs(prove_span)["vibeguardian.vantages"] == "europe-west1, runner"
