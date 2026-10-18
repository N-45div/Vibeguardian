from datetime import datetime, timedelta, timezone

import pytest

from fakes import FakeHttp, FakeResponse
from vibeguardian.exposure import MONITORING, apis_used, check_record, exposure_report, key_uid, service_regions, usage_by_region

START = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
END = START + timedelta(minutes=10)


def series(region, code_class, *counts, method="ModelService.GenerateContent", ends=None):
    ends = ends or [END] * len(counts)
    return {
        "resource": {"labels": {"location": region, "credential_id": "apikey:u1",
                                "method": f"google.ai.generativelanguage.v1beta.{method}"}},
        "metric": {"labels": {"response_code_class": code_class}},
        "points": [{"value": {"int64Value": str(c)},
                    "interval": {"endTime": e.isoformat().replace("+00:00", "Z")}} for c, e in zip(counts, ends)],
    }


def test_usage_by_region_sums_points_and_splits_ok_from_errors():
    http = FakeHttp({("GET", f"{MONITORING}/projects/p/timeSeries"): FakeResponse(200, {"timeSeries": [
        series("us-central1", "2xx", 3, 4),
        series("asia-southeast1", "2xx", 2),
        series("asia-southeast1", "4xx", 5),
    ]})})
    usage = usage_by_region(http, "p", "u1", START, END)
    zero = dict.fromkeys(("checks", "probe_like"), 0)
    assert usage == {"us-central1": {"ok": 7, "error": 0, "used_ok": 7, "used_failed": 0, **zero},
                     "asia-southeast1": {"ok": 2, "error": 5, "used_ok": 2, "used_failed": 5, **zero}}
    assert 'credential_id = "apikey:u1"' in http.calls[0][2]["params"]["filter"]


def test_calls_from_other_regions_are_flagged():
    usage = {"us-central1": {"ok": 120, "error": 0, "used_ok": 120}, "europe-west1": {"ok": 37, "error": 0, "used_ok": 37}}
    report = exposure_report(usage, {"us-central1"}, START, END, now=END + timedelta(hours=1))
    assert report["verdict"] == "used_elsewhere"
    assert report["calls_from_elsewhere"] == 37
    assert report["complete"] is True
    assert "europe-west1" in report["summary"]


def test_only_your_own_regions_means_no_use_elsewhere():
    usage = {"us-central1": {"ok": 50, "error": 0}, "asia-southeast1": {"ok": 0, "error": 9}}
    report = exposure_report(usage, {"us-central1"}, START, END, now=END + timedelta(hours=1))
    assert report["verdict"] == "no_use_elsewhere"
    assert report["calls_from_your_services"] == 50


def test_a_recent_window_is_marked_partial_with_a_recheck_time():
    report = exposure_report({}, {"us-central1"}, START, END, now=END + timedelta(minutes=5))
    assert report["complete"] is False
    assert "check again after" in report["summary"]


def test_helpers():
    assert key_uid("projects/9/locations/global/keys/abc-123") == "abc-123"
    assert service_regions(["projects/p/locations/us-central1/services/a",
                            "projects/p/locations/europe-west1/services/b"]) == {"us-central1", "europe-west1"}


DELETED = END.timestamp()
INCIDENT = {
    "leaked_fingerprint": "sha256:aaa",
    "old_key": "projects/9/locations/global/keys/u1",
    "services": [{"service": "projects/p/locations/us-central1/services/app"}],
    "timeline": [{"event": "identified", "at": DELETED - 20}, {"event": "old_key_deleted", "at": DELETED}],
}


def test_check_record_reads_a_respond_record_and_waits_for_counts_to_settle():
    record = {"responses": [
        {"leak": {"fingerprint": "sha256:aaa", "commit": "c1"}, "incident": INCIDENT},
        {"leak": {"fingerprint": "sha256:bbb", "commit": "c2"}, "incident": {"outcome": "error", "reason": "x"}},
        {"leak": {"fingerprint": "sha256:ccc", "commit": "c3"},
         "incident": {"outcome": "already_deleted", "old_key": "projects/9/locations/global/keys/u3",
                      "timeline": [{"event": "identified", "at": DELETED}]}},
    ]}
    asked, slept = [], []
    reports = check_record(
        record,
        lambda uid, start, end, began: asked.append((uid, start, end, began)) or {"europe-west1": {"ok": 2, "error": 0, "used_ok": 2}},
        lambda leak: START if leak["commit"] == "c1" else None,
        settle=timedelta(seconds=90),
        clock=lambda: END + timedelta(seconds=30),
        sleep=slept.append,
    )
    assert slept == [60.0]
    assert asked == [("u1", START, END, START)]  # no finished_at in this record: probes may have begun at once
    assert reports[0]["fingerprint"] == "sha256:aaa"
    assert reports[0]["verdict"] == "used_elsewhere"
    assert reports[1] == {"fingerprint": "sha256:bbb", "verdict": "not_retired",
                          "summary": "This key was not deleted, so there is no exposure window to check."}
    assert reports[2]["verdict"] == "already_deleted"


def test_check_record_reads_a_single_retire_record():
    reports = check_record(INCIDENT, lambda *_: {"us-central1": {"ok": 4, "error": 0}}, lambda leak: START,
                           clock=lambda: END + timedelta(hours=1), sleep=lambda s: None)
    assert [r["verdict"] for r in reports] == ["no_use_elsewhere"]


def test_check_record_refuses_a_window_that_starts_after_the_deletion():
    with pytest.raises(ValueError, match="must start before"):
        check_record(INCIDENT, lambda *_: {}, lambda leak: END + timedelta(minutes=1),
                     clock=lambda: END + timedelta(hours=1), sleep=lambda s: None)


def test_apis_used_counts_only_successful_calls_per_api():
    def api_series(service, code_class, n):
        return {"resource": {"labels": {"service": service, "credential_id": "apikey:u1", "location": "us"}},
                "metric": {"labels": {"response_code_class": code_class}},
                "points": [{"value": {"int64Value": str(n)}}]}

    http = FakeHttp({("GET", f"{MONITORING}/projects/p/timeSeries"): FakeResponse(200, {"timeSeries": [
        api_series("generativelanguage.googleapis.com", "2xx", 40),
        api_series("generativelanguage.googleapis.com", "4xx", 2),
        api_series("maps-backend.googleapis.com", "4xx", 9),
    ]})})
    assert apis_used(http, "p", "u1", START, END) == {"generativelanguage.googleapis.com": 40}
    assert http.calls[0][2]["params"]["aggregation.perSeriesAligner"] == "ALIGN_SUM"


def test_model_list_calls_are_checks_before_vibeguardian_probes_and_probe_like_after():
    began = START + timedelta(minutes=5)
    http = FakeHttp({("GET", f"{MONITORING}/projects/p/timeSeries"): FakeResponse(200, {"timeSeries": [
        series("asia-southeast1", "2xx", 3, 4, method="ModelService.ListModels",
               ends=[START + timedelta(minutes=2), START + timedelta(minutes=7)]),
        series("europe-west1", "2xx", 6, method="ModelService.GenerateContent"),
    ]})})
    usage = usage_by_region(http, "p", "u1", START, END, began)
    assert usage["asia-southeast1"] == {"ok": 7, "error": 0, "used_ok": 0, "used_failed": 0, "checks": 3, "probe_like": 4}
    assert usage["europe-west1"] == {"ok": 6, "error": 0, "used_ok": 6, "used_failed": 0, "checks": 0, "probe_like": 0}


def test_verdicts_separate_use_from_checks_from_our_own_probes():
    later = END + timedelta(hours=1)
    used = exposure_report({"europe-west1": {"ok": 6, "error": 5, "used_ok": 6, "used_failed": 5}},
                           {"us-central1"}, START, END, now=later)
    assert used["verdict"] == "used_elsewhere" and used["calls_from_elsewhere"] == 11
    assert used["succeeded_from_elsewhere"] == 6
    refused = exposure_report({"asia-southeast1": {"ok": 0, "error": 5, "used_ok": 0, "used_failed": 5}},
                              {"us-central1"}, START, END, now=later)
    assert refused["verdict"] == "used_elsewhere" and "0 succeeded" in refused["summary"]
    checked = exposure_report({"asia-southeast1": {"ok": 3, "error": 0, "checks": 3, "probe_like": 0}},
                              {"us-central1"}, START, END, now=later)
    assert checked["verdict"] == "checked_elsewhere" and checked["checks_from_elsewhere"] == 3
    assert "someone else found the key" in checked["summary"]
    ours = exposure_report({"asia-east1": {"ok": 39, "error": 0, "checks": 0, "probe_like": 39}},
                           {"us-central1"}, START, END, now=later)
    assert ours["verdict"] == "no_use_elsewhere" and ours["likely_vibeguardian_probes"] == 39
    assert "its own probes make that call" in ours["summary"]


def test_after_an_approval_every_model_list_call_may_be_ours():
    approved = {**INCIDENT, "finished_at": DELETED + 1,
                "timeline": [{"event": "approved", "at": DELETED - 30}, *INCIDENT["timeline"]]}
    seen = []
    check_record(approved, lambda uid, start, end, began: seen.append(began) or {}, lambda leak: START,
                 clock=lambda: END + timedelta(hours=1), sleep=lambda s: None)
    plain = {**INCIDENT, "finished_at": DELETED + 1}
    check_record(plain, lambda uid, start, end, began: seen.append(began) or {}, lambda leak: START,
                 clock=lambda: END + timedelta(hours=1), sleep=lambda s: None)
    assert seen == [START, datetime.fromtimestamp(DELETED + 1, tz=timezone.utc)]
