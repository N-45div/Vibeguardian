from datetime import datetime, timezone

from fakes import FakeHttp, FakeResponse
from vibeguardian.exposure import MONITORING
from vibeguardian.gcp.apikeys import BASE, ApiKeys
from vibeguardian.inventory import inventory

NOW = datetime(2026, 10, 16, 6, 0, tzinfo=timezone.utc)
KEYS_URL = f"{BASE}/projects/p/locations/global/keys"


def counts(uid, region, code_class, n):
    return {
        "resource": {"labels": {"location": region, "credential_id": f"apikey:{uid}"}},
        "metric": {"labels": {"response_code_class": code_class}},
        "points": [{"value": {"int64Value": str(n)}}],
    }


def test_list_keys_follows_pages():
    http = FakeHttp({("GET", KEYS_URL): [
        FakeResponse(200, {"keys": [{"name": "k1"}], "nextPageToken": "t"}),
        FakeResponse(200, {"keys": [{"name": "k2"}]}),
    ]})
    assert [k["name"] for k in ApiKeys(http).list_keys("p")] == ["k1", "k2"]
    assert http.calls[1][2]["params"]["pageToken"] == "t"


def test_inventory_flags_unrestricted_old_and_unused_keys():
    keys_http = FakeHttp({("GET", KEYS_URL): FakeResponse(200, {"keys": [
        {"name": "projects/9/locations/global/keys/fresh", "displayName": "app",
         "createTime": "2026-10-01T00:00:00Z", "restrictions": {"apiTargets": [{"service": "generativelanguage.googleapis.com"}]}},
        {"name": "projects/9/locations/global/keys/ancient", "displayName": "old browser key",
         "createTime": "2025-01-01T00:00:00Z"},
    ]})})
    monitoring = FakeHttp({("GET", f"{MONITORING}/projects/p/timeSeries"): FakeResponse(200, {"timeSeries": [
        counts("fresh", "us-central1", "2xx", 40),
        counts("fresh", "europe-west1", "4xx", 3),
    ]})})
    result = inventory(ApiKeys(keys_http), monitoring, "p", now=NOW)
    first, second = result["keys"]
    assert first["uid"] == "ancient"
    assert first["flags"] == ["unrestricted", "old", "unused"]
    assert second["uid"] == "fresh"
    assert second["flags"] == []
    assert second["calls"] == 40
    assert second["regions"] == ["us-central1"]
    params = monitoring.calls[0][2]["params"]
    assert 'starts_with("apikey:")' in params["filter"]
    assert params["aggregation.alignmentPeriod"] == "604800s"
