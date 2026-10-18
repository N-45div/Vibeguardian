import pytest

from fakes import FakeHttp, FakeResponse
from vibeguardian.gcp.client import GoogleApiError
from vibeguardian.gcp.iam import BASE, ServiceAccountKeys, ServiceAccounts

KEY = "projects/p/serviceAccounts/a@p/keys/k1"


def test_get_reads_the_disabled_flag_and_treats_404_as_deleted():
    http = FakeHttp({
        ("GET", f"{BASE}/{KEY}"): FakeResponse(200, {"name": KEY, "disabled": True}),
        ("GET", f"{BASE}/projects/-/serviceAccounts/a@p"): FakeResponse(404, {"error": {"message": "gone"}}),
    })
    assert ServiceAccountKeys(http).get(KEY)["disabled"] is True
    assert ServiceAccounts(http).get("a@p") is None


def test_get_still_raises_on_other_errors():
    http = FakeHttp({("GET", f"{BASE}/{KEY}"): FakeResponse(403, {"error": {"message": "denied"}})})
    with pytest.raises(GoogleApiError):
        ServiceAccountKeys(http).get(KEY)
