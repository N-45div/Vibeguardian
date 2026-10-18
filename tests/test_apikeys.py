import pytest

from fakes import FakeHttp, FakeResponse
from vibeguardian.gcp.apikeys import BASE, ApiKeys
from vibeguardian.gcp.client import GoogleApiError

NAME = "projects/123/locations/global/keys/abc"
RESTRICTIONS = {"apiTargets": [{"service": "generativelanguage.googleapis.com"}]}


def keys(routes):
    http = FakeHttp(routes)
    return ApiKeys(http, poll=0, sleep=lambda _: None), http


def test_lookup_returns_resource_name_and_sends_key_as_param():
    api, http = keys({("GET", f"{BASE}/keys:lookupKey"): FakeResponse(200, {"name": NAME})})
    assert api.lookup("leaked") == NAME
    assert http.calls[0][2]["params"] == {"keyString": "leaked"}


def test_lookup_without_name_raises():
    api, _ = keys({("GET", f"{BASE}/keys:lookupKey"): FakeResponse(200, {})})
    with pytest.raises(LookupError):
        api.lookup("leaked")


def test_errors_carry_status_and_reason_but_not_the_url():
    body = {
        "error": {
            "code": 403,
            "message": "Permission denied",
            "details": [{"reason": "IAM_PERMISSION_DENIED"}],
        }
    }
    api, _ = keys({("GET", f"{BASE}/keys:lookupKey"): FakeResponse(403, body)})
    with pytest.raises(GoogleApiError) as err:
        api.lookup("leaked")
    assert err.value.http_status == 403
    assert err.value.reason == "IAM_PERMISSION_DENIED"
    assert "leaked" not in str(err.value)


def test_create_waits_for_the_operation():
    op = {"name": "operations/akmf.1", "done": False}
    done = {"name": "operations/akmf.1", "done": True, "response": {"name": NAME, "uid": "abc"}}
    api, http = keys(
        {
            ("POST", f"{BASE}/projects/p/locations/global/keys"): FakeResponse(200, op),
            ("GET", f"{BASE}/operations/akmf.1"): FakeResponse(200, done),
        }
    )
    key = api.create("p", "replacement", RESTRICTIONS)
    assert key["name"] == NAME
    assert http.calls[0][2]["json"] == {"displayName": "replacement", "restrictions": RESTRICTIONS}


def test_create_truncates_long_display_names():
    done = {"name": "operations/akmf.9", "done": True, "response": {"name": NAME}}
    api, http = keys({("POST", f"{BASE}/projects/p/locations/global/keys"): FakeResponse(200, done)})
    api.create("p", "x" * 100)
    assert len(http.calls[0][2]["json"]["displayName"]) == 63


def test_clone_copies_restrictions_into_the_same_project():
    created = {"name": "operations/akmf.2", "done": True, "response": {"name": NAME + "2"}}
    api, http = keys(
        {
            ("GET", f"{BASE}/{NAME}"): FakeResponse(200, {"name": NAME, "restrictions": RESTRICTIONS}),
            ("POST", f"{BASE}/projects/123/locations/global/keys"): FakeResponse(200, created),
        }
    )
    api.clone(NAME, "rotated")
    assert http.calls[1][2]["json"]["restrictions"] == RESTRICTIONS


def test_failed_operation_raises():
    op = {"name": "operations/akmf.3", "done": True, "error": {"code": 409, "message": "conflict"}}
    api, _ = keys({("DELETE", f"{BASE}/{NAME}"): FakeResponse(200, op)})
    with pytest.raises(GoogleApiError) as err:
        api.delete(NAME)
    assert err.value.http_status == 409


def test_key_string_reads_the_value():
    api, _ = keys({("GET", f"{BASE}/{NAME}/keyString"): FakeResponse(200, {"keyString": "v"})})
    assert api.key_string(NAME) == "v"
