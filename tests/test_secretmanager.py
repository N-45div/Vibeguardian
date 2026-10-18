import base64

from fakes import FakeHttp, FakeResponse
from vibeguardian.gcp.secretmanager import BASE, SecretManager
from vibeguardian.secret import fingerprint

PROJECT = "42"
P = f"projects/{PROJECT}"


def b64(text):
    return base64.b64encode(text.encode()).decode()


def accessed(name, value):
    return FakeResponse(200, {"name": name, "payload": {"data": b64(value)}})


def test_find_holders_matches_on_fingerprint_only():
    http = FakeHttp(
        {
            ("GET", f"{BASE}/{P}/secrets"): FakeResponse(
                200, {"secrets": [{"name": f"{P}/secrets/gemini"}, {"name": f"{P}/secrets/other"}]}
            ),
            ("GET", f"{BASE}/{P}/secrets/gemini/versions/latest:access"): accessed(
                f"{P}/secrets/gemini/versions/3", "leaked-value\n"
            ),
            ("GET", f"{BASE}/{P}/secrets/other/versions/latest:access"): accessed(
                f"{P}/secrets/other/versions/1", "something-else"
            ),
        }
    )
    matches = SecretManager(http).find_holders(PROJECT, fingerprint("leaked-value"))
    assert [m.secret for m in matches] == [f"{P}/secrets/gemini"]
    assert matches[0].version == f"{P}/secrets/gemini/versions/3"


def test_secrets_without_an_enabled_version_are_skipped():
    http = FakeHttp(
        {
            ("GET", f"{BASE}/{P}/secrets"): FakeResponse(200, {"secrets": [{"name": f"{P}/secrets/s"}]}),
            ("GET", f"{BASE}/{P}/secrets/s/versions/latest:access"): FakeResponse(
                404, {"error": {"code": 404, "message": "no enabled versions"}}
            ),
        }
    )
    assert SecretManager(http).find_holders(PROJECT, fingerprint("x")) == []


def test_list_secrets_follows_pages():
    http = FakeHttp(
        {
            ("GET", f"{BASE}/{P}/secrets"): [
                FakeResponse(200, {"secrets": [{"name": "a"}], "nextPageToken": "t"}),
                FakeResponse(200, {"secrets": [{"name": "b"}]}),
            ]
        }
    )
    assert SecretManager(http).list_secrets(PROJECT) == ["a", "b"]


def test_add_version_sends_base64_payload():
    http = FakeHttp(
        {("POST", f"{BASE}/{P}/secrets/s:addVersion"): FakeResponse(200, {"name": f"{P}/secrets/s/versions/4"})}
    )
    assert SecretManager(http).add_version(f"{P}/secrets/s", "new") == f"{P}/secrets/s/versions/4"
    assert http.calls[0][2]["json"] == {"payload": {"data": b64("new")}}
