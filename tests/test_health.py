import requests

from vibeguardian import health

SERVICE = {"uri": "https://app.run.app"}


class Reply:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError
        return self._body


def check_with(monkeypatch, reply=None, exc=None):
    def fake_get(url, timeout):
        assert url == "https://app.run.app/health"
        if exc:
            raise exc
        return reply

    monkeypatch.setattr(health.requests, "get", fake_get)
    return health.http_health("/health")


def test_healthy_only_on_the_expected_fingerprint(monkeypatch):
    check = check_with(monkeypatch, Reply(200, {"key_fingerprint": "sha256:new"}))
    assert check(SERVICE, "sha256:new")[0]
    ok, detail = check(SERVICE, "sha256:other")
    assert not ok and "still serving sha256:new" in detail


def test_error_status_is_unhealthy(monkeypatch):
    check = check_with(monkeypatch, Reply(503, {}))
    assert check(SERVICE, "sha256:new") == (False, "/health returned 503")


def test_unreachable_is_unhealthy(monkeypatch):
    check = check_with(monkeypatch, exc=requests.ConnectionError())
    assert not check(SERVICE, "sha256:new")[0]


def test_service_without_fingerprint_passes_on_200(monkeypatch):
    check = check_with(monkeypatch, Reply(200, None))
    assert check(SERVICE, "sha256:new")[0]
