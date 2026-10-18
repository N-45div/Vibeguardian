import requests

from vibeguardian.probe import ProbeResult, Verdict, classify, probe, watch


def google_error(status, reason=None, message="error"):
    error = {"code": status, "message": message, "status": "X"}
    if reason:
        error["details"] = [
            {"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason}
        ]
    return {"error": error}


def test_success_is_alive():
    assert classify(200, {"models": []}) == (Verdict.ALIVE, None)


def test_invalid_key_is_dead():
    body = google_error(400, "API_KEY_INVALID", "API key not valid. Please pass a valid API key.")
    assert classify(400, body) == (Verdict.DEAD, "API_KEY_INVALID")


def test_expired_key_is_dead():
    assert classify(400, google_error(400, "API_KEY_EXPIRED")) == (Verdict.DEAD, "API_KEY_EXPIRED")


def test_invalid_message_without_error_info_is_dead():
    body = google_error(400, None, "API key not valid. Please pass a valid API key.")
    assert classify(400, body) == (Verdict.DEAD, "API_KEY_INVALID")


def test_restricted_key_is_still_alive():
    assert classify(403, google_error(403, "API_KEY_SERVICE_BLOCKED")) == (
        Verdict.ALIVE,
        "API_KEY_SERVICE_BLOCKED",
    )


def test_disabled_api_still_proves_the_key_exists():
    assert classify(403, google_error(403, "SERVICE_DISABLED"))[0] == Verdict.ALIVE


def test_quota_errors_are_alive():
    assert classify(429, google_error(429))[0] == Verdict.ALIVE


def test_server_errors_are_unknown():
    assert classify(503, google_error(503))[0] == Verdict.UNKNOWN


def test_unrecognised_client_errors_are_unknown_not_alive():
    assert classify(404, google_error(404, "NOT_FOUND"))[0] == Verdict.UNKNOWN
    assert classify(403, google_error(403, "SOMETHING_NEW"))[0] == Verdict.UNKNOWN


def test_non_json_body_is_unknown():
    assert classify(400, None)[0] == Verdict.UNKNOWN


class FakeResponse:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body

    def json(self):
        if self._body is None:
            raise ValueError("no json")
        return self._body


class FakeSession:
    def __init__(self, response=None, exc=None):
        self.response = response
        self.exc = exc
        self.calls = []

    def get(self, url, headers=None, timeout=None):
        self.calls.append((url, headers))
        if self.exc:
            raise self.exc
        return self.response


def test_probe_sends_key_in_header_not_url():
    session = FakeSession(FakeResponse(200, {}))
    result = probe("secret-key", "https://example.test/v1/models", session=session)
    url, headers = session.calls[0]
    assert "secret-key" not in url
    assert headers == {"x-goog-api-key": "secret-key"}
    assert result.verdict == Verdict.ALIVE


def test_probe_network_failure_is_unknown():
    session = FakeSession(exc=requests.ConnectionError("boom"))
    result = probe("k", session=session)
    assert result.verdict == Verdict.UNKNOWN
    assert result.reason == "NETWORK_ERROR"


def run_watch(verdicts, **kwargs):
    clock = {"t": 1000.0}
    sequence = iter(verdicts)

    def check():
        return ProbeResult(next(sequence), 400, None, 5, clock["t"])

    def sleep(seconds):
        clock["t"] += seconds

    return watch(check, sleep=sleep, clock=lambda: clock["t"], **kwargs)


def test_watch_needs_a_stable_streak():
    result = run_watch(
        [Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD, Verdict.DEAD],
        until=Verdict.DEAD,
        stable=3,
        interval=10,
    )
    assert result.reached
    assert result.first_at == 1010.0
    assert result.stable_at == 1030.0
    assert result.probes == 4


def test_watch_counts_flaps_and_resets_first_seen():
    result = run_watch(
        [Verdict.DEAD, Verdict.ALIVE, Verdict.DEAD, Verdict.DEAD],
        until=Verdict.DEAD,
        stable=2,
        interval=10,
    )
    assert result.reached
    assert result.flaps == 1
    assert result.first_at == 1020.0


def test_watch_unknown_does_not_break_a_streak():
    result = run_watch(
        [Verdict.DEAD, Verdict.UNKNOWN, Verdict.DEAD],
        until=Verdict.DEAD,
        stable=2,
        interval=10,
    )
    assert result.reached
    assert result.first_at == 1000.0


def test_watch_gives_up_at_the_deadline():
    result = run_watch(
        [Verdict.ALIVE] * 10,
        until=Verdict.DEAD,
        stable=2,
        interval=10,
        max_seconds=35,
    )
    assert not result.reached
    assert result.probes == 4


def test_a_deleted_authorization_key_is_dead():
    # What Google answered for a real deleted "AQ." key, every probe for 3 minutes.
    body = google_error(401, "ACCESS_TOKEN_TYPE_UNSUPPORTED", "API key not valid. Please pass a valid API key.")
    assert classify(401, body) == (Verdict.DEAD, "ACCESS_TOKEN_TYPE_UNSUPPORTED")


def test_a_401_with_another_message_is_not_proof_of_death():
    body = google_error(401, "ACCESS_TOKEN_TYPE_UNSUPPORTED",
                        "Request had invalid authentication credentials. Expected OAuth 2 access token.")
    assert classify(401, body)[0] == Verdict.UNKNOWN
