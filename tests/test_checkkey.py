from datetime import datetime, timezone

from vibeguardian.checkkey import age_days, check_key, describe_restrictions
from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.secret import fingerprint

NOW = datetime(2026, 10, 14, tzinfo=timezone.utc)
NAME = "projects/895/locations/global/keys/abc"


def alive(value):
    return ProbeResult(Verdict.ALIVE, 200, None, 1, 0.0)


def dead(value):
    return ProbeResult(Verdict.DEAD, 400, "API_KEY_INVALID", 1, 0.0)


class Keys:
    def __init__(self, key=None, missing=False, error=None):
        self.key = key or {}
        self.missing = missing
        self.error = error

    def lookup(self, value):
        if self.error:
            raise self.error
        if self.missing:
            raise LookupError
        return NAME

    def get(self, name):
        return self.key


def test_unrestricted_old_live_key():
    keys = Keys({"displayName": "prod", "createTime": "2025-08-14T00:00:00Z"})
    report = check_key("k", probe=alive, keys=keys, now=NOW)
    assert report["live"] is True
    assert report["owned"] is True
    assert report["age_days"] == 426
    assert report["restrictions"]["unrestricted"] is True
    assert report["fingerprint"] == fingerprint("k")
    assert "k" not in {v for v in report.values() if isinstance(v, str)}


def test_restricted_key_lists_what_it_is_limited_to():
    restrictions = {"apiTargets": [{"service": "generativelanguage.googleapis.com"}],
                    "serverKeyRestrictions": {"allowedIps": ["1.2.3.4"]}}
    assert describe_restrictions(restrictions) == {
        "apis": ["generativelanguage.googleapis.com"], "apps": ["server"], "unrestricted": False}


def test_without_a_google_login_it_still_says_if_the_key_is_live():
    report = check_key("k", probe=dead)
    assert report["live"] is False
    assert report["google_says"] == "API_KEY_INVALID"
    assert report["owned"] is None


def test_a_key_from_someone_elses_project():
    assert check_key("k", probe=alive, keys=Keys(missing=True))["owned"] is False


def test_no_permission_to_look_up_is_reported_not_raised():
    report = check_key("k", probe=alive, keys=Keys(error=PermissionError("403")))
    assert report["lookup_error"] == "PermissionError"


def test_age_days_handles_missing_dates():
    assert age_days(None) is None
