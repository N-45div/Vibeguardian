from vibeguardian.gcp.secretmanager import SecretMatch
from vibeguardian.gcp.cloudrun import SecretUse
from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.retire import (
    ABORTED, ALREADY_DELETED, DRY_RUN, NEEDS_APPROVAL, NOT_OURS, RETIRED, retire, used_api_restrictions,
)
from vibeguardian.secret import fingerprint

OLD = "projects/9/locations/global/keys/old"
NEW = "projects/9/locations/global/keys/new"
SECRET = "projects/9/secrets/gemini-api-key"
SVC = "projects/p/locations/us-central1/services/app"


class Keys:
    def __init__(self, known=True, delete_time=None):
        self.known = known
        self.delete_time = delete_time
        self.deleted = []
        self.cloned = []

    def lookup(self, value):
        if not self.known:
            raise LookupError
        return OLD

    def get(self, name):
        return {"name": name, "deleteTime": self.delete_time} if self.delete_time else {"name": name}

    def clone(self, name, label, restrictions=None):
        self.cloned.append(name)
        self.clone_restrictions = restrictions
        return {"name": NEW}

    def key_string(self, name):
        return "new-secret-value"

    def delete(self, name):
        self.deleted.append(name)


class Secrets:
    def __init__(self):
        self.added = []
        self.disabled = []

    def find_holders(self, project, fp):
        assert fp == fingerprint("leaked-value")
        return [SecretMatch(secret=SECRET, version=f"{SECRET}/versions/3")]

    def add_version(self, secret, value):
        self.added.append((secret, value))
        return f"{SECRET}/versions/4"

    def disable_version(self, version):
        self.disabled.append(version)


class Run:
    def __init__(self):
        self.pins = []

    def consumers_of(self, project, secret):
        return [SecretUse(SVC, "env:GEMINI_API_KEY", "gemini-api-key", "3")]

    def pin_secret(self, service, secret, version):
        self.pins.append((service, version))
        return {
            "name": service,
            "uri": "https://app.run.app",
            "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
            "latestReadyRevision": f"rev-{version}",
            "latestCreatedRevision": f"rev-{version}",
        }


def alive_after(n):
    calls = {"n": 0}

    def check(value):
        calls["n"] += 1
        verdict = Verdict.ALIVE if calls["n"] > n else Verdict.DEAD
        return ProbeResult(verdict, 200, None, 1, 0.0)

    return check


def healthy_if_new_key(service, expected_fp):
    return expected_fp == fingerprint("new-secret-value"), "serving new key"


def do(keys=None, secrets=None, run=None, check_key=None, check_health=healthy_if_new_key, **kw):
    keys, secrets, run = keys or Keys(), secrets or Secrets(), run or Run()
    clock = {"t": 0.0}
    incident = retire(
        "leaked-value",
        "p",
        keys=keys,
        secrets=secrets,
        run=run,
        check_key=check_key or alive_after(0),
        check_health=check_health,
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s),
        clock=lambda: clock["t"],
        **kw,
    )
    return incident, keys, secrets, run


def test_happy_path_rolls_out_before_deleting_the_old_key():
    incident, keys, secrets, run = do()
    assert incident.outcome == RETIRED
    assert run.pins == [(SVC, "4")]
    assert keys.deleted == [OLD]
    assert secrets.disabled == [f"{SECRET}/versions/3"]
    events = [e["event"] for e in incident.timeline]
    assert events.index("service_rolled") < events.index("old_key_deleted")


def test_no_secret_value_reaches_the_incident_record():
    incident, *_ = do()
    text = repr(incident.as_dict())
    assert "leaked-value" not in text
    assert "new-secret-value" not in text
    assert incident.new_fingerprint == fingerprint("new-secret-value")


def test_unknown_key_changes_nothing():
    incident, keys, secrets, run = do(keys=Keys(known=False))
    assert incident.outcome == NOT_OURS
    assert keys.deleted == [] and secrets.added == [] and run.pins == []


def test_a_key_google_already_deleted_mints_no_replacement():
    # Seen on a branch that carried an already-retired leak in its history:
    # Google still looks the deleted key up, so this must stop before cloning.
    incident, keys, secrets, run = do(keys=Keys(delete_time="2026-10-15T19:10:34Z"))
    assert incident.outcome == ALREADY_DELETED
    assert "2026-10-15T19:10:34Z" in incident.reason
    assert keys.cloned == [] and keys.deleted == []
    assert secrets.added == [] and run.pins == []


def test_a_retirement_the_policy_holds_back_changes_nothing_until_approved():
    incident, keys, secrets, run = do(approval=lambda services: f"{len(services)} services, limit 0")
    assert incident.outcome == NEEDS_APPROVAL
    assert incident.reason == "1 services, limit 0"
    assert keys.cloned == [] and keys.deleted == [] and secrets.added == [] and run.pins == []
    assert [e["event"] for e in incident.timeline][-2:] == ["approval_needed", "finished"]

    incident, keys, *_ = do(approval=lambda services: "limit 0", approved_by="ndivij2004")
    assert incident.outcome == RETIRED
    assert incident.approved_by == "ndivij2004"
    assert {"event": "approved", "by": "ndivij2004", "policy_reason": "limit 0"}.items() <= next(
        e for e in incident.timeline if e["event"] == "approved").items()


def test_the_replacement_can_be_limited():
    limit = {"apiTargets": [{"service": "generativelanguage.googleapis.com"}]}
    incident, keys, *_ = do(limit_replacement=lambda old_key: limit)
    assert incident.outcome == RETIRED
    assert keys.clone_restrictions == limit
    assert incident.replacement_restrictions == limit
    created = next(e for e in incident.timeline if e["event"] == "replacement_created")
    assert created["limited_to"] == ["generativelanguage.googleapis.com"]


def test_used_api_restrictions_only_narrow_an_unrestricted_key_with_seen_calls():
    used = {"generativelanguage.googleapis.com": 40, "maps-backend.googleapis.com": 2}
    assert used_api_restrictions({}, used) == {"apiTargets": [
        {"service": "generativelanguage.googleapis.com"}, {"service": "maps-backend.googleapis.com"}]}
    assert used_api_restrictions({"restrictions": {"apiTargets": [{"service": "x"}]}}, used) is None
    assert used_api_restrictions({"restrictions": {"browserKeyRestrictions": {}}}, used) is None
    assert used_api_restrictions({}, {}) is None


def test_dry_run_only_reports_the_plan():
    incident, keys, secrets, run = do(dry_run=True)
    assert incident.outcome == DRY_RUN
    assert keys.deleted == [] and secrets.added == [] and run.pins == []


def test_replacement_that_never_works_is_removed_and_old_key_kept():
    incident, keys, secrets, run = do(check_key=alive_after(10_000))
    assert incident.outcome == ABORTED
    assert keys.deleted == [NEW]
    assert run.pins == []


def test_unhealthy_service_rolls_back_and_keeps_the_old_key():
    incident, keys, secrets, run = do(check_health=lambda s, fp: (False, "500 from /healthz"))
    assert incident.outcome == ABORTED
    assert run.pins == [(SVC, "4"), (SVC, "3")]
    # The old value goes back on top so "latest" never points at a disabled version.
    assert secrets.added == [(SECRET, "new-secret-value"), (SECRET, "leaked-value")]
    assert secrets.disabled == [f"{SECRET}/versions/4"]
    assert keys.deleted == [NEW]
    assert OLD not in keys.deleted
    assert "500 from /healthz" in incident.reason
