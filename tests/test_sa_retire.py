import json

from vibeguardian.gcp.cloudrun import SecretUse
from vibeguardian.gcp.secretmanager import SecretMatch
from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.retire import ABORTED, ALREADY_DELETED, RETIRED
from vibeguardian.sa_retire import (
    KEY_ONLY,
    holds_key,
    parse_key_file,
    prove_service_account_key,
    replacement_id,
    retire_service_account_key,
)

ACCOUNT = "leaky-app@p.iam.gserviceaccount.com"
INFO = {"type": "service_account", "client_email": ACCOUNT, "private_key_id": "kid1",
        "private_key": "fake-key-material-for-tests"}
NEW_INFO = {"type": "service_account", "client_email": "new@p", "private_key_id": "kid2",
            "private_key": "fake-new-key-material"}
SECRET = "projects/9/secrets/app-sa-key"
SVC = "projects/p/locations/us-central1/services/app"


def ok(_):
    return ProbeResult(Verdict.ALIVE, None, None, 1, 0.0)


class World:
    """Records every call so tests can check the order of operations."""

    def __init__(self, runtime=False, unhealthy=False, old_key=None, old_account=None):
        self.log = []
        self.runtime = runtime
        self.unhealthy = unhealthy
        self.old_key = old_key if old_key is not None else {"disabled": False}
        self.old_account = old_account if old_account is not None else {"disabled": False}

    # accounts
    def get(self, email):
        return self.old_account or None
    def create(self, project, account_id, display):
        self.log.append(("create_account", account_id))
        return "new@p"

    def delete(self, what):
        self.log.append(("delete", what))

    def disable(self, what):
        self.log.append(("disable", what))

    # roles
    def copy_member(self, project, source, target):
        self.log.append(("copy_roles", source, target))
        return ["roles/browser"]

    # secrets
    def find_holders_matching(self, project, match):
        assert match(json.dumps(INFO)) and not match(json.dumps(NEW_INFO))
        return [SecretMatch(SECRET, f"{SECRET}/versions/1")]

    def add_version(self, secret, value):
        self.log.append(("add_version", json.loads(value)["private_key_id"]))
        return f"{SECRET}/versions/2"

    def disable_version(self, version):
        self.log.append(("disable_version", version))

    # run
    def consumers_of(self, project, secret):
        return [SecretUse(SVC, "env:SA_KEY", "app-sa-key", "latest")]

    def list_services(self, project):
        return [{"name": SVC, "template": {"serviceAccount": ACCOUNT if self.runtime else "other@p"}}]

    def pin_secret(self, service, secret, version):
        self.log.append(("pin", version))
        return {"name": service, "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
                "latestReadyRevision": "r2", "latestCreatedRevision": "r2"}


class Keys:
    def __init__(self, world):
        self.world = world

    def get(self, name):
        return self.world.old_key or None

    def create(self, email):
        self.world.log.append(("create_key", email))
        return "projects/p/serviceAccounts/new@p/keys/kid2", dict(NEW_INFO)

    def disable(self, name):
        self.world.log.append(("disable_key", name))

    def delete(self, name):
        self.world.log.append(("delete_key", name))


def retire(world):
    clock = {"t": 0.0}
    return retire_service_account_key(
        dict(INFO), "p", accounts=world, keys=Keys(world), roles=world, secrets=world, run=world,
        probe_mint=ok, check_health=lambda s: (not world.unhealthy, "health 200" if not world.unhealthy else "500"),
        sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"],
    )


def test_parse_key_file_accepts_only_service_account_keys():
    assert parse_key_file(json.dumps(INFO))["private_key_id"] == "kid1"
    assert parse_key_file("{not json") is None
    assert parse_key_file(json.dumps({"type": "authorized_user"})) is None


def test_holds_key_matches_on_key_id():
    assert holds_key("kid1")(json.dumps(INFO))
    assert not holds_key("kid1")("plain text")


def test_replacement_id_fits_google_limits():
    rid = replacement_id("a-very-long-service-account-name-here@p.iam.gserviceaccount.com")
    assert len(rid) <= 30 and rid[0].isalpha()


def test_rolls_out_a_new_identity_before_cutting_the_old_one_off():
    world = World()
    incident = retire(world)
    assert incident.outcome == RETIRED
    names = [entry[0] for entry in world.log]
    assert names.index("create_account") < names.index("copy_roles") < names.index("create_key")
    assert names.index("pin") < names.index("disable_key") < len(names)
    assert world.log[-1] == ("disable", ACCOUNT)
    assert ("add_version", "kid2") in world.log
    assert "fake-key-material" not in repr(incident.as_dict())


def test_a_credential_already_off_gets_no_second_replacement():
    for state, world in [
        ("key deleted", World(old_key={})),
        ("key disabled", World(old_key={"disabled": True})),
        ("account deleted", World(old_account={})),
        ("account disabled", World(old_account={"disabled": True})),
    ]:
        incident = retire(world)
        assert incident.outcome == ALREADY_DELETED
        assert state in incident.reason
        assert world.log == []


def test_account_that_runs_a_service_is_not_disabled():
    world = World(runtime=True)
    incident = retire(world)
    assert incident.outcome == KEY_ONLY
    assert ("disable", ACCOUNT) not in world.log
    assert "runtime identity" in incident.reason


def test_unhealthy_service_rolls_everything_back():
    world = World(unhealthy=True)
    incident = retire(world)
    assert incident.outcome == ABORTED
    assert ("pin", "1") in world.log  # rolled back to the old version
    assert ("add_version", "kid1") in world.log  # old key restored as "latest"
    assert ("delete", "new@p") in world.log
    assert not any(e[0] == "disable_key" for e in world.log)


def run_prove(mint_seq, canary_seq, minted=True):
    clock = {"t": 0.0}
    mints, canaries = iter(mint_seq), iter(canary_seq)

    def result(v):
        return ProbeResult(v, None, None, 1, clock["t"])

    return prove_service_account_key(
        dict(INFO), mint=lambda info: "canary-token" if minted else None,
        probe_mint=lambda info: result(next(mints)), probe_access=lambda token: result(next(canaries)),
        stable=2, interval=10, sleep=lambda s: clock.__setitem__("t", clock["t"] + s), clock=lambda: clock["t"],
    )


def test_proof_needs_both_the_canary_refused_and_minting_refused():
    A, D = Verdict.ALIVE, Verdict.DEAD
    verdict = run_prove([A, D, D, D, D], [A, A, D, D, D])
    assert verdict["dead"]
    assert verdict["seconds_until_key_cannot_mint"] == 10.0
    assert verdict["seconds_until_canary_refused"] == 20.0


def test_proof_when_the_key_was_already_dead_at_the_start():
    verdict = run_prove([Verdict.DEAD] * 5, [], minted=False)
    assert verdict["dead"]
    assert verdict["canary_minted"] is False
