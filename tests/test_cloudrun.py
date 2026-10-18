import pytest

from fakes import FakeHttp, FakeResponse
from vibeguardian.gcp.cloudrun import BASE, CloudRun, is_ready, secret_id, secret_uses

SVC = "projects/p/locations/us-central1/services/app"


def service(version="latest", secret="gemini-api-key", extra_env=None, volumes=None):
    env = [
        {"name": "GEMINI_API_KEY", "valueSource": {"secretKeyRef": {"secret": secret, "version": version}}},
        {"name": "PLAIN", "value": "x"},
    ] + (extra_env or [])
    template = {"containers": [{"image": "img", "env": env}]}
    if volumes:
        template["volumes"] = volumes
    return {
        "name": SVC,
        "uri": "https://app.run.app",
        "template": template,
        "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
        "latestReadyRevision": "r2",
        "latestCreatedRevision": "r2",
    }


def test_secret_id_handles_every_form():
    assert secret_id("gemini") == "gemini"
    assert secret_id("projects/1/secrets/gemini") == "gemini"
    assert secret_id("projects/1/secrets/gemini/versions/7") == "gemini"


def test_secret_uses_reads_env_and_volumes():
    volumes = [{"name": "keys", "secret": {"secret": "other", "items": [{"version": "2", "path": "k"}]}}]
    uses = secret_uses(service(volumes=volumes))
    assert [(u.where, u.secret, u.version) for u in uses] == [
        ("env:GEMINI_API_KEY", "gemini-api-key", "latest"),
        ("volume:keys", "other", "2"),
    ]


def test_consumers_of_matches_full_or_short_secret_names():
    http = FakeHttp(
        {("GET", f"{BASE}/projects/p/locations/-/services"): FakeResponse(200, {"services": [service()]})}
    )
    uses = CloudRun(http).consumers_of("p", "projects/123/secrets/gemini-api-key")
    assert [u.service for u in uses] == [SVC]


def test_pin_secret_patches_only_matching_refs_and_strips_output_fields():
    op = {"name": "projects/p/locations/us-central1/operations/o1", "done": True, "response": {}}
    http = FakeHttp(
        {
            ("GET", f"{BASE}/{SVC}"): FakeResponse(200, service()),
            ("PATCH", f"{BASE}/{SVC}"): FakeResponse(200, op),
        }
    )
    CloudRun(http, poll=0, sleep=lambda _: None).pin_secret(SVC, "gemini-api-key", "4")
    sent = [c for c in http.calls if c[0] == "PATCH"][0][2]["json"]
    env = sent["template"]["containers"][0]["env"]
    assert env[0]["valueSource"]["secretKeyRef"]["version"] == "4"
    assert env[1] == {"name": "PLAIN", "value": "x"}
    assert "uri" not in sent and "terminalCondition" not in sent


def test_pin_secret_refuses_a_service_that_does_not_use_the_secret():
    http = FakeHttp({("GET", f"{BASE}/{SVC}"): FakeResponse(200, service(secret="unrelated"))})
    with pytest.raises(LookupError):
        CloudRun(http).pin_secret(SVC, "gemini-api-key", "4")


def test_is_ready_needs_the_latest_revision_serving():
    assert is_ready(service())
    stale = service()
    stale["latestCreatedRevision"] = "r3"
    assert not is_ready(stale)


def test_deploy_creates_or_updates_a_private_service_for_named_invokers_only():
    name = "projects/p/locations/europe-west1/services/vg-vantage"
    http = FakeHttp({
        ("PATCH", f"{BASE}/{name}"): FakeResponse(200, {"name": "operations/op1", "done": True, "response": {}}),
        ("POST", f"{BASE}/{name}:setIamPolicy"): FakeResponse(200, {}),
        ("GET", f"{BASE}/{name}"): FakeResponse(200, {"name": name, "uri": "https://vg-vantage.run.app"}),
    })
    service = CloudRun(http).deploy("p", "europe-west1", "vg-vantage", "img:1", service_account="sa@p",
                                    invokers=["serviceAccount:prover@p"], env={"VANTAGE_REGION": "europe-west1"})
    assert service["uri"] == "https://vg-vantage.run.app"
    method, _, patch = http.calls[0]
    assert method == "PATCH" and patch["params"] == {"allowMissing": "true"}
    template = patch["json"]["template"]
    assert template["serviceAccount"] == "sa@p"
    assert template["containers"][0]["image"] == "img:1"
    assert template["containers"][0]["env"] == [{"name": "VANTAGE_REGION", "value": "europe-west1"}]
    assert template["containers"][0]["resources"]["cpuIdle"] is True
    policy = http.calls[1][2]["json"]["policy"]
    assert policy == {"bindings": [{"role": "roles/run.invoker", "members": ["serviceAccount:prover@p"]}]}
