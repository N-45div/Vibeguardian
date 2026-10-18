import json

import pytest

from vibeguardian import ci

ENV = {"GCP_PROJECT_NUMBER": "123", "GCP_POOL": "gitlab", "GCP_PROVIDER": "gitlab-com", "GCP_ID_TOKEN": "eyJ-fake-id-token"}


def test_audience_matches_what_the_job_must_request():
    assert ci.audience(ENV) == (
        "https://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/gitlab/providers/gitlab-com"
    )


def test_write_credentials_points_at_the_token_file_and_service_account(tmp_path):
    out = ci.write_credentials("sa@p.iam.gserviceaccount.com", str(tmp_path / ".gcp.creds.json"), env=ENV)
    config = json.loads(out.read_text())
    token_file = config["credential_source"]["file"]
    assert open(token_file).read() == "eyJ-fake-id-token"
    assert config["audience"].startswith("//iam.googleapis.com/projects/123/")
    assert config["service_account_impersonation_url"].endswith(
        "serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken"
    )
    assert "eyJ-fake-id-token" not in out.read_text()


def test_missing_id_token_fails_clearly(tmp_path):
    env = dict(ENV, GCP_ID_TOKEN="")
    with pytest.raises(SystemExit):
        ci.write_credentials("sa@p", str(tmp_path / "c.json"), env=env)
