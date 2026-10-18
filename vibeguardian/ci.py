"""Google credentials for GitLab CI jobs, with no stored key.

The job declares an ID token (``id_tokens: GCP_ID_TOKEN``). Google's Security
Token Service trades it for a short-lived token, which then impersonates one
narrow service account. The pool only trusts this GitLab project.

Configuration comes from CI variables in ``.gitlab-ci.yml`` (none of them
secret): GCP_PROJECT_NUMBER, GCP_POOL, GCP_PROVIDER.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping


def provider_resource(env: Mapping[str, str]) -> str:
    return (
        f"projects/{env['GCP_PROJECT_NUMBER']}/locations/global/"
        f"workloadIdentityPools/{env['GCP_POOL']}/providers/{env['GCP_PROVIDER']}"
    )


def audience(env: Mapping[str, str]) -> str:
    """The value the job's ID token must carry as ``aud``."""
    return f"https://iam.googleapis.com/{provider_resource(env)}"


def credential_config(env: Mapping[str, str], token_file: str, service_account: str) -> dict:
    return {
        "type": "external_account",
        "audience": f"//iam.googleapis.com/{provider_resource(env)}",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": {"file": token_file},
        "service_account_impersonation_url": (
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/"
            f"{service_account}:generateAccessToken"
        ),
    }


def write_credentials(
    service_account: str,
    out: str = ".gcp.creds.json",
    token_env: str = "GCP_ID_TOKEN",
    env: Mapping[str, str] | None = None,
) -> Path:
    """Write the job's ID token and a credential file that uses it. Returns the file."""
    env = env if env is not None else os.environ
    token = env.get(token_env, "")
    if not token:
        raise SystemExit(f"{token_env} is empty: declare it under id_tokens in the job")
    out_path = Path(out).resolve()
    token_path = out_path.with_name(".ci_job_jwt")
    token_path.write_text(token, encoding="utf-8")
    config = credential_config(env, str(token_path), service_account)
    out_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return out_path
