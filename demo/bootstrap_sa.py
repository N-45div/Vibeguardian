"""Set up a throwaway service account whose key lives in Secret Manager, for
service-account leak drills. The key file never touches a screen or disk.

    python demo/bootstrap_sa.py --project <project-id>

Creates (if missing) the account `vg-leaky-app` with read-only project
metadata access (roles/browser), a key for it, and the secret `leaky-sa-key`
holding that key file.
"""

from __future__ import annotations

import argparse
import json

from vibeguardian.gcp import GoogleApiError, session
from vibeguardian.gcp.iam import ServiceAccountKeys, ServiceAccounts
from vibeguardian.gcp.secretmanager import SecretManager
from vibeguardian.secret import fingerprint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--account-id", default="vg-leaky-app")
    parser.add_argument("--secret-id", default="leaky-sa-key")
    args = parser.parse_args()

    http = session(quota_project=args.project)
    email = f"{args.account_id}@{args.project}.iam.gserviceaccount.com"
    try:
        ServiceAccounts(http).create(args.project, args.account_id, "VibeGuardian drill: leaky app")
        print(f"created {email}")
    except GoogleApiError as err:
        if err.http_status != 409:
            raise
    rm = "https://cloudresourcemanager.googleapis.com/v1"
    policy = http.post(f"{rm}/projects/{args.project}:getIamPolicy", json={}).json()
    member = f"serviceAccount:{email}"
    binding = next((b for b in policy.get("bindings", []) if b["role"] == "roles/browser"), None)
    if binding is None:
        policy.setdefault("bindings", []).append({"role": "roles/browser", "members": [member]})
    elif member not in binding["members"]:
        binding["members"].append(member)
    http.post(f"{rm}/projects/{args.project}:setIamPolicy", json={"policy": policy}).raise_for_status()

    name, info = ServiceAccountKeys(http).create(email)
    secrets = SecretManager(http)
    try:
        secret = secrets.create_secret(args.project, args.secret_id)
    except GoogleApiError as err:
        if err.http_status != 409:
            raise
        secret = f"projects/{args.project}/secrets/{args.secret_id}"
    version = secrets.add_version(secret, json.dumps(info))
    print(f"key {name.rsplit('/', 1)[-1]} ({fingerprint(info['private_key'])}) stored as {version}")


if __name__ == "__main__":
    main()
