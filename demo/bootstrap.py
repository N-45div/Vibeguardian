"""Give the demo app a Gemini key without the value ever touching a screen.

Creates an API key restricted to the Gemini API and stores it as the first
version of a Secret Manager secret. Run once per demo project:

    python demo/bootstrap.py --project <project-id>

Then deploy with demo/deploy.sh.
"""

from __future__ import annotations

import argparse

from vibeguardian.gcp import GoogleApiError, session
from vibeguardian.gcp.apikeys import ApiKeys
from vibeguardian.gcp.secretmanager import SecretManager
from vibeguardian.experiment import GEMINI_ONLY
from vibeguardian.secret import fingerprint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", required=True)
    parser.add_argument("--secret-id", default="gemini-api-key")
    args = parser.parse_args()

    http = session(quota_project=args.project)
    keys, secrets = ApiKeys(http), SecretManager(http)
    key = keys.create(args.project, "vg-demo-app Gemini key", GEMINI_ONLY)
    value = keys.key_string(key["name"])
    try:
        secret = secrets.create_secret(args.project, args.secret_id)
    except GoogleApiError as err:
        if err.http_status != 409:
            raise
        secret = f"projects/{args.project}/secrets/{args.secret_id}"
    version = secrets.add_version(secret, value)
    print(f"key {key['name']} ({fingerprint(value)}) stored as {version}")


if __name__ == "__main__":
    main()
