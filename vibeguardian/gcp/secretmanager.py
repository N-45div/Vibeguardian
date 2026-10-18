"""Google Secret Manager: find which secrets hold a leaked value and roll them.

Matching is done on fingerprints, so the leaked value is compared but never
stored or logged.

Docs: https://cloud.google.com/secret-manager/docs/reference/rest
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from vibeguardian.gcp.client import GoogleApiError, check
from vibeguardian.secret import fingerprint

BASE = "https://secretmanager.googleapis.com/v1"


@dataclass(frozen=True)
class SecretMatch:
    secret: str  # projects/<number>/secrets/<id>
    version: str  # full version resource name that holds the leaked value


class SecretManager:
    def __init__(self, http: Any):
        self._http = http

    def list_secrets(self, project: str) -> list[str]:
        names: list[str] = []
        page_token = None
        while True:
            params = {"pageSize": 250}
            if page_token:
                params["pageToken"] = page_token
            body = check(self._http.get(f"{BASE}/projects/{project}/secrets", params=params))
            names += [s["name"] for s in body.get("secrets", [])]
            page_token = body.get("nextPageToken")
            if not page_token:
                return names

    def access(self, version: str) -> tuple[str, str]:
        """Return (resolved version name, value) for a version such as ``.../versions/latest``."""
        body = check(self._http.get(f"{BASE}/{version}:access"))
        value = base64.b64decode(body["payload"]["data"]).decode("utf-8")
        return body["name"], value

    def find_holders(self, project: str, leaked_fingerprint: str) -> list[SecretMatch]:
        """Return every secret whose latest enabled version holds the leaked value."""
        return self.find_holders_matching(
            project, lambda value: bool(value) and fingerprint(value.strip()) == leaked_fingerprint
        )

    def find_holders_matching(self, project: str, matches_value) -> list[SecretMatch]:
        """Return every secret whose latest enabled version satisfies ``matches_value``."""
        matches = []
        for secret in self.list_secrets(project):
            try:
                version, value = self.access(f"{secret}/versions/latest")
            except GoogleApiError as err:
                if err.http_status in (400, 403, 404):  # no enabled version, or no access
                    continue
                raise
            if matches_value(value):
                matches.append(SecretMatch(secret=secret, version=version))
        return matches

    def create_secret(self, project: str, secret_id: str) -> str:
        body = check(
            self._http.post(
                f"{BASE}/projects/{project}/secrets",
                params={"secretId": secret_id},
                json={"replication": {"automatic": {}}},
            )
        )
        return body["name"]

    def add_version(self, secret: str, value: str) -> str:
        data = base64.b64encode(value.encode("utf-8")).decode("ascii")
        body = check(self._http.post(f"{BASE}/{secret}:addVersion", json={"payload": {"data": data}}))
        return body["name"]

    def disable_version(self, version: str) -> dict[str, Any]:
        return check(self._http.post(f"{BASE}/{version}:disable", json={}))

    def enable_version(self, version: str) -> dict[str, Any]:
        return check(self._http.post(f"{BASE}/{version}:enable", json={}))
