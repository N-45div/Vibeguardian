"""Google Cloud IAM: service-account keys.

Docs: https://cloud.google.com/iam/docs/reference/rest/v1/projects.serviceAccounts.keys
"""

from __future__ import annotations

import base64
import json
from typing import Any

from vibeguardian.gcp.client import GoogleApiError, check, wait_operation

BASE = "https://iam.googleapis.com/v1"


def _get_or_none(http: Any, url: str) -> dict[str, Any] | None:
    try:
        return check(http.get(url))
    except GoogleApiError as err:
        if err.http_status == 404:
            return None
        raise


class ServiceAccountKeys:
    def __init__(self, http: Any):
        self._http = http

    def create(self, email: str) -> tuple[str, dict[str, Any]]:
        """Create a key and return (key resource name, key file contents).

        The key file holds a private key. Callers must never log it.
        """
        body = check(self._http.post(f"{BASE}/projects/-/serviceAccounts/{email}/keys", json={}))
        info = json.loads(base64.b64decode(body["privateKeyData"]))
        return body["name"], info

    def list(self, email: str) -> list[dict[str, Any]]:
        body = check(
            self._http.get(f"{BASE}/projects/-/serviceAccounts/{email}/keys", params={"keyTypes": "USER_MANAGED"})
        )
        return body.get("keys", [])

    def get(self, name: str) -> dict[str, Any] | None:
        """The key's metadata (``disabled`` is true once turned off), or None once deleted."""
        return _get_or_none(self._http, f"{BASE}/{name}")

    def disable(self, name: str) -> None:
        check(self._http.post(f"{BASE}/{name}:disable", json={}))

    def enable(self, name: str) -> None:
        check(self._http.post(f"{BASE}/{name}:enable", json={}))

    def delete(self, name: str) -> None:
        check(self._http.delete(f"{BASE}/{name}"))


class ServiceAccounts:
    """Create, delete, and turn service accounts off and on. Disabling one
    stops every credential it has, including tokens minted earlier."""

    def __init__(self, http: Any):
        self._http = http

    def create(self, project: str, account_id: str, display_name: str) -> str:
        """Create a service account and return its email."""
        body = check(self._http.post(
            f"{BASE}/projects/{project}/serviceAccounts",
            json={"accountId": account_id, "serviceAccount": {"displayName": display_name}},
        ))
        return body["email"]

    def get(self, email: str) -> dict[str, Any] | None:
        """The account (``disabled`` is true once turned off), or None once deleted."""
        return _get_or_none(self._http, f"{BASE}/projects/-/serviceAccounts/{email}")

    def delete(self, email: str) -> None:
        check(self._http.delete(f"{BASE}/projects/-/serviceAccounts/{email}"))

    def disable(self, email: str) -> None:
        check(self._http.post(f"{BASE}/projects/-/serviceAccounts/{email}:disable", json={}))

    def enable(self, email: str) -> None:
        check(self._http.post(f"{BASE}/projects/-/serviceAccounts/{email}:enable", json={}))


class ProjectRoles:
    """Remove one member from every role on a project, and put it back exactly.

    Uses the policy etag, so a concurrent change makes the write fail rather
    than overwrite someone else's edit.
    """

    RM = "https://cloudresourcemanager.googleapis.com/v1"

    def __init__(self, http: Any):
        self._http = http

    def _get(self, project: str) -> dict[str, Any]:
        return check(self._http.post(f"{self.RM}/projects/{project}:getIamPolicy",
                                     json={"options": {"requestedPolicyVersion": 3}}))

    def _set(self, project: str, policy: dict[str, Any]) -> None:
        check(self._http.post(f"{self.RM}/projects/{project}:setIamPolicy", json={"policy": policy}))

    def remove_member(self, project: str, member: str) -> list[dict[str, Any]]:
        """Remove ``member`` from all bindings. Returns the bindings it was in, for restore."""
        policy = self._get(project)
        removed = []
        for binding in policy.get("bindings", []):
            if member in binding.get("members", []):
                removed.append({k: v for k, v in binding.items() if k != "members"})
                binding["members"] = [m for m in binding["members"] if m != member]
        policy["bindings"] = [b for b in policy.get("bindings", []) if b.get("members")]
        if removed:
            self._set(project, policy)
        return removed

    def copy_member(self, project: str, source: str, target: str) -> list[str]:
        """Give ``target`` every project role ``source`` has. Returns the roles."""
        policy = self._get(project)
        roles = []
        for binding in policy.get("bindings", []):
            if source in binding.get("members", []) and target not in binding["members"]:
                binding["members"].append(target)
                roles.append(binding["role"])
        if roles:
            self._set(project, policy)
        return roles

    def restore_member(self, project: str, member: str, bindings: list[dict[str, Any]]) -> None:
        if not bindings:
            return
        policy = self._get(project)
        current = policy.setdefault("bindings", [])
        for wanted in bindings:
            match = next((b for b in current if b.get("role") == wanted.get("role")
                          and b.get("condition") == wanted.get("condition")), None)
            if match is None:
                current.append({**wanted, "members": [member]})
            elif member not in match["members"]:
                match["members"].append(member)
        self._set(project, policy)


class DenyPolicies:
    """IAM deny policies: block one principal on a project without touching
    anyone's roles. Removing the policy undoes it."""

    V2 = "https://iam.googleapis.com/v2"

    def __init__(self, http: Any):
        self._http = http

    def _parent(self, project: str) -> str:
        return f"policies/cloudresourcemanager.googleapis.com%2Fprojects%2F{project}/denypolicies"

    def deny(self, project: str, policy_id: str, principal: str, permissions: list[str]) -> None:
        body = {
            "displayName": "VibeGuardian: cut off a leaked credential",
            "rules": [{"denyRule": {"deniedPrincipals": [principal], "deniedPermissions": permissions}}],
        }
        operation = check(self._http.post(f"{self.V2}/{self._parent(project)}", params={"policyId": policy_id},
                                          json=body))
        if not operation.get("done"):
            wait_operation(self._http, self.V2, operation, poll=2.0, timeout=120.0)

    def remove(self, project: str, policy_id: str) -> None:
        operation = check(self._http.delete(f"{self.V2}/{self._parent(project)}/{policy_id}"))
        if not operation.get("done"):
            wait_operation(self._http, self.V2, operation, poll=2.0, timeout=120.0)


def principal_for(email: str) -> str:
    """Deny-policy principal identifier for a service account."""
    return f"principal://iam.googleapis.com/projects/-/serviceAccounts/{email}"


def key_name_for(info: dict[str, Any]) -> str:
    """The key resource name for a leaked key file, from its own fields."""
    return f"projects/-/serviceAccounts/{info['client_email']}/keys/{info['private_key_id']}"
