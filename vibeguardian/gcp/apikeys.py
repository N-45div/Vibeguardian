"""Google Cloud API Keys: find, create, read, and delete keys.

Docs: https://cloud.google.com/api-keys/docs/reference/rest
"""

from __future__ import annotations

from typing import Any

from vibeguardian.gcp.client import check, wait_operation

BASE = "https://apikeys.googleapis.com/v2"
MAX_DISPLAY_NAME = 63  # Google rejects longer display names


class ApiKeys:
    def __init__(self, http: Any, *, poll: float = 2.0, timeout: float = 180.0, sleep=None):
        self._http = http
        self._wait_kwargs: dict[str, Any] = {"poll": poll, "timeout": timeout}
        if sleep is not None:
            self._wait_kwargs["sleep"] = sleep

    def lookup(self, key_string: str) -> str:
        """Return the resource name of the key with this value.

        Needs ``apikeys.keys.lookup`` on the project that owns the key.
        """
        body = check(self._http.get(f"{BASE}/keys:lookupKey", params={"keyString": key_string}))
        name = body.get("name")
        if not name:
            raise LookupError("Google returned no key for that value")
        return name

    def get(self, name: str) -> dict[str, Any]:
        return check(self._http.get(f"{BASE}/{name}"))

    def list_keys(self, project: str) -> list[dict[str, Any]]:
        """Every key in the project that is not deleted. Values are not included."""
        keys: list[dict[str, Any]] = []
        params: dict[str, Any] = {"pageSize": 300}
        while True:
            body = check(self._http.get(f"{BASE}/projects/{project}/locations/global/keys", params=params))
            keys.extend(body.get("keys", []))
            if not body.get("nextPageToken"):
                return keys
            params["pageToken"] = body["nextPageToken"]

    def key_string(self, name: str) -> str:
        """Return the secret value of a key. Callers must never log it."""
        return check(self._http.get(f"{BASE}/{name}/keyString"))["keyString"]

    def create(
        self,
        project: str,
        display_name: str,
        restrictions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a key and return its resource once Google finishes."""
        payload: dict[str, Any] = {"displayName": display_name[:MAX_DISPLAY_NAME]}
        if restrictions:
            payload["restrictions"] = restrictions
        operation = check(
            self._http.post(f"{BASE}/projects/{project}/locations/global/keys", json=payload)
        )
        return wait_operation(self._http, BASE, operation, **self._wait_kwargs)

    def clone(self, name: str, display_name: str, restrictions: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create a new key in the same project, with the same restrictions unless given others."""
        old = self.get(name)
        project = name.split("/")[1]
        return self.create(project, display_name, restrictions or old.get("restrictions"))

    def delete(self, name: str) -> dict[str, Any]:
        """Delete a key. Google keeps it restorable for 30 days."""
        operation = check(self._http.delete(f"{BASE}/{name}"))
        return wait_operation(self._http, BASE, operation, **self._wait_kwargs)

    def undelete(self, name: str) -> dict[str, Any]:
        operation = check(self._http.post(f"{BASE}/{name}:undelete", json={}))
        return wait_operation(self._http, BASE, operation, **self._wait_kwargs)
