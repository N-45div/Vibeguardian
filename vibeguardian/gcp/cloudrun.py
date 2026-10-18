"""Google Cloud Run: find services that read a secret and roll them to a new version.

Cloud Run resolves secret environment variables when an instance starts, so a
new secret version only reaches a service through a new revision. Pinning the
service to the new version number creates that revision.

Docs: https://cloud.google.com/run/docs/reference/rest/v2/projects.locations.services
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Iterator

from vibeguardian.gcp.client import check, wait_operation

BASE = "https://run.googleapis.com/v2"


@dataclass(frozen=True)
class SecretUse:
    service: str  # projects/<p>/locations/<region>/services/<name>
    where: str  # "env:<NAME>" or "volume:<name>"
    secret: str  # as written in the service: an id or a full resource name
    version: str  # "latest" or a version number


def secret_id(name: str) -> str:
    """``projects/p/secrets/x`` or ``projects/p/secrets/x/versions/3`` or ``x`` -> ``x``."""
    parts = name.split("/")
    if "secrets" in parts:
        return parts[parts.index("secrets") + 1]
    return name


def version_number(version_name: str) -> str:
    return version_name.rsplit("/", 1)[-1]


def _env_refs(service: dict[str, Any]) -> Iterator[tuple[dict[str, Any], str]]:
    for container in service.get("template", {}).get("containers", []):
        for env in container.get("env", []):
            ref = env.get("valueSource", {}).get("secretKeyRef")
            if ref:
                yield ref, f"env:{env.get('name')}"


def _volume_refs(service: dict[str, Any]) -> Iterator[tuple[dict[str, Any], str]]:
    for volume in service.get("template", {}).get("volumes", []):
        secret = volume.get("secret")
        if not secret:
            continue
        items = secret.get("items") or [{"version": "latest"}]
        for item in items:
            yield {"secret": secret.get("secret"), "item": item}, f"volume:{volume.get('name')}"


def secret_uses(service: dict[str, Any]) -> list[SecretUse]:
    uses = []
    for ref, where in _env_refs(service):
        uses.append(SecretUse(service["name"], where, ref.get("secret", ""), str(ref.get("version", "latest"))))
    for ref, where in _volume_refs(service):
        uses.append(
            SecretUse(service["name"], where, ref["secret"] or "", str(ref["item"].get("version", "latest")))
        )
    return uses


class CloudRun:
    def __init__(self, http: Any, *, poll: float = 3.0, timeout: float = 600.0, sleep=None):
        self._http = http
        self._wait_kwargs: dict[str, Any] = {"poll": poll, "timeout": timeout}
        if sleep is not None:
            self._wait_kwargs["sleep"] = sleep

    def list_services(self, project: str, location: str = "-") -> list[dict[str, Any]]:
        services: list[dict[str, Any]] = []
        page_token = None
        while True:
            params = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            body = check(
                self._http.get(f"{BASE}/projects/{project}/locations/{location}/services", params=params)
            )
            services += body.get("services", [])
            page_token = body.get("nextPageToken")
            if not page_token:
                return services

    def consumers_of(self, project: str, secret: str) -> list[SecretUse]:
        """Every place in every service that reads ``secret`` (matched by secret id)."""
        wanted = secret_id(secret)
        return [
            use
            for service in self.list_services(project)
            for use in secret_uses(service)
            if secret_id(use.secret) == wanted
        ]

    def get(self, name: str) -> dict[str, Any]:
        return check(self._http.get(f"{BASE}/{name}"))

    def pin_secret(self, name: str, secret: str, version: str) -> dict[str, Any]:
        """Point every reference to ``secret`` in the service at ``version``; wait for the revision."""
        service = self.get(name)
        updated = copy.deepcopy(service)
        wanted = secret_id(secret)
        changed = False
        for ref, _ in _env_refs(updated):
            if secret_id(ref.get("secret", "")) == wanted:
                ref["version"] = version
                changed = True
        for volume in updated.get("template", {}).get("volumes", []):
            vol_secret = volume.get("secret")
            if vol_secret and secret_id(vol_secret.get("secret", "")) == wanted:
                items = vol_secret.get("items") or []
                for item in items:
                    item["version"] = version
                changed = changed or bool(items)
        if not changed:
            raise LookupError(f"{name} does not reference secret {wanted}")
        operation = check(self._http.patch(f"{BASE}/{name}", json=_writable(updated)))
        wait_operation(self._http, BASE, operation, **self._wait_kwargs)
        return self.get(name)

    def deploy(
        self,
        project: str,
        location: str,
        service_id: str,
        image: str,
        *,
        service_account: str,
        invokers: list[str],
        env: dict[str, str] | None = None,
        max_instances: int = 2,
    ) -> dict[str, Any]:
        """Create or update a private service running ``image``, callable only by ``invokers``."""
        name = f"projects/{project}/locations/{location}/services/{service_id}"
        spec = {
            "ingress": "INGRESS_TRAFFIC_ALL",
            "template": {
                "serviceAccount": service_account,
                "scaling": {"maxInstanceCount": max_instances},
                "containers": [{
                    "image": image,
                    "env": [{"name": k, "value": v} for k, v in (env or {}).items()],
                    # CPU only while serving a request: cheaper, and needed for 256Mi.
                    "resources": {"limits": {"cpu": "1", "memory": "256Mi"}, "cpuIdle": True},
                }],
            },
        }
        operation = check(self._http.patch(f"{BASE}/{name}", params={"allowMissing": "true"}, json=spec))
        wait_operation(self._http, BASE, operation, **self._wait_kwargs)
        # Replaces the whole policy: nobody else, and never allUsers, may call it.
        policy = {"bindings": [{"role": "roles/run.invoker", "members": list(invokers)}]}
        check(self._http.post(f"{BASE}/{name}:setIamPolicy", json={"policy": policy}))
        return self.get(name)


_OUTPUT_ONLY = {
    "uid",
    "generation",
    "createTime",
    "updateTime",
    "deleteTime",
    "expireTime",
    "creator",
    "lastModifier",
    "observedGeneration",
    "terminalCondition",
    "conditions",
    "latestReadyRevision",
    "latestCreatedRevision",
    "trafficStatuses",
    "uri",
    "urls",
    "reconciling",
    "satisfiesPzs",
}


def _writable(service: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in service.items() if k not in _OUTPUT_ONLY}


def is_ready(service: dict[str, Any]) -> bool:
    condition = service.get("terminalCondition", {})
    return (
        condition.get("state") == "CONDITION_SUCCEEDED"
        and service.get("latestReadyRevision") == service.get("latestCreatedRevision")
    )
