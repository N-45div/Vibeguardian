"""Health checks for services after they move to a replacement key.

"Up" is not enough. If the service reports the fingerprint of the key it is
serving with, it must be the replacement's fingerprint, or the rollout has
not really happened.
"""

from __future__ import annotations

from typing import Any, Callable

import requests


def http_health(path: str = "/health", timeout: float = 10.0) -> Callable[[dict[str, Any], str], tuple[bool, str]]:
    def check(service: dict[str, Any], expected_fp: str) -> tuple[bool, str]:
        uri = service.get("uri")
        if not uri:
            return False, "service has no URL"
        try:
            response = requests.get(uri.rstrip("/") + path, timeout=timeout)
        except requests.RequestException as err:
            return False, f"{path} unreachable: {type(err).__name__}"
        if response.status_code != 200:
            return False, f"{path} returned {response.status_code}"
        try:
            reported = response.json().get("key_fingerprint")
        except ValueError:
            reported = None
        if reported is None:
            return True, f"{path} 200 (service does not report a key fingerprint)"
        if reported != expected_fp:
            return False, f"still serving {reported}"
        return True, f"{path} 200 on {reported}"

    return check
