"""Authenticated HTTP for Google Cloud REST APIs.

Credentials come from Application Default Credentials. Locally that is
``gcloud auth application-default login``; in GitLab CI it is a Workload
Identity Federation credential file built from the job's ID token, so no
long-lived key is ever stored.
"""

from __future__ import annotations

import time
from typing import Any

import google.auth
import requests
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2 import credentials as user_credentials
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)

# Retry dropped or refused connections. Read errors are retried only for
# idempotent methods, so a POST that reached Google (such as creating a key)
# is never sent twice.
RETRY = Retry(
    total=6,
    connect=5,
    read=3,
    other=3,
    status=3,
    status_forcelist=(500, 502, 503, 504),
    allowed_methods=frozenset({"GET", "DELETE", "HEAD", "OPTIONS"}),
    backoff_factor=0.5,
    raise_on_status=False,
)


# Fetching an access token twice is harmless, so token requests (POSTs to
# the OAuth endpoint) may be retried even after a dropped read.
TOKEN_RETRY = RETRY.new(allowed_methods=frozenset({"GET", "POST"}))


def _mount_retries(http: requests.Session, retry: Retry = RETRY) -> requests.Session:
    http.mount("https://", HTTPAdapter(max_retries=retry))
    return http


class GoogleApiError(RuntimeError):
    """A Google API call failed. The message never includes request URLs."""

    def __init__(self, http_status: int, message: str, reason: str | None = None):
        super().__init__(f"HTTP {http_status}: {message}")
        self.http_status = http_status
        self.reason = reason


def session(quota_project: str | None = None) -> AuthorizedSession:
    """Return a session that signs every request with ADC credentials.

    ``quota_project`` is needed when ADC holds user credentials: APIs such as
    API Keys refuse user calls that do not name a project to bill.
    """
    credentials, _ = google.auth.default(scopes=list(SCOPES))
    # Only user credentials need a quota project. Setting one on federated or
    # service-account credentials makes Google demand serviceusage permission
    # from the caller before it will even issue a token.
    if quota_project and isinstance(credentials, user_credentials.Credentials):
        credentials = credentials.with_quota_project(quota_project)
    token_request = Request(session=_mount_retries(requests.Session(), TOKEN_RETRY))
    return _mount_retries(AuthorizedSession(credentials, auth_request=token_request))


def check(response: Any) -> dict[str, Any]:
    """Return the JSON body of a successful response or raise GoogleApiError."""
    try:
        body = response.json()
    except ValueError:
        body = {}
    if 200 <= response.status_code < 300:
        return body if isinstance(body, dict) else {}
    error = body.get("error", {}) if isinstance(body, dict) else {}
    reason = None
    for detail in error.get("details") or []:
        if isinstance(detail, dict) and detail.get("reason"):
            reason = detail["reason"]
            break
    raise GoogleApiError(response.status_code, str(error.get("message", "request failed")), reason)


def wait_operation(
    http: Any,
    base_url: str,
    operation: dict[str, Any],
    *,
    poll: float = 2.0,
    timeout: float = 180.0,
    sleep=time.sleep,
) -> dict[str, Any]:
    """Poll a long-running operation until it is done and return its response."""
    deadline = time.monotonic() + timeout
    while not operation.get("done"):
        if time.monotonic() > deadline:
            raise TimeoutError(f"operation {operation.get('name')} did not finish in {timeout}s")
        sleep(poll)
        operation = check(http.get(f"{base_url}/{operation['name']}"))
    if "error" in operation:
        error = operation["error"]
        raise GoogleApiError(int(error.get("code", 500)), str(error.get("message", "operation failed")))
    return operation.get("response", {})
