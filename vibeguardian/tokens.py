"""What a leaked service-account key still lets an attacker do.

Two separate questions, because Google answers them differently:

1. Can the key still mint new access tokens?
2. Does an access token minted *before* the key was disabled still work?

Disabling or deleting a key answers (1) quickly. It does not revoke tokens
already issued, which live for up to an hour by default.
"""

from __future__ import annotations

import time
from typing import Any, Callable

import requests
from google.auth.exceptions import RefreshError, TransportError
from google.auth.transport.requests import Request
from google.oauth2 import service_account

from vibeguardian.probe import ProbeResult, Verdict

SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]


def mint(info: dict[str, Any]) -> str | None:
    """Mint an access token from a key file. Return None if Google refuses."""
    credentials = service_account.Credentials.from_service_account_info(info, scopes=SCOPES)
    try:
        credentials.refresh(Request())
    except RefreshError:
        return None
    return credentials.token


def probe_mint(info: dict[str, Any], clock: Callable[[], float] = time.time) -> ProbeResult:
    started = clock()
    try:
        token = mint(info)
    except TransportError:
        return ProbeResult(Verdict.UNKNOWN, None, "NETWORK_ERROR", 0, started)
    verdict = Verdict.ALIVE if token else Verdict.DEAD
    return ProbeResult(verdict, None, None if token else "MINT_REFUSED", int((clock() - started) * 1000), started)


def probe_access(token: str, url: str, clock: Callable[[], float] = time.time) -> ProbeResult:
    """Can this token still DO something? 200 means yes (ALIVE); 401 or 403
    means its access is cut (DEAD). Use this to time a cut-off, where a
    permission error is the goal, unlike probe_token."""
    started = clock()
    try:
        response = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    except requests.RequestException:
        return ProbeResult(Verdict.UNKNOWN, None, "NETWORK_ERROR", 0, started)
    latency = int((clock() - started) * 1000)
    if response.status_code == 200:
        return ProbeResult(Verdict.ALIVE, 200, None, latency, started)
    if response.status_code in (401, 403):
        return ProbeResult(Verdict.DEAD, response.status_code, "ACCESS_CUT", latency, started)
    return ProbeResult(Verdict.UNKNOWN, response.status_code, None, latency, started)


def probe_token(token: str, url: str, clock: Callable[[], float] = time.time) -> ProbeResult:
    """Call ``url`` with a bearer token. 401 means the token is dead."""
    started = clock()
    try:
        response = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=10)
    except requests.RequestException:
        return ProbeResult(Verdict.UNKNOWN, None, "NETWORK_ERROR", 0, started)
    latency = int((clock() - started) * 1000)
    if response.status_code == 401:
        return ProbeResult(Verdict.DEAD, 401, "UNAUTHENTICATED", latency, started)
    if response.status_code in (200, 403, 404):
        # 403/404 still mean Google accepted who we are.
        return ProbeResult(Verdict.ALIVE, response.status_code, None, latency, started)
    return ProbeResult(Verdict.UNKNOWN, response.status_code, None, latency, started)
