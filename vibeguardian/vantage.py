"""Ask Google about a key from other regions, through the vg-vantage services.

Each vantage is a private Cloud Run service in one region (demo/vantage). The
prover calls it with an ID token for the vg-prover identity, the only one
allowed to; the service makes one read-only call to Google from its region
and answers with the verdict and the key's fingerprint.

Anything short of a clear answer from Google (the relay is down, refuses the
call, or answers for a different key) is UNKNOWN, which never counts as
proof either way.
"""

from __future__ import annotations

import time
from typing import Any, Callable

import requests

from vibeguardian.gcp.client import check
from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.secret import fingerprint

IAM_CREDENTIALS = "https://iamcredentials.googleapis.com/v1"


def parse_vantages(specs: list[str]) -> dict[str, str]:
    """``["europe-west1=https://..."]`` -> ``{"europe-west1": "https://..."}``."""
    vantages = {}
    for spec in specs:
        name, sep, url = spec.partition("=")
        if not sep or not name or not url.startswith("https://"):
            raise ValueError(f"vantage must look like REGION=https://URL, got {spec!r}")
        vantages[name] = url.rstrip("/")
    return vantages


def id_token(http: Any, service_account: str, audience: str) -> str:
    """A Google-signed ID token for ``service_account``, valid for ``audience`` (one hour)."""
    body = check(http.post(f"{IAM_CREDENTIALS}/projects/-/serviceAccounts/{service_account}:generateIdToken",
                           json={"audience": audience, "includeEmail": True}))
    return body["token"]


def _ms_since(started: float) -> int:
    return int((time.time() - started) * 1000)


def vantage_check(
    url: str, token: str | Callable[[], str], *, session: Any = None, timeout: float = 30.0,
) -> Callable[[str], ProbeResult]:
    """A probe that asks Google through the vantage at ``url``.

    ``token`` may be a function: it is called once, on the first probe, so no
    token is minted when there is nothing to prove. If it fails, every probe
    from this vantage is UNKNOWN and the proof lists it as unreachable.
    """
    http = session or requests
    minted: dict[str, str | None] = {}

    def bearer() -> str | None:
        if "token" not in minted:
            try:
                minted["token"] = token() if callable(token) else token
            except Exception:  # noqa: BLE001 - any failure means this vantage cannot answer
                minted["token"] = None
        return minted["token"]

    def check_key(key: str) -> ProbeResult:
        started = time.time()
        auth = bearer()
        if auth is None:
            return ProbeResult(Verdict.UNKNOWN, None, "VANTAGE_NO_TOKEN", _ms_since(started), started)
        try:
            response = http.post(f"{url}/probe", json={"key": key}, timeout=timeout,
                                 headers={"Authorization": f"Bearer {auth}"})
        except requests.RequestException:
            return ProbeResult(Verdict.UNKNOWN, None, "VANTAGE_UNREACHABLE", _ms_since(started), started)
        if response.status_code != 200:
            return ProbeResult(Verdict.UNKNOWN, None, f"VANTAGE_HTTP_{response.status_code}",
                               _ms_since(started), started)
        try:
            body = response.json()
            verdict = Verdict(body["verdict"])
        except (ValueError, KeyError, TypeError):
            return ProbeResult(Verdict.UNKNOWN, None, "VANTAGE_BAD_ANSWER", _ms_since(started), started)
        if body.get("fingerprint") != fingerprint(key):
            return ProbeResult(Verdict.UNKNOWN, None, "VANTAGE_WRONG_KEY", _ms_since(started), started)
        return ProbeResult(verdict, body.get("http_status"), body.get("reason"), _ms_since(started), started)

    return check_key
