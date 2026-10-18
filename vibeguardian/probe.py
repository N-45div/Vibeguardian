"""Ask Google whether an API key is still accepted.

The verdict comes from Google's own response, never from our records. A key
is DEAD only when Google says the key itself is not valid. Any answer showing
Google still recognised the key (success, quota, restriction, or disabled-API
errors) means it is ALIVE. Anything else is UNKNOWN and never counts as proof
either way.

The key travels in the ``x-goog-api-key`` header, not the URL, so it cannot
end up in proxy logs or exception messages.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable

import requests

DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"


class Verdict(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"


# google.rpc.ErrorInfo reasons that mean Google no longer accepts the key.
DEAD_REASONS = frozenset({"API_KEY_INVALID", "API_KEY_EXPIRED"})

# Reasons that prove Google looked the key up and still knows it.
ALIVE_REASONS = frozenset(
    {
        "API_KEY_SERVICE_BLOCKED",
        "API_KEY_HTTP_REFERRER_BLOCKED",
        "API_KEY_IP_ADDRESS_BLOCKED",
        "API_KEY_ANDROID_APP_BLOCKED",
        "API_KEY_IOS_APP_BLOCKED",
        "SERVICE_DISABLED",
        "BILLING_DISABLED",
        "RATE_LIMIT_EXCEEDED",
        "RESOURCE_EXHAUSTED",
    }
)

# Older endpoints sometimes omit ErrorInfo; fall back to the message text.
_DEAD_MESSAGES = ("api key not valid", "api key expired")


@dataclass(frozen=True)
class ProbeResult:
    verdict: Verdict
    http_status: int | None
    reason: str | None
    latency_ms: int
    at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict.value,
            "http_status": self.http_status,
            "reason": self.reason,
            "latency_ms": self.latency_ms,
            "at": round(self.at, 3),
        }


def _error_info(body: Any) -> tuple[str | None, str]:
    """Return (ErrorInfo reason, lower-cased message) from a Google error body."""
    if not isinstance(body, dict):
        return None, ""
    error = body.get("error") or {}
    message = str(error.get("message", "")).lower()
    for detail in error.get("details") or []:
        if isinstance(detail, dict) and detail.get("reason"):
            return str(detail["reason"]), message
    return None, message


def classify(http_status: int, body: Any) -> tuple[Verdict, str | None]:
    """Turn one HTTP response from a Google API into a verdict about the key."""
    if http_status == 200:
        return Verdict.ALIVE, None
    reason, message = _error_info(body)
    if reason in DEAD_REASONS:
        return Verdict.DEAD, reason
    if reason is None and http_status == 400 and message.startswith(_DEAD_MESSAGES):
        return Verdict.DEAD, "API_KEY_INVALID"
    if http_status >= 500:
        return Verdict.UNKNOWN, reason
    if reason in ALIVE_REASONS or http_status == 429:
        return Verdict.ALIVE, reason or "RESOURCE_EXHAUSTED"
    return Verdict.UNKNOWN, reason


def probe(
    key: str,
    endpoint: str = DEFAULT_ENDPOINT,
    *,
    timeout: float = 10.0,
    session: requests.Session | None = None,
) -> ProbeResult:
    """Make one cheap, read-only call with ``key`` and classify Google's answer."""
    http = session or requests
    started = time.time()
    try:
        response = http.get(endpoint, headers={"x-goog-api-key": key}, timeout=timeout)
    except requests.RequestException:
        return ProbeResult(Verdict.UNKNOWN, None, "NETWORK_ERROR", _ms_since(started), started)
    try:
        body = response.json()
    except ValueError:
        body = None
    verdict, reason = classify(response.status_code, body)
    return ProbeResult(verdict, response.status_code, reason, _ms_since(started), started)


@dataclass(frozen=True)
class WatchResult:
    reached: bool
    target: Verdict
    first_at: float | None
    stable_at: float | None
    probes: int
    flaps: int


def watch(
    check: Callable[[], ProbeResult],
    *,
    until: Verdict,
    stable: int = 6,
    interval: float = 10.0,
    max_seconds: float = 2400.0,
    on_probe: Callable[[ProbeResult], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.time,
) -> WatchResult:
    """Probe until ``until`` is seen ``stable`` times in a row, or time runs out.

    A key that was seen DEAD and then answers ALIVE again is a "flap": the
    streak and the first-seen time both reset. UNKNOWN answers neither extend
    nor break a streak.
    """
    deadline = clock() + max_seconds
    streak = 0
    first_at: float | None = None
    probes = 0
    flaps = 0
    while True:
        result = check()
        probes += 1
        if on_probe:
            on_probe(result)
        if result.verdict == until:
            streak += 1
            if first_at is None:
                first_at = result.at
            if streak >= stable:
                return WatchResult(True, until, first_at, result.at, probes, flaps)
        elif result.verdict != Verdict.UNKNOWN:
            if streak:
                flaps += 1
            streak = 0
            first_at = None
        if clock() + interval > deadline:
            return WatchResult(False, until, first_at, None, probes, flaps)
        sleep(interval)


def _ms_since(started: float) -> int:
    return int((time.time() - started) * 1000)
