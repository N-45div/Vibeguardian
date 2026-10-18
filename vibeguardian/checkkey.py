"""Tell someone what a Google API key they just copied can do.

Used by the desktop companion when a key lands on the clipboard: is it live,
which project and key it is, how old it is, and whether it is restricted.
Only the fingerprint is ever returned; the value never leaves this process.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable

from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.secret import fingerprint

RESTRICTION_KINDS = (
    "browserKeyRestrictions",
    "serverKeyRestrictions",
    "androidKeyRestrictions",
    "iosKeyRestrictions",
)


def describe_restrictions(restrictions: dict[str, Any] | None) -> dict[str, Any]:
    restrictions = restrictions or {}
    apis = [t.get("service") for t in restrictions.get("apiTargets", []) if t.get("service")]
    apps = [kind.replace("KeyRestrictions", "") for kind in RESTRICTION_KINDS if restrictions.get(kind)]
    return {"apis": apis, "apps": apps, "unrestricted": not apis and not apps}


def age_days(create_time: str | None, now: datetime | None = None) -> int | None:
    if not create_time:
        return None
    created = datetime.fromisoformat(create_time.replace("Z", "+00:00"))
    return ((now or datetime.now(timezone.utc)) - created).days


def check_key(
    value: str,
    *,
    probe: Callable[[str], ProbeResult],
    keys: Any | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Report on a key. ``keys`` (an ApiKeys client) is optional: without a
    Google login we can still say whether the key is live."""
    result = probe(value)
    report: dict[str, Any] = {
        "fingerprint": fingerprint(value),
        "live": result.verdict == Verdict.ALIVE,
        "google_says": result.reason or result.http_status,
        "owned": None,
    }
    if keys is None:
        return report
    try:
        name = keys.lookup(value)
    except LookupError:
        report["owned"] = False
        return report
    except Exception as err:  # noqa: BLE001 - no permission to look it up is an answer too
        report["owned"] = None
        report["lookup_error"] = type(err).__name__
        return report
    key = keys.get(name)
    report.update(
        {
            "owned": True,
            "key": name,
            "project_number": name.split("/")[1],
            "display_name": key.get("displayName"),
            "age_days": age_days(key.get("createTime"), now),
            "restrictions": describe_restrictions(key.get("restrictions")),
        }
    )
    return report
