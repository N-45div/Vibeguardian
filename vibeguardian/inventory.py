"""Every API key in a project, and what makes each one risky.

For each key: how old it is, what it is limited to, and how many calls it
made recently and from which Google regions (one Cloud Monitoring query for
the whole project). Never reads a key's value.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from vibeguardian.checkkey import age_days, describe_restrictions
from vibeguardian.exposure import key_uid, request_counts

OLD_AFTER_DAYS = 180


def key_report(key: dict[str, Any], usage: dict[str, dict[str, int]], now: datetime) -> dict[str, Any]:
    restrictions = describe_restrictions(key.get("restrictions"))
    age = age_days(key.get("createTime"), now)
    calls = sum(c["ok"] for c in usage.values())
    flags = []
    if restrictions["unrestricted"]:
        flags.append("unrestricted")
    if age is not None and age > OLD_AFTER_DAYS:
        flags.append("old")
    if not calls:
        flags.append("unused")
    return {
        "name": key["name"],
        "uid": key_uid(key["name"]),
        "display_name": key.get("displayName"),
        "created": key.get("createTime"),
        "age_days": age,
        "restrictions": restrictions,
        "calls": calls,
        "regions": sorted(r for r, c in usage.items() if c["ok"]),
        "flags": flags,
    }


def inventory(keys: Any, http: Any, project: str, *, days: int = 7, now: datetime | None = None) -> dict[str, Any]:
    """``keys`` is an ApiKeys client; ``http`` reads Cloud Monitoring."""
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    counts = request_counts(http, project, 'starts_with("apikey:")', start, now, summed=True)
    reports = [key_report(k, counts.get(f"apikey:{key_uid(k['name'])}", {}), now) for k in keys.list_keys(project)]
    reports.sort(key=lambda r: (-len(r["flags"]), r["display_name"] or ""))
    return {"project": project, "days": days, "keys": reports}
