"""Did anyone else use a leaked API key while it was exposed?

Google counts every request to an API with the key's id
(``credential_id = apikey:<uid>``) and the Google region that served it. A
key's own services call from where they run; calls from anywhere else, while
the key was exposed, are a sign someone else had it.

Counts can lag: Cloud Monitoring says data may take up to 30 minutes to
appear, so a check run soon after an incident is marked partial. Counts come
in one-minute buckets, so the window's edges are rounded to the minute.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator

from vibeguardian.gcp.client import check

MONITORING = "https://monitoring.googleapis.com/v3"
MAX_DATA_DELAY = timedelta(minutes=30)
# The method VibeGuardian's probes call (vibeguardian.probe.DEFAULT_ENDPOINT):
# it only lists models, so it costs nothing and reveals nothing.
LISTING_METHOD = "ModelService.ListModels"


def _rfc3339(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def key_uid(key_name: str) -> str:
    """``projects/9/locations/global/keys/<uid>`` -> ``<uid>``."""
    return key_name.rstrip("/").rsplit("/", 1)[-1]


def _points_total(points: list[dict[str, Any]]) -> int:
    return sum(int(p["value"].get("int64Value", 0)) for p in points)


def _request_series(
    http: Any, project: str, credential: str, start: datetime, end: datetime, *, summed: bool = False,
) -> Iterator[tuple[dict[str, str], bool, list[dict[str, Any]]]]:
    """(resource labels, succeeded, points) for every request-count series of the credential."""
    params = {
        "filter": ('metric.type = "serviceruntime.googleapis.com/api/request_count" '
                   'AND resource.type = "consumed_api" '
                   f"AND resource.labels.credential_id = {credential}"),
        "interval.startTime": _rfc3339(start),
        "interval.endTime": _rfc3339(end),
    }
    if summed:
        params["aggregation.alignmentPeriod"] = f"{max(60, int((end - start).total_seconds()))}s"
        params["aggregation.perSeriesAligner"] = "ALIGN_SUM"
    while True:
        body = check(http.get(f"{MONITORING}/projects/{project}/timeSeries", params=params))
        for series in body.get("timeSeries", []):
            ok = series.get("metric", {}).get("labels", {}).get("response_code_class") == "2xx"
            yield series["resource"]["labels"], ok, series.get("points", [])
        if not body.get("nextPageToken"):
            return
        params["pageToken"] = body["nextPageToken"]


def request_counts(
    http: Any, project: str, credential: str, start: datetime, end: datetime, *, summed: bool = False,
) -> dict[str, dict[str, dict[str, int]]]:
    """Calls per credential id, then per Google region, split into ok and error.

    ``credential`` is a Monitoring filter value for the credential id, such as
    ``"apikey:<uid>"`` or ``starts_with("apikey:")``. ``summed`` asks Google
    to add each series up over the whole window, for long windows.
    """
    counts: dict[str, dict[str, dict[str, int]]] = {}
    for labels, ok, points in _request_series(http, project, credential, start, end, summed=summed):
        regions = counts.setdefault(labels.get("credential_id", "unknown"), {})
        bucket = regions.setdefault(labels.get("location", "unknown"), {"ok": 0, "error": 0})
        bucket["ok" if ok else "error"] += _points_total(points)
    return counts


def apis_used(http: Any, project: str, uid: str, start: datetime, end: datetime) -> dict[str, int]:
    """Successful calls the key made, per Google API (``generativelanguage.googleapis.com``...)."""
    used: dict[str, int] = {}
    for labels, ok, points in _request_series(http, project, f'"apikey:{uid}"', start, end, summed=True):
        count = _points_total(points)
        if ok and count:
            used[labels.get("service", "unknown")] = used.get(labels.get("service", "unknown"), 0) + count
    return used


def usage_by_region(
    http: Any, project: str, uid: str, start: datetime, end: datetime, probes_began: datetime | None = None,
) -> dict[str, dict[str, int]]:
    """Calls made with the key, per Google region.

    Google files a call under the key's id only once it has recognised the
    key, so every call counted here came from someone who had the key, even
    one Google then refused (out of credit, unknown model, rate limit).

    ``ok`` and ``error`` count every call. Calls that only listed models, the
    call VibeGuardian's own probes make, are ``checks`` before ``probes_began``
    (someone else tried the key) and ``probe_like`` from then on (they may be
    our probes). Every other call is ``used_ok`` or ``used_failed``. Counts
    come in one-minute buckets; a bucket that ends after ``probes_began``
    counts as ``probe_like``.
    """
    usage: dict[str, dict[str, int]] = {}
    for labels, ok, points in _request_series(http, project, f'"apikey:{uid}"', start, end):
        bucket = usage.setdefault(labels.get("location", "unknown"), dict.fromkeys(
            ("ok", "error", "used_ok", "used_failed", "checks", "probe_like"), 0))
        listing = labels.get("method", "").endswith(LISTING_METHOD)
        for point in points:
            calls = int(point["value"].get("int64Value", 0))
            bucket["ok" if ok else "error"] += calls
            if not listing:
                bucket["used_ok" if ok else "used_failed"] += calls
                continue
            ended = point.get("interval", {}).get("endTime")
            ours = probes_began is not None and (
                ended is None or datetime.fromisoformat(ended.replace("Z", "+00:00")) > probes_began)
            bucket["probe_like" if ours else "checks"] += calls
    return usage


def service_regions(services: list[str]) -> set[str]:
    """``projects/p/locations/us-central1/services/app`` -> ``{"us-central1"}``."""
    regions = set()
    for name in services:
        parts = name.split("/")
        if "locations" in parts:
            regions.add(parts[parts.index("locations") + 1])
    return regions


def exposure_report(
    usage: dict[str, dict[str, int]],
    expected_regions: set[str],
    start: datetime,
    end: datetime,
    now: datetime | None = None,
) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    expected = {r: c["ok"] for r, c in usage.items() if r in expected_regions and c["ok"]}
    elsewhere = {r: c for r, c in usage.items() if r not in expected_regions}
    used = {r: n for r, c in elsewhere.items() if (n := c.get("used_ok", 0) + c.get("used_failed", 0))}
    succeeded = sum(c.get("used_ok", 0) for c in elsewhere.values())
    checks = {r: c["checks"] for r, c in elsewhere.items() if c.get("checks")}
    ours = sum(c.get("probe_like", 0) for c in elsewhere.values())
    complete = now - end >= MAX_DATA_DELAY
    report = {
        "window": {"start": _rfc3339(start), "end": _rfc3339(end)},
        "expected_regions": sorted(expected_regions),
        "calls_from_your_services": sum(expected.values()),
        "calls_from_elsewhere": sum(used.values()),
        "succeeded_from_elsewhere": succeeded,
        "elsewhere_by_region": used,
        "checks_from_elsewhere": sum(checks.values()),
        "checks_by_region": checks,
        "likely_vibeguardian_probes": ours,
        "by_region": usage,
        "complete": complete,
    }
    if used:
        report["verdict"] = "used_elsewhere"
        report["summary"] = (f"{sum(used.values())} call(s) that used this key came from "
                             f"{', '.join(sorted(used))}, where none of its services run "
                             f"({succeeded} succeeded; Google refused the rest, but only someone "
                             "holding the key could make them).")
    elif checks:
        report["verdict"] = "checked_elsewhere"
        report["summary"] = (f"Nobody else used this key, but {sum(checks.values())} check(s) of it came from "
                             f"{', '.join(sorted(checks))} before VibeGuardian began probing: someone else "
                             "found the key and tried it.")
    else:
        report["verdict"] = "no_use_elsewhere"
        report["summary"] = "No successful calls with this key came from outside the regions its services run in."
    if ours:
        report["summary"] += (f" {ours} model-list call(s) from other regions came after VibeGuardian began "
                              "checking the key; its own probes make that call, so they are not counted.")
    if not complete:
        recheck = end + MAX_DATA_DELAY
        report["summary"] += f" Google's counts can lag up to 30 minutes: check again after {_rfc3339(recheck)}."
    return report


def _deleted_at(incident: dict[str, Any]) -> datetime | None:
    times = [e["at"] for e in incident.get("timeline", []) if e.get("event") == "old_key_deleted"]
    if not incident.get("old_key") or not times:
        return None
    return datetime.fromtimestamp(times[0], tz=timezone.utc)


def incident_pairs(record: dict[str, Any]) -> list[tuple[dict[str, Any] | None, dict[str, Any]]]:
    """(leak, incident) pairs from what ``vg respond`` writes (a ``responses``
    list) or what ``vg retire`` writes (one incident, with no leak record)."""
    if "responses" in record:
        return [(r.get("leak"), r.get("incident") or {}) for r in record["responses"]]
    return [(None, record)]


def _probes_began(incident: dict[str, Any], window_start: datetime) -> datetime:
    """When VibeGuardian may first have probed the leaked key itself.

    The prover starts after the responder finishes. If a person approved the
    retirement, VibeGuardian already checked the key during the hold, at an
    unrecorded time, so every model-list call in the window may be its own.
    """
    if any(e.get("event") == "approved" for e in incident.get("timeline", [])):
        return window_start
    finished = incident.get("finished_at")
    return datetime.fromtimestamp(finished, tz=timezone.utc) if finished else window_start


def check_record(
    record: dict[str, Any],
    usage_for: Callable[[str, datetime, datetime, datetime | None], dict[str, dict[str, int]]],
    since_for: Callable[[dict[str, Any] | None], datetime | None],
    *,
    also_regions: set[str] | None = None,
    settle: timedelta = timedelta(0),
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """One exposure report per key an incident record says was deleted.

    ``record`` is what ``vg retire`` writes (one incident) or what
    ``vg respond`` writes (a ``responses`` list with each leak). The window
    runs from ``since_for(leak)``, when the key was exposed, to the moment it
    was deleted. ``settle`` waits that long after the last deletion first, so
    the newest calls have time to reach Cloud Monitoring.
    """
    pairs = incident_pairs(record)
    ends = [end for _, incident in pairs if (end := _deleted_at(incident))]
    if ends:
        wait = (max(ends) + settle - clock()).total_seconds()
        if wait > 0:
            sleep(wait)
    reports = []
    for leak, incident in pairs:
        fp = incident.get("leaked_fingerprint") or (leak or {}).get("fingerprint")
        end = _deleted_at(incident)
        if incident.get("outcome") == "already_deleted":
            reports.append({"fingerprint": fp, "verdict": "already_deleted",
                            "summary": "Google had already deleted this key; the incident that deleted it "
                                       "covers who used it."})
            continue
        if end is None:
            reports.append({"fingerprint": fp, "verdict": "not_retired",
                            "summary": "This key was not deleted, so there is no exposure window to check."})
            continue
        start = since_for(leak)
        if start is None or start >= end:
            raise ValueError(f"exposure for {fp} must start before the key was deleted at {_rfc3339(end)}, "
                             f"got {start and _rfc3339(start)}")
        regions = service_regions([s["service"] for s in incident.get("services", [])]) | (also_regions or set())
        usage = usage_for(key_uid(incident["old_key"]), start, end, _probes_began(incident, start))
        reports.append({"fingerprint": fp, **exposure_report(usage, regions, start, end, now=clock())})
    return reports
