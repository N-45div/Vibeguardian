"""Send each leak incident to an OpenTelemetry backend (GitLab Observability).

One trace per leaked key: a root span for the incident, a child span for each
retire step (from the previous event to this one), and a span for the proof.
Exposure counts go out as a metric per region, and each verdict as a log.
Everything sent is already in the incident record: fingerprints and resource
names, never key values. OTLP over HTTP with JSON bodies, so no SDK is needed.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Mapping

from vibeguardian.exposure import incident_pairs

SCOPE = {"name": "vibeguardian"}
OK, ERROR = 1, 2  # span status codes
INFO, WARN = 9, 13  # log severity numbers
SETTLED = ("retired", "already_deleted")


def _hex(length: int, *parts: Any) -> str:
    return hashlib.sha256(":".join(str(p) for p in parts).encode()).hexdigest()[:length]


def _ns(seconds: float) -> str:
    return str(int(seconds * 1e9))


def _value(v: Any) -> dict[str, Any]:
    if isinstance(v, bool):
        return {"boolValue": v}
    if isinstance(v, int):
        return {"intValue": str(v)}
    if isinstance(v, float):
        return {"doubleValue": v}
    if isinstance(v, (list, tuple)):
        return {"stringValue": ", ".join(str(x) for x in v)}
    return {"stringValue": str(v)}


def _attrs(values: Mapping[str, Any]) -> list[dict[str, Any]]:
    return [{"key": k, "value": _value(v)} for k, v in values.items() if v is not None and v != []]


def resource(env: Mapping[str, str]) -> dict[str, Any]:
    return {"attributes": _attrs({
        "service.name": "vibeguardian",
        "service.version": env.get("CI_COMMIT_SHA"),
        "deployment.environment.name": env.get("CI_ENVIRONMENT_NAME") or env.get("CI_COMMIT_REF_NAME"),
        "gitlab.project.id": env.get("CI_PROJECT_ID"),
        "gitlab.project.name": env.get("CI_PROJECT_NAME"),
    })}


def _span(trace: str, span: str, parent: str | None, name: str, start: float, end: float,
          attributes: Mapping[str, Any], error: bool = False) -> dict[str, Any]:
    out = {
        "traceId": trace, "spanId": span, "name": name, "kind": 1,
        "startTimeUnixNano": _ns(start), "endTimeUnixNano": _ns(max(start, end)),
        "attributes": _attrs(attributes), "status": {"code": ERROR if error else OK},
    }
    if parent:
        out["parentSpanId"] = parent
    return out


def _step_attributes(event: dict[str, Any]) -> dict[str, Any]:
    return {f"vibeguardian.{k}": v for k, v in event.items() if k not in ("event", "at")}


def build(
    record: dict[str, Any],
    proof: dict[str, Any] | None = None,
    exposure: dict[str, Any] | None = None,
    env: Mapping[str, str] = os.environ,
    now: float | None = None,
) -> dict[str, dict[str, Any] | None]:
    """OTLP JSON bodies for traces, metrics and logs; None where there is nothing to send."""
    now = now or time.time()
    pipeline = record.get("pipeline_id") or env.get("CI_PIPELINE_ID") or "local"
    proven = (proof or {}).get("keys", {})
    exposed = {r.get("fingerprint"): r for r in (exposure or {}).get("reports", [])}
    spans, points, logs = [], [], []

    for leak, incident in incident_pairs(record):
        fp = incident.get("leaked_fingerprint") or (leak or {}).get("fingerprint")
        trace = _hex(32, pipeline, fp)
        root = _hex(16, trace, "incident")
        timeline = incident.get("timeline") or []
        start = incident.get("started_at") or (timeline[0]["at"] if timeline else now)
        end = incident.get("finished_at") or (timeline[-1]["at"] if timeline else start)
        outcome = incident.get("outcome")
        spans.append(_span(trace, root, None, "leak incident", start, end, {
            "vibeguardian.fingerprint": fp,
            "vibeguardian.outcome": outcome,
            "vibeguardian.reason": incident.get("reason"),
            "vibeguardian.old_key": incident.get("old_key"),
            "vibeguardian.new_key": incident.get("new_key"),
            "vibeguardian.new_fingerprint": incident.get("new_fingerprint"),
            "vibeguardian.file": (leak or {}).get("file"),
            "vibeguardian.line": (leak or {}).get("line"),
            "vibeguardian.commit": (leak or {}).get("commit"),
            "gitlab.pipeline.id": pipeline,
        }, error=outcome not in SETTLED))
        previous = start
        for i, event in enumerate(e for e in timeline if e.get("event") != "finished"):
            spans.append(_span(trace, _hex(16, trace, i, event["event"]), root, event["event"],
                               previous, event["at"], _step_attributes(event),
                               error=event.get("healthy") is False))
            previous = event["at"]
        if outcome == "retired":
            points.append(("vibeguardian.retire.duration", "s", end - start, {"vibeguardian.fingerprint": fp}))
        logs.append((INFO if outcome in SETTLED else WARN, end, trace, root,
                     f"{fp}: {outcome}" + (f" ({incident['reason']})" if incident.get("reason") else ""),
                     {"vibeguardian.fingerprint": fp, "vibeguardian.outcome": outcome}))

        verdict = proven.get(fp)
        if verdict:
            watched = verdict.get("seconds_watched") or 0.0
            p_end = verdict.get("stable_dead_at") or end + watched
            prove_span = _hex(16, trace, "prove")
            vantages = verdict.get("vantages") or {}
            spans.append(_span(trace, prove_span, root, "prove", p_end - watched, p_end, {
                "vibeguardian.state": verdict.get("state"),
                "vibeguardian.probes": verdict.get("probes"),
                "vibeguardian.rejected": verdict.get("rejected"),
                "vibeguardian.accepted": verdict.get("accepted"),
                "vibeguardian.flaps": verdict.get("flaps"),
                "vibeguardian.vantages": sorted(vantages) or None,
                "vibeguardian.unreachable": verdict.get("unreachable"),
            }, error=not verdict.get("dead")))
            for name, one in vantages.items():
                v_watched = one.get("seconds_watched") or 0.0
                v_end = one.get("stable_dead_at") or p_end
                spans.append(_span(trace, _hex(16, trace, "prove", name), prove_span, f"prove from {name}",
                                   v_end - v_watched, v_end, {
                                       "cloud.region": name,
                                       "vibeguardian.state": one.get("state"),
                                       "vibeguardian.rejected": one.get("rejected"),
                                       "vibeguardian.accepted": one.get("accepted"),
                                       "vibeguardian.flaps": one.get("flaps"),
                                   }, error=not one.get("dead")))
            points.append(("vibeguardian.prove.rejections", "{probe}", verdict.get("rejected", 0),
                           {"vibeguardian.fingerprint": fp, "vibeguardian.state": verdict.get("state")}))

        report = exposed.get(fp)
        if report:
            expected = set(report.get("expected_regions", []))
            for region, counts in (report.get("by_region") or {}).items():
                for result in ("ok", "error"):
                    points.append(("vibeguardian.exposure.calls", "{call}", counts.get(result, 0), {
                        "vibeguardian.fingerprint": fp, "cloud.region": region, "vibeguardian.result": result,
                        "vibeguardian.expected_region": region in expected,
                        "vibeguardian.complete": report.get("complete", False),
                    }))
            logs.append((WARN if report.get("verdict") in ("used_elsewhere", "checked_elsewhere") else INFO, now, trace, root,
                         f"{fp}: {report.get('summary', report.get('verdict'))}",
                         {"vibeguardian.fingerprint": fp, "vibeguardian.verdict": report.get("verdict")}))

    res = resource(env)
    traces = {"resourceSpans": [{"resource": res, "scopeSpans": [{"scope": SCOPE, "spans": spans}]}]}
    metrics = {"resourceMetrics": [{"resource": res, "scopeMetrics": [{"scope": SCOPE, "metrics": [
        {"name": name, "unit": unit, "gauge": {"dataPoints": [{
            "timeUnixNano": _ns(now), "attributes": _attrs(attrs),
            **({"asDouble": float(value)} if isinstance(value, float) else {"asInt": str(int(value))}),
        }]}} for name, unit, value, attrs in points
    ]}]}]}
    log_body = {"resourceLogs": [{"resource": res, "scopeLogs": [{"scope": SCOPE, "logRecords": [
        {"timeUnixNano": _ns(at), "severityNumber": severity, "severityText": "WARN" if severity == WARN else "INFO",
         "body": {"stringValue": body}, "attributes": _attrs(attrs), "traceId": trace, "spanId": span}
        for severity, at, trace, span, body, attrs in logs
    ]}]}]}
    return {"traces": traces if spans else None, "metrics": metrics if points else None,
            "logs": log_body if logs else None}


def export(http: Any, endpoint: str, bodies: dict[str, dict[str, Any] | None],
           token: str | None = None) -> dict[str, int]:
    """POST each non-empty body to ``<endpoint>/v1/<signal>``; returns HTTP status per signal."""
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    sent = {}
    for signal, body in bodies.items():
        if body is not None:
            response = http.post(f"{endpoint.rstrip('/')}/v1/{signal}", json=body, headers=headers, timeout=30)
            sent[signal] = response.status_code
    return sent
