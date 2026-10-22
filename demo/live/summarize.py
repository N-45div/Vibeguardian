"""Summarize the live drills kept in the bucket, and export them as raw records.

    python demo/live/summarize.py --bucket vg-live-drills-<number> --project <id> \
        [--since 2026-10-22T19:00:00Z] [--out docs/measurements/raw/<file>.jsonl]

Only drills that time each answer by when its call left (t_basis "sent") count
toward times; every finished drill counts toward how often a deleted key worked.
Records carry fingerprints and resource names only, never a key.
"""

from __future__ import annotations

import argparse
import json
import statistics
from datetime import datetime
from urllib.parse import quote

from vibeguardian.gcp.client import session

STORAGE = "https://storage.googleapis.com/storage/v1"


def records(http, bucket: str) -> list[dict]:
    out, params = [], {"prefix": "drills/"}
    while True:
        body = http.get(f"{STORAGE}/b/{bucket}/o", params=params, timeout=30).json()
        for item in body.get("items", []):
            r = http.get(f"{STORAGE}/b/{bucket}/o/{quote(item['name'], safe='')}", params={"alt": "media"}, timeout=30)
            if r.status_code == 200:
                out.append(r.json())
        if not body.get("nextPageToken"):
            return sorted(out, key=lambda r: r.get("started_at") or 0)
        params["pageToken"] = body["nextPageToken"]


def summarize(drills: list[dict]) -> dict:
    done = [r for r in drills if (r.get("verdict") or {}).get("state") in ("proven_dead", "not_proven")]
    revivals = [(r, e) for r in done for e in r["verdict"].get("revivals") or []]
    late = [(r, e) for r, e in revivals if e["t"] >= 5.0]
    proven = [r["verdict"]["seconds"] for r in done if r["verdict"]["state"] == "proven_dead"]
    by_place: dict[str, int] = {}
    for r in {r["id"]: r for r, _ in revivals}.values():
        for label in {e["label"] for e in r["verdict"]["revivals"]}:
            by_place[label] = by_place.get(label, 0) + 1
    return {
        "drills": len(done),
        "failed": len([r for r in drills if (r.get("verdict") or {}).get("state") == "failed"]),
        "proven_dead": len(proven),
        "with_revival": len({r["id"] for r, _ in revivals}),
        "gemini_generated": len({r["id"] for r, e in revivals if "ask" in e.get("how", "")}),
        "answers_after_delete": len(revivals),
        "answers_to_calls_sent_5s_or_later": len(late),
        "drills_with_a_late_answer": len({r["id"] for r, _ in late}),
        "latest_answered_call_s": max((e["t"] for _, e in revivals), default=None),
        "drills_with_revival_by_place": dict(sorted(by_place.items(), key=lambda kv: -kv[1])),
        "median_proven_s": statistics.median(proven) if proven else None,
        "slowest_proven_s": max(proven, default=None),
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--bucket", required=True)
    p.add_argument("--project", required=True)
    p.add_argument("--since", help="only drills started at or after this time (ISO 8601)")
    p.add_argument("--out", help="write the drills as JSON lines here")
    args = p.parse_args()
    drills = records(session(quota_project=args.project), args.bucket)
    if args.since:
        since = datetime.fromisoformat(args.since.replace("Z", "+00:00")).timestamp()
        drills = [r for r in drills if (r.get("started_at") or 0) >= since]
    if args.out:
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            for r in drills:
                f.write(json.dumps(r, ensure_ascii=False, separators=(",", ":")) + "\n")
    timed = [r for r in drills if r.get("t_basis") == "sent"]
    print(json.dumps({"all": summarize(drills), "timed_by_send": summarize(timed)}, indent=1, ensure_ascii=False))


if __name__ == "__main__":
    main()
