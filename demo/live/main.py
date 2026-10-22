"""VibeGuardian live drill: anyone can watch a real Gemini key get deleted and proven dead.

A visitor presses one button. This service makes a throwaway Gemini-only key,
waits until Gemini answers with it, uses it five times, deletes it, then asks
Google from here (Iowa) and through the four private vantage services
(Belgium, Tokyo, Sydney, Sao Paulo) until every place refuses the deleted key
12 rounds in a row. Gemini's own answer is the judge. The page draws every
round as it happens; the record is kept, fingerprint only, at /d/<id>.

Guards: one drill at a time (a visitor who arrives mid-drill watches it), a
daily cap, keys named vg-live-<id> and nothing else touched, the key value
only ever in this process's memory, and a sweep of any leftover vg-live key
before each drill.

Endpoints:
  GET  /            the page          GET  /d/<id>          one drill's page
  POST /api/drills  start a drill     GET  /api/drills/<id> its record (JSON)
  GET  /api/stats   every drill so far
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

import requests
from flask import Flask, abort, jsonify, request, send_from_directory
from google.auth.transport.requests import AuthorizedSession, Request
from google.oauth2 import id_token

from vibeguardian.drill import Place, local_round, run_drill, sweep
from vibeguardian.gcp.apikeys import ApiKeys
from vibeguardian.gcp.client import session as gcp_session
from vibeguardian.secret import fingerprint
from vibeguardian.vantage import parse_vantages

PROJECT = os.environ.get("GCP_PROJECT_ID", "")
BUCKET = os.environ.get("BUCKET", "")
DAILY_CAP = int(os.environ.get("DAILY_CAP", "60"))
HERE_REGION = os.environ.get("HERE_REGION", "us-central1")
LABELS = {"us-central1": "Iowa", "europe-west1": "Belgium", "asia-northeast1": "Tokyo",
          "australia-southeast1": "Sydney", "southamerica-east1": "São Paulo"}
STATIC = Path(__file__).with_name("static")
DRILL_ID = re.compile(r"[a-z0-9]{10}")
STORAGE = "https://storage.googleapis.com"
CSP = ("default-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
       "font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; base-uri 'none'; "
       "form-action 'none'; frame-ancestors 'none'")

app = Flask(__name__, static_folder=None)
_lock = threading.Lock()
_state: dict = {"current": None, "record": None, "persisted": 0.0, "stats": None, "stats_at": 0.0}


def _session() -> AuthorizedSession:
    """Signed requests with retries on dropped connections (a DELETE is retried; a POST that reached Google is not)."""
    return gcp_session()


# --- storage: one JSON object per drill, in a private bucket -------------------------------------

def _put(record: dict) -> None:
    _session().post(f"{STORAGE}/upload/storage/v1/b/{BUCKET}/o",
                    params={"uploadType": "media", "name": f"drills/{record['id']}.json"},
                    data=json.dumps(record), headers={"Content-Type": "application/json"}, timeout=20)


def _get(drill: str) -> dict | None:
    r = _session().get(f"{STORAGE}/storage/v1/b/{BUCKET}/o/{quote(f'drills/{drill}.json', safe='')}",
                       params={"alt": "media"}, timeout=20)
    return r.json() if r.status_code == 200 else None


def _list() -> list[dict]:
    items, params = [], {"prefix": "drills/", "fields": "items(name,timeCreated),nextPageToken"}
    http = _session()
    while True:
        body = http.get(f"{STORAGE}/storage/v1/b/{BUCKET}/o", params=params, timeout=20).json()
        items += body.get("items", [])
        if not body.get("nextPageToken"):
            return items
        params["pageToken"] = body["nextPageToken"]


def _save(record: dict) -> None:
    """Keep the running drill in memory for the page; write it to the bucket at most every 5 s, and at the end."""
    _state["record"] = json.loads(json.dumps(record))
    now = time.time()
    if record.get("status") != "running" or now - _state["persisted"] >= 5:
        _state["persisted"] = now
        try:
            _put(record)
        except Exception:  # noqa: BLE001 - the next save, or the final one, writes it
            pass


# --- places ---------------------------------------------------------------------------------------

def _vantage_round(url: str):
    token: dict = {}

    def round_(key: str) -> dict:
        if not token or token["at"] < time.time() - 3000:
            token.update(value=id_token.fetch_id_token(Request(), url), at=time.time())
        r = requests.post(f"{url}/round", json={"key": key}, timeout=30,
                          headers={"Authorization": f"Bearer {token['value']}"})
        body = r.json() if r.status_code == 200 else {}
        if body.get("fingerprint") != fingerprint(key):
            unknown = {"verdict": "unknown", "reason": f"VANTAGE_HTTP_{r.status_code}"}
            return {"list": unknown, "ask": unknown}
        return {"list": body.get("list") or {}, "ask": body.get("ask") or {}}
    return round_


def _places() -> list[Place]:
    places = [Place(HERE_REGION, LABELS.get(HERE_REGION, HERE_REGION), local_round)]
    specs = [s for s in os.environ.get("VANTAGES", "").replace(",", " ").split() if s]
    for region, url in parse_vantages(specs).items():
        places.append(Place(region, LABELS.get(region, region), _vantage_round(url)))
    return places


# --- drills ---------------------------------------------------------------------------------------

def _today_count() -> int:
    today = datetime.now(timezone.utc).date().isoformat()
    return sum(1 for item in _list() if str(item.get("timeCreated", "")).startswith(today))


def _run(drill: str) -> None:
    try:
        keys = ApiKeys(_session())
        try:
            sweep(keys, PROJECT)
        except Exception:  # noqa: BLE001 - a failed sweep must not stop the drill
            pass
        run_drill(drill, project=PROJECT, keys=keys, places=_places(), save=_save)
    finally:
        with _lock:
            _state["current"] = None
            _state["stats_at"] = 0.0


@app.post("/api/drills")
def start():
    # Only the page's own script sends this header; a form or a cross-site request cannot.
    if request.headers.get("X-VG-Drill") != "1":
        abort(403)
    with _lock:
        if _state["current"]:
            return jsonify({"id": _state["current"], "running": True})
        if _today_count() >= DAILY_CAP:
            return jsonify({"error": f"Today's {DAILY_CAP} drills have run. Past drills are below."}), 429
        drill = "".join(secrets.choice("abcdefghijkmnpqrstuvwxyz23456789") for _ in range(10))
        _state["current"] = drill
        _state["record"] = {"id": drill, "status": "running", "steps": [], "places": {}, "verdict": None}
        _state["persisted"] = 0.0
    threading.Thread(target=_run, args=(drill,), daemon=True).start()
    return jsonify({"id": drill, "running": False}), 201


@app.get("/api/drills/<drill>")
def drill_record(drill: str):
    if not DRILL_ID.fullmatch(drill):
        abort(404)
    if drill == _state["current"] and _state["record"]:
        return jsonify(_state["record"])
    record = _get(drill)
    if record is None:
        abort(404)
    return jsonify(record)


@app.get("/api/stats")
def stats():
    if _state["stats"] is None or time.time() - _state["stats_at"] > 60:
        names = [i["name"][len("drills/"):-len(".json")] for i in _list()]
        with ThreadPoolExecutor(max_workers=8) as pool:
            records = [r for r in pool.map(_get, names) if r]
        finished = [r for r in records if (r.get("verdict") or {}).get("state") in ("proven_dead", "not_proven")]
        revived = [r for r in finished if (r["verdict"].get("revivals") or [])]
        gemini = [r for r in finished if any("ask" in e.get("how", "") for e in r["verdict"].get("revivals") or [])]
        events = [e for r in finished for e in r["verdict"].get("revivals") or []]
        # Times count only from drills that time each answer by when its call left (t_basis "sent").
        timed = [e for r in finished if r.get("t_basis") == "sent" for e in r["verdict"].get("revivals") or []]
        proven = sorted(r["verdict"]["seconds"] for r in finished if r["verdict"]["state"] == "proven_dead")
        by_place: dict = {}
        for e in events:
            by_place[e["label"]] = by_place.get(e["label"], 0) + 1
        _state["stats"] = {
            "drills": len(finished), "with_revival": len(revived), "gemini_answered": len(gemini),
            "revival_events": len(events),
            "latest_revival_s": max((e["t"] for e in timed), default=None), "revivals_by_place": by_place,
            "median_proven_s": proven[len(proven) // 2] if proven else None,
            "recent": [{"id": r["id"], "started_at": r.get("started_at"), "state": (r.get("verdict") or {}).get("state"),
                        "seconds": (r.get("verdict") or {}).get("seconds"),
                        "revivals": len((r.get("verdict") or {}).get("revivals") or [])}
                       for r in sorted(records, key=lambda r: r.get("started_at") or 0, reverse=True)[:12]],
            "running": _state["current"],
        }
        _state["stats_at"] = time.time()
    return jsonify({**_state["stats"], "running": _state["current"]})


@app.get("/")
@app.get("/d/<drill>")
def page(drill: str | None = None):
    return send_from_directory(STATIC, "index.html")


@app.get("/static/<path:name>")
def static_file(name: str):
    return send_from_directory(STATIC, name)


@app.after_request
def headers(response):
    response.headers["Content-Security-Policy"] = CSP
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    if response.mimetype == "application/json":
        response.headers["Cache-Control"] = "no-store"
    return response
