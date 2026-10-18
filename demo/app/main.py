"""Demo service that holds a Gemini API key: the thing VibeGuardian protects.

It reads its key from the GEMINI_API_KEY environment variable, which Cloud
Run fills from Secret Manager when an instance starts. It never shows or logs
the key, only its fingerprint, so anyone can see which key is live.

Endpoints:
  GET  /         small page: which key is serving, and an "ask" box
  GET  /health   200 if Google accepts the key, with its fingerprint
                (not /healthz: Cloud Run reserves paths ending in "z")
  POST /ask      one short Gemini answer (rate-limited; demo only)

Every call to Gemini is logged as one JSON line with the key fingerprint, so
VibeGuardian can compare our own calls against Google's count for the key.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import threading
import time

import requests
from flask import Flask, jsonify, request

GEMINI = "https://generativelanguage.googleapis.com/v1beta"
MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash-lite")
MAX_QUESTION = 400
MIN_SECONDS_BETWEEN_ASKS = 5.0

app = Flask(__name__)
_last_ask = 0.0
_ask_lock = threading.Lock()


def _key() -> str:
    return os.environ.get("GEMINI_API_KEY", "").strip()


def fingerprint(secret: str) -> str:
    return "sha256:" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:12]


def _gemini(method: str, path: str, **kwargs) -> requests.Response:
    key = _key()
    started = time.time()
    response = requests.request(
        method, f"{GEMINI}/{path}", headers={"x-goog-api-key": key}, timeout=20, **kwargs
    )
    print(
        json.dumps(
            {
                "event": "gemini_call",
                "key_fingerprint": fingerprint(key) if key else None,
                "path": path.split("?")[0],
                "status": response.status_code,
                "latency_ms": int((time.time() - started) * 1000),
                "revision": os.environ.get("K_REVISION"),
            }
        ),
        flush=True,
    )
    return response


@app.get("/health")
def health():
    key = _key()
    if not key:
        return jsonify(ok=False, error="no key configured"), 503
    response = _gemini("GET", "models?pageSize=1")
    ok = response.status_code == 200
    return (
        jsonify(ok=ok, key_fingerprint=fingerprint(key), google_status=response.status_code,
                revision=os.environ.get("K_REVISION")),
        200 if ok else 503,
    )


@app.post("/ask")
def ask():
    global _last_ask
    question = str((request.get_json(silent=True) or {}).get("question", "")).strip()[:MAX_QUESTION]
    if not question:
        return jsonify(error="ask a question"), 400
    with _ask_lock:
        if time.time() - _last_ask < MIN_SECONDS_BETWEEN_ASKS:
            return jsonify(error="slow down, this is a demo"), 429
        _last_ask = time.time()
    body = {
        "contents": [{"parts": [{"text": question}]}],
        "generationConfig": {"maxOutputTokens": 120},
    }
    response = _gemini("POST", f"models/{MODEL}:generateContent", json=body)
    if response.status_code != 200:
        return jsonify(error="Gemini refused the request", status=response.status_code), 502
    try:
        answer = response.json()["candidates"][0]["content"]["parts"][0]["text"]
    except (KeyError, IndexError, ValueError):
        answer = "(no answer)"
    return jsonify(answer=answer)


@app.get("/")
def index():
    key = _key()
    fp = fingerprint(key) if key else "none"
    revision = html.escape(os.environ.get("K_REVISION", "local"))
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>VibeGuardian demo app</title>
<style>
 body{{font:16px/1.5 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#1b1b1b}}
 code{{background:#f2f2f2;padding:.1rem .3rem;border-radius:4px}}
 textarea{{width:100%;min-height:5rem}} button{{margin-top:.5rem}}
</style></head><body>
<h1>Demo app</h1>
<p>A small service that calls the Gemini API with a key from Secret Manager.
VibeGuardian watches it.</p>
<p>Serving with key <code>{fp}</code> on revision <code>{revision}</code>.</p>
<form id="f"><textarea name="q" maxlength="{MAX_QUESTION}" placeholder="Ask something short"></textarea>
<br><button>Ask</button></form><pre id="out"></pre>
<script>
document.getElementById('f').onsubmit=async e=>{{e.preventDefault();
 const r=await fetch('/ask',{{method:'POST',headers:{{'Content-Type':'application/json'}},
 body:JSON.stringify({{question:e.target.q.value}})}});
 const j=await r.json();document.getElementById('out').textContent=j.answer||j.error;}};
</script></body></html>"""


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))
