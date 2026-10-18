"""A vantage point for the prover: asks Google about one key from this region.

The prover sends a leaked key here so Google is asked from several regions,
not only from wherever the CI runner happens to be. This service:

  - answers only callers Cloud Run has already authenticated: it is deployed
    without public access, and only the vg-prover identity may invoke it;
  - accepts only a string shaped like a Google API key;
  - calls only one fixed, read-only Google endpoint;
  - never logs or returns the key; the answer carries its fingerprint.

Endpoints:
  POST /probe   {"key": "AIza..."} -> {"region", "fingerprint", "verdict", ...}
  GET  /health  {"ok": true, "region": ...}
"""

from __future__ import annotations

import os

from flask import Flask, jsonify, request

from vibeguardian.leaks import GOOGLE_API_KEY
from vibeguardian.probe import probe
from vibeguardian.secret import fingerprint

REGION = os.environ.get("VANTAGE_REGION", "unknown")

app = Flask(__name__)


@app.post("/probe")
def probe_key():
    key = (request.get_json(silent=True) or {}).get("key")
    if not isinstance(key, str) or not GOOGLE_API_KEY.fullmatch(key):
        return jsonify({"error": 'send one Google API key as {"key": "..."}'}), 400
    result = probe(key)
    return jsonify({"region": REGION, "fingerprint": fingerprint(key), **result.as_dict()})


@app.get("/health")
def health():
    return jsonify({"ok": True, "region": REGION})
