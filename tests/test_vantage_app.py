import importlib.util
import sys
from pathlib import Path

import pytest

from vibeguardian.probe import ProbeResult, Verdict
from vibeguardian.secret import fingerprint

pytest.importorskip("flask")

APP = Path(__file__).resolve().parents[1] / "demo" / "vantage" / "main.py"
KEY = "AIza" + "Q" * 35  # built at runtime so no key-shaped literal sits in the source


@pytest.fixture
def vantage(monkeypatch):
    monkeypatch.setenv("VANTAGE_REGION", "europe-west1")
    spec = importlib.util.spec_from_file_location("vantage_main", APP)
    module = importlib.util.module_from_spec(spec)
    sys.modules["vantage_main"] = module
    spec.loader.exec_module(module)
    asked = []

    def fake_probe(key):
        asked.append(key)
        return ProbeResult(Verdict.DEAD, 400, "API_KEY_INVALID", 120, 1.0)

    monkeypatch.setattr(module, "probe", fake_probe)
    return module, asked


def test_probe_answers_with_region_and_fingerprint_never_the_key(vantage):
    module, asked = vantage
    response = module.app.test_client().post("/probe", json={"key": KEY})
    assert response.status_code == 200
    body = response.get_json()
    assert body["region"] == "europe-west1"
    assert body["fingerprint"] == fingerprint(KEY)
    assert body["verdict"] == "dead" and body["reason"] == "API_KEY_INVALID"
    assert KEY not in response.get_data(as_text=True)
    assert asked == [KEY]


@pytest.mark.parametrize("payload", [{}, {"key": "not a key"}, {"key": KEY + "x"}, {"key": ["list"]}, None])
def test_anything_but_one_google_key_is_refused_without_calling_google(vantage, payload):
    module, asked = vantage
    response = module.app.test_client().post("/probe", json=payload)
    assert response.status_code == 400
    assert asked == []


def test_health(vantage):
    module, _ = vantage
    assert module.app.test_client().get("/health").get_json() == {"ok": True, "region": "europe-west1"}


def test_round_lists_and_asks_gemini_and_never_returns_the_key(vantage, monkeypatch):
    module, asked = vantage
    from vibeguardian.probe import GeminiAnswer

    gemini = []

    def fake_ask(key):
        gemini.append(key)
        return GeminiAnswer(ProbeResult(Verdict.ALIVE, 200, None, 900, 1.0), "ALIVE")

    monkeypatch.setattr(module, "ask_gemini", fake_ask)
    response = module.app.test_client().post("/round", json={"key": KEY})
    assert response.status_code == 200
    body = response.get_json()
    assert body["region"] == "europe-west1" and body["fingerprint"] == fingerprint(KEY)
    assert body["list"]["verdict"] == "dead"
    assert body["ask"]["verdict"] == "alive" and body["ask"]["answer"] == "ALIVE"
    assert KEY not in response.get_data(as_text=True)
    assert asked == [KEY] and gemini == [KEY]


def test_round_refuses_anything_but_one_google_key(vantage):
    module, asked = vantage
    assert module.app.test_client().post("/round", json={"key": "nope"}).status_code == 400
    assert asked == []
