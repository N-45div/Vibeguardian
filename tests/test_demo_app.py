import importlib.util
import sys
from pathlib import Path

import pytest

pytest.importorskip("flask")

APP = Path(__file__).resolve().parents[1] / "demo" / "app" / "main.py"


@pytest.fixture
def demo(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "demo-secret-key")
    spec = importlib.util.spec_from_file_location("demo_main", APP)
    module = importlib.util.module_from_spec(spec)
    sys.modules["demo_main"] = module
    spec.loader.exec_module(module)
    return module


class Reply:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body or {}

    def json(self):
        return self._body


def test_health_reports_fingerprint_not_key(demo, monkeypatch, capsys):
    monkeypatch.setattr(demo.requests, "request", lambda *a, **k: Reply(200))
    response = demo.app.test_client().get("/health")
    body = response.get_json()
    assert response.status_code == 200
    assert body["key_fingerprint"] == demo.fingerprint("demo-secret-key")
    logged = capsys.readouterr().out
    assert "demo-secret-key" not in response.get_data(as_text=True) + logged
    assert '"event": "gemini_call"' in logged


def test_health_fails_when_google_rejects_the_key(demo, monkeypatch):
    monkeypatch.setattr(demo.requests, "request", lambda *a, **k: Reply(400))
    assert demo.app.test_client().get("/health").status_code == 503


def test_ask_is_rate_limited(demo, monkeypatch):
    answer = {"candidates": [{"content": {"parts": [{"text": "hi"}]}}]}
    monkeypatch.setattr(demo.requests, "request", lambda *a, **k: Reply(200, answer))
    client = demo.app.test_client()
    assert client.post("/ask", json={"question": "hello"}).get_json() == {"answer": "hi"}
    assert client.post("/ask", json={"question": "again"}).status_code == 429


def test_index_never_shows_the_key(demo):
    page = demo.app.test_client().get("/").get_data(as_text=True)
    assert "demo-secret-key" not in page
    assert demo.fingerprint("demo-secret-key") in page
