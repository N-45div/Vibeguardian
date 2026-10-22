import importlib.util
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from vibeguardian.secret import fingerprint

pytest.importorskip("flask")

APP = Path(__file__).resolve().parents[1] / "demo" / "live" / "main.py"
KEY = "AIza" + "L" * 35  # built at runtime so no key-shaped literal sits in the source


@pytest.fixture
def live(monkeypatch):
    monkeypatch.setenv("GCP_PROJECT_ID", "p")
    monkeypatch.setenv("BUCKET", "b")
    monkeypatch.setenv("DAILY_CAP", "3")
    spec = importlib.util.spec_from_file_location("live_main", APP)
    module = importlib.util.module_from_spec(spec)
    sys.modules["live_main"] = module
    spec.loader.exec_module(module)
    store = {"objects": {}, "listed": [], "puts": []}
    monkeypatch.setattr(module, "_put", lambda r: store["puts"].append(dict(r)))
    monkeypatch.setattr(module, "_get", lambda d: store["objects"].get(d))
    monkeypatch.setattr(module, "_list", lambda: store["listed"])
    started = []
    monkeypatch.setattr(module, "_run", lambda d: started.append(d))
    return module, store, started


def post(client, header=True):
    return client.post("/api/drills", headers={"X-VG-Drill": "1"} if header else {})


def test_a_drill_needs_the_page_header(live):
    module, _, started = live
    assert post(module.app.test_client(), header=False).status_code == 403
    assert started == []


def test_one_drill_at_a_time_and_a_late_visitor_watches_it(live):
    module, _, started = live
    client = module.app.test_client()
    first = post(client)
    assert first.status_code == 201
    drill = first.get_json()["id"]
    second = post(client)
    assert second.status_code == 200 and second.get_json() == {"id": drill, "running": True}
    assert len(started) == 1


def test_the_daily_cap(live):
    module, store, started = live
    today = datetime.now(timezone.utc).date().isoformat()
    store["listed"] = [{"name": f"drills/x{i}.json", "timeCreated": f"{today}T01:00:00Z"} for i in range(3)]
    response = post(module.app.test_client())
    assert response.status_code == 429 and started == []


def test_records_are_served_from_memory_while_running_and_the_bucket_after(live):
    module, store, _ = live
    client = module.app.test_client()
    assert client.get("/api/drills/NOT-AN-ID").status_code == 404
    assert client.get("/api/drills/abcdefghij").status_code == 404
    drill = post(client).get_json()["id"]
    assert client.get(f"/api/drills/{drill}").get_json()["status"] == "running"
    store["objects"]["abcdefghij"] = {"id": "abcdefghij", "status": "done"}
    response = client.get("/api/drills/abcdefghij")
    assert response.get_json()["status"] == "done" and response.headers["Cache-Control"] == "no-store"


def test_save_writes_the_bucket_at_most_every_5s_while_running_and_always_at_the_end(live, monkeypatch):
    module, store, _ = live
    clock = {"t": 100.0}
    monkeypatch.setattr(module.time, "time", lambda: clock["t"])
    module._save({"id": "abcdefghij", "status": "running"})
    clock["t"] += 1
    module._save({"id": "abcdefghij", "status": "running"})
    clock["t"] += 1
    module._save({"id": "abcdefghij", "status": "done"})
    assert [p["status"] for p in store["puts"]] == ["running", "done"]


def test_stats_count_revivals_and_proofs(live):
    module, store, _ = live
    store["listed"] = [{"name": f"drills/{x}.json"} for x in "abcd"]
    store["objects"] = {
        "a": {"id": "a", "started_at": 3, "verdict": {"state": "proven_dead", "seconds": 60.0, "revivals": []}},
        "b": {"id": "b", "started_at": 2, "t_basis": "sent",
              "verdict": {"state": "proven_dead", "seconds": 120.0,
                          "revivals": [{"t": 41.5, "label": "Belgium", "how": "ask+list"}]}},
        "d": {"id": "d", "started_at": 0, "verdict": {"state": "proven_dead", "seconds": 90.0,
                                                       "revivals": [{"t": 77.0, "label": "Iowa", "how": "list"}]}},
        "c": {"id": "c", "started_at": 1, "verdict": {"state": "failed", "message": "x"}},
    }
    s = module.app.test_client().get("/api/stats").get_json()
    assert s["drills"] == 3 and s["with_revival"] == 2 and s["gemini_answered"] == 1
    # only drills that time answers by when the call left count toward the latest time
    assert s["latest_revival_s"] == 41.5
    assert s["revivals_by_place"] == {"Belgium": 1, "Iowa": 1} and s["median_proven_s"] == 90.0
    assert [r["id"] for r in s["recent"]] == ["a", "b", "c", "d"]


def test_pages_carry_a_strict_csp(live):
    module, _, _ = live
    for path in ("/", "/d/abcdefghij"):
        response = module.app.test_client().get(path)
        assert response.status_code == 200
        assert "script-src 'self'" in response.headers["Content-Security-Policy"]
        assert "default-src 'none'" in response.headers["Content-Security-Policy"]


def test_a_vantage_that_answers_for_another_key_proves_nothing(live, monkeypatch):
    module, _, _ = live
    monkeypatch.setattr(module.id_token, "fetch_id_token", lambda request, audience: "token")

    class Response:
        status_code = 200

        def json(self):
            return {"fingerprint": "sha256:000000000000", "list": {"verdict": "dead"}, "ask": {"verdict": "dead"}}

    monkeypatch.setattr(module.requests, "post", lambda *a, **k: Response())
    result = module._vantage_round("https://vantage.example")(KEY)
    assert result["list"]["verdict"] == "unknown" and result["ask"]["verdict"] == "unknown"

    class Good(Response):
        def json(self):
            return {"fingerprint": fingerprint(KEY), "list": {"verdict": "dead"}, "ask": {"verdict": "dead", "answer": None}}

    monkeypatch.setattr(module.requests, "post", lambda *a, **k: Good())
    assert module._vantage_round("https://vantage.example")(KEY)["ask"]["verdict"] == "dead"
