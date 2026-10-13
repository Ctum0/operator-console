import asyncio
import importlib
import os

import pytest
from fastapi.testclient import TestClient

AUTH = {"Authorization": "Bearer testtoken"}


@pytest.fixture()
def m(tmp_path, monkeypatch):
    monkeypatch.setenv("CONSOLE_TOKEN", "testtoken")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GITHUB_TOKEN", "")
    import app.main as main
    return importlib.reload(main)


def test_fresh_start_is_empty(m):
    with TestClient(m.app) as c:
        r = c.get("/api/proposals", headers=AUTH)
        assert r.status_code == 200 and r.json()["total"] == 0


def test_api_requires_token_and_sets_security_headers(m):
    with TestClient(m.app) as c:
        r = c.get("/api/proposals")
        assert r.status_code == 401
        assert r.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
        assert c.get("/api/proposals", headers=AUTH).headers["cache-control"] == "no-store"


def test_ci_gate_returns_head_sha(m, monkeypatch):
    class R:
        def __init__(self, code, js):
            self.status_code, self._js = code, js
            self.is_success = code < 400
        def json(self):
            return self._js

    async def fake_get(url, *a, **k):
        return R(200, {"state": "open", "merged": False, "head": {"sha": "abc12345"}})

    async def fake_ci(sha):
        return [], [], True

    monkeypatch.setattr(m, "_gh_get", fake_get)
    monkeypatch.setattr(m, "_commit_ci", fake_ci)
    ok, detail, sha = asyncio.run(m._ci_gate(7))
    assert ok and sha == "abc12345"


def test_ci_gate_blocks_closed_pr(m, monkeypatch):
    class R:
        status_code, is_success = 200, True
        def json(self):
            return {"state": "closed", "merged": False, "head": {"sha": "x"}}

    async def fake_get(url, *a, **k):
        return R()

    monkeypatch.setattr(m, "_gh_get", fake_get)
    ok, detail, sha = asyncio.run(m._ci_gate(7))
    assert not ok and sha is None
