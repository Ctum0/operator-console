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


VALID_SIGMA = """
title: Suspicious DNS Query via Powershell
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: 'Resolve-DnsName'
    condition: selection
tags:
    - attack.execution
    - attack.t1059.001
"""

INVALID_SIGMA = """
title: Bad Rule
logsource: not-a-dict
detection:
    condition: selection
"""


def test_validate_rule_endpoint(m):
    with TestClient(m.app) as c:
        # Valid YAML
        r = c.post("/api/rules/validate", json={"sigma_yaml": VALID_SIGMA}, headers=AUTH)
        assert r.status_code == 200
        d = r.json()
        assert d["valid"] is True
        assert d["title"] == "Suspicious DNS Query via Powershell"
        assert d["technique"] == "T1059.001"
        assert len(d["errors"]) == 0

        # Invalid YAML
        r = c.post("/api/rules/validate", json={"sigma_yaml": INVALID_SIGMA}, headers=AUTH)
        assert r.status_code == 200
        d = r.json()
        assert d["valid"] is False
        assert len(d["errors"]) > 0


def test_submit_rule_happy_path(m, monkeypatch):
    class FakeResp:
        def __init__(self, code, js=None):
            self.status_code = code
            self.is_success = code < 400
            self._js = js or {}
        def json(self):
            return self._js

    calls = []
    async def fake_get(url, *a, **k):
        calls.append(("GET", url))
        if "contents/detections/sigma" in url:
            return FakeResp(404)
        if "git/ref/heads/main" in url:
            return FakeResp(200, {"object": {"sha": "mainsha123"}})
        return FakeResp(200, {})

    async def fake_post(url, *a, **k):
        calls.append(("POST", url, k.get("json")))
        if "git/refs" in url:
            return FakeResp(201, {"ref": "refs/heads/rule/dns-query"})
        if "pulls" in url:
            return FakeResp(201, {"number": 42, "html_url": "https://github.com/Ctum0/detection-platform/pull/42"})
        return FakeResp(200, {})

    async def fake_put(url, *a, **k):
        calls.append(("PUT", url))
        return FakeResp(201, {"content": {"name": "dns-query.yml"}})

    monkeypatch.setattr(m, "GITHUB_TOKEN", "fakeghpat")
    monkeypatch.setattr(m, "_gh_get", fake_get)
    monkeypatch.setattr(m._client, "post", fake_post)
    monkeypatch.setattr(m._client, "put", fake_put)

    with TestClient(m.app) as c:
        payload = {
            "slug": "dns-query",
            "sigma_yaml": VALID_SIGMA,
            "submitted_by": "sithum",
            "reasoning": "Catch DNS recon",
        }
        r = c.post("/api/rules/submit", json=payload, headers=AUTH)
        assert r.status_code == 201
        data = r.json()
        assert data["origin"] == "human"
        assert data["pr_number"] == 42
        assert "pull/42" in data["pr_url"]
        pid = data["id"]

        # Shows up in list_proposals with origin: human
        p_list = c.get("/api/proposals", headers=AUTH).json()
        prop = next(p for p in p_list["proposals"] if p["id"] == pid)
        assert prop["origin"] == "human"
        assert prop["technique"] == "T1059.001"

        # origin filter
        human_only = c.get("/api/proposals?origin=human", headers=AUTH).json()
        assert any(p["id"] == pid for p in human_only["proposals"])

        ai_only = c.get("/api/proposals?origin=ai", headers=AUTH).json()
        assert not any(p["id"] == pid for p in ai_only["proposals"])


def test_submit_rule_validations_and_conflict(m, monkeypatch):
    monkeypatch.setattr(m, "GITHUB_TOKEN", "fakeghpat")
    with TestClient(m.app) as c:
        # Invalid YAML -> 400
        r = c.post("/api/rules/submit", json={"slug": "bad-rule", "sigma_yaml": INVALID_SIGMA}, headers=AUTH)
        assert r.status_code == 400

        # Invalid slug -> 422
        r = c.post("/api/rules/submit", json={"slug": "Bad/Slug!", "sigma_yaml": VALID_SIGMA}, headers=AUTH)
        assert r.status_code == 422


def test_origin_defaults_to_ai_for_legacy(m):
    # Seed a proposal without origin field
    data = [{
        "id": "prop-legacy-1",
        "technique": "T1059.001",
        "title": "Legacy AI Proposal",
        "sigma_yaml": VALID_SIGMA,
        "reasoning": "from n8n",
        "pr_url": "https://github.com/Ctum0/detection-platform/pull/1",
        "pr_number": 1,
        "branch": "rule/legacy",
        "created_at": "2026-10-01T00:00:00Z",
        "status": "pending",
    }]
    m._write_json(m.PROPOSALS_FILE, data)

    with TestClient(m.app) as c:
        # list_proposals populates origin=ai
        r = c.get("/api/proposals", headers=AUTH)
        assert r.status_code == 200
        prop = r.json()["proposals"][0]
        assert prop["origin"] == "ai"

        # get_proposal populates origin=ai
        r2 = c.get(f"/api/proposals/{prop['id']}", headers=AUTH)
        assert r2.status_code == 200
        assert r2.json()["origin"] == "ai"


def test_artifacts_and_validation_dispatch(m, monkeypatch):
    class FakeResp:
        def __init__(self, code, js=None):
            self.status_code = code
            self.is_success = code < 400
            self._js = js or {}
        def json(self):
            return self._js

    async def fake_post(url, *a, **k):
        return FakeResp(204)

    monkeypatch.setattr(m, "GITHUB_TOKEN", "fakeghpat")
    monkeypatch.setattr(m._client, "post", fake_post)

    with TestClient(m.app) as c:
        # Query artifacts for DET-002
        r = c.get("/api/rules/DET-002/artifacts", headers=AUTH)
        assert r.status_code == 200
        art = r.json()
        assert art["detection_id"] == "DET-002"
        assert art["status"] == "deployed"
        assert "powershell" in art["sigma_yaml"].lower()
        assert "100005" in art["wazuh_xml"]
        assert len(art["splunk_spl"]) > 0

        # Query artifacts for rule ID 100005
        r2 = c.get("/api/rules/100005/artifacts", headers=AUTH)
        assert r2.status_code == 200
        assert r2.json()["rule_id"] == "100005"

        # Test validation dispatch on a proposal
        prop_data = [{
            "id": "prop-test-val",
            "technique": "T1059.001",
            "title": "Test Dispatch",
            "sigma_yaml": VALID_SIGMA,
            "reasoning": "test",
            "pr_url": "https://github.com/Ctum0/detection-platform/pull/99",
            "pr_number": 99,
            "branch": "rule/test",
            "created_at": "2026-10-01T00:00:00Z",
            "status": "merged",
        }]
        m._write_json(m.PROPOSALS_FILE, prop_data)

        # Deployment status
        r_dep = c.get("/api/proposals/prop-test-val/deployment-status", headers=AUTH)
        assert r_dep.status_code == 200
        assert "stage" in r_dep.json()

        # Run validation
        r_val = c.post("/api/proposals/prop-test-val/run-validation", headers=AUTH)
        assert r_val.status_code == 200
        assert r_val.json()["dispatched"] is True

