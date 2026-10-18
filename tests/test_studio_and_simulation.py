"""Tests for Multi-Backend Query Studio and Offline Alert Simulation."""

import importlib
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


def test_rule_presets(m):
    with TestClient(m.app) as c:
        resp = c.get("/api/rules/presets", headers=AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 3
        slugs = [p.get("slug") for p in data]
        assert "registry_run_key_persistence" in slugs


def test_rule_translate(m):
    yaml_sample = """
title: Test LSASS Access
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage|endswith: '\\lsass.exe'
  condition: selection
tags:
  - attack.t1003.001
"""
    with TestClient(m.app) as c:
        resp = c.post("/api/rules/translate", headers=AUTH, json={"sigma_yaml": yaml_sample})
        assert resp.status_code == 200
        data = resp.json()
        assert data["valid"] is True
        assert "wazuh" in data["queries"]
        assert "splunk" in data["queries"]
        assert "kql" in data["queries"]
        assert "lucene" in data["queries"]
        assert "cql" in data["queries"]
        assert "lsass" in data["queries"]["splunk"].lower() or "lsass" in data["queries"]["wazuh"].lower()


def test_simulate_alert(m):
    with TestClient(m.app) as c:
        m._write_json(m.PROPOSALS_FILE, [{
            "id": "prop-sim-test",
            "technique": "T1547.001",
            "title": "Registry Run Key Test",
            "sigma_yaml": "title: Test",
            "status": "merged",
            "origin": "human",
            "rule_id": "100021"
        }])

        resp = c.post("/api/proposals/prop-sim-test/simulate-alert", headers=AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["rule_id"] == "100021"
        assert data["technique"] == "T1547.001"
        assert "alert" in data
        assert data["alert"]["status"] == "alert_fired"


def test_proposal_ci_status(m, monkeypatch):
    with TestClient(m.app) as c:
        m._write_json(m.PROPOSALS_FILE, [{
            "id": "prop-ci-test",
            "pr_number": 12,
            "status": "pending",
        }])

        async def fake_ci_gate(pr_number):
            return True, "all CI checks passed on head 12345678", "12345678"

        monkeypatch.setattr(m, "_ci_gate", fake_ci_gate)
        resp = c.get("/api/proposals/prop-ci-test/ci-status", headers=AUTH)
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["state"] == "passed"
        assert data["head_sha"] == "12345678"


def test_proposal_deployment_status_stages(m):
    with TestClient(m.app) as c:
        m._write_json(m.PROPOSALS_FILE, [
            {"id": "p-val", "status": "validated"},
            {"id": "p-merg", "status": "merged"},
            {"id": "p-pend", "status": "pending"},
        ])

        # Validated proposal returns validated stage
        r1 = c.get("/api/proposals/p-val/deployment-status", headers=AUTH)
        assert r1.status_code == 200
        assert r1.json()["stage"] == "validated"

        # Pending proposal returns pending
        r2 = c.get("/api/proposals/p-pend/deployment-status", headers=AUTH)
        assert r2.status_code == 200
        assert r2.json()["stage"] == "pending"

        # Merged proposal returns merged (without GitHub token)
        r3 = c.get("/api/proposals/p-merg/deployment-status", headers=AUTH)
        assert r3.status_code == 200
        assert r3.json()["stage"] == "merged"
