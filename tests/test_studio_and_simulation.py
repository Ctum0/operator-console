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
