"""Backend edge cases. All GitHub / n8n / Wazuh traffic is mocked."""
import asyncio
import importlib
import json
import time
from datetime import datetime, timezone, timedelta

import httpx
import pytest
from fastapi.testclient import TestClient

AUTH = {"Authorization": "Bearer testtoken"}
_n = {"i": 0}


@pytest.fixture()
def m(tmp_path, monkeypatch):
    monkeypatch.setenv("CONSOLE_TOKEN", "testtoken")
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    monkeypatch.setenv("GITHUB_TOKEN", "")
    import app.main as main
    return importlib.reload(main)


class R:
    def __init__(self, code=200, js=None, text=None):
        self.status_code = code
        self.is_success = code < 400
        self._js = js if js is not None else {}
        self.text = text if text is not None else json.dumps(self._js)

    def json(self):
        return self._js


def body(**kw):
    _n["i"] += 1
    d = {"technique": f"T{1000 + _n['i']}", "title": "t", "sigma_yaml": "title: x", "reasoning": "r",
         "pr_url": "https://github.com/o/r/pull/1", "pr_number": 100 + _n["i"], "branch": "b"}
    d.update(kw)
    return d


def mk(c, **kw):
    r = c.post("/api/proposals", json=body(**kw), headers=AUTH)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def get(c, pid):
    return c.get(f"/api/proposals/{pid}", headers=AUTH).json()


def set_status(m, pid, status, **extra):
    props = json.loads(m.PROPOSALS_FILE.read_text())
    for p in props:
        if p["id"] == pid:
            p["status"] = status
            p.update(extra)
    m.PROPOSALS_FILE.write_text(json.dumps(props))


def wait_settled(c, pid, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        p = get(c, pid)
        if p["status"] != "merging":
            return p
        time.sleep(0.02)
    raise AssertionError("still merging")


def fake_github(m, monkeypatch, pr=None, runs=None, status=None, put=None, pr_code=200):
    pr = pr if pr is not None else {"state": "open", "merged": False, "head": {"sha": "abcdef123456"}}
    runs = runs if runs is not None else [{"name": "ci", "status": "completed", "conclusion": "success"}]
    puts = []

    async def gget(url, *a, **k):
        if url.endswith("/check-runs"):
            return R(200, {"check_runs": runs})
        if url.endswith("/status"):
            return R(200, status or {"statuses": [], "state": "pending"})
        if "/pulls/" in url:
            return R(pr_code, pr)
        return R(404, {})

    async def gput(url, **k):
        puts.append(k["json"])
        if isinstance(put, Exception):
            raise put
        return put or R(200, {"merged": True})

    monkeypatch.setattr(m, "_gh_get", gget)
    monkeypatch.setattr(m._client, "put", gput)
    monkeypatch.setattr(m, "GITHUB_TOKEN", "tok")
    return puts


# ---------------------------------------------------------------- validation
@pytest.mark.parametrize("field", ["technique", "title", "sigma_yaml", "reasoning", "pr_url", "branch"])
def test_empty_and_whitespace_only_fields_rejected(m, field):
    with TestClient(m.app) as c:
        for v in ("", "   ", "\n\t"):
            r = c.post("/api/proposals", json=body(**{field: v}), headers=AUTH)
            assert r.status_code == 422, (field, v)
        assert c.get("/api/proposals", headers=AUTH).json()["total"] == 0


def test_null_bytes_rejected(m):
    with TestClient(m.app) as c:
        r = c.post("/api/proposals", json=body(title="a\u0000b"), headers=AUTH)
        assert r.status_code == 422 and "null bytes" in r.text


@pytest.mark.parametrize("field,limit", [("title", 300), ("sigma_yaml", 20000), ("reasoning", 4000),
                                         ("branch", 200)])
def test_oversized_fields_rejected_and_boundary_accepted(m, field, limit):
    with TestClient(m.app) as c:
        assert c.post("/api/proposals", json=body(**{field: "x" * (limit + 1)}), headers=AUTH).status_code == 422
        assert c.post("/api/proposals", json=body(**{field: "x" * limit}), headers=AUTH).status_code == 201


def test_unicode_fields_roundtrip(m):
    with TestClient(m.app) as c:
        pid = mk(c, title="détection ‮ 検知 \U0001f600", reasoning="ünï")
        assert get(c, pid)["title"] == "détection ‮ 検知 \U0001f600"


@pytest.mark.parametrize("bad", [0, -1, 1.5, "abc", "-3", None, [], {}, "²"])
def test_bad_pr_number(m, bad):
    with TestClient(m.app) as c:
        assert c.post("/api/proposals", json=body(pr_number=bad), headers=AUTH).status_code == 422


def test_pr_number_numeric_string_coerced(m):
    with TestClient(m.app) as c:
        pid = mk(c, pr_number=" 77 ")
        assert get(c, pid)["pr_number"] == 77


@pytest.mark.parametrize("tech", ["t1059", "T105", "T1059.01", "T1059\n", "T1059 ", "X1059", "T1059.001.002"])
def test_bad_technique(m, tech):
    with TestClient(m.app) as c:
        assert c.post("/api/proposals", json=body(technique=tech), headers=AUTH).status_code == 422


@pytest.mark.parametrize("url", ["ftp://x", "javascript:alert(1)", "github.com/x"])
def test_bad_pr_url(m, url):
    with TestClient(m.app) as c:
        assert c.post("/api/proposals", json=body(pr_url=url), headers=AUTH).status_code == 422


def test_malformed_json_and_non_object_bodies(m):
    with TestClient(m.app) as c:
        h = {**AUTH, "content-type": "application/json"}
        assert c.post("/api/proposals", content=b"{nope", headers=h).status_code == 422
        assert c.post("/api/proposals", content=b"[]", headers=h).status_code == 422
        assert c.post("/api/proposals", content=b"null", headers=h).status_code == 422


def test_duplicate_pr_number_is_idempotent_and_ignores_rate_limit(m):
    with TestClient(m.app) as c:
        b = body()
        r1 = c.post("/api/proposals", json=b, headers=AUTH).json()
        r2 = c.post("/api/proposals", json={**b, "title": "new"}, headers=AUTH)
        assert r2.status_code == 201 and r2.json()["id"] == r1["id"] and r2.json()["updated"] is True
        assert c.get("/api/proposals", headers=AUTH).json()["total"] == 1
        assert get(c, r1["id"])["title"] == "new"


@pytest.mark.parametrize("status", ["merging", "merged", "validated"])
def test_reregistration_does_not_reset_shipping_proposals(m, status):
    with TestClient(m.app) as c:
        b = body()
        pid = c.post("/api/proposals", json=b, headers=AUTH).json()["id"]
        set_status(m, pid, status)
        r = c.post("/api/proposals", json=b, headers=AUTH)
        assert r.status_code == 201 and r.json()["created"] is False
        assert get(c, pid)["status"] == status


def test_rate_limit_per_technique_only(m):
    with TestClient(m.app) as c:
        assert c.post("/api/proposals", json=body(technique="T1059"), headers=AUTH).status_code == 201
        r = c.post("/api/proposals", json=body(technique="T1059"), headers=AUTH)
        assert r.status_code == 429
        assert c.post("/api/proposals", json=body(technique="T1060"), headers=AUTH).status_code == 201
        # sub-technique is a different key
        assert c.post("/api/proposals", json=body(technique="T1059.001"), headers=AUTH).status_code == 201


def test_rate_limit_expires_and_survives_corrupt_ratefile(m):
    with TestClient(m.app) as c:
        mk(c, technique="T1059")
        m.RATE_FILE.write_text(json.dumps({"T1059": time.time() - 601}))
        assert c.post("/api/proposals", json=body(technique="T1059"), headers=AUTH).status_code == 201
        m.RATE_FILE.write_text("[1,2")
        assert c.post("/api/proposals", json=body(technique="T1059"), headers=AUTH).status_code == 201


# ------------------------------------------------------------- state machine
def test_illegal_transitions_from_every_state(m):
    allowed = {
        "approve": {"pending", "merge_failed"},
        "retry": {"merge_failed"},
        "reject": {"pending", "merge_failed"},
        "reopen": {"rejected"},
        "delete": {"pending", "rejected", "merge_failed"},
        "validated": {"merged"},
    }
    with TestClient(m.app) as c:
        for state in m.STATUSES:
            for action, ok_states in allowed.items():
                if state in ok_states:
                    continue  # legal transitions are covered separately
                pid = mk(c)
                set_status(m, pid, state, merged_at="2020-01-01T00:00:00Z")
                if action == "delete":
                    r = c.delete(f"/api/proposals/{pid}", headers=AUTH)
                elif action == "validated":
                    r = c.post(f"/api/proposals/{pid}/validated", headers=AUTH,
                               json={"rule_id": "1", "attack": "a", "fired_at": "2026-01-01T00:00:00Z"})
                else:
                    r = c.post(f"/api/proposals/{pid}/{action}", headers=AUTH, json={})
                assert r.status_code == 409, (state, action, r.status_code)
                assert get(c, pid)["status"] == state


def test_unknown_id_is_404_everywhere(m):
    with TestClient(m.app) as c:
        for path in ("approve", "retry", "reject", "reopen", "notes", "validated"):
            r = c.post(f"/api/proposals/nope/{path}", headers=AUTH,
                       json={"text": "x", "rule_id": "1", "attack": "a", "fired_at": "2026-01-01T00:00:00Z"})
            assert r.status_code == 404, path
        assert c.delete("/api/proposals/nope", headers=AUTH).status_code == 404
        assert c.get("/api/proposals/nope", headers=AUTH).status_code == 404


def test_reject_reopen_delete_cycle(m):
    with TestClient(m.app) as c:
        pid = mk(c)
        r = c.post(f"/api/proposals/{pid}/reject", json={"reason": "  noisy  "}, headers=AUTH)
        assert r.json() == {"id": pid, "status": "rejected", "reason": "noisy"}
        assert c.post(f"/api/proposals/{pid}/reject", json={}, headers=AUTH).status_code == 409  # double click
        assert c.post(f"/api/proposals/{pid}/reopen", headers=AUTH).json()["status"] == "pending"
        assert "reject_reason" not in get(c, pid)
        assert c.delete(f"/api/proposals/{pid}", headers=AUTH).json()["deleted"] is True
        assert c.delete(f"/api/proposals/{pid}", headers=AUTH).status_code == 404


@pytest.mark.parametrize("payload", [None, {}, {"reason": None}, {"reason": 5}, {"reason": ["a"]}, {"reason": "x" * 5000}])
def test_reject_body_variants(m, payload):
    with TestClient(m.app) as c:
        pid = mk(c)
        kw = {"json": payload} if payload is not None else {}
        r = c.post(f"/api/proposals/{pid}/reject", headers=AUTH, **kw)
        assert r.status_code == 200
        assert len(r.json()["reason"] or "") <= 1000


def test_delete_blocked_while_merge_in_flight(m):
    with TestClient(m.app) as c:
        pid = mk(c)
        set_status(m, pid, "merge_failed")
        m._pending_merges.add(pid)
        assert c.delete(f"/api/proposals/{pid}", headers=AUTH).status_code == 409
        assert c.post(f"/api/proposals/{pid}/approve", headers=AUTH).status_code == 409
        m._pending_merges.discard(pid)


def test_approve_without_github_token_marks_merge_failed(m):
    with TestClient(m.app) as c:
        pid = mk(c)
        assert c.post(f"/api/proposals/{pid}/approve", headers=AUTH).status_code == 503
        p = get(c, pid)
        assert p["status"] == "merge_failed" and "GITHUB_TOKEN" in p["merge_error"]


def test_approve_corrupt_pr_number(m, monkeypatch):
    monkeypatch.setattr(m, "GITHUB_TOKEN", "tok")
    with TestClient(m.app) as c:
        pid = mk(c)
        set_status(m, pid, "pending", pr_number="abc")
        assert c.post(f"/api/proposals/{pid}/approve", headers=AUTH).status_code == 422
        assert get(c, pid)["status"] == "pending"


# ----------------------------------------------------------------- merge flow
def test_merge_happy_path_pins_head_sha(m, monkeypatch):
    puts = fake_github(m, monkeypatch)
    with TestClient(m.app) as c:
        pid = mk(c)
        r = c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        assert r.status_code == 202 and r.json()["status"] == "merging"
        p = wait_settled(c, pid)
        assert p["status"] == "merged" and p["merged_at"]
        assert puts == [{"merge_method": "merge", "sha": "abcdef123456"}]
        assert pid not in m._pending_merges


def test_double_approve_second_is_409_and_merges_once(m, monkeypatch):
    puts = fake_github(m, monkeypatch)
    with TestClient(m.app) as c:
        pid = mk(c)
        codes = [c.post(f"/api/proposals/{pid}/approve", headers=AUTH).status_code for _ in range(2)]
        wait_settled(c, pid)
        assert codes[0] == 202 and codes[1] == 409
        assert len(puts) == 1


@pytest.mark.parametrize("pr", [
    {"state": "closed", "merged": False, "head": {"sha": "a"}},
    {"state": "closed", "merged": True, "head": {"sha": "a"}},
    {"state": "weird", "merged": False, "head": {"sha": "a"}},
    {"state": "open", "merged": False, "head": {}},
    {"state": "open", "merged": True, "head": {"sha": "a"}},
])
def test_pr_not_open_blocks_merge(m, monkeypatch, pr):
    puts = fake_github(m, monkeypatch, pr=pr)
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        p = wait_settled(c, pid)
        assert p["status"] == "merge_failed" and p["merge_error"].startswith("merge blocked")
        assert puts == []


@pytest.mark.parametrize("runs,needle", [
    ([{"name": "ci", "status": "completed", "conclusion": "failure"}], "CI failed"),
    ([{"name": "ci", "status": "in_progress", "conclusion": None}], "still running"),
    ([{"name": "a", "status": "completed", "conclusion": "success"},
      {"name": "b", "status": "queued", "conclusion": None}], "still running"),
    ([{"name": "ci", "status": "completed", "conclusion": "mystery"}], "unknown conclusion"),
    ([{"name": "ci", "status": "completed", "conclusion": None}], "unknown conclusion"),
    ([], "no CI results"),
])
def test_ci_not_green_blocks_merge(m, monkeypatch, runs, needle):
    puts = fake_github(m, monkeypatch, runs=runs)
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        p = wait_settled(c, pid)
        assert p["status"] == "merge_failed" and needle in p["merge_error"]
        assert puts == []


def test_failing_legacy_status_blocks_even_if_checks_pass(m, monkeypatch):
    puts = fake_github(m, monkeypatch, status={"statuses": [{"state": "failure"}], "state": "failure"})
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        assert wait_settled(c, pid)["status"] == "merge_failed" and puts == []


def test_only_passing_legacy_status_is_enough(m, monkeypatch):
    puts = fake_github(m, monkeypatch, runs=[], status={"statuses": [{"state": "success"}], "state": "success"})
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        assert wait_settled(c, pid)["status"] == "merged" and len(puts) == 1


@pytest.mark.parametrize("resp", [R(409, {"message": "Head branch was modified"}),
                                  R(405, {"message": "not mergeable"}),
                                  R(422, {"message": "invalid"}),
                                  R(500, text="boom")])
def test_merge_put_error_responses_fail_the_merge(m, monkeypatch, resp):
    fake_github(m, monkeypatch, put=resp)
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        p = wait_settled(c, pid)
        assert p["status"] == "merge_failed" and p["merge_error"]
        assert pid not in m._pending_merges
        # and it is retryable
        set_status(m, pid, "merge_failed")
        fake_github(m, monkeypatch)
        assert c.post(f"/api/proposals/{pid}/retry", headers=AUTH).status_code == 202
        assert wait_settled(c, pid)["status"] == "merged"


def test_merge_put_network_error(m, monkeypatch):
    fake_github(m, monkeypatch, put=httpx.ConnectError("down"))
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        p = wait_settled(c, pid)
        assert p["status"] == "merge_failed" and p["merge_error"] == "network error"


def test_github_unreachable_and_http_errors_in_gate(m, monkeypatch):
    fake_github(m, monkeypatch)

    async def boom(url, *a, **k):
        raise httpx.ConnectTimeout("t")
    monkeypatch.setattr(m, "_gh_get", boom)
    ok, detail, sha = asyncio.run(m._ci_gate(5))
    assert not ok and sha is None and "unreachable" in detail
    for code, needle in ((404, "not found"), (500, "HTTP 500")):
        async def g(url, *a, code=code, **k):
            return R(code, {})
        monkeypatch.setattr(m, "_gh_get", g)
        ok, detail, sha = asyncio.run(m._ci_gate(5))
        assert not ok and needle in detail


def test_non_json_pr_response_does_not_strand_merging(m, monkeypatch):
    fake_github(m, monkeypatch)

    class Bad(R):
        def json(self):
            raise ValueError("not json")

    async def gget(url, *a, **k):
        return Bad(200)
    monkeypatch.setattr(m, "_gh_get", gget)
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/approve", headers=AUTH)
        assert wait_settled(c, pid)["status"] == "merge_failed"
        assert pid not in m._pending_merges


def test_ci_bot_commit_parent_fallback_requires_splunk_only(m, monkeypatch):
    sha = "b" * 40
    seen = []

    async def gget(url, *a, **k):
        seen.append(url)
        if "/pulls/" in url:
            return R(200, {"state": "open", "head": {"sha": sha}})
        if url.endswith(f"/commits/{sha}"):
            return R(200, {"commit": {"message": "x [skip ci]"}, "author": {"login": "github-actions[bot]"},
                           "parents": [{"sha": "p" * 40}],
                           "files": [{"filename": "detections/splunk/a.spl"}, {"filename": "detections/sigma/a.yml"}]})
        return R(200, {"check_runs": []})
    monkeypatch.setattr(m, "_gh_get", gget)
    ok, detail, _ = asyncio.run(m._ci_gate(1))
    assert not ok and "no CI results" in detail
    assert not any("p" * 40 in u for u in seen)


# --------------------------------------------------------------- startup
def test_startup_recovers_merging_and_logs(m):
    with TestClient(m.app) as c:
        pid = mk(c)
        set_status(m, pid, "merging")
    with TestClient(m.app) as c:
        p = get(c, pid)
        assert p["status"] == "merge_failed" and "restart" in p["merge_error"]
        acts = c.get("/api/activity", params={"proposal_id": pid}, headers=AUTH).json()["activity"]
        assert any(a["action"] == "proposal.merge_failed" for a in acts)


def test_startup_tolerates_corrupt_and_wrong_shaped_files(m):
    m.DATA_DIR.mkdir(parents=True, exist_ok=True)
    m.PROPOSALS_FILE.write_text("{broken")
    m.ACTIVITY_FILE.write_text(json.dumps({"not": "a list"}))
    m.TRIGGERS_FILE.write_text("")
    with TestClient(m.app) as c:
        assert c.get("/api/proposals", headers=AUTH).json()["total"] == 0
        assert c.get("/api/activity", headers=AUTH).json()["total"] == 0
        assert c.get("/api/triggers", headers=AUTH).json()["total"] == 0
        mk(c)
        assert c.get("/api/proposals", headers=AUTH).json()["total"] == 1
    assert list(m.DATA_DIR.glob("proposals.json.corrupt.*"))


def test_binary_garbage_data_file_does_not_500(m):
    m.DATA_DIR.mkdir(parents=True, exist_ok=True)
    m.PROPOSALS_FILE.write_bytes(b"\xff\xfe\x00\x80garbage")
    with TestClient(m.app) as c:
        assert c.get("/api/proposals", headers=AUTH).status_code == 200


def test_non_dict_entries_in_proposals_file_are_skipped(m):
    m.DATA_DIR.mkdir(parents=True, exist_ok=True)
    m.PROPOSALS_FILE.write_text(json.dumps([1, "x", None, {"id": "p1", "status": "pending", "title": "T"}]))
    with TestClient(m.app) as c:
        j = c.get("/api/proposals", headers=AUTH).json()
        assert j["total"] == 1
        assert c.post("/api/proposals/p1/reject", json={}, headers=AUTH).status_code == 200


def test_missing_data_dir_is_created(m, tmp_path, monkeypatch):
    monkeypatch.setattr(m, "DATA_DIR", tmp_path / "a" / "b")
    monkeypatch.setattr(m, "PROPOSALS_FILE", tmp_path / "a" / "b" / "proposals.json")
    monkeypatch.setattr(m, "ACTIVITY_FILE", tmp_path / "a" / "b" / "activity.json")
    with TestClient(m.app) as c:
        assert c.get("/api/proposals", headers=AUTH).status_code == 200
    assert (tmp_path / "a" / "b" / "proposals.json").exists()


def test_concurrent_registrations_lose_nothing(m):
    async def go():
        t = httpx.ASGITransport(app=m.app)
        async with httpx.AsyncClient(transport=t, base_url="http://x", headers=AUTH) as cl:
            rs = await asyncio.gather(*[cl.post("/api/proposals", json=body()) for _ in range(25)])
            assert all(r.status_code == 201 for r in rs)
            return (await cl.get("/api/proposals")).json()["total"], \
                (await cl.get("/api/activity")).json()["total"]
    m._ensure_files()
    total, acts = asyncio.run(go())
    assert total == 25 and acts == 25


def test_write_failure_leaves_no_tmp_and_keeps_old_file(m, monkeypatch):
    m._ensure_files()
    m._write_json(m.PROPOSALS_FILE, [{"id": "a"}])

    def bad(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(m.os, "replace", bad)
    with pytest.raises(OSError):
        m._write_json(m.PROPOSALS_FILE, [{"id": "b"}])
    monkeypatch.undo()
    assert json.loads(m.PROPOSALS_FILE.read_text()) == [{"id": "a"}]
    assert not list(m.DATA_DIR.glob("*.tmp"))


# ------------------------------------------------------------- notes / validated
def test_notes_validation_and_cap(m):
    with TestClient(m.app) as c:
        pid = mk(c)
        u = f"/api/proposals/{pid}/notes"
        assert c.post(u, json={"text": "   "}, headers=AUTH).status_code == 422
        assert c.post(u, json={}, headers=AUTH).status_code == 422
        assert c.post(u, json={"text": "x" * 2001}, headers=AUTH).status_code == 422
        assert c.post(u, json={"text": None}, headers=AUTH).status_code == 422
        r = c.post(u, json={"text": " hi ", "author": "a" * 200}, headers=AUTH)
        assert r.status_code == 201 and r.json()["text"] == "hi" and len(r.json()["author"]) == 64
        assert c.post(u, json={"text": "y", "author": "  "}, headers=AUTH).json()["author"] == "operator"
        set_status(m, pid, "pending", notes=[{}] * m.NOTES_CAP)
        assert c.post(u, json={"text": "over"}, headers=AUTH).status_code == 409
        set_status(m, pid, "pending", notes="garbage")
        assert c.post(u, json={"text": "ok"}, headers=AUTH).status_code == 201


def _val(**kw):
    d = {"rule_id": "100100", "attack": "mimikatz", "fired_at": "2026-01-01T00:00:00Z"}
    d.update(kw)
    return d


def test_validated_inputs(m):
    with TestClient(m.app) as c:
        pid = mk(c)
        set_status(m, pid, "merged", merged_at="2026-01-01T00:00:00Z")
        u = f"/api/proposals/{pid}/validated"
        bad = [
            _val(rule_id=""), _val(attack="  "), _val(fired_at=""), _val(fired_at="yesterday"),
            _val(fired_at="2999-01-01T00:00:00Z"), _val(fired_at="2025-12-01T00:00:00Z"),  # before merge
            _val(rule_id="x" * 65), _val(attack="x" * 301),
            _val(evidence_url="javascript:alert(1)"), _val(evidence_url="http://" + "a" * 500),
            _val(fired_at="0001-01-01T00:00:00+05:00"),  # cannot be converted to UTC
        ]
        for b in bad:
            assert c.post(u, json=b, headers=AUTH).status_code == 422, b
        assert get(c, pid)["status"] == "merged"
        r = c.post(u, json=_val(rule_id=100100, evidence_url=" https://e.x/1 "), headers=AUTH)
        assert r.status_code == 200 and r.json()["validation"]["rule_id"] == "100100"
        assert c.post(u, json=_val(), headers=AUTH).status_code == 409  # already validated


# ------------------------------------------------------------ list / activity
def test_list_pagination_and_filters(m):
    with TestClient(m.app) as c:
        ids = [mk(c, title=f"Alpha{i}") for i in range(5)]
        set_status(m, ids[0], "rejected")
        g = lambda **p: c.get("/api/proposals", params=p, headers=AUTH)
        assert g(limit=2).json()["total"] == 5 and len(g(limit=2).json()["proposals"]) == 2
        assert g(offset=99).json()["proposals"] == []
        for bad in ({"limit": -1}, {"limit": 0}, {"limit": 501}, {"limit": "x"}, {"offset": -1}, {"status": "bogus"},
                    {"status": "pending,bogus"}, {"q": "x" * 201}):
            assert g(**bad).status_code == 422, bad
        assert g(status="rejected").json()["total"] == 1
        assert g(status="rejected, pending").json()["total"] == 5
        assert g(status=",").json()["total"] == 5
        assert g(q="ALPHA3").json()["total"] == 1
        assert g(q="%").json()["total"] == 0
        assert g().json()["counts"]["rejected"] == 1


def test_activity_filters_and_limits(m):
    with TestClient(m.app) as c:
        pid = mk(c)
        c.post(f"/api/proposals/{pid}/reject", json={}, headers=AUTH)
        g = lambda **p: c.get("/api/activity", params=p, headers=AUTH)
        assert g(limit=1).json()["total"] == 2 and len(g(limit=1).json()["activity"]) == 1
        assert g(action="proposal.rej").json()["total"] == 1
        assert g(actor="agent").json()["total"] == 1
        assert g(proposal_id=pid).json()["total"] == 2
        assert g(offset=50).json()["activity"] == []
        for bad in ({"limit": 0}, {"limit": -5}, {"limit": 2001}, {"offset": -1}, {"actor": "x" * 65}):
            assert g(**bad).status_code == 422, bad


def test_activity_export_csv_neutralises_formulas(m):
    with TestClient(m.app) as c:
        mk(c, title="=cmd|' /C calc'!A0")
        c.post(f"/api/proposals/{mk(c, title='@SUM(1)')}/notes", json={"text": "+1+1", "author": "-x"}, headers=AUTH)
        r = c.get("/api/activity/export", params={"format": "csv"}, headers=AUTH)
        assert r.headers["content-type"].startswith("text/csv")
        import csv, io
        rows = list(csv.reader(io.StringIO(r.text)))
        assert rows[0] == ["ts", "actor", "action", "detail", "proposal_id"]
        for row in rows[1:]:
            for cell in row:
                assert cell[:1] not in ("=", "+", "-", "@", "\t", "\r"), cell
        assert any(row[1] == "'-x" for row in rows[1:])
        assert c.get("/api/activity/export", params={"format": "xml"}, headers=AUTH).status_code == 422
        j = c.get("/api/activity/export", headers=AUTH).json()
        assert len(j["activity"]) >= 3


def test_csv_cell_unit(m):
    assert m._csv_cell(None) == ""
    assert m._csv_cell(5) == "5"
    assert m._csv_cell("\tx") == "'\tx"
    assert m._csv_cell("a=b") == "a=b"


# ------------------------------------------------------------------ triggers
class FakeClient:
    def __init__(self, resp=None, exc=None):
        self.resp, self.exc, self.calls = resp, exc, []

    async def post(self, url, **k):
        self.calls.append((url, k))
        if self.exc:
            raise self.exc
        return self.resp


def test_trigger_not_configured(m):
    with TestClient(m.app) as c:
        assert c.post("/api/trigger/propose", headers=AUTH).status_code == 503


def test_trigger_webhook_down_records_failure(m, monkeypatch):
    monkeypatch.setattr(m, "N8N_PROPOSE_WEBHOOK", "http://n8n.invalid/hook")
    monkeypatch.setattr(m, "_client", FakeClient(exc=httpx.ConnectError("x")))
    with TestClient(m.app) as c:
        r = c.post("/api/trigger/propose", headers=AUTH)
        assert r.status_code == 202 and r.json()["triggered"] is False and r.json()["status"] == "failed"
        t = c.get("/api/triggers", headers=AUTH).json()
        assert t["total"] == 1 and t["triggers"][0]["completed_at"]
        # failed triggers can not be settled again
        tid = r.json()["trigger_id"]
        assert c.post(f"/api/triggers/{tid}/result", json={"status": "succeeded"}, headers=AUTH).status_code == 409


def test_trigger_invalid_url_does_not_500(m, monkeypatch):
    monkeypatch.setattr(m, "N8N_PROPOSE_WEBHOOK", "http://bad url")
    monkeypatch.setattr(m, "_client", FakeClient(exc=httpx.InvalidURL("bad")))
    with TestClient(m.app) as c:
        r = c.post("/api/trigger/propose", headers=AUTH)
        assert r.status_code == 202 and r.json()["triggered"] is False


def test_trigger_secret_header_only_when_set(m, monkeypatch):
    monkeypatch.setattr(m, "N8N_PROPOSE_WEBHOOK", "http://n8n/hook")
    fc = FakeClient(resp=R(200, {}, "ok"))
    monkeypatch.setattr(m, "_client", fc)
    with TestClient(m.app) as c:
        c.post("/api/trigger/propose", headers=AUTH)
        assert "X-Webhook-Secret" not in fc.calls[-1][1]["headers"]
        monkeypatch.setattr(m, "N8N_WEBHOOK_SECRET", "s3cret")
        c.post("/api/trigger/propose", headers=AUTH)
        assert fc.calls[-1][1]["headers"]["X-Webhook-Secret"] == "s3cret"


def test_trigger_non_2xx_is_failed_and_result_callbacks(m, monkeypatch):
    monkeypatch.setattr(m, "N8N_PROPOSE_WEBHOOK", "http://n8n/hook")
    fc = FakeClient(resp=R(500, {}, "x" * 1000))
    monkeypatch.setattr(m, "_client", fc)
    with TestClient(m.app) as c:
        assert c.post("/api/trigger/propose", headers=AUTH).json()["status"] == "failed"
        fc.resp = R(200, {}, "ok")
        tid = c.post("/api/trigger/propose", headers=AUTH).json()["trigger_id"]
        u = f"/api/triggers/{tid}/result"
        assert c.post(u, json={"status": "bogus"}, headers=AUTH).status_code == 422
        assert c.post(u, json={}, headers=AUTH).status_code == 422
        assert c.post("/api/triggers/trg-none/result", json={"status": "failed"}, headers=AUTH).status_code == 404
        r = c.post(u, json={"status": "failed", "proposal_id": "p" * 500}, headers=AUTH)
        assert r.status_code == 200 and r.json()["status"] == "failed" and len(r.json()["proposal_id"]) == 64
        assert c.post(u, json={"status": "failed"}, headers=AUTH).status_code == 409
        acts = c.get("/api/activity", params={"action": "trigger."}, headers=AUTH).json()["activity"]
        assert all(len(a.get("proposal_id", "")) <= 64 for a in acts)


def test_proposal_with_trigger_id_settles_trigger(m, monkeypatch):
    monkeypatch.setattr(m, "N8N_PROPOSE_WEBHOOK", "http://n8n/hook")
    monkeypatch.setattr(m, "_client", FakeClient(resp=R(200, {}, "ok")))
    with TestClient(m.app) as c:
        tid = c.post("/api/trigger/propose", headers=AUTH).json()["trigger_id"]
        pid = mk(c, trigger_id=tid)
        t = c.get("/api/triggers", headers=AUTH).json()["triggers"][0]
        assert t["status"] == "succeeded" and t["proposal_id"] == pid
        mk(c, trigger_id="trg-unknown")  # unknown trigger id is ignored, not an error
    for bad in ({"limit": 0}, {"limit": 201}):
        with TestClient(m.app) as c:
            assert c.get("/api/triggers", params=bad, headers=AUTH).status_code == 422


# ------------------------------------------------------------------ coverage
def test_parse_md_table_malformed():
    import app.main as main
    assert main._parse_md_table("") == ([], [])
    assert main._parse_md_table("no table here\n| only | two |") == ([], [])
    assert main._parse_md_table("|a|b|c|\n|---|---|---|\n") == (["a", "b", "c"], [])
    cols, rows = main._parse_md_table("| A | B | C | D |\n|:--|--:|:-:|-:|\n| 1 | 2 | 3 |\n| A | B | C | D |\n"
                                      "| x | y | z | w | extra |\n| 1 | 2 |\nnot a row\n|||")
    assert cols == ["A", "B", "C", "D"]
    assert rows == [["1", "2", "3", ""], ["x", "y", "z", "w", "extra"]]  # ragged row padded; repeated header dropped
    cols, rows = main._parse_md_table("  | A | B | C |  \r\n|---|---|---|\r\n| é | 日本 | 😀 |\r\n")
    assert rows == [["é", "日本", "😀"]]


def test_coverage_fetch_paths(m, monkeypatch):
    good = "| Technique | Name | R | S |\n| --- | --- | --- | --- |\n| T1 | n | r | covered |\n"

    async def ok(url, *a, **k):
        return R(200, {}, good)
    monkeypatch.setattr(m, "_gh_get", ok)
    with TestClient(m.app) as c:
        j = c.get("/api/coverage", headers=AUTH).json()
        assert j["stale"] is False and j["rows"] == [["T1", "n", "r", "covered"]]

        async def down(url, *a, **k):
            raise httpx.ConnectError("x")
        monkeypatch.setattr(m, "_gh_get", down)
        m._coverage_cache["ts"] = 0
        j = c.get("/api/coverage", headers=AUTH).json()
        assert j["stale"] is True and j["rows"] == [["T1", "n", "r", "covered"]] and j["error"]

        async def junk(url, *a, **k):
            return R(200, {}, "# nothing")
        monkeypatch.setattr(m, "_gh_get", junk)
        m._coverage_cache["ts"] = 0
        m.COVERAGE_CACHE_FILE.unlink()
        j = c.get("/api/coverage", headers=AUTH).json()
        assert j["sample"] is True and j["stale"] is True and j["rows"]


# -------------------------------------------------------------------- health
def test_empty_wazuh_host_reports_not_configured_and_never_probes(m, monkeypatch):
    monkeypatch.setattr(m, "WAZUH_HOST", "")
    probed = []

    async def tcp(*a, **k):
        probed.append(a)
        return True

    async def none(*a, **k):
        return {"name": "x", "status": "unknown", "level": "unknown", "detail": ""}
    monkeypatch.setattr(m, "_check_tcp", tcp)
    monkeypatch.setattr(m, "_probe_ci", none)
    monkeypatch.setattr(m, "_probe_runners", none)
    monkeypatch.setattr(m, "_probe_wazuh_api", none)
    with TestClient(m.app) as c:
        comps = {x["name"]: x for x in c.get("/api/health/pipeline", headers=AUTH).json()["components"]}
    assert probed == []
    assert comps["Wazuh Manager"]["status"] == "unknown"
    assert comps["Wazuh Manager"]["level"] == "unknown"
    assert "not configured" in comps["Wazuh Manager"]["detail"]


def test_wazuh_host_default_preserved(m):
    assert m.WAZUH_HOST == "100.81.241.62"


def test_tcp_probe_bad_host_never_raises(m):
    assert asyncio.run(m._check_tcp("a" * 300, 1514, timeout=1)) is False
    assert asyncio.run(m._check_tcp("127.0.0.1", 99999999, timeout=1)) is False


# ---------------------------------------------------------------------- auth
@pytest.mark.parametrize("hdr", [
    None, "", "Bearer", "Bearer ", "Bearer  testtoken", "Basic testtoken", "testtoken", "Bearer wrong",
    "Bearer testtokenX", "Bearer testtoke", "Bearer tëst", "Bearer ÿþ",
])
def test_bad_auth_headers_are_401_not_500(m, hdr):
    with TestClient(m.app) as c:
        headers = {} if hdr is None else {"Authorization": hdr.encode("latin-1")}
        assert c.get("/api/proposals", headers=headers).status_code == 401


def test_bearer_scheme_is_case_insensitive_and_healthz_open(m):
    with TestClient(m.app) as c:
        assert c.get("/api/proposals", headers={"Authorization": "bearer testtoken"}).status_code == 200
        assert c.get("/healthz").status_code == 200
        # every API route is gated, including unknown ones and wrong methods
        assert c.get("/api/does-not-exist").status_code == 401
        assert c.delete("/api/proposals/x").status_code == 401


def test_empty_console_token_rejects_everything(m, monkeypatch):
    monkeypatch.setattr(m, "CONSOLE_TOKEN", "")
    with TestClient(m.app) as c:
        assert c.get("/api/proposals", headers={"Authorization": "Bearer "}).status_code == 401
        assert c.get("/api/proposals", headers={"Authorization": "Bearer x"}).status_code == 401


def test_non_ascii_console_token_never_500(m, monkeypatch):
    monkeypatch.setattr(m, "CONSOLE_TOKEN", "tøken")
    with TestClient(m.app) as c:
        assert c.get("/api/proposals", headers={"Authorization": "Bearer token"}).status_code == 401


def test_submit_rule_edge_cases(m, monkeypatch):
    valid_sigma = """
title: Test Duplicate Title
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image: 'test.exe'
    condition: selection
tags:
    - attack.t1059.001
"""
    # Seed an existing proposal with this title and slug
    existing = [{
        "id": "prop-exist-1",
        "technique": "T1059.001",
        "title": "Test Duplicate Title",
        "sigma_yaml": valid_sigma,
        "reasoning": "first",
        "pr_url": "https://github.com/Ctum0/detection-platform/pull/1",
        "pr_number": 1,
        "branch": "rule/existing-slug",
        "slug": "existing-slug",
        "created_at": "2026-10-01T00:00:00Z",
        "status": "pending",
        "origin": "human",
    }]
    m._write_json(m.PROPOSALS_FILE, existing)

    with TestClient(m.app) as c:
        # 1. Duplicate title -> 409
        r = c.post("/api/rules/submit", json={"slug": "new-slug", "sigma_yaml": valid_sigma}, headers=AUTH)
        assert r.status_code == 409
        assert "already exists in proposals" in r.json()["detail"]

        # 2. Duplicate slug -> 409
        other_yaml = valid_sigma.replace("Test Duplicate Title", "Completely New Title")
        r = c.post("/api/rules/submit", json={"slug": "existing-slug", "sigma_yaml": other_yaml}, headers=AUTH)
        assert r.status_code == 409
        assert "already exists in proposals" in r.json()["detail"]

        # 3. Missing GITHUB_TOKEN -> 503
        monkeypatch.setattr(m, "GITHUB_TOKEN", "")
        r = c.post("/api/rules/submit", json={"slug": "brand-new-slug", "sigma_yaml": other_yaml}, headers=AUTH)
        assert r.status_code == 503

        # 4. Unknown origin in list_proposals -> 422
        r_orig = c.get("/api/proposals?origin=invalid", headers=AUTH)
        assert r_orig.status_code == 422

        # 5. Run validation on unknown proposal -> 404
        r_val = c.post("/api/proposals/prop-nonexistent/run-validation", headers=AUTH)
        assert r_val.status_code == 404

        # 6. Run validation without token -> 503
        r_val503 = c.post("/api/proposals/prop-exist-1/run-validation", headers=AUTH)
        assert r_val503.status_code == 503

        # 7. Deployment status on non-existent -> 404
        assert c.get("/api/proposals/prop-nonexistent/deployment-status", headers=AUTH).status_code == 404

        # 8. Artifacts on non-existent proposal -> 404
        assert c.get("/api/proposals/prop-nonexistent/artifacts", headers=AUTH).status_code == 404

        # 9. Artifacts by identifier on custom/unknown -> returns preview structure
        r_art = c.get("/api/rules/unknown-rule-slug/artifacts", headers=AUTH)
        assert r_art.status_code == 200
        assert r_art.json()["status"] == "preview"


def test_agent_health_failed_trigger_recovery(m, monkeypatch):
    monkeypatch.setattr(m, "N8N_PROPOSE_WEBHOOK", "http://n8n/hook")
    # Old trigger (10 minutes ago)
    ten_min_ago = (datetime.now(timezone.utc) - timedelta(minutes=10)).isoformat()
    m._write_json(m.TRIGGERS_FILE, [{
        "id": "trg-old",
        "ts": ten_min_ago,
        "status": "failed",
        "detail": "connection timeout"
    }])
    with TestClient(m.app) as c:
        h = c.get("/api/health/pipeline", headers=AUTH).json()
        comp = next(x for x in h["components"] if x["name"] == "Agent Link (n8n)")
        assert comp["level"] == "ok"
        assert "idle · ready" in comp["detail"]

        # Recent trigger (30 seconds ago)
        recent = (datetime.now(timezone.utc) - timedelta(seconds=30)).isoformat()
        m._write_json(m.TRIGGERS_FILE, [{
            "id": "trg-recent",
            "ts": recent,
            "status": "failed",
            "detail": "connection timeout"
        }])
        m._invalidate_health()
        h2 = c.get("/api/health/pipeline", headers=AUTH).json()
        comp2 = next(x for x in h2["components"] if x["name"] == "Agent Link (n8n)")
        assert comp2["level"] == "warn"
        assert "last trigger failed" in comp2["detail"]


def test_security_headers_and_body_limits(m):
    with TestClient(m.app) as c:
        # 1. Security headers check
        r = c.get("/api/proposals", headers=AUTH)
        assert "object-src 'none'" in r.headers["content-security-policy"]
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["x-frame-options"] == "DENY"
        assert r.headers["x-permitted-cross-domain-policies"] == "none"
        assert "geolocation=()" in r.headers["permissions-policy"]

        # 2. Oversized payload rejected with 413
        oversized = {"sigma_yaml": "x" * 200}
        r_large = c.post(
            "/api/rules/validate",
            json=oversized,
            headers={**AUTH, "content-length": str(3 * 1024 * 1024)}
        )
        assert r_large.status_code == 413
        assert "limit of 2MB" in r_large.json()["detail"]


def test_auth_brute_force_rate_limit(m):
    with TestClient(m.app) as c:
        m._failed_auth_attempts.clear()
        for _ in range(m.AUTH_BRUTE_FORCE_LIMIT):
            r = c.get("/api/proposals", headers={"Authorization": "Bearer wrong"})
            assert r.status_code == 401
        
        # Next attempt triggers 429
        r_blocked = c.get("/api/proposals", headers={"Authorization": "Bearer wrong"})
        assert r_blocked.status_code == 429
        assert "too many failed authentication attempts" in r_blocked.json()["error"]
        m._failed_auth_attempts.clear()



