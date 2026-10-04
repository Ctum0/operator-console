"""Detection Platform - Operator Console backend.

FastAPI service: registers AI-generated Sigma detection proposals (file-backed),
lets the human operator approve (merge GitHub PR) or reject them, and reports
pipeline health / ATT&CK coverage / activity.

All configuration via environment variables. No secrets in code.

Lifecycle: pending -> merging -> merged -> validated (purple-team evidence that
the deployed rule fired), with rejected and merge_failed (retryable) off-ramps.

Robustness contract (v1.1.0):
- /data writes are atomic (unique tmp file + os.replace) and fsync'd (file + dir).
- POST /api/proposals is pydantic-validated and rate-limited (1 registration per
  technique / 10 min, persisted in /data so restarts do not reset it; idempotent
  re-registration of the same PR stays allowed).
- Proposals left in "merging" by a crash are settled to merge_failed at startup.
- Coverage serves the last good parse (stale=true) when the source is unreachable.
- Proposal-cycle triggers are tracked in /data/triggers.json until n8n reports back.
- GitHub merges are gated: the PR must be OPEN and its head-commit CI checks must
  have passed before the merge PUT is issued.
- All outbound httpx calls share a 10s timeout; GitHub GETs retry once on
  network errors.
- Logs are single-line JSON: {"ts","level","event","detail"}.
- /api/health/pipeline is cached for 60s and reports uptime_seconds.
- CORS is same-origin only by default (no CORS headers are emitted unless
  CONSOLE_CORS_ORIGINS is explicitly configured; wildcards are never allowed).
"""

import asyncio
import csv
import hmac
import io
import json
import logging
import os
import platform
import re
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import fastapi
import httpx
import uvicorn
from fastapi import Body, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Configuration (env only)
# ---------------------------------------------------------------------------
APP_VERSION = "1.1.0"
CONSOLE_TOKEN = os.getenv("CONSOLE_TOKEN", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_API = os.getenv("GITHUB_API_URL", "https://api.github.com").rstrip("/")
REPO = os.getenv("REPO", "Ctum0/detection-platform")
WAZUH_HOST = os.getenv("WAZUH_HOST", "100.81.241.62")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "1514"))
# Optional Wazuh manager API probe (e.g. https://100.81.241.62:55000). When
# unset, the health panel reports the API component as "not configured".
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "").rstrip("/")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
WAZUH_API_VERIFY_TLS = os.getenv("WAZUH_API_VERIFY_TLS", "true").strip().lower() not in ("0", "false", "no")
N8N_PROPOSE_WEBHOOK = os.getenv("N8N_PROPOSE_WEBHOOK", "")
# Shared secret sent as X-Webhook-Secret so the n8n webhook can reject callers
# that are not this console. Optional; never logged.
N8N_WEBHOOK_SECRET = os.getenv("N8N_WEBHOOK_SECRET", "")
COVERAGE_PATH = os.getenv("COVERAGE_PATH", "modules/detection-pipeline/docs/attack-matrix.md").lstrip("/")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
PROPOSALS_FILE = DATA_DIR / "proposals.json"
ACTIVITY_FILE = DATA_DIR / "activity.json"
TRIGGERS_FILE = DATA_DIR / "triggers.json"
RATE_FILE = DATA_DIR / "ratelimit.json"
COVERAGE_CACHE_FILE = DATA_DIR / "coverage_cache.json"
# GIT_SHA is baked in at build time (Dockerfile ARG) or set at runtime; Coolify
# exposes the deployed commit as SOURCE_COMMIT to the running container.
GIT_SHA = os.getenv("GIT_SHA") or os.getenv("SOURCE_COMMIT") or "unknown"
# Comma-separated extra allowed origins for CORS. Empty (default) = same-origin
# only: no CORS headers are emitted at all, so browsers block every cross-origin
# call. A "*" entry is rejected at startup - never enable a wildcard.
CORS_ORIGINS = [o.strip() for o in os.getenv("CONSOLE_CORS_ORIGINS", "").split(",") if o.strip()]
OUTBOUND_TIMEOUT = httpx.Timeout(10.0)
HEALTH_CACHE_TTL = 60.0
COVERAGE_CACHE_TTL = 120.0
RATE_LIMIT_WINDOW = 600.0  # 1 registration per technique per 10 minutes
ACTIVITY_CAP = 2000
TRIGGERS_CAP = 200
NOTES_CAP = 200

STATUSES = ("pending", "approved", "rejected", "merging", "merged", "merge_failed", "validated")

if "*" in CORS_ORIGINS:
    raise RuntimeError("CONSOLE_CORS_ORIGINS must not contain '*' - same-origin only")
if not CONSOLE_TOKEN:
    logging.getLogger("console").warning(
        "CONSOLE_TOKEN is not set - API will reject every request until configured"
    )

_START_TIME = time.time()


# ---------------------------------------------------------------------------
# Structured single-line JSON logging
# ---------------------------------------------------------------------------
class JsonFormatter(logging.Formatter):
    """One JSON object per line: ts / level / event / detail."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
        }
        detail = getattr(record, "detail", None)
        if detail:
            payload["detail"] = detail
        if record.exc_info:
            try:
                payload["detail"] = f"{payload.get('detail', '')} {self.formatException(record.exc_info)}".strip()
            except Exception:  # never let logging blow up the app
                payload["detail"] = str(payload.get("detail", "")).strip()
        try:
            return json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError):
            return json.dumps({"ts": payload["ts"], "level": payload["level"],
                               "event": str(payload["event"]), "detail": "unserializable"})


def _setup_logging() -> logging.Handler:
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(os.getenv("LOG_LEVEL", "INFO"))
    # Route uvicorn's loggers through the same JSON handler so every line is
    # structured (uvicorn installs its own handlers at import of its loggers).
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        lg = logging.getLogger(name)
        lg.handlers[:] = [handler]
        lg.propagate = False
    return handler


_setup_logging()
log = logging.getLogger("console")


def jlog(level: str, event: str, detail: Any = None) -> None:
    """Emit one structured log line. detail may be a str or a JSON-able dict."""
    getattr(log, level)(event, extra={"detail": detail})


# ---------------------------------------------------------------------------
# Storage helpers (plain JSON files; atomic, fsync'd writes; asyncio file lock)
# ---------------------------------------------------------------------------
_file_lock = asyncio.Lock()

SAMPLE_PROPOSALS: list[dict[str, Any]] = [
    {
        "id": "prop-a1b2c3d4e5f6",
        "created_at": "2026-10-01T09:12:00Z",
        "status": "pending",
        "technique": "T1078.003",
        "title": "Local account login outside business hours",
        "sigma_yaml": (
            "title: Local account login outside business hours\n"
            "id: 0f21a4d9-8b1e-4c2a-9f3e-6d7a01b2c3d4\n"
            "status: experimental\n"
            "logsource:\n"
            "  product: windows\n"
            "  service: security\n"
            "detection:\n"
            "  selection:\n"
            "    EventID: 4624\n"
            "    LogonType: 10\n"
            "  filter:\n"
            "    Computer|startswith: WK-\n"
            "  condition: selection and not filter\n"
            "falsepositives:\n"
            "  - Legitimate after-hours administration\n"
            "level: medium\n"
            "tags:\n"
            "  - attack.lateral_movement\n"
            "  - attack.t1078.003\n"
        ),
        "reasoning": (
            "RDP-based interactive logons (LogonType 10) arriving outside the "
            "standard 08:00-18:00 window are a strong privilege-abuse signal for "
            "this environment; no known scheduled jobs use RDP."
        ),
        "pr_url": "https://github.com/Ctum0/detection-platform/pull/12",
        "pr_number": 12,
        "branch": "ai/proposal-t1078-003-offhours-rdp",
    }
]

SAMPLE_ACTIVITY: list[dict[str, Any]] = [
    {
        "ts": "2026-10-01T09:12:05Z",
        "actor": "agent",
        "action": "proposal.registered",
        "detail": "T1078.003 - Local account login outside business hours (PR #12)",
    }
]

SAMPLE_COVERAGE_MD = """\
# ATT&CK coverage matrix

| Technique | Name | Rule | Status |
| --- | --- | --- | --- |
| T1078.003 | Local Accounts | offhours-rdp-login.yaml | covered |
| T1059.001 | PowerShell | powershell-encoded-command.yaml | covered |
| T1548.002 | Bypass User Account Control | cmstp-uac-bypass.yaml | partial |
"""


def _ensure_files() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not PROPOSALS_FILE.exists():
        _write_json(PROPOSALS_FILE, SAMPLE_PROPOSALS)
        jlog("info", "created_sample_file", {"path": str(PROPOSALS_FILE)})
    if not ACTIVITY_FILE.exists():
        _write_json(ACTIVITY_FILE, SAMPLE_ACTIVITY)
        jlog("info", "created_sample_file", {"path": str(ACTIVITY_FILE)})


def _read_json(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default
    except json.JSONDecodeError:
        # Corrupt file: quarantine it (timestamped so concurrent quarantines
        # never clobber each other) and fall back rather than crash the API.
        jlog("error", "corrupt_json_file", {"path": str(path)})
        try:
            quarantine = path.with_suffix(f"{path.suffix}.corrupt.{int(time.time())}")
            path.rename(quarantine)
            jlog("info", "quarantined_corrupt_file", {"path": str(quarantine)})
        except OSError:
            pass
        return default


def _fsync_dir(directory: Path) -> None:
    """fsync a directory so the rename itself is durable. Best-effort."""
    try:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError:
        pass  # some filesystems (e.g. overlayfs) do not support dir fsync


def _write_json(path: Path, data: Any) -> None:
    """Atomic + durable write: unique tmp file in the same dir, fsync, os.replace,
    then fsync the directory. A crash can never leave a torn/partial file."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(json.dumps(data, indent=2, ensure_ascii=False))
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)  # atomic on POSIX and Windows
    except BaseException:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    _fsync_dir(path.parent)


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _read_list(path: Path) -> list[Any]:
    data = _read_json(path, [])
    return data if isinstance(data, list) else []


def _find_proposal(proposals: list[Any], pid: str) -> dict[str, Any] | None:
    return next((p for p in proposals if isinstance(p, dict) and p.get("id") == pid), None)


def _log_activity(actor: str, action: str, detail: str, proposal_id: str | None = None) -> None:
    """Append an entry to the activity log. MUST be called while holding
    _file_lock (read-modify-write would race otherwise)."""
    entries = _read_list(ACTIVITY_FILE)
    entry: dict[str, Any] = {"ts": _now_iso(), "actor": actor, "action": action, "detail": detail[:500]}
    if proposal_id:
        entry["proposal_id"] = proposal_id
    entries.append(entry)
    _write_json(ACTIVITY_FILE, entries[-ACTIVITY_CAP:])
    jlog("info", "activity", {"actor": actor, "action": action, "detail": detail[:500]})


def _recover_interrupted_merges() -> None:
    """A process that died mid-merge leaves proposals in "merging" with no task
    to settle them. At startup nothing can be in flight, so flip them to
    merge_failed: the retry endpoint re-runs the full PR + CI gate."""
    proposals = _read_list(PROPOSALS_FILE)
    stuck = [p for p in proposals if isinstance(p, dict) and p.get("status") == "merging"]
    if not stuck:
        return
    for p in stuck:
        p["status"] = "merge_failed"
        p["merge_error"] = "merge interrupted by a console restart; retry the merge"
    _write_json(PROPOSALS_FILE, proposals)
    for p in stuck:
        _log_activity("system", "proposal.merge_failed",
                      f"PR #{p.get('pr_number')}: merge interrupted by restart", p.get("id"))


# ---------------------------------------------------------------------------
# App + auth + CORS
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    _ensure_files()
    _recover_interrupted_merges()
    jlog("info", "startup", {"version": APP_VERSION, "data_dir": str(DATA_DIR)})
    yield
    # Wait (briefly) for in-flight background merges so a rolling restart does
    # not strand a proposal in status "merging".
    pending = [t for t in _bg_tasks if not t.done()]
    if pending:
        jlog("info", "shutdown_waiting_background_tasks", {"count": len(pending)})
        await asyncio.wait(pending, timeout=10.0)


app = FastAPI(
    title="Detection Platform Operator Console",
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)

# Static files are mounted early; the mount only owns /static/* and does not
# interfere with the API routes registered below.
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

if CORS_ORIGINS:
    from fastapi.middleware.cors import CORSMiddleware

    app.add_middleware(
        CORSMiddleware,
        allow_origins=CORS_ORIGINS,  # explicit list only; "*" refused at import
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
# else: no CORS middleware at all -> no Access-Control-* headers -> browsers
# enforce same-origin, which is exactly what the console needs (the UI is
# served from this same origin).


@app.middleware("http")
async def _auth(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        header = request.headers.get("authorization", "")
        supplied = header[len("Bearer "):] if header.lower().startswith("bearer ") else ""
        ok = False
        if supplied and CONSOLE_TOKEN:
            try:
                ok = hmac.compare_digest(supplied, CONSOLE_TOKEN)
            except TypeError:
                ok = False  # non-ASCII token can't match; never 500 on it
        if not ok:
            jlog("warning", "unauthorized_request", {"path": request.url.path})
            return JSONResponse({"error": "unauthorized"}, status_code=401)
    return await call_next(request)


@app.get("/")
async def index():
    # no-cache: the browser must revalidate on every load (cheap 304 via the
    # ETag), so a new deploy is picked up at once instead of a stale page.
    return FileResponse(str(Path(__file__).parent / "static" / "index.html"), media_type="text/html",
                        headers={"Cache-Control": "no-cache"})


@app.get("/healthz")
async def healthz():
    return {"ok": True}


@app.exception_handler(Exception)
async def _unhandled_exception(request: Request, exc: Exception):
    jlog("error", "unhandled_exception", {"path": request.url.path, "error": repr(exc)})
    return JSONResponse({"detail": "internal server error"}, status_code=500)


@app.exception_handler(RequestValidationError)
async def _validation_exception(request: Request, exc: RequestValidationError):
    jlog("warning", "request_validation_failed",
         {"path": request.url.path, "errors": str(exc.errors()[:5])})
    return JSONResponse({"detail": "invalid request payload"}, status_code=422)


# ---------------------------------------------------------------------------
# Shared httpx client + GitHub helpers
# ---------------------------------------------------------------------------
# Shared httpx client for all outbound calls (10s timeout, GitHub-flavoured headers)
_client = httpx.AsyncClient(
    timeout=OUTBOUND_TIMEOUT,
    headers={"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"},
)


def _gh_headers() -> dict[str, str]:
    # An empty token would yield "Bearer " (trailing space), which h11 rejects as
    # an illegal header value, so unauthenticated public reads must omit it.
    return {"Authorization": f"Bearer {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}


async def _gh_get(url: str, retries: int = 1, auth: bool = True) -> httpx.Response:
    """GET with exactly `retries` retries on network errors (not on HTTP error
    statuses). Raises httpx.HTTPError only after the final attempt."""
    last_exc: httpx.HTTPError | None = None
    for attempt in range(retries + 1):
        try:
            return await _client.get(url, headers=_gh_headers() if auth else {})
        except httpx.HTTPError as exc:
            last_exc = exc
            if attempt < retries:
                jlog("warning", "github_get_retry", {"url": url, "error": exc.__class__.__name__})
                await asyncio.sleep(1.0)
    assert last_exc is not None
    raise last_exc


# ---------------------------------------------------------------------------
# Background merge with CI gate
# ---------------------------------------------------------------------------
# In-flight guard so a double-clicked APPROVE cannot double-merge.
_pending_merges: set[str] = set()
# Strong references: asyncio only keeps weak refs to tasks, so an unreferenced
# create_task can be garbage-collected mid-run. Done-callbacks prune this set.
_bg_tasks: set[asyncio.Task] = set()

_CI_BAD_CONCLUSIONS = {"failure", "timed_out", "cancelled", "action_required", "startup_failure", "stale"}
_CI_OK_CONCLUSIONS = {"success", "neutral", "skipped"}


async def _ci_gate(pr_number: int) -> tuple[bool, str]:
    """Verify the PR is OPEN and its head-commit CI has passed.

    Returns (ok, detail). Never raises: network failures surface as ok=False
    with a clear reason so the operator can retry the approve later.
    """
    # 1. PR must exist and be open.
    try:
        resp = await _gh_get(f"{GITHUB_API}/repos/{REPO}/pulls/{pr_number}")
    except httpx.HTTPError as exc:
        return False, f"GitHub unreachable while checking PR state: {exc.__class__.__name__}"
    if resp.status_code == 404:
        return False, f"PR #{pr_number} not found in {REPO} (HTTP 404)"
    if not resp.is_success:
        return False, f"GitHub PR fetch failed (HTTP {resp.status_code})"
    prj = resp.json()
    state = prj.get("state")
    if prj.get("merged") or state == "closed":
        return False, f"PR #{pr_number} is {state} (merged={bool(prj.get('merged'))}), not open"
    if state != "open":
        return False, f"PR #{pr_number} is in unexpected state '{state}'"
    sha = (prj.get("head") or {}).get("sha")
    if not sha:
        return False, f"PR #{pr_number} head SHA unavailable"

    # 2. Check runs (GitHub Actions et al.) on the head commit.
    failures: list[str] = []
    pending: list[str] = []
    any_runs = False
    try:
        resp = await _gh_get(f"{GITHUB_API}/repos/{REPO}/commits/{sha}/check-runs")
        if resp.is_success:
            runs = resp.json().get("check_runs") or []
            any_runs = any_runs or bool(runs)
            for run in runs:
                name = str(run.get("name", "?"))[:64]
                if run.get("status") != "completed":
                    pending.append(name)
                elif run.get("conclusion") in _CI_BAD_CONCLUSIONS:
                    failures.append(f"{name}: {run.get('conclusion')}")
                elif run.get("conclusion") not in _CI_OK_CONCLUSIONS:
                    failures.append(f"{name}: unknown conclusion {run.get('conclusion')}")
        else:
            jlog("warning", "check_runs_fetch_failed", {"http": resp.status_code, "sha": sha})
    except httpx.HTTPError as exc:
        jlog("warning", "check_runs_fetch_error", {"error": exc.__class__.__name__, "sha": sha})

    # 3. Legacy commit statuses (repos still using the status API).
    try:
        resp = await _gh_get(f"{GITHUB_API}/repos/{REPO}/commits/{sha}/status")
        if resp.is_success:
            combined = resp.json().get("state")
            any_runs = any_runs or bool(resp.json().get("statuses"))
            if combined in ("failure", "error"):
                failures.append(f"combined-status: {combined}")
            elif combined == "pending":
                pending.append("combined-status: pending")
        else:
            jlog("warning", "combined_status_fetch_failed", {"http": resp.status_code, "sha": sha})
    except httpx.HTTPError as exc:
        jlog("warning", "combined_status_fetch_error", {"error": exc.__class__.__name__, "sha": sha})

    if failures:
        return False, f"CI failed on head {sha[:8]}: {'; '.join(failures[:3])}"
    if pending:
        return False, f"CI still running on head {sha[:8]}: {'; '.join(pending[:3])}"
    if not any_runs:
        # Repo has no CI configured for this commit - nothing to wait for.
        return True, "no CI checks configured for head commit"
    return True, f"all CI checks passed on head {sha[:8]}"


async def _merge_pr(pid: str, pr_number: int) -> None:
    """Gate (open + CI) then merge the proposal's PR; settle proposal status.
    Runs as a background task."""
    try:
        ok, gate_detail = await _ci_gate(pr_number)
        merged = False
        body = ""
        if not ok:
            # Do not merge. Surface as merge_failed with a clear, retryable
            # reason (approve accepts both "pending" and "merge_failed").
            body = f"merge blocked: {gate_detail}"
            jlog("warning", "merge_blocked", {"pid": pid, "pr": pr_number, "reason": gate_detail})
        else:
            try:
                resp = await _client.put(
                    f"{GITHUB_API}/repos/{REPO}/pulls/{pr_number}/merge",
                    headers=_gh_headers(),
                    json={"merge_method": "merge"},
                )
                merged = resp.is_success
                body = resp.text[:300]
                if not merged:
                    jlog("warning", "pr_merge_failed",
                         {"pr": pr_number, "http": resp.status_code, "body": body})
            except httpx.HTTPError:
                jlog("error", "pr_merge_network_failure", {"pr": pr_number})
                body = "network error"

        new_status = "merged" if merged else "merge_failed"
        async with _file_lock:
            proposals = _read_list(PROPOSALS_FILE)
            p = _find_proposal(proposals, pid)
            if p is not None:
                p["status"] = new_status
                if merged:
                    p.pop("merge_error", None)
                    p["merged_at"] = _now_iso()
                else:
                    p["merge_error"] = body
            _write_json(PROPOSALS_FILE, proposals)
            detail = f"PR #{pr_number} merged" if merged else f"PR #{pr_number}: {body}"
            _log_activity("operator", f"proposal.{new_status}", detail, pid)
    except Exception:
        # The task must never die with the proposal stuck in "merging".
        jlog("error", "merge_task_crashed", {"pid": pid, "pr": pr_number})
        try:
            async with _file_lock:
                proposals = _read_json(PROPOSALS_FILE, [])
                for p in proposals:
                    if isinstance(p, dict) and p.get("id") == pid and p.get("status") == "merging":
                        p["status"] = "merge_failed"
                        p["merge_error"] = "internal error during merge; retry approve"
                _write_json(PROPOSALS_FILE, proposals)
        except Exception:
            jlog("error", "merge_task_recovery_failed", {"pid": pid})
    finally:
        # try/finally: if the task is cancelled mid-merge the pid MUST be
        # released, otherwise the proposal is un-approvable until restart.
        _pending_merges.discard(pid)


# ---------------------------------------------------------------------------
# Proposals
# ---------------------------------------------------------------------------
REQUIRED_FIELDS = ("technique", "title", "sigma_yaml", "reasoning", "pr_url", "pr_number", "branch")

_FIELD_LIMITS = {
    "technique": 32,
    "title": 300,
    "sigma_yaml": 20000,
    "reasoning": 4000,
    "pr_url": 500,
    "branch": 200,
}
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class ProposalIn(BaseModel):
    """Registration payload from the AI agent (n8n). Field names/types match the
    published contract exactly; constraints only reject payloads that would
    previously have been stored and then crashed later endpoints. trigger_id is
    optional: when n8n echoes back the id it received from /api/trigger/propose,
    that trigger is marked succeeded and linked to this proposal."""

    technique: str = ""
    title: str = ""
    sigma_yaml: str = ""
    reasoning: str = ""
    pr_url: str = ""
    pr_number: int | None = None
    branch: str = ""
    trigger_id: str | None = None

    @field_validator("pr_number", mode="before")
    @classmethod
    def _coerce_pr_number(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip().isdigit():
            return int(v.strip())
        return v


class RejectIn(BaseModel):
    reason: str | None = None

    @field_validator("reason", mode="before")
    @classmethod
    def _coerce_reason(cls, v: Any) -> Any:
        return None if v is None else str(v)


class NoteIn(BaseModel):
    text: str = ""
    author: str = "operator"


class ValidatedIn(BaseModel):
    """Purple-team evidence that the deployed rule fired on a real attack."""

    rule_id: str = ""
    attack: str = ""
    fired_at: str = ""
    evidence_url: str | None = None
    actor: str = "operator"

    @field_validator("rule_id", mode="before")
    @classmethod
    def _coerce_rule_id(cls, v: Any) -> Any:
        return str(v) if isinstance(v, int) else v


def _validate_proposal(payload: ProposalIn) -> list[str]:
    """Return the list of missing/invalid fields ([] = valid). Message text for
    missing fields is byte-identical to the pre-pydantic 422 contract."""
    missing: list[str] = []
    if payload.pr_number is None:
        missing.append("pr_number")
    for f in ("technique", "title", "sigma_yaml", "reasoning", "pr_url", "branch"):
        if not getattr(payload, f):
            missing.append(f)
    problems = [f"missing fields: {', '.join(missing)}"] if missing else []
    if payload.pr_number is not None and payload.pr_number < 1:
        problems.append("pr_number must be a positive integer")
    if payload.technique and not _TECHNIQUE_RE.fullmatch(payload.technique):
        problems.append("technique must look like 'T1234' or 'T1234.001'")
    if payload.pr_url and not payload.pr_url.lower().startswith(("http://", "https://")):
        problems.append("pr_url must be an http(s) URL")
    for field, limit in _FIELD_LIMITS.items():
        if len(getattr(payload, field) or "") > limit:
            problems.append(f"{field} exceeds {limit} characters")
    return problems


def _parse_iso(value: str) -> datetime | None:
    """Parse an ISO 8601 timestamp; naive values are taken as UTC."""
    try:
        dt = datetime.fromisoformat(value.strip())
    except (ValueError, AttributeError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _rate_limit_check(technique: str, now: float) -> int:
    """Persisted rate limiter (survives restarts): returns 0 and records the
    registration when allowed, else the seconds until the next one is allowed.
    MUST be called while holding _file_lock."""
    data = _read_json(RATE_FILE, {})
    if not isinstance(data, dict):
        data = {}
    cutoff = now - RATE_LIMIT_WINDOW
    data = {k: v for k, v in data.items() if isinstance(v, (int, float)) and v > cutoff}
    last = data.get(technique)
    if last is not None:
        return int(RATE_LIMIT_WINDOW - (now - last)) + 1
    data[technique] = now
    _write_json(RATE_FILE, data)
    return 0


@app.get("/api/proposals")
async def list_proposals(
    status: str | None = Query(None, max_length=200),
    q: str | None = Query(None, max_length=200),
    limit: int | None = Query(None, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    """No query params = every proposal (the original contract). status takes a
    comma-separated list; q is a case-insensitive substring match across title,
    technique and reasoning. counts are per-status over all proposals."""
    proposals = [p for p in _read_list(PROPOSALS_FILE) if isinstance(p, dict)]
    proposals.sort(key=lambda p: str(p.get("created_at", "")), reverse=True)
    counts = {s: 0 for s in STATUSES}
    for p in proposals:
        s = str(p.get("status", ""))
        counts[s] = counts.get(s, 0) + 1
    if status:
        wanted = {s.strip() for s in status.split(",") if s.strip()}
        unknown = sorted(wanted - set(STATUSES))
        if unknown:
            raise HTTPException(422, f"unknown status {', '.join(unknown)}; allowed: {', '.join(STATUSES)}")
        proposals = [p for p in proposals if p.get("status") in wanted]
    needle = (q or "").strip().lower()
    if needle:
        proposals = [
            p for p in proposals
            if any(needle in str(p.get(f) or "").lower() for f in ("title", "technique", "reasoning"))
        ]
    total = len(proposals)
    page = proposals[offset:offset + limit] if limit else proposals[offset:]
    return {"proposals": page, "total": total, "counts": counts}


@app.get("/api/proposals/{pid}")
async def get_proposal(pid: str):
    prop = _find_proposal(_read_list(PROPOSALS_FILE), pid)
    if prop is None:
        raise HTTPException(404, "proposal not found")
    return prop


@app.post("/api/proposals", status_code=201)
async def create_proposal(payload: ProposalIn):
    problems = _validate_proposal(payload)
    if problems:
        raise HTTPException(422, "; ".join(problems))

    pid: str | None = None
    updated = False
    technique_norm = payload.technique.strip().upper()
    async with _file_lock:
        proposals = _read_list(PROPOSALS_FILE)
        # Idempotent re-registration keyed on PR number (agent retries / webhook
        # redelivery) - always allowed, even inside the rate-limit window.
        existing = next((p for p in proposals if isinstance(p, dict)
                         and p.get("pr_number") == payload.pr_number), None)
        if existing is not None:
            if existing.get("status") in ("merging", "merged", "validated"):
                # The PR is already being merged or has shipped: a redelivered
                # registration must not reset it back to pending.
                return {"id": existing["id"], "updated": False, "created": False,
                        "status": existing.get("status")}
            existing.update({k: getattr(payload, k) for k in REQUIRED_FIELDS})
            existing["status"] = "pending"
            existing.pop("merge_error", None)
            existing.pop("reject_reason", None)
            pid = existing["id"]
            updated = True
        else:
            # Rate limit: max 1 NEW registration per technique per 10 min.
            retry_after = _rate_limit_check(technique_norm, time.time())
            if retry_after:
                jlog("warning", "proposal_rate_limited",
                     {"technique": technique_norm, "retry_after_s": retry_after})
                raise HTTPException(
                    429,
                    f"rate limit: technique {technique_norm} was already registered in the "
                    f"last 10 minutes; retry in {retry_after}s",
                )
            pid = "prop-" + uuid.uuid4().hex[:12]
            proposals.append({
                **{k: getattr(payload, k) for k in REQUIRED_FIELDS},
                "id": pid,
                "created_at": _now_iso(),
                "status": "pending",
            })
        if payload.trigger_id:
            prop = _find_proposal(proposals, pid)
            if prop is not None:
                prop["trigger_id"] = payload.trigger_id[:64]
        _write_json(PROPOSALS_FILE, proposals)
        # Activity append happens INSIDE the lock: it is a read-modify-write of
        # activity.json and would lose entries if two registrations raced.
        _log_activity(
            "agent",
            "proposal.updated" if updated else "proposal.registered",
            f"{payload.technique} - {payload.title} (PR #{payload.pr_number})"
            + (" re-registered" if updated else ""),
            pid,
        )
        if payload.trigger_id:
            _settle_trigger(payload.trigger_id, "succeeded", f"proposal {pid} registered", pid)
    return {"id": pid, "updated": updated, "created": not updated}


async def _start_merge(pid: str, allowed: tuple[str, ...], action: str) -> dict[str, Any]:
    """Shared by approve and retry: guard the state, flip to merging and hand
    the PR to the background merge task (which runs the PR-open + CI gate)."""
    async with _file_lock:
        proposals = _read_list(PROPOSALS_FILE)
        prop = _find_proposal(proposals, pid)
        if not prop:
            raise HTTPException(404, "proposal not found")
        if pid in _pending_merges:
            raise HTTPException(409, "merge already in progress")
        if prop.get("status") not in allowed:
            raise HTTPException(409, f"proposal is {prop.get('status')}; expected {' or '.join(allowed)}")
        if not GITHUB_TOKEN:
            prop["status"] = "merge_failed"
            prop["merge_error"] = "GITHUB_TOKEN not configured on server"
            _write_json(PROPOSALS_FILE, proposals)
            _log_activity("system", "proposal.merge_failed", "GITHUB_TOKEN not configured", pid)
            raise HTTPException(503, "GITHUB_TOKEN not configured on server")
        try:
            pr_number = int(prop["pr_number"])
        except (KeyError, TypeError, ValueError):
            raise HTTPException(422, f"proposal has invalid pr_number: {prop.get('pr_number')!r}")
        # Reserve in-flight slot and flip status INSIDE the lock so two
        # concurrent approves cannot both pass the guards.
        _pending_merges.add(pid)
        prop["status"] = "merging"
        prop.pop("merge_error", None)
        _write_json(PROPOSALS_FILE, proposals)
        _log_activity("operator", action, f"{prop.get('technique')} - merging PR #{pr_number}", pid)
    task = asyncio.create_task(_merge_pr(pid, pr_number))
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return {"id": pid, "status": "merging", "accepted": True}


@app.post("/api/proposals/{pid}/approve", status_code=202)
async def approve_proposal(pid: str):
    return await _start_merge(pid, ("pending", "merge_failed"), "proposal.approved")


@app.post("/api/proposals/{pid}/retry", status_code=202)
async def retry_merge(pid: str):
    """Explicit retry for merge_failed. Re-runs the same PR-open + CI gate."""
    return await _start_merge(pid, ("merge_failed",), "proposal.retried")


@app.post("/api/proposals/{pid}/reject")
async def reject_proposal(pid: str, payload: RejectIn | None = Body(default=None)):
    reason = (payload.reason if payload and payload.reason else "") or ""
    reason = reason.strip()[:1000]
    async with _file_lock:
        proposals = _read_list(PROPOSALS_FILE)
        prop = _find_proposal(proposals, pid)
        if not prop:
            raise HTTPException(404, "proposal not found")
        if prop.get("status") not in ("pending", "merge_failed"):
            raise HTTPException(409, f"proposal already {prop.get('status')}")
        prop["status"] = "rejected"
        prop["reject_reason"] = reason or None
        _write_json(PROPOSALS_FILE, proposals)
        _log_activity("operator", "proposal.rejected",
                      f"{prop.get('technique')} (PR #{prop.get('pr_number')}) - reason: {reason or 'none given'}",
                      pid)
    return {"id": pid, "status": "rejected", "reason": reason or None}


@app.post("/api/proposals/{pid}/notes", status_code=201)
async def add_note(pid: str, payload: NoteIn):
    """Append-only operator annotations ("blocked on ART", "FP risk, checking")."""
    text = payload.text.strip()
    if not text:
        raise HTTPException(422, "text is required")
    if len(text) > 2000:
        raise HTTPException(422, "text exceeds 2000 characters")
    author = (payload.author or "").strip()[:64] or "operator"
    async with _file_lock:
        proposals = _read_list(PROPOSALS_FILE)
        prop = _find_proposal(proposals, pid)
        if not prop:
            raise HTTPException(404, "proposal not found")
        notes = prop.get("notes")
        if not isinstance(notes, list):
            notes = []
        if len(notes) >= NOTES_CAP:
            raise HTTPException(409, f"note limit reached ({NOTES_CAP})")
        note = {"id": "note-" + uuid.uuid4().hex[:10], "ts": _now_iso(), "author": author, "text": text}
        notes.append(note)
        prop["notes"] = notes
        _write_json(PROPOSALS_FILE, proposals)
        _log_activity(author, "proposal.note", f"{prop.get('technique')}: {text[:160]}", pid)
    return note


@app.post("/api/proposals/{pid}/validated")
async def mark_validated(pid: str, payload: ValidatedIn):
    """Close the purple-team loop: record that the merged, deployed rule fired
    on a real attack. Only a merged proposal can be validated."""
    rule_id = payload.rule_id.strip()
    attack = payload.attack.strip()
    evidence_url = (payload.evidence_url or "").strip()
    actor = (payload.actor or "").strip()[:64] or "operator"
    missing = [f for f, v in (("rule_id", rule_id), ("attack", attack), ("fired_at", payload.fired_at.strip())) if not v]
    if missing:
        raise HTTPException(422, f"missing fields: {', '.join(missing)}")
    problems: list[str] = []
    if len(rule_id) > 64:
        problems.append("rule_id exceeds 64 characters")
    if len(attack) > 300:
        problems.append("attack exceeds 300 characters")
    fired = _parse_iso(payload.fired_at)
    if fired is None:
        problems.append("fired_at must be an ISO 8601 timestamp")
    elif fired.timestamp() > time.time() + 300:
        problems.append("fired_at is in the future")
    if evidence_url and (len(evidence_url) > 500 or not evidence_url.lower().startswith(("http://", "https://"))):
        problems.append("evidence_url must be an http(s) URL up to 500 characters")
    if problems:
        raise HTTPException(422, "; ".join(problems))
    assert fired is not None
    async with _file_lock:
        proposals = _read_list(PROPOSALS_FILE)
        prop = _find_proposal(proposals, pid)
        if not prop:
            raise HTTPException(404, "proposal not found")
        if prop.get("status") != "merged":
            raise HTTPException(409, f"proposal is {prop.get('status')}; only merged proposals can be validated")
        merged_at = _parse_iso(str(prop.get("merged_at") or ""))
        # 5 min tolerance for clock skew between the SIEM and this host.
        if merged_at is not None and fired.timestamp() < merged_at.timestamp() - 300:
            raise HTTPException(422, f"fired_at {_iso(fired)} is before the PR was merged ({_iso(merged_at)})")
        validation = {
            "rule_id": rule_id,
            "attack": attack,
            "fired_at": _iso(fired),
            "evidence_url": evidence_url or None,
            "recorded_at": _now_iso(),
            "recorded_by": actor,
        }
        prop["validation"] = validation
        prop["status"] = "validated"
        _write_json(PROPOSALS_FILE, proposals)
        _log_activity(actor, "proposal.validated",
                      f"{prop.get('technique')}: rule {rule_id} fired on {attack} at {_iso(fired)}", pid)
    return {"id": pid, "status": "validated", "validation": validation}


# ---------------------------------------------------------------------------
# Pipeline health (60s cache to avoid hammering GitHub)
# ---------------------------------------------------------------------------
async def _check_tcp(host: str, port: int, timeout: float = 5.0) -> bool:
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        writer.close()
        await writer.wait_closed()
        return True
    except (OSError, asyncio.TimeoutError):
        return False


_health_cache: dict[str, Any] = {"ts": 0.0, "payload": None}
_health_lock = asyncio.Lock()


_CI_RUNNING = {"queued", "in_progress", "pending", "waiting", "requested"}
# Daemons whose absence means alerts are not being produced at all.
_WAZUH_CRITICAL_DAEMONS = ("wazuh-analysisd", "wazuh-remoted", "wazuh-db")

# Wazuh managers usually serve a self-signed cert, hence a dedicated client
# whose TLS verification is controlled by WAZUH_API_VERIFY_TLS.
_wazuh_client = httpx.AsyncClient(timeout=OUTBOUND_TIMEOUT, verify=WAZUH_API_VERIFY_TLS)


def _ci_level(status: str) -> str:
    if status in _CI_OK_CONCLUSIONS:
        return "ok"
    if status in _CI_RUNNING:
        return "warn"
    if status in _CI_BAD_CONCLUSIONS:
        return "bad"
    return "unknown"


def _age(ts: str | None) -> str:
    dt = _parse_iso(ts or "")
    if dt is None:
        return "?"
    secs = max(0, int(time.time() - dt.timestamp()))
    if secs < 90:
        return f"{secs}s ago"
    if secs < 5400:
        return f"{secs // 60}m ago"
    if secs < 172800:
        return f"{secs // 3600}h ago"
    return f"{secs // 86400}d ago"


async def _probe_ci() -> dict[str, Any]:
    status, level, detail = "unknown", "unknown", "no data"
    try:
        resp = await _gh_get(f"{GITHUB_API}/repos/{REPO}/actions/runs?per_page=3")
        if resp.is_success:
            runs = resp.json().get("workflow_runs", [])
            if runs:
                run = runs[0]
                status = run.get("status", "unknown")
                if status == "completed":
                    status = run.get("conclusion") or "completed"
                level = _ci_level(status)
                detail = (f"{str(run.get('display_title', ''))[:48]} ({run.get('head_branch', '?')}) "
                          f"· {_age(run.get('updated_at'))}")
            else:
                detail = "no workflow runs yet"
        else:
            detail = f"GitHub API HTTP {resp.status_code}"
    except httpx.HTTPError as exc:
        detail = f"GitHub API unreachable: {exc.__class__.__name__}"
    return {"name": "CI (GitHub Actions)", "status": status, "level": level, "detail": detail}


async def _probe_runners() -> dict[str, Any]:
    """Self-hosted runner liveness: Actions history can show old successes
    while the CD runner is dead, so check the runners themselves."""
    name = "CD runner (self-hosted)"
    if not GITHUB_TOKEN:
        return {"name": name, "status": "unknown", "level": "unknown", "detail": "GITHUB_TOKEN not set"}
    try:
        resp = await _gh_get(f"{GITHUB_API}/repos/{REPO}/actions/runners?per_page=100")
    except httpx.HTTPError as exc:
        return {"name": name, "status": "unknown", "level": "unknown",
                "detail": f"GitHub API unreachable: {exc.__class__.__name__}"}
    if resp.status_code in (403, 404):
        return {"name": name, "status": "unknown", "level": "unknown",
                "detail": f"HTTP {resp.status_code}: token needs Administration: Read to list runners"}
    if not resp.is_success:
        return {"name": name, "status": "unknown", "level": "unknown", "detail": f"GitHub API HTTP {resp.status_code}"}
    runners = resp.json().get("runners") or []
    if not runners:
        return {"name": name, "status": "none", "level": "warn", "detail": "no self-hosted runners registered"}
    online = [r for r in runners if r.get("status") == "online"]
    offline = [str(r.get("name", "?"))[:32] for r in runners if r.get("status") != "online"]
    busy = sum(1 for r in online if r.get("busy"))
    detail = f"{len(online)}/{len(runners)} online" + (f", {busy} busy" if busy else "")
    if offline:
        detail += f" · offline: {', '.join(offline[:3])}"
    if not online:
        return {"name": name, "status": "offline", "level": "bad", "detail": detail}
    return {"name": name, "status": "online" if not offline else "degraded",
            "level": "ok" if not offline else "warn", "detail": detail}


async def _probe_wazuh_api() -> dict[str, Any]:
    """Authenticate to the Wazuh manager API and check version, core daemons
    and the loaded ruleset. Credentials are env-only and never logged."""
    name = "Wazuh API"
    if not (WAZUH_API_URL and WAZUH_API_USER and WAZUH_API_PASSWORD):
        return {"name": name, "status": "unknown", "level": "unknown",
                "detail": "not configured (WAZUH_API_URL / _USER / _PASSWORD)"}
    try:
        auth = await _wazuh_client.post(f"{WAZUH_API_URL}/security/user/authenticate",
                                        auth=(WAZUH_API_USER, WAZUH_API_PASSWORD))
        if auth.status_code == 401:
            return {"name": name, "status": "down", "level": "bad", "detail": "authentication failed (HTTP 401)"}
        if not auth.is_success:
            return {"name": name, "status": "down", "level": "bad", "detail": f"auth HTTP {auth.status_code}"}
        token = ((auth.json() or {}).get("data") or {}).get("token")
        if not token:
            return {"name": name, "status": "down", "level": "bad", "detail": "auth returned no token"}
        headers = {"Authorization": f"Bearer {token}"}
        info, status_resp, rules = await asyncio.gather(
            _wazuh_client.get(f"{WAZUH_API_URL}/", headers=headers),
            _wazuh_client.get(f"{WAZUH_API_URL}/manager/status", headers=headers),
            _wazuh_client.get(f"{WAZUH_API_URL}/rules?limit=1", headers=headers),
        )
    except httpx.HTTPError as exc:
        return {"name": name, "status": "down", "level": "bad", "detail": f"unreachable: {exc.__class__.__name__}"}
    except ValueError:
        return {"name": name, "status": "down", "level": "bad", "detail": "invalid JSON from API"}

    parts: list[str] = []
    try:
        version = (info.json().get("data") or {}).get("api_version") if info.is_success else None
        if version:
            parts.append(f"v{version}")
        daemons = {}
        if status_resp.is_success:
            items = (status_resp.json().get("data") or {}).get("affected_items") or [{}]
            daemons = items[0] if isinstance(items[0], dict) else {}
        rule_total = (rules.json().get("data") or {}).get("total_affected_items") if rules.is_success else None
    except ValueError:
        return {"name": name, "status": "down", "level": "bad", "detail": "invalid JSON from API"}
    if rule_total is not None:
        parts.append(f"{rule_total} rules loaded")
    if not daemons:
        return {"name": name, "status": "degraded", "level": "warn",
                "detail": " · ".join(parts + [f"manager status HTTP {status_resp.status_code}"])}
    stopped = [d for d in _WAZUH_CRITICAL_DAEMONS if daemons.get(d) != "running"]
    if stopped:
        return {"name": name, "status": "degraded", "level": "bad",
                "detail": " · ".join(parts + [f"stopped: {', '.join(stopped)}"])}
    if rule_total == 0:
        return {"name": name, "status": "degraded", "level": "bad", "detail": " · ".join(parts + ["empty ruleset"])}
    return {"name": name, "status": "up", "level": "ok", "detail": " · ".join(parts + ["core daemons running"])}


async def _build_pipeline_health() -> dict[str, Any]:
    ci, runners, wazuh_api, wazuh_ok = await asyncio.gather(
        _probe_ci(), _probe_runners(), _probe_wazuh_api(), _check_tcp(WAZUH_HOST, WAZUH_PORT)
    )
    wazuh_detail = f"tcp {WAZUH_HOST}:{WAZUH_PORT} " + ("reachable" if wazuh_ok else "unreachable")

    # Agent link: webhook configured, plus how the most recent trigger went.
    agent_ok = bool(N8N_PROPOSE_WEBHOOK)
    agent_level = "ok" if agent_ok else "bad"
    agent_detail = "propose webhook configured" if agent_ok else "N8N_PROPOSE_WEBHOOK not set"
    triggers = [t for t in _read_list(TRIGGERS_FILE) if isinstance(t, dict)]
    if agent_ok and triggers:
        last = triggers[-1]
        agent_detail = f"last trigger {last.get('status')} · {_age(last.get('ts'))}"
        if last.get("status") == "failed":
            agent_level = "warn"

    return {
        "checked_at": _now_iso(),
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "components": [
            ci,
            runners,
            {"name": "Wazuh Manager", "status": "up" if wazuh_ok else "down",
             "level": "ok" if wazuh_ok else "bad", "detail": wazuh_detail},
            wazuh_api,
            {"name": "Agent Link (n8n)", "status": "up" if agent_ok else "down",
             "level": agent_level, "detail": agent_detail},
        ],
    }


def _invalidate_health() -> None:
    _health_cache["ts"] = 0.0


@app.get("/api/health/pipeline")
async def pipeline_health():
    now = time.time()
    cached = _health_cache["payload"]
    if cached is not None and now - _health_cache["ts"] < HEALTH_CACHE_TTL:
        return cached
    async with _health_lock:
        # Double-check: another request may have refreshed while we waited.
        cached = _health_cache["payload"]
        if cached is not None and time.time() - _health_cache["ts"] < HEALTH_CACHE_TTL:
            return cached
        payload = await _build_pipeline_health()
        _health_cache["ts"] = time.time()
        _health_cache["payload"] = payload
        return payload


# ---------------------------------------------------------------------------
# Coverage - parse the markdown matrix from the repo (robust pipe-table regex)
# ---------------------------------------------------------------------------
_COVERAGE_URL = f"https://raw.githubusercontent.com/{REPO}/main/{COVERAGE_PATH}"
_SEP_CELL = re.compile(r":?-{2,}:?\s*")
_coverage_cache: dict[str, Any] = {"ts": 0.0, "payload": None}
_coverage_lock = asyncio.Lock()


def _parse_md_table(text: str) -> tuple[list[str], list[list[str]]]:
    headers: list[str] | None = None
    rows: list[list[str]] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not (line.startswith("|") and line.endswith("|") and len(line) > 2):
            continue
        cells = [c.strip() for c in line[1:-1].split("|")]
        if len(cells) < 3:
            continue
        if all(_SEP_CELL.fullmatch(c) for c in cells):  # |---|---| separator row
            continue
        if headers is None:
            headers = cells
            continue
        if cells[0].lower() == headers[0].lower():
            continue  # stray repeated header row in body
        rows.append(cells)
    return headers or [], rows


async def _fetch_coverage() -> dict[str, Any]:
    """Fresh parse on success (persisted as the last good copy). On any failure
    serve the last good parse with stale=true, or the sample if none exists."""
    error = ""
    try:
        # Public file: fetch without the PAT so an expired or revoked token cannot
        # break coverage. A private repo answers 404, so retry with the token.
        resp = await _gh_get(_COVERAGE_URL, auth=False)
        if resp.status_code == 404 and GITHUB_TOKEN:
            resp = await _gh_get(_COVERAGE_URL)
        if resp.is_success:
            cols, rows = _parse_md_table(resp.text)
            if cols and rows:
                fresh = {"source": _COVERAGE_URL, "columns": cols, "rows": rows, "fetched_at": _now_iso()}
                try:
                    _write_json(COVERAGE_CACHE_FILE, fresh)
                except OSError as exc:
                    jlog("warning", "coverage_cache_write_failed", {"error": exc.__class__.__name__})
                return {**fresh, "stale": False}
            error = "no markdown table found in source"
        else:
            error = f"HTTP {resp.status_code}"
    except httpx.HTTPError as exc:
        error = exc.__class__.__name__
    jlog("warning", "coverage_fetch_failed", {"error": error})
    cached = _read_json(COVERAGE_CACHE_FILE, None)
    if isinstance(cached, dict) and cached.get("rows"):
        return {**cached, "stale": True, "error": error}
    cols, rows = _parse_md_table(SAMPLE_COVERAGE_MD)
    return {"source": _COVERAGE_URL, "columns": cols, "rows": rows, "fetched_at": None,
            "stale": True, "sample": True, "error": error}


@app.get("/api/coverage")
async def coverage():
    cached = _coverage_cache["payload"]
    if cached is not None and time.time() - _coverage_cache["ts"] < COVERAGE_CACHE_TTL:
        return cached
    async with _coverage_lock:
        cached = _coverage_cache["payload"]
        if cached is not None and time.time() - _coverage_cache["ts"] < COVERAGE_CACHE_TTL:
            return cached
        payload = await _fetch_coverage()
        _coverage_cache["ts"] = time.time()
        _coverage_cache["payload"] = payload
        return payload


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------
def _filtered_activity(actor: str | None, action: str | None, proposal_id: str | None) -> list[dict[str, Any]]:
    """Newest first. action matches as a prefix ("proposal." or "proposal.merged")."""
    entries = [e for e in _read_list(ACTIVITY_FILE) if isinstance(e, dict)]
    if actor:
        entries = [e for e in entries if e.get("actor") == actor]
    if action:
        entries = [e for e in entries if str(e.get("action", "")).startswith(action)]
    if proposal_id:
        entries = [e for e in entries if e.get("proposal_id") == proposal_id]
    entries.sort(key=lambda e: str(e.get("ts", "")), reverse=True)
    return entries


@app.get("/api/activity")
async def activity(
    limit: int | None = Query(None, ge=1, le=ACTIVITY_CAP),
    offset: int = Query(0, ge=0),
    actor: str | None = Query(None, max_length=64),
    action: str | None = Query(None, max_length=64),
    proposal_id: str | None = Query(None, max_length=64),
):
    entries = _filtered_activity(actor, action, proposal_id)
    page = entries[offset:offset + limit] if limit else entries[offset:]
    return {"activity": page, "total": len(entries)}


_CSV_FIELDS = ("ts", "actor", "action", "detail", "proposal_id")


def _csv_cell(value: Any) -> str:
    s = "" if value is None else str(value)
    # Neutralise spreadsheet formula injection from agent-supplied text.
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


@app.get("/api/activity/export")
async def export_activity(format: str = Query("json", pattern="^(json|csv)$")):
    """Full audit trail, oldest first, as a download."""
    entries = list(reversed(_filtered_activity(None, None, None)))
    stamp = time.strftime("%Y-%m-%d", time.gmtime())
    if format == "csv":
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(_CSV_FIELDS)
        for e in entries:
            writer.writerow([_csv_cell(e.get(f)) for f in _CSV_FIELDS])
        body, media = buf.getvalue(), "text/csv; charset=utf-8"
    else:
        body = json.dumps({"exported_at": _now_iso(), "repo": REPO, "activity": entries},
                          indent=2, ensure_ascii=False)
        media = "application/json"
    return Response(
        content=body,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="operator-console-activity-{stamp}.{format}"'},
    )


# ---------------------------------------------------------------------------
# Trigger proposal cycle via the n8n webhook, with job tracking
# ---------------------------------------------------------------------------
_TRIGGER_FINAL = ("succeeded", "failed")


class TriggerResultIn(BaseModel):
    status: str = ""
    detail: str = ""
    proposal_id: str | None = None


def _settle_trigger(tid: str, status: str, detail: str, proposal_id: str | None = None) -> dict[str, Any] | None:
    """Move a "sent" trigger to a final state. Returns it, or None when it does
    not exist or is already final. MUST be called while holding _file_lock."""
    triggers = _read_list(TRIGGERS_FILE)
    trig = next((t for t in triggers if isinstance(t, dict) and t.get("id") == tid), None)
    if trig is None or trig.get("status") != "sent":
        return None
    trig["status"] = status
    trig["detail"] = detail[:300]
    trig["completed_at"] = _now_iso()
    if proposal_id:
        trig["proposal_id"] = proposal_id[:64]
    _write_json(TRIGGERS_FILE, triggers)
    _invalidate_health()
    return trig


@app.post("/api/trigger/propose", status_code=202)
async def trigger_propose():
    if not N8N_PROPOSE_WEBHOOK:
        raise HTTPException(503, "N8N_PROPOSE_WEBHOOK is not configured")
    tid = "trg-" + uuid.uuid4().hex[:10]
    response_snippet = ""
    http_status: int | None = None
    try:
        # trigger_id lets the workflow report back: either echo it in the
        # proposal registration or POST /api/triggers/{id}/result.
        resp = await _client.post(
            N8N_PROPOSE_WEBHOOK,
            json={"source": "operator-console", "trigger_id": tid,
                  "result_path": f"/api/triggers/{tid}/result"},
            headers={"Content-Type": "application/json",
                     **({"X-Webhook-Secret": N8N_WEBHOOK_SECRET} if N8N_WEBHOOK_SECRET else {})},
        )
        ok = resp.is_success
        http_status = resp.status_code
        detail = f"n8n webhook HTTP {resp.status_code}"
        response_snippet = resp.text[:300]
        if not ok:
            jlog("warning", "trigger_webhook_bad_response", {"http": resp.status_code})
    except httpx.HTTPError as exc:
        ok = False
        detail = f"n8n webhook failed: {exc.__class__.__name__}"
        jlog("warning", "trigger_webhook_failed", {"error": exc.__class__.__name__})
    record: dict[str, Any] = {
        "id": tid,
        "ts": _now_iso(),
        "status": "sent" if ok else "failed",
        "detail": detail,
        "http_status": http_status,
        "response": response_snippet or None,
        "completed_at": None if ok else _now_iso(),
        "proposal_id": None,
    }
    async with _file_lock:
        triggers = _read_list(TRIGGERS_FILE)
        triggers.append(record)
        _write_json(TRIGGERS_FILE, triggers[-TRIGGERS_CAP:])
        _log_activity("operator", "propose.triggered", f"{tid}: {detail}")
    _invalidate_health()
    return {"triggered": ok, "detail": detail, "trigger_id": tid, "status": record["status"]}


@app.get("/api/triggers")
async def list_triggers(limit: int = Query(50, ge=1, le=TRIGGERS_CAP)):
    triggers = [t for t in _read_list(TRIGGERS_FILE) if isinstance(t, dict)]
    triggers.sort(key=lambda t: str(t.get("ts", "")), reverse=True)
    return {"triggers": triggers[:limit], "total": len(triggers)}


@app.post("/api/triggers/{tid}/result")
async def trigger_result(tid: str, payload: TriggerResultIn):
    """Callback for the n8n workflow to report how the triggered run ended."""
    if payload.status not in _TRIGGER_FINAL:
        raise HTTPException(422, f"status must be one of: {', '.join(_TRIGGER_FINAL)}")
    detail = payload.detail.strip() or f"workflow {payload.status}"
    async with _file_lock:
        triggers = _read_list(TRIGGERS_FILE)
        trig = next((t for t in triggers if isinstance(t, dict) and t.get("id") == tid), None)
        if trig is None:
            raise HTTPException(404, "trigger not found")
        if trig.get("status") != "sent":
            raise HTTPException(409, f"trigger already {trig.get('status')}")
        settled = _settle_trigger(tid, payload.status, detail, payload.proposal_id)
        _log_activity("agent", f"trigger.{payload.status}", f"{tid}: {detail[:200]}", payload.proposal_id)
    return settled


# ---------------------------------------------------------------------------
# Version / build info
# ---------------------------------------------------------------------------
@app.get("/api/version")
async def version():
    return {
        "version": APP_VERSION,
        "build_info": {
            "git_sha": GIT_SHA,
            "python": platform.python_version(),
            "fastapi": fastapi.__version__,
            "uvicorn": uvicorn.__version__,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(_START_TIME)),
            "repo": REPO,
        },
    }
