"""Detection Platform - Operator Console backend.

FastAPI service: registers AI-generated Sigma detection proposals (file-backed),
lets the human operator approve (merge GitHub PR) or reject them, and reports
pipeline health / ATT&CK coverage / activity.

All configuration via environment variables. No secrets in code.

Robustness contract (v1.0.0):
- /data writes are atomic (unique tmp file + os.replace) and fsync'd (file + dir).
- POST /api/proposals is pydantic-validated and rate-limited (1 registration per
  technique / 10 min; idempotent re-registration of the same PR stays allowed).
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
import hmac
import json
import logging
import os
import platform
import re
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import fastapi
import httpx
import uvicorn
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# Configuration (env only)
# ---------------------------------------------------------------------------
APP_VERSION = "1.0.0"
CONSOLE_TOKEN = os.getenv("CONSOLE_TOKEN", "")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
REPO = os.getenv("REPO", "Ctum0/detection-platform")
WAZUH_HOST = os.getenv("WAZUH_HOST", "100.81.241.62")
WAZUH_PORT = int(os.getenv("WAZUH_PORT", "1514"))
N8N_PROPOSE_WEBHOOK = os.getenv("N8N_PROPOSE_WEBHOOK", "")
DATA_DIR = Path(os.getenv("DATA_DIR", "/data"))
PROPOSALS_FILE = DATA_DIR / "proposals.json"
ACTIVITY_FILE = DATA_DIR / "activity.json"
GIT_SHA = os.getenv("GIT_SHA", "unknown")
# Comma-separated extra allowed origins for CORS. Empty (default) = same-origin
# only: no CORS headers are emitted at all, so browsers block every cross-origin
# call. A "*" entry is rejected at startup - never enable a wildcard.
CORS_ORIGINS = [o.strip() for o in os.getenv("CONSOLE_CORS_ORIGINS", "").split(",") if o.strip()]
OUTBOUND_TIMEOUT = httpx.Timeout(10.0)
HEALTH_CACHE_TTL = 60.0
RATE_LIMIT_WINDOW = 600.0  # 1 registration per technique per 10 minutes

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


def _log_activity(actor: str, action: str, detail: str) -> None:
    """Append an entry to the activity log. MUST be called while holding
    _file_lock (read-modify-write would race otherwise)."""
    entries = _read_json(ACTIVITY_FILE, [])
    if not isinstance(entries, list):
        entries = []
    entries.append(
        {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "actor": actor,
            "action": action,
            "detail": detail[:500],
        }
    )
    _write_json(ACTIVITY_FILE, entries[-500:])
    jlog("info", "activity", {"actor": actor, "action": action, "detail": detail[:500]})


# ---------------------------------------------------------------------------
# App + auth + CORS
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    _ensure_files()
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
    return FileResponse(str(Path(__file__).parent / "static" / "index.html"), media_type="text/html")


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


async def _gh_get(url: str, retries: int = 1) -> httpx.Response:
    """GET with exactly `retries` retries on network errors (not on HTTP error
    statuses). Raises httpx.HTTPError only after the final attempt."""
    last_exc: httpx.HTTPError | None = None
    for attempt in range(retries + 1):
        try:
            return await _client.get(url, headers=_gh_headers())
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
        resp = await _gh_get(f"https://api.github.com/repos/{REPO}/pulls/{pr_number}")
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
        resp = await _gh_get(f"https://api.github.com/repos/{REPO}/commits/{sha}/check-runs")
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
        resp = await _gh_get(f"https://api.github.com/repos/{REPO}/commits/{sha}/status")
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
                    f"https://api.github.com/repos/{REPO}/pulls/{pr_number}/merge",
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
            proposals = _read_json(PROPOSALS_FILE, [])
            if not isinstance(proposals, list):
                proposals = []
            for p in proposals:
                if isinstance(p, dict) and p.get("id") == pid:
                    p["status"] = new_status
                    if merged:
                        p.pop("merge_error", None)
                    else:
                        p["merge_error"] = body
                    break
            _write_json(PROPOSALS_FILE, proposals)
            _log_activity("operator", f"proposal.{new_status}", f"PR #{pr_number}: {body}")
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
    previously have been stored and then crashed later endpoints."""

    technique: str = ""
    title: str = ""
    sigma_yaml: str = ""
    reasoning: str = ""
    pr_url: str = ""
    pr_number: int | None = None
    branch: str = ""

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


# Rate limiter: technique (normalized) -> last registration epoch second.
_proposal_rate: dict[str, float] = {}


@app.get("/api/proposals")
async def list_proposals():
    proposals = _read_json(PROPOSALS_FILE, [])
    if not isinstance(proposals, list):
        proposals = []
    proposals.sort(key=lambda p: str(p.get("created_at", "")) if isinstance(p, dict) else "", reverse=True)
    return {"proposals": proposals}


@app.post("/api/proposals", status_code=201)
async def create_proposal(payload: ProposalIn):
    problems = _validate_proposal(payload)
    if problems:
        raise HTTPException(422, "; ".join(problems))

    pid: str | None = None
    updated = False
    technique_norm = payload.technique.strip().upper()
    now = time.time()
    async with _file_lock:
        proposals = _read_json(PROPOSALS_FILE, [])
        if not isinstance(proposals, list):
            proposals = []
        # Idempotent re-registration keyed on PR number (agent retries / webhook
        # redelivery) - always allowed, even inside the rate-limit window.
        for existing in proposals:
            if isinstance(existing, dict) and existing.get("pr_number") == payload.pr_number:
                existing.update({k: getattr(payload, k) for k in REQUIRED_FIELDS})
                existing["status"] = "pending"
                existing.pop("merge_error", None)
                pid = existing["id"]
                updated = True
                break
        if pid is None:
            # Rate limit: max 1 NEW registration per technique per 10 min.
            last = _proposal_rate.get(technique_norm, 0.0)
            if now - last < RATE_LIMIT_WINDOW:
                retry_after = int(RATE_LIMIT_WINDOW - (now - last)) + 1
                jlog("warning", "proposal_rate_limited",
                     {"technique": technique_norm, "retry_after_s": retry_after})
                raise HTTPException(
                    429,
                    f"rate limit: technique {technique_norm} was already registered in the "
                    f"last 10 minutes; retry in {retry_after}s",
                )
            if len(_proposal_rate) > 1000:  # prune so the map cannot grow unbounded
                cutoff = now - RATE_LIMIT_WINDOW
                for stale_key in [k for k, v in _proposal_rate.items() if v <= cutoff]:
                    del _proposal_rate[stale_key]
            _proposal_rate[technique_norm] = now

            pid = "prop-" + uuid.uuid4().hex[:12]
            proposals.append({
                **{k: getattr(payload, k) for k in REQUIRED_FIELDS},
                "id": pid,
                "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "status": "pending",
            })
        _write_json(PROPOSALS_FILE, proposals)
        # Activity append happens INSIDE the lock: it is a read-modify-write of
        # activity.json and would lose entries if two registrations raced.
        _log_activity(
            "agent",
            "proposal.updated" if updated else "proposal.registered",
            f"{payload.technique} - {payload.title} (PR #{payload.pr_number})"
            + (" re-registered" if updated else ""),
        )
    return {"id": pid, "updated": updated, "created": not updated}


@app.post("/api/proposals/{pid}/approve", status_code=202)
async def approve_proposal(pid: str):
    async with _file_lock:
        proposals = _read_json(PROPOSALS_FILE, [])
        if not isinstance(proposals, list):
            proposals = []
        prop = next((p for p in proposals if isinstance(p, dict) and p.get("id") == pid), None)
        if not prop:
            raise HTTPException(404, "proposal not found")
        if pid in _pending_merges:
            raise HTTPException(409, "merge already in progress")
        if prop.get("status") not in ("pending", "merge_failed"):
            raise HTTPException(409, f"proposal already {prop.get('status')}")
        if not GITHUB_TOKEN:
            prop["status"] = "merge_failed"
            prop["merge_error"] = "GITHUB_TOKEN not configured on server"
            _write_json(PROPOSALS_FILE, proposals)
            _log_activity("system", "proposal.merge_failed", "GITHUB_TOKEN not configured")
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
        _log_activity("operator", "proposal.approved",
                      f"{prop.get('technique')} - merging PR #{pr_number}")
    task = asyncio.create_task(_merge_pr(pid, pr_number))
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return {"id": pid, "status": "merging", "accepted": True}


@app.post("/api/proposals/{pid}/reject")
async def reject_proposal(pid: str, payload: RejectIn | None = Body(default=None)):
    reason = (payload.reason if payload and payload.reason else "") or ""
    reason = reason.strip()
    async with _file_lock:
        proposals = _read_json(PROPOSALS_FILE, [])
        if not isinstance(proposals, list):
            proposals = []
        prop = next((p for p in proposals if isinstance(p, dict) and p.get("id") == pid), None)
        if not prop:
            raise HTTPException(404, "proposal not found")
        if prop.get("status") not in ("pending", "merge_failed"):
            raise HTTPException(409, f"proposal already {prop.get('status')}")
        prop["status"] = "rejected"
        prop["reject_reason"] = reason or None
        _write_json(PROPOSALS_FILE, proposals)
        _log_activity("operator", "proposal.rejected",
                      f"{prop.get('technique')} (PR #{prop.get('pr_number')}) - reason: {reason or 'none given'}")
    return {"id": pid, "status": "rejected", "reason": reason or None}


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


async def _build_pipeline_health() -> dict[str, Any]:
    # 1. GitHub Actions - latest run on the default branch
    ci_status, ci_detail = "unknown", "no data"
    try:
        resp = await _gh_get(f"https://api.github.com/repos/{REPO}/actions/runs?per_page=3")
        if resp.is_success:
            runs = resp.json().get("workflow_runs", [])
            if runs:
                run = runs[0]
                ci_status = run.get("status", "unknown")
                if ci_status == "completed":
                    ci_status = run.get("conclusion") or "completed"
                ci_detail = f"{str(run.get('display_title', ''))[:48]} ({run.get('head_branch', '?')})"
            else:
                ci_detail = "no workflow runs yet"
        else:
            ci_detail = f"GitHub API HTTP {resp.status_code}"
    except httpx.HTTPError as exc:
        ci_detail = f"GitHub API unreachable: {exc.__class__.__name__}"

    # 2. Wazuh manager link - plain TCP probe, no credentials needed
    wazuh_ok = await _check_tcp(WAZUH_HOST, WAZUH_PORT)
    wazuh_detail = f"tcp {WAZUH_HOST}:{WAZUH_PORT} " + ("reachable" if wazuh_ok else "unreachable")

    # 3. Agent link - n8n propose webhook configured
    agent_ok = bool(N8N_PROPOSE_WEBHOOK)
    agent_detail = "propose webhook configured" if agent_ok else "N8N_PROPOSE_WEBHOOK not set"

    return {
        "checked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "uptime_seconds": round(time.time() - _START_TIME, 1),
        "components": [
            {"name": "CI (GitHub Actions)", "status": ci_status, "detail": ci_detail},
            {"name": "Wazuh Manager", "status": "up" if wazuh_ok else "down", "detail": wazuh_detail},
            {"name": "Agent Link (n8n)", "status": "up" if agent_ok else "down", "detail": agent_detail},
        ],
    }


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
_COVERAGE_URL = (
    f"https://raw.githubusercontent.com/{REPO}/main/"
    "modules/detection-pipeline/docs/attack-matrix.md"
)
_SEP_CELL = re.compile(r":?-{2,}:?\s*")


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


@app.get("/api/coverage")
async def coverage():
    text = ""
    try:
        resp = await _gh_get(_COVERAGE_URL)  # GitHub read -> 1 retry on network errors
        if not resp.is_success:
            jlog("warning", "coverage_fetch_http_error", {"http": resp.status_code})
        else:
            text = resp.text
    except httpx.HTTPError as exc:
        jlog("warning", "coverage_fetch_failed", {"error": exc.__class__.__name__})

    if not text.strip():
        # Repo file unavailable -> serve sample so the panel still renders.
        text = SAMPLE_COVERAGE_MD

    cols, rows = _parse_md_table(text)
    return {"source": _COVERAGE_URL, "columns": cols, "rows": rows}


# ---------------------------------------------------------------------------
# Activity
# ---------------------------------------------------------------------------
@app.get("/api/activity")
async def activity():
    entries = _read_json(ACTIVITY_FILE, [])
    if not isinstance(entries, list):
        entries = []
    entries.sort(key=lambda e: str(e.get("ts", "")) if isinstance(e, dict) else "", reverse=True)
    return {"activity": entries}


# ---------------------------------------------------------------------------
# Trigger proposal cycle via the n8n webhook
# ---------------------------------------------------------------------------
@app.post("/api/trigger/propose", status_code=202)
async def trigger_propose():
    if not N8N_PROPOSE_WEBHOOK:
        raise HTTPException(503, "N8N_PROPOSE_WEBHOOK is not configured")
    try:
        resp = await _client.post(
            N8N_PROPOSE_WEBHOOK,
            json={"source": "operator-console"},
            headers={"Content-Type": "application/json"},
        )
        ok = resp.is_success
        detail = f"n8n webhook HTTP {resp.status_code}"
        if not ok:
            jlog("warning", "trigger_webhook_bad_response", {"http": resp.status_code})
    except httpx.HTTPError as exc:
        ok = False
        detail = f"n8n webhook failed: {exc.__class__.__name__}"
        jlog("warning", "trigger_webhook_failed", {"error": exc.__class__.__name__})
    async with _file_lock:
        _log_activity("operator", "propose.triggered", detail)
    return {"triggered": ok, "detail": detail}


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
