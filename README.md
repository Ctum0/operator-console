# Operator Console — AI Detection Review Queue

FastAPI control plane for reviewing AI-proposed Sigma detection rules and merging
their GitHub PRs into [`Ctum0/detection-platform`](https://github.com/Ctum0/detection-platform)
(which triggers that repo's own CI/CD: Sigma validation, then deployment to Wazuh).

Part of the Detection Platform project — the console is the human approval gate:
AI proposes → operator reviews here → approve merges the PR → CI/CD ships it.

## Lifecycle

```
pending ──approve──▶ merging ──▶ merged ──validated──▶ validated
   │                    │
   │                    └──▶ merge_failed ──retry──▶ merging
   └──reject──▶ rejected   (merge_failed can also be rejected)
```

- **approve / retry** run the merge gate first: the PR must be open and every CI
  check on its head commit must have passed. A blocked or failed merge becomes
  `merge_failed` with the reason, and can be retried.
- **validated** closes the purple-team loop. It records evidence that the
  deployed rule fired on a real attack (Wazuh rule ID, the attack, when it fired),
  and only applies to a `merged` proposal.
- Proposals left in `merging` by a crash are moved to `merge_failed` at startup.

## Run locally

```bash
export CONSOLE_TOKEN="$(openssl rand -hex 32)"
export GITHUB_TOKEN="github_pat_..."          # fine-grained PAT, see permissions below
export N8N_PROPOSE_WEBHOOK="https://n8n.example/webhook/propose"
export GIT_SHA="$(git rev-parse HEAD)"        # optional: shown by /api/version
docker compose up -d --build
```

Console: `http://localhost:8000/`. Paste the token once and the browser keeps it
in `localStorage`. **Lock** in the header forgets it.

## Configuration

| Variable | Required | Purpose |
| --- | --- | --- |
| `CONSOLE_TOKEN` | yes | Bearer token for every `/api/*` call |
| `GITHUB_TOKEN` | for merges | Fine-grained PAT on `REPO`: **Pull requests: Read and write** (merge), **Actions: Read** (CI health), **Administration: Read** (self-hosted runner liveness; without it the runner row shows "unknown") |
| `REPO` | no | Default `Ctum0/detection-platform` |
| `N8N_PROPOSE_WEBHOOK` | for triggers | n8n webhook started by "Request proposal" |
| `N8N_WEBHOOK_SECRET` | no | Sent as `X-Webhook-Secret` on every trigger so the n8n webhook can reject anyone else. Must match the n8n Header Auth credential |
| `WAZUH_HOST`, `WAZUH_PORT` | no | TCP probe target, default `100.81.241.62:1514` |
| `WAZUH_API_URL` | no | Wazuh manager API, e.g. `https://100.81.241.62:55000`. Enables the deep Wazuh check |
| `WAZUH_API_USER`, `WAZUH_API_PASSWORD` | with `WAZUH_API_URL` | A read-only API user is enough |
| `WAZUH_API_VERIFY_TLS` | no | Default `true`. Set `false` for the manager's default self-signed certificate |
| `COVERAGE_PATH` | no | Matrix file in `REPO`, default `modules/detection-pipeline/docs/attack-matrix.md` |
| `GIT_SHA` | no | Commit reported by `/api/version`. Falls back to `SOURCE_COMMIT`, then `unknown` |
| `GITHUB_API_URL` | no | Default `https://api.github.com` (GitHub Enterprise or a test mock) |

Secrets come from the environment only and are never written to logs.

## Deploy (Coolify)

- Connect this repo, build from `Dockerfile`, expose port **8000**.
- Set the variables above (at least `CONSOLE_TOKEN`).
- Persistent volume: mount a volume at `/data`.
- **Commit SHA:** nothing to configure. Coolify passes the deployed commit to the
  running container as `SOURCE_COMMIT`, and the console reports it when `GIT_SHA`
  is unset. Leave Advanced → "Include Source Commit in Build" off: it only adds the
  SHA at build time and invalidates the Docker build cache on every commit.

## Storage (`/data` volume)

| File | Contents |
| --- | --- |
| `proposals.json` | Proposals with notes and validation evidence. Created with one sample entry on first boot |
| `activity.json` | Append-only audit log, capped at 2000 entries |
| `triggers.json` | Proposal-cycle trigger records, last 200 |
| `ratelimit.json` | Registration rate limiter, so a restart does not reset it |
| `coverage_cache.json` | Last good coverage parse, served with `stale: true` when GitHub is unreachable |

## API

Every `/api/*` route requires `Authorization: Bearer <CONSOLE_TOKEN>`. Only
`/healthz` is unauthenticated. Responses only ever gain fields, so existing
clients keep working.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/proposals` | `{proposals, total, counts}`. With no query params it returns every proposal. Filters: `status` (comma-separated), `q` (search title, technique, reasoning), `limit` (1–500), `offset` |
| GET | `/api/proposals/{id}` | One proposal, 404 if unknown |
| POST | `/api/proposals` | Register (agent). 201. Idempotent per PR number. Rate-limited to 1 new proposal per technique per 10 min. Optional `trigger_id` links it to a trigger |
| POST | `/api/proposals/{id}/approve` | 202, merge runs async behind the PR-open + CI gate. From `pending` or `merge_failed` |
| POST | `/api/proposals/{id}/retry` | 202, same gate. From `merge_failed` only |
| POST | `/api/proposals/{id}/reject` | Body `{"reason": "..."}`. From `pending` or `merge_failed` |
| POST | `/api/proposals/{id}/notes` | 201. Body `{"text", "author"?}`. Append-only, any status |
| POST | `/api/proposals/{id}/validated` | Body `{"rule_id", "attack", "fired_at", "evidence_url"?}`. From `merged` only. `fired_at` is ISO 8601, not in the future, not before the merge |
| GET | `/api/health/pipeline` | `{components: [{name, status, level, detail}]}`, cached 60 s. `level` is `ok`, `warn`, `bad` or `unknown` |
| GET | `/api/coverage` | `{columns, rows, source, fetched_at, stale}`. Rows are arrays. `sample: true` when no good copy has ever been fetched |
| GET | `/api/activity` | `{activity, total}`, newest first. Filters: `limit`, `offset`, `actor`, `action` (prefix, e.g. `proposal.`), `proposal_id` |
| GET | `/api/activity/export` | Full audit trail as a download, oldest first. `?format=csv` or `json` |
| POST | `/api/trigger/propose` | 202. Fires the n8n webhook and returns `{triggered, detail, trigger_id, status}` |
| GET | `/api/triggers` | `{triggers, total}`, newest first, `?limit=` up to 200 |
| POST | `/api/triggers/{id}/result` | n8n callback. Body `{"status": "succeeded" \| "failed", "detail"?, "proposal_id"?}` |
| GET | `/api/version` | Version and build info |
| GET | `/healthz` | Container healthcheck |

Agent registration payload:

```json
{
  "technique": "T1078.003",
  "title": "Local account login outside business hours",
  "sigma_yaml": "title: ...\n",
  "reasoning": "why this rule",
  "pr_url": "https://github.com/Ctum0/detection-platform/pull/12",
  "pr_number": 12,
  "branch": "ai/proposal-t1078-003",
  "trigger_id": "trg-0123456789"
}
```

Validation evidence (for example from the Atomic Red Team runner, or entered in the UI):

```bash
curl -X POST -H "Authorization: Bearer $CONSOLE_TOKEN" -H 'Content-Type: application/json' \
  http://localhost:8000/api/proposals/prop-abc123/validated \
  -d '{"rule_id": "100013", "attack": "ART T1003.001 #1", "fired_at": "2026-10-04T07:31:00Z"}'
```

### Trigger tracking with n8n

"Request proposal" sends the workflow
`{"source": "operator-console", "trigger_id": "trg-…", "result_path": "/api/triggers/trg-…/result"}`.
The trigger shows as **running** until the workflow reports back, in either of two ways:

1. Include `trigger_id` in the `POST /api/proposals` registration. The trigger is
   marked `succeeded` and linked to the new proposal.
2. Call `POST /api/triggers/{trigger_id}/result` from the workflow's success and
   error branches, with the console token.

A webhook that does not answer with 2xx is recorded as `failed` straight away.
The health panel's n8n row shows the latest trigger's status, and a trigger with
no result after 30 minutes is flagged in the UI.

## Rotate the token

```bash
export CONSOLE_TOKEN="$(openssl rand -hex 32)"
docker compose up -d        # recreates the container with the new env
```

The browser caches the old token. Click **Lock** in the header (or run
`localStorage.removeItem('consoleToken')` in DevTools) and paste the new one.

## Ops notes

- Health: `docker inspect --format '{{.State.Health.Status}}' operator-console`
- Version: `curl -s -H "Authorization: Bearer $CONSOLE_TOKEN" http://localhost:8000/api/version`
  returns `{version, build_info{git_sha, python, fastapi, uvicorn, started_at, repo}}`
  (`build_info.git_sha` comes from `GIT_SHA`, baked in at build time by compose, or Coolify's `SOURCE_COMMIT`).
- Logs are single-line JSON (`ts`, `level`, `event`, `detail`) on stdout, e.g.:
  `docker logs operator-console | jq -c 'select(.level=="error")'`

### Backup / restore of /data

State lives in the JSON files listed under Storage, in the `console-data` named volume, mounted at
`/data` in the container. Docker Compose prefixes the volume with the project
name, so locally it is `operator-console_console-data` (check with
`docker volume ls`; Coolify uses its own name). The commands below run `tar`
from the app image itself, so files keep `appuser` ownership. The current
directory must be writable by uid 1000.

```bash
VOL=operator-console_console-data

# Backup (safe while the service is running; writes are atomic)
docker run --rm -v "$VOL":/data:ro -v "$PWD":/backup --entrypoint tar \
  operator-console:latest czf "/backup/console-data-$(date +%F).tar.gz" \
  -C /data .

# Restore (stop first so the app cannot write mid-restore)
docker compose stop operator-console
docker run --rm -v "$VOL":/data -v "$PWD":/backup:ro --entrypoint tar \
  operator-console:latest xzf /backup/console-data-2026-10-03.tar.gz -C /data
docker compose up -d operator-console
curl -s http://localhost:8000/healthz            # verify container is back
```

Notes:

- On boot the app creates `proposals.json` and `activity.json` with one sample
  entry **only if they are missing**, so restoring a zero-byte or absent file
  silently re-seeds samples. Check file sizes after a restore.
- A corrupt JSON file is quarantined at runtime as `<name>.json.corrupt.<epoch>`
  and the API falls back to empty/sample data; if you see `.corrupt` files in
  the volume, restore from backup rather than hand-editing.
- All writes are atomic (temp file + `fsync` + `os.replace`), so a crash or
  `kill -9` mid-write can never tear a state file.

### Token rotation runbook

The console has two independent secrets, rotated the same way (env → container
recreate) but with different blast radius:

```bash
# 1. Console API token (affects the UI and the n8n agent workflow immediately)
export CONSOLE_TOKEN="$(openssl rand -hex 32)"
docker compose up -d        # recreates the container with the new env

# 2. GitHub PAT (fine-grained; PRs: Read and write, Actions: Read, Administration: Read)
#    a. GitHub -> Settings -> Developer settings -> Fine-grained tokens:
#       create the new token, note its expiry (max 1 year).
#    b. Put it in the environment / .env used by docker-compose:
#       export GITHUB_TOKEN="github_pat_..."
#       docker compose up -d
#    c. Revoke the OLD PAT only after a successful approve round-trip
#       (approve any pending proposal, or wait 60 s for the health cache and
#       confirm the "CD runner" row reports runners, which needs the PAT).
```

- After rotating `CONSOLE_TOKEN`: the browser caches the old token. Click
  **Lock** in the header (or run `localStorage.removeItem('consoleToken')`)
  and paste the new one. The n8n workflow's Bearer header must be updated in the
  same window or agent registrations will start failing with 401.
- Rotation is atomic per restart; there is no dual-token window, so rotate the
  n8n credential and the UI token together and verify one 201 from
  `POST /api/proposals` before revoking anything.
- A proposal left in `merging` by a process that died mid-merge is moved to
  `merge_failed` at the next startup. Use **Retry merge** (or
  `POST /api/proposals/{id}/retry`): it re-checks PR state and CI before merging.

### Health checks

| Component | What it checks |
| --- | --- |
| CI (GitHub Actions) | Latest workflow run on `REPO` and how long ago it ran |
| CD runner (self-hosted) | Registered self-hosted runners and whether they are online. Old Actions successes can hide a dead runner, so this checks the runners directly |
| Wazuh Manager | Plain TCP probe to `$WAZUH_HOST:$WAZUH_PORT` |
| Wazuh API | Authenticates, then reads the API version, the core daemons (`analysisd`, `remoted`, `wazuh-db`) and the loaded rule count. Skipped until `WAZUH_API_URL` is set |
| Agent Link (n8n) | Webhook configured, and how the latest trigger ended |

- The coverage file is fetched without the PAT, because the repo is public, so an
  expired token cannot break coverage. The PAT is only tried after a 404, which
  is what a private repo returns.
- Rate limiting is 1 new registration per technique per 10 minutes, kept in
  `/data/ratelimit.json` so restarts do not reset it. Re-registering the same PR
  number is always allowed, and never moves an already merged PR back to pending.
