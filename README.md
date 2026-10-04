# Operator Console — AI Detection Review Queue

FastAPI control plane for reviewing AI-proposed Sigma detection rules and merging
their GitHub PRs into [`Ctum0/detection-platform`](https://github.com/Ctum0/detection-platform)
(which triggers that repo's own CI/CD: Sigma validation, then deployment to Wazuh).

Part of the Detection Platform project — the console is the human approval gate:
AI proposes → operator reviews here → approve merges the PR → CI/CD ships it.

## Run locally

```bash
export CONSOLE_TOKEN="$(openssl rand -hex 32)"
export GITHUB_TOKEN="github_pat_..."          # fine-grained PAT: PRs read/write, Actions read
export N8N_PROPOSE_WEBHOOK="https://n8n.example/webhook/propose"
docker compose up -d --build
```

Console: `http://localhost:8000/` — paste the token once; the browser stores it in
localStorage.

## Deploy (Coolify)

- Connect this repo, build from `Dockerfile`, expose port **8000**.
- Set env vars: `CONSOLE_TOKEN` (required), `GITHUB_TOKEN`, `N8N_PROPOSE_WEBHOOK`,
  `REPO` (default `Ctum0/detection-platform`), `WAZUH_HOST`, `WAZUH_PORT`.
- Persistent volume: mount a volume at `/data` (holds `proposals.json`, `activity.json`).
- No code changes needed between local and Coolify — same image, env-driven config.

## Storage (`/data` volume)

- `proposals.json` — proposals, auto-created with one sample entry on first boot
- `activity.json` — append-only activity log, capped at 500 entries

## API (all `/api/*` require `Authorization: Bearer <CONSOLE_TOKEN>`)

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/api/proposals` | list proposals |
| POST | `/api/proposals` | register proposal (agent); idempotent per PR number |
| POST | `/api/proposals/{id}/approve` | merge PR; returns 202, merge runs async |
| POST | `/api/proposals/{id}/reject` | reject; optional body `{"reason": "..."}` |
| GET | `/api/health/pipeline` | GitHub Actions latest run + Wazuh TCP probe + agent link |
| GET | `/api/coverage` | ATT&CK matrix parsed from repo markdown |
| GET | `/api/activity` | recent activity, reverse-chron |
| POST | `/api/trigger/propose` | fire the n8n proposal webhook (202) |
| GET | `/healthz` | unauthenticated container healthcheck |

Agent registration payload:

```json
{
  "technique": "T1078.003",
  "title": "Local account login outside business hours",
  "sigma_yaml": "title: ...\n",
  "reasoning": "why this rule",
  "pr_url": "https://github.com/Ctum0/detection-platform/pull/12",
  "pr_number": 12,
  "branch": "ai/proposal-t1078-003"
}
```

## Rotate the token

```bash
export CONSOLE_TOKEN="$(openssl rand -hex 32)"
docker compose up -d        # recreates the container with the new env
```

The browser caches the old token — click "Change token" on the gate screen (or
`localStorage.removeItem('consoleToken')` in DevTools) and paste the new one.

## Ops notes

- Health: `docker inspect --format '{{.State.Health.Status}}' operator-console`
- Version: `curl -s -H "Authorization: Bearer $CONSOLE_TOKEN" http://localhost:8000/api/version`
  returns `{version, build_info{git_sha, python, fastapi, uvicorn, started_at, repo}}`
  (`build_info.git_sha` comes from the `GIT_SHA` env var; set it in docker-compose at build/deploy time).
- Logs are single-line JSON (`ts`, `level`, `event`, `detail`) on stdout, e.g.:
  `docker logs operator-console | jq -c 'select(.level=="error")'`

### Backup / restore of /data

State lives in two JSON files in the `console-data` named volume, mounted at
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
  -C /data proposals.json activity.json

# Restore (stop first so the app cannot write mid-restore)
docker compose stop operator-console
docker run --rm -v "$VOL":/data -v "$PWD":/backup:ro --entrypoint tar \
  operator-console:latest xzf /backup/console-data-2026-10-03.tar.gz -C /data
docker compose up -d operator-console
curl -s http://localhost:8000/healthz            # verify container is back
```

Notes:

- On boot the app creates either file with one sample entry **only if it is
  missing** — restoring a zero-byte or absent file silently re-seeds samples,
  so verify file sizes after a restore.
- A corrupt JSON file is quarantined at runtime as `<name>.json.corrupt.<epoch>`
  and the API falls back to empty/sample data; if you see `.corrupt` files in
  the volume, restore from backup rather than hand-editing.
- All writes are atomic (temp file + `fsync` + `os.replace`), so a crash or
  `kill -9` mid-write can never tear `proposals.json`/`activity.json`.

### Token rotation runbook

The console has two independent secrets, rotated the same way (env → container
recreate) but with different blast radius:

```bash
# 1. Console API token (affects the UI and the n8n agent workflow immediately)
export CONSOLE_TOKEN="$(openssl rand -hex 32)"
docker compose up -d        # recreates the container with the new env

# 2. GitHub PAT (fine-grained; PRs: Read and write, Actions: Read)
#    a. GitHub -> Settings -> Developer settings -> Fine-grained tokens:
#       create the new token, note its expiry (max 1 year).
#    b. Put it in the environment / .env used by docker-compose:
#       export GITHUB_TOKEN="github_pat_..."
#       docker compose up -d
#    c. Revoke the OLD PAT only after a successful approve round-trip
#       (approve any pending proposal, or POST /api/health/pipeline and
#       confirm the CI component reports fresh data — both exercise the PAT).
```

- After rotating `CONSOLE_TOKEN`: the browser caches the old token — click
  "Change token" on the gate screen (or `localStorage.removeItem('consoleToken')`)
  and paste the new one. The n8n workflow's Bearer header must be updated in the
  same window or agent registrations will start failing with 401.
- Rotation is atomic per restart; there is no dual-token window, so rotate the
  n8n credential and the UI token together and verify one 201 from
  `POST /api/proposals` before revoking anything.
- If a proposal is stuck in `merging` across a restart (old process died
  mid-merge), re-approve it: the merge flow re-checks PR state + CI and settles
  the status (`merged` or `merge_failed` with the reason).

## Ops notes (legacy)

- Logs: `docker logs -f operator-console` (app logs to stdout only, no secrets in log lines)
- Token perms: fine-grained PAT with **Pull requests: Read and write** (merge) and
  **Actions: Read** (health panel). Contents read is not required; the coverage
  file comes from raw.githubusercontent.com unauthenticated.
- Approve flow: 202 accepted → status `merging` → `merged` or `merge_failed`
  (failure detail is stored on the proposal and visible in the activity feed).
- Wazuh check is a plain TCP probe to `$WAZUH_HOST:$WAZUH_PORT` (defaults to the
  tailscale IP 100.81.241.62:1514). No Wazuh credentials are used or needed.
