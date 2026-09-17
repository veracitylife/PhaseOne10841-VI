# PhaseOne10841 Operations (Phase 5)

**Veracity Integrity LLC** · https://VeracityIntegrity.com

DEFENSIVE ONLY — retention, backups, rate limits, and local Docker hardening.

## Rate limiting

| Surface | Default | Env |
|---------|---------|-----|
| Public-ish gateway APIs (`/v1/chat/*`, tools, events, A2A, scan, permissions) | 120 req / 60s per client key | `PHASEONE_API_RATE_LIMIT`, `PHASEONE_API_RATE_WINDOW_MS` |
| Dashboard OTP request | 5 / 15 min per email | `PHASEONE_OTP_RATE_LIMIT`, `PHASEONE_OTP_RATE_WINDOW_MS` |

Client key prefers `X-Forwarded-For` → `X-Real-Ip` → `X-PhaseOne-Agent-Id` → `anon`.

Health probes (`/healthz`, `/readyz`, `/metrics`) are **not** rate limited.

429 responses include `Retry-After` and `X-RateLimit-*` headers.

Inspect live config: `GET /v1/phaseone/rate-limits`

## Retention & cleanup

```bash
# Dry-run (default)
npm run retention -- --dry-run --days 30

# Apply deletes
npm run retention -- --execute --days 30
```

Env (also written by `npm run onboard`):

- `PHASEONE_RETENTION_DAYS` (default 30)
- `PHASEONE_RETENTION_PRUNE_APPROVALS` (default true)
- `PHASEONE_RETENTION_PRUNE_AUDIT` (default true)

Deletes events older than the cutoff, then orphaned sessions, then optional resolved approvals / admin_audit rows.

API (defaults to **dry_run=true**): `POST /v1/phaseone/retention/run`

## Backup / restore

```bash
npm run backup
# → backups/<timestamp>/phaseone-postgres.sql + policy/ + rules/

./scripts/restore.sh backups/<timestamp>
# prompts for confirmation: type RESTORE
```

Uses `docker compose exec postgres pg_dump` when compose postgres is healthy; otherwise `pg_dump` / `psql` against `DATABASE_URL`.

Policy editor already keeps per-save backups under `policy/backups/`; the backup script copies those too.

## Security headers & cookies

Gateway and dashboard set:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Permissions-Policy` (camera/mic/geo disabled)
- Dashboard CSP (`default-src 'self'` + inline for the SPA)

Session cookie: **HttpOnly**, **SameSite=Lax**. Set `PHASEONE_SECURE_COOKIES=true` when serving over HTTPS. Local compose defaults to `false` so HTTP localhost works.

CSRF: double-submit cookie (readable by JS) + `X-CSRF-Token` on mutating dashboard APIs.

## Docker (production-ish local)

```bash
cp .env.example .env   # or npm run onboard -- --defaults
docker compose up --build
npm run smoke
```

Compose profile includes:

- `restart: unless-stopped`
- healthchecks (postgres, gateway, dashboard)
- non-root `user: "1000:1000"` for gateway/dashboard
- commented resource limit examples
- Phase 5 env passthrough (retention, API rate limits)

## OpenAPI

See [`docs/openapi.yaml`](./openapi.yaml) — linked from the main README.


## Mock-first upstream

Default `UPSTREAM_PROVIDER=mock`. After compose health is green:

```bash
curl -s http://localhost:8080/healthz
curl -s http://localhost:8080/readyz
# Option A — env override
UPSTREAM_PROVIDER=ollama docker compose up -d --force-recreate gateway
# Option B — compose overlay
docker compose -f docker-compose.yml -f docker-compose.upstream-ollama.yml up -d --force-recreate gateway
```

See [RECOMMENDATIONS.md](./RECOMMENDATIONS.md) item 2.

## TLS edge (Caddy)

See [proxy.md](./proxy.md). Overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d
```

## Gatekeeper operations (Phase 7)

The automated gatekeeper runs a Sense → Decide → Act → Learn loop using YAML playbooks.

### CLI commands

```bash
# Status
npm run phaseone -- gatekeeper status

# List playbooks
npm run phaseone -- gatekeeper list-playbooks

# Safe dry-run (DEFAULT)
npm run phaseone -- gatekeeper dry-run

# Live processing
npm run phaseone -- gatekeeper run

# Check LLM advisor health
npm run phaseone -- gatekeeper llm-check

# Confirm/deny pending harden-tier actions
npm run phaseone -- gatekeeper confirm <id>
npm run phaseone -- gatekeeper deny <id>
```

### Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PHASEONE_GATEKEEPER_ENABLED` | `false` | Enable gatekeeper worker |
| `PHASEONE_GATEKEEPER_DRY_RUN` | `true` | Dry-run mode (no mutations) |
| `PHASEONE_PLAYBOOKS_DIR` | `./playbooks` | Playbooks directory |
| `PHASEONE_GATEKEEPER_POLL_MS` | `5000` | Event polling interval |
| `PHASEONE_GATEKEEPER_WEBHOOK_URL` | (none) | Webhook for gatekeeper alerts |

### LLM advisor (optional)

The gatekeeper includes an optional LLM advisor (OpenRouter primary, Ollama fallback). The advisor is **purely advisory** — playbooks decide mutations.

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENROUTER_API_KEY` | (required for OpenRouter) | API key |
| `PHASEONE_GATEKEEPER_LLM_PRIMARY` | `openrouter` | Primary provider |
| `PHASEONE_GATEKEEPER_LLM_FALLBACK` | `ollama` | Fallback provider |
| `PHASEONE_GATEKEEPER_OLLAMA_BASE_URL` | `http://100.124.238.112:11434/v1` | Ollama endpoint |

See [`docs/gatekeeper.md`](./gatekeeper.md) for full playbook schema and API documentation.

### Safety notes

- **Dry-run is default** — enable `PHASEONE_GATEKEEPER_DRY_RUN=false` only when ready
- **Harden tier requires confirmation** — `rotate_canary`, `reload_rules` wait for human approval
- **LLM never in enforcement path** — deterministic playbooks decide all actions
- All gatekeeper actions are logged to admin audit with actor `gatekeeper`

## Windows scheduled backup / retention

As Administrator, once:

```powershell
.\scripts\windows\Register-PhaseOneScheduledTasks.ps1
```

Registers daily 2am tasks for `scripts/backup.sh` and `npm run retention`.
