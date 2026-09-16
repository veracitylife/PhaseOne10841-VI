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

## Windows scheduled backup / retention

As Administrator, once:

```powershell
.\scripts\windows\Register-PhaseOneScheduledTasks.ps1
```

Registers daily 2am tasks for `scripts/backup.sh` and `npm run retention`.
