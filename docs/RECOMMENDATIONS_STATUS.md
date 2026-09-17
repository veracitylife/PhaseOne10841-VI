# Approved recommendations — execution status (2026-09-17)

1. **Onboard / session secret** — DONE (real `PHASEONE_SESSION_SECRET` set; not change-me)
2. **Mock upstream until healthy** — DONE (`UPSTREAM_PROVIDER=mock`; healthz/readyz green; smoke PASS)
3. **GitHub Dependabot / secret scanning** — Dependabot config in repo; API enable attempted (see CI/settings if still pending)
4. **Real SMTP for MFA** — DONE (`SMTP_FROM=noreply@clovisstar.com` → `techpronow@gmail.com`; OTP channel=smtp verified)
5. **Reverse proxy + TLS (Caddy)** — READY (`docker-compose.proxy.yml`); use when exposing beyond localhost
6. **Viewer emails** — DONE (`PHASEONE_VIEWER_EMAILS=viewer@localhost`; tighten for prod)
7. **Retention + backup schedule** — Script present; registration attempted via `Register-PhaseOneScheduledTasks.ps1`
8. **Detection rules tuning** — Docs at `docs/rules-tuning.md`; walk rules against real tools next
9. **Admin allowlist + Clovis Star SMTP** — DONE (`PHASEONE_ADMIN_EMAILS` includes `techpronow@gmail.com`; from `noreply@clovisstar.com`)

---

## Phase 8 Wave A Status (v0.8.0-pre)

### #1 OIDC/SSO — DONE ✅
- Callback handler with state/nonce validation
- Token exchange with PKCE support
- Session binding with IdP identity and role claims
- Logout with IdP end-session support
- Dashboard IdP status panel
- Documentation: `docs/oidc-setup.md`
- Unit tests: `tests/oidc.test.ts`

### #9 Gatekeeper Simulation — DONE ✅
- API: `POST /v1/phaseone/gatekeeper/simulate`
- Blast-radius summary calculation
- Rate caps + cooldowns configuration
- CLI: `npm run gatekeeper -- simulate`
- Dashboard simulation controls
- Unit tests: `tests/gatekeeper.test.ts`

### #8 Packaged SDKs — DONE ✅
- `packages/sdk-js/` — `@phaseone/client` TypeScript SDK
- `packages/sdk-python/` — `phaseone-client` Python SDK
- Features: gateway URL, headers, enforce(), scan(), chat helpers
- Documentation: `docs/sdk-js.md`, `docs/sdk-python.md`
- CI workflows: `.github/workflows/publish-sdk-*.yml` (manual dispatch)
- Tests: `packages/sdk-js/src/index.test.ts`, `packages/sdk-python/tests/test_client.py`

---

## Login
Use **techpronow@gmail.com** (must be on `PHASEONE_ADMIN_EMAILS`). OTP arrives from **noreply@clovisstar.com** — check Inbox and Spam.

**OIDC/SSO (v0.8.0+)**: Configure `PHASEONE_OIDC_*` env vars for enterprise SSO. See `docs/oidc-setup.md`.
