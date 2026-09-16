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

## Login
Use **techpronow@gmail.com** (must be on `PHASEONE_ADMIN_EMAILS`). OTP arrives from **noreply@clovisstar.com** — check Inbox and Spam.
