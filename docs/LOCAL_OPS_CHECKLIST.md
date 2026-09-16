# PhaseOne10841 — local ops checklist (Veracity Integrity LLC)

## Done in this bring-up
- [x] PHASEONE_SESSION_SECRET set (not change-me)
- [x] UPSTREAM_PROVIDER=mock for first bring-up
- [x] PHASEONE_VIEWER_EMAILS=viewer@localhost
- [x] Local Docker: postgres + gateway + dashboard healthy
- [x] Smoke PASS (healthz/readyz/metrics/chat/deny/canary)

## Do before non-local
- [ ] Real SMTP for MFA (SMTP_HOST/USER/PASS) — console OTP is lab-only
- [ ] Reverse proxy + TLS (Caddy/nginx) in front of :3000 and :8080
- [ ] Tighten PHASEONE_ADMIN_EMAILS to real operators only
- [ ] Schedule retention + backup (Task Scheduler examples below)
- [ ] Tune rules/*.yaml to your real agent tool names

## Task Scheduler (Windows)
Retention (daily 2am):
  Program: npx
  Arguments: tsx scripts/retention-cleanup.ts
  Start in: C:\Users\disru\Documents\PhaseOne10841ME

Backup (daily 2:30am):
  Program: bash
  Arguments: scripts/backup.sh
  Start in: C:\Users\disru\Documents\PhaseOne10841ME
  (or run via Git Bash / WSL)

## Proxy sketch (Caddy)
phaseone.local {
  reverse_proxy /v1/* localhost:8080
  reverse_proxy localhost:3000
}
