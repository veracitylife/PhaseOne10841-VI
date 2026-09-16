# PhaseOne10841 — local deploy recommendations
**Veracity Integrity LLC · https://VeracityIntegrity.com**

## Checklist status (operator)

| Item | Guidance |
|------|----------|
| `npm run onboard` before first compose | **Required.** Never leave `PHASEONE_SESSION_SECRET=change-me…`. Use `npm run onboard` or `npm run onboard -- --defaults`. |
| First bring-up upstream | Keep `UPSTREAM_PROVIDER=mock` until `GET /healthz` and `GET /readyz` are green; then switch to Ollama/OpenAI. |
| GitHub Dependabot / secret scanning | Enable on private repo (Settings → Code security). Repo includes `.github/dependabot.yml`. |
| SMTP for MFA | Console/OTP fallback file is **lab only**. Set real `SMTP_*` before any shared/non-local use. |
| Reverse proxy + TLS | Do not expose `:3000`/`:8080` beyond localhost. Use `docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d` (Caddy). |
| Viewer emails | Set `PHASEONE_VIEWER_EMAILS` for read-only ops; keep `PHASEONE_ADMIN_EMAILS` tight. |
| Retention + backup schedule | Windows: run `scripts/windows/Register-PhaseOneScheduledTasks.ps1` as Admin. |
| Detection rules | Walk `rules/*.yaml` vs real tool names — see `docs/rules-tuning.md`. |

## Suggested bring-up order
1. `npm install && npm run onboard`
2. Confirm `.env`: mock upstream, real session secret, admin email, optional viewer emails
3. `docker compose up --build -d`
4. `curl http://localhost:8080/healthz` && `curl http://localhost:8080/readyz`
5. `npm run smoke` (from host with gateway up)
6. Open `http://localhost:3000` → MFA (check OTP fallback file if no SMTP)
7. Only then: real upstream + SMTP + Caddy proxy + scheduled tasks + rules tuning
