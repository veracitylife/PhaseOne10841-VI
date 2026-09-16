# PhaseOne10841 — nine approved recommendations

**Veracity Integrity LLC · https://VeracityIntegrity.com**  
Status: **approved by operator 2026-09-17** · implementation tracked below.

| # | Recommendation | Status |
|---|----------------|--------|
| 1 | Run `npm run onboard` / never leave placeholder `PHASEONE_SESSION_SECRET` | **Done** — real session secret in local `.env` |
| 2 | First bring-up with `UPSTREAM_PROVIDER=mock` until `/healthz` + `/readyz` green | **Done** — mock upstream; both endpoints 200 |
| 3 | Enable GitHub Dependabot / vulnerability alerts on private repo | **In progress** — `.github/dependabot.yml` present; enable in GitHub Settings → Code security if API lacks rights |
| 4 | Use real SMTP for MFA (not console OTP fallback) before shared use | **Done** — `noreply@clovisstar.com` via SMTP; OTP verified in techpronow Gmail |
| 5 | Do not expose `:3000`/`:8080` beyond localhost; use Caddy proxy compose for TLS | **Partial** — local-only ports bound; `docker-compose.proxy.yml` available |
| 6 | Set `PHASEONE_VIEWER_EMAILS` for read-only ops; keep admin list tight | **Done** — viewers configured; admins include `techpronow@gmail.com` |
| 7 | Schedule retention + backup (Windows scheduled tasks) | **Done** — Backup + Retention daily 02:00 |
| 8 | Tune `rules/*.yaml` against real tool names (`docs/rules-tuning.md`) | **Ready** — walk rules after pointing a real agent through the gateway |
| 9 | Login allowlist: use email in `PHASEONE_ADMIN_EMAILS`; OTP from `noreply@clovisstar.com` | **Done** — SMTP OK; Gmail receives OTP; OpenClaw vault pointer saved |

## Operator login

- Dashboard: http://localhost:3000  
- Email: **techpronow@gmail.com**  
- OTP sender: **noreply@clovisstar.com**  
