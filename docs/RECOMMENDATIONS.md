# PhaseOne10841 — Approved recommendations (1–9)

**Veracity Integrity LLC** · https://VeracityIntegrity.com  
Product: PhaseOne10841ME · **v0.5.1**  
All nine items below are **Approved**. Status reflects this tree after the implementation pass.

---

## 1. Onboard / session secret

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

Ensure onboard docs + defaults never leave a `change-me` session secret; warn at startup if weak.

- `npm run onboard` / `--defaults` always writes a 64-char hex `PHASEONE_SESSION_SECRET` (never `change-me`); weak env placeholders are discarded and regenerated.
- `.env.example` keeps an explicit placeholder so operators know to run onboard.
- Dashboard startup: `warnIfWeakSessionSecret()` in `shared/src/session-secret.ts` (flags `change-me`, `dev-only`, short/empty).
- Compose lab default `dev-only-change-me` still boots but triggers the loud warn until onboard is run.

---

## 2. Mock-first upstream

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

Keep `UPSTREAM_PROVIDER=mock` until health is green; clear path to switch afterward.

- Defaults: `.env.example`, onboard, `docker-compose.yml`.
- Compose header + README §2b + `docs/operations.md`: after `/healthz` + `/readyz`,  
  env override **or** overlay `docker-compose.upstream-ollama.yml`.

---

## 3. Dependabot (+ secret scanning note)

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** (in-repo) · **Partial** (GitHub UI toggle) |

Solid Dependabot for npm + Docker; note secret scanning for the private repo.

- `.github/dependabot.yml` — weekly **npm** (grouped), **docker**, **github-actions**.
- **Operator (GitHub Settings → Code security):** enable **Secret scanning** and **Push protection**. Dependabot does not replace secret scanning.

---

## 4. SMTP MFA production path

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

Document `noreply@clovisstar.com` as the Veracity/Clovis Star SMTP sender; clear OTP template; lab-only console fallback with loud warning.

- Default / docs: `SMTP_FROM=noreply@clovisstar.com` (`.env.example`, compose, onboard, `loadAuthConfig`).
- OTP email body identifies PhaseOne + Veracity + Clovis Star sender path.
- No `SMTP_HOST`: console/file fallback + **LAB-ONLY** warnings (auth + dashboard startup). Not for shared/production.

---

## 5. Reverse proxy + TLS

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

Complete Caddy overlay + short proxy doc.

- `docker-compose.proxy.yml` + `deploy/caddy/Caddyfile` (`phaseone.localhost`, `gateway.phaseone.localhost`, `tls internal`).
- **`docs/proxy.md`** — bring-up, verify curls, ACME notes, `PHASEONE_SECURE_COOKIES=true`.

```bash
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d
```

---

## 6. Viewer RBAC

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

`PHASEONE_VIEWER_EMAILS` works; documented; tests cover read-only.

- `shared/src/rbac.ts` + dashboard `requireMutatingAuth` — viewers MFA-login but cannot mutate.
- Documented in README, onboard, this checklist.
- Tests: `tests/auth-otp.test.ts`, `tests/phase4.test.ts` (incl. multi-viewer allowlist).

---

## 7. Retention + backup schedule

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

Windows scheduled tasks + backup/restore scripts correct and documented.

- `scripts/backup.sh` / `scripts/restore.sh` / `npm run retention`.
- `scripts/windows/Register-PhaseOneScheduledTasks.ps1` — daily 2am Backup + Retention.
- Documented here and in `docs/operations.md`.

```powershell
.\scripts\windows\Register-PhaseOneScheduledTasks.ps1
```

---

## 8. Detection rules tuning

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

Coherent `docs/rules-tuning.md` + sample rules; linked from README.

- `docs/rules-tuning.md` aligned with `rules/*.yaml`.
- `shell-denied.yaml` matches real tool ids (`run_shell`, `shell_exec`, `unrestricted_shell`, …).
- README Operator checklist links RECOMMENDATIONS + rules-tuning + proxy.

---

## 9. Admin allowlist + MFA email

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

Operators must set `PHASEONE_ADMIN_EMAILS` to real addresses; onboard prompts clearly.

- Interactive onboard prompts for real admin emails (example: `techpronow@gmail.com`) and warns on `admin@localhost`.
- `.env.example` + this checklist state the same.
- Production MFA delivery requires SMTP (item 4); lab fallback will not reach Gmail.

---

## Suggested bring-up order

1. `npm install && npm run onboard` — real admin email(s), generated session secret, mock upstream  
2. Confirm `.env`: no `change-me` secret, real `PHASEONE_ADMIN_EMAILS`, optional viewers  
3. `docker compose up --build -d`  
4. `curl http://localhost:8080/healthz` && `curl http://localhost:8080/readyz`  
5. `npm run smoke`  
6. Open `http://localhost:3000` → MFA (OTP fallback file only if SMTP unset — lab)  
7. Then: real upstream + SMTP (`noreply@clovisstar.com`) + Caddy (`docs/proxy.md`) + scheduled tasks + rules tuning  

DEFENSIVE ONLY — no exploit tooling.
