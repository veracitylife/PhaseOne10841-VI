# Phase 8 Approved Recommendations — Status Tracker

**Approved by Ryan:** 2026-09-17  
**Current version:** v0.8.0-pre (Phase 8 Wave A shipped)  
**Phase 8 status:** Wave A complete, Wave B/C pending

---

> **Archive note:** Phase 1–7 ops recommendations 1–9 are **complete** and shipped in v0.7.0.
> This tracker now covers Phase 8 approved backlog.

---

## Status summary

| # | Recommendation | Status | Wave | Notes |
|---|----------------|--------|------|-------|
| 1 | Finish real IdP for OIDC/SSO | **DONE** ✅ | A | Okta/Azure AD/Auth0 support |
| 2 | Playbook effectiveness / learn loop | **Planned** | B | Human-gated suggestions |
| 3 | Full MCP wire proxy (selective) | **Planned** | B | Trusted MCP servers only |
| 4 | Operator MCP (read-mostly) | **Planned** | C | Management MCP; write requires MFA |
| 5 | Kubernetes Helm + operator path | **Planned** | C | Helm chart + CronJobs |
| 6 | Multi-tenant org controls | **Planned** | C | Orgs, scoped policy/audit |
| 7 | Signed canary packages | **Planned** | B | Ed25519 signatures + SIEM provenance |
| 8 | Packaged SDKs (npm + PyPI) | **DONE** ✅ | A | @phaseone/client, phaseone-client |
| 9 | Gatekeeper blast-radius & simulation | **DONE** ✅ | A | API, CLI, rate caps, dashboard |

---

## Phase 8 Wave A — COMPLETE (v0.8.0-pre)

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
- CLI: `npm run phaseone -- gatekeeper simulate`
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

## Wave B — Defense depth (Planned)

### 2. Playbook effectiveness / learn loop
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Phase 7 playbooks (complete)
- **Demo value:** Medium — operational maturity

### 3. Full MCP wire proxy (selective)
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Existing `mcp_call` enforce (complete)
- **Demo value:** Medium — MCP ecosystem integration

### 7. Signed canary packages
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Existing canary system (complete)
- **Demo value:** Medium — production hardening

---

## Wave C — Platform scale (Planned)

### 4. Operator MCP (read-mostly)
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Gatekeeper API (complete)
- **Demo value:** Medium — operator agent automation

### 5. Kubernetes Helm + operator path
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Docker deployment (complete)
- **Demo value:** High for enterprise — k8s required

### 6. Multi-tenant org controls
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** RBAC (complete), audit (complete)
- **Demo value:** High for enterprise — SaaS readiness

---

## Login (Phase 1-7 ops)

Use **techpronow@gmail.com** (must be on `PHASEONE_ADMIN_EMAILS`). OTP arrives from **noreply@clovisstar.com** — check Inbox and Spam.

**OIDC/SSO (v0.8.0+)**: Configure `PHASEONE_OIDC_*` env vars for enterprise SSO. See `docs/oidc-setup.md`.

---

## Approval record

| Date | Approver | Items | Notes |
|------|----------|-------|-------|
| 2026-09-17 | Ryan | All 9 items | Phase 8 backlog approved |

---

## Change log

| Date | Change |
|------|--------|
| 2026-09-17 | Initial Phase 8 planning; all items set to Planned |
| 2026-09-17 | Wave A complete: OIDC/SSO, Gatekeeper simulation, Packaged SDKs |

---

DEFENSIVE ONLY — no exploit tooling, no secrets, no attack payloads.
