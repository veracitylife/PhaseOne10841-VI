# Phase 8 Approved Recommendations — Status Tracker

**Approved by Ryan:** 2026-09-17  
**Current version:** v0.7.0 (Phase 7 shipped)  
**Phase 8 status:** Planning complete, implementation pending

---

> **Archive note:** Phase 1–7 ops recommendations 1–9 are **complete** and shipped in v0.7.0.
> This tracker now covers Phase 8 approved backlog.

---

## Status summary

| # | Recommendation | Status | Wave | Notes |
|---|----------------|--------|------|-------|
| 1 | Finish real IdP for OIDC/SSO | **Planned** | A | Demo-critical; enterprise auth |
| 2 | Playbook effectiveness / learn loop | **Planned** | B | Human-gated suggestions |
| 3 | Full MCP wire proxy (selective) | **Planned** | B | Trusted MCP servers only |
| 4 | Operator MCP (read-mostly) | **Planned** | C | Management MCP; write requires MFA |
| 5 | Kubernetes Helm + operator path | **Planned** | C | Helm chart + CronJobs |
| 6 | Multi-tenant org controls | **Planned** | C | Orgs, scoped policy/audit |
| 7 | Signed canary packages | **Planned** | B | Ed25519 signatures + SIEM provenance |
| 8 | Packaged SDKs (npm + PyPI) | **Planned** | A | Official clients with enforce helpers |
| 9 | Gatekeeper blast-radius & simulation | **Planned** | A | Pre-flight simulation + rate caps |

---

## Detailed status

### Wave A — Sales/demo leverage

#### 1. Finish real IdP for OIDC/SSO
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** None (builds on Phase 6 OIDC stub)
- **Demo value:** High — enterprise customers require SSO

#### 9. Gatekeeper blast-radius & simulation
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Phase 7 gatekeeper (complete)
- **Demo value:** High — shows operational safety

#### 8. Packaged SDKs (npm + PyPI)
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Stable gateway API (complete)
- **Demo value:** High — easy integration story

---

### Wave B — Defense depth

#### 2. Playbook effectiveness / learn loop
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Phase 7 playbooks (complete)
- **Demo value:** Medium — operational maturity

#### 3. Full MCP wire proxy (selective)
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Existing `mcp_call` enforce (complete)
- **Demo value:** Medium — MCP ecosystem integration

#### 7. Signed canary packages
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Existing canary system (complete)
- **Demo value:** Medium — production hardening

---

### Wave C — Platform scale

#### 4. Operator MCP (read-mostly)
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Gatekeeper API (complete)
- **Demo value:** Medium — operator agent automation

#### 5. Kubernetes Helm + operator path
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** Docker deployment (complete)
- **Demo value:** High for enterprise — k8s required

#### 6. Multi-tenant org controls
- **Status:** Planned
- **Approved:** Ryan 2026-09-17
- **Dependencies:** RBAC (complete), audit (complete)
- **Demo value:** High for enterprise — SaaS readiness

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

---

DEFENSIVE ONLY — no exploit tooling, no secrets, no attack payloads.
