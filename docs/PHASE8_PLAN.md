# Phase 8 Implementation Plan

**Veracity Integrity LLC** · https://VeracityIntegrity.com  
Product: PhaseOne10841ME · **v0.8.0** (Phase 8 complete)  
**Approved by Ryan:** 2026-09-17

---

## Overview

Phase 8 introduces nine approved recommendations organized into three implementation waves. Each wave targets a specific value proposition:

- **Wave A:** Sales/demo leverage — features that improve demo quality and sales conversations
- **Wave B:** Defense depth — features that strengthen security posture
- **Wave C:** Platform scale — features that enable enterprise/SaaS deployment

---

## Wave structure

```
Wave A (Sales/Demo)     Wave B (Defense)        Wave C (Platform)
─────────────────────   ─────────────────────   ─────────────────────
#1 OIDC/SSO             #2 Learn loop           #4 Operator MCP
#9 Blast-radius sim     #3 MCP wire proxy       #5 Helm + K8s
#8 Packaged SDKs        #7 Signed canaries      #6 Multi-tenant
```

---

## Wave A — Sales/demo leverage

**Goal:** Improve demo quality and enterprise sales readiness.

### #1. Finish real IdP for OIDC/SSO

| Aspect | Detail |
|--------|--------|
| **Priority** | High |
| **Demo value** | Enterprise customers require SSO; shows maturity |
| **Dependencies** | Phase 6 OIDC stub (complete) |
| **Risk** | Low — extending existing code |

**Implementation phases:**
1. Complete callback handler with state/nonce validation
2. Add session binding (IdP ↔ PhaseOne)
3. Implement logout with IdP session termination
4. Test with real IdP (Okta/Azure AD/Auth0)
5. Write `docs/oidc-setup.md`

**Deliverables:**
- `/auth/oidc/callback` and `/auth/oidc/logout` routes
- Dashboard IdP status panel
- Documentation for 3 major IdPs

---

### #9. Gatekeeper blast-radius & simulation

| Aspect | Detail |
|--------|--------|
| **Priority** | High |
| **Demo value** | Shows operational safety; "what-if" scenarios |
| **Dependencies** | Phase 7 gatekeeper (complete) |
| **Risk** | Low — read-only feature |

**Implementation phases:**
1. Add simulation API endpoint
2. Implement historical event replay
3. Add blast-radius calculation
4. Implement rate caps and cooldowns
5. Build dashboard simulation UI

**Deliverables:**
- `/v1/phaseone/gatekeeper/simulate` endpoint
- Rate caps config in `gatekeeper.yaml`
- Dashboard "Simulate" button on playbook detail

---

### #8. Packaged SDKs (npm + PyPI)

| Aspect | Detail |
|--------|--------|
| **Priority** | High |
| **Demo value** | Easy integration story; copy-paste to production |
| **Dependencies** | Stable gateway API (complete) |
| **Risk** | Medium — external package publishing |

**Implementation phases:**
1. Create `packages/sdk-js/` TypeScript client
2. Create `packages/sdk-python/` Python client
3. Add header injection and `enforce()` wrapper
4. Set up CI publish workflow
5. Write versioned documentation

**Deliverables:**
- `@phaseone/client` on npm
- `phaseone-client` on PyPI
- SDK documentation in `docs/sdk-*.md`

---

## Wave B — Defense depth

**Goal:** Strengthen security posture and detection capabilities.

### #2. Playbook effectiveness / learn loop

| Aspect | Detail |
|--------|--------|
| **Priority** | Medium |
| **Demo value** | Operational maturity; continuous improvement |
| **Dependencies** | Phase 7 playbooks (complete) |
| **Risk** | Low — analytics feature |

**Implementation phases:**
1. Add `playbook_outcomes` table
2. Record outcomes on confirm/deny
3. Build effectiveness metrics API
4. Add dashboard "Learn" tab
5. Implement suggestion heuristics (human-gated)

**Deliverables:**
- `/v1/phaseone/gatekeeper/effectiveness` endpoint
- Dashboard effectiveness charts
- Suggested tweaks (require human approval)

---

### #3. Full MCP wire proxy (selective)

| Aspect | Detail |
|--------|--------|
| **Priority** | Medium |
| **Demo value** | MCP ecosystem integration |
| **Dependencies** | Existing `mcp_call` enforce (complete) |
| **Risk** | Medium — new proxy surface |

**Implementation phases:**
1. Add `/v1/mcp/proxy` endpoint
2. Parse and validate MCP JSON-RPC
3. Apply tool policy to MCP tools
4. Add injection scanning on responses
5. Record MCP calls in event store

**Deliverables:**
- MCP proxy endpoint
- `mcp_servers` allowlist in policy
- MCP audit events

---

### #7. Signed canary packages

| Aspect | Detail |
|--------|--------|
| **Priority** | Medium |
| **Demo value** | Production hardening; supply chain security |
| **Dependencies** | Existing canary system (complete) |
| **Risk** | Low — cryptographic signing |

**Implementation phases:**
1. Generate Ed25519 keypair during onboard
2. Sign canary JSON on create/rotate
3. Add signature verification on load
4. Include signature in SIEM export
5. Add `canary verify` CLI command

**Deliverables:**
- Signed canary files
- `npm run phaseone -- canary verify`
- SIEM `canary_signature` field

---

## Wave C — Platform scale

**Goal:** Enable enterprise deployment and SaaS multi-tenancy.

### #4. Operator MCP (read-mostly)

| Aspect | Detail |
|--------|--------|
| **Priority** | Medium |
| **Demo value** | Operator agent automation |
| **Dependencies** | Gatekeeper API (complete) |
| **Risk** | Medium — new API surface |

**Implementation phases:**
1. Create `mcp-server/` with JSON-RPC handler
2. Implement read tools (health, status, pending, metrics)
3. Implement write tools (confirm, deny, override)
4. Add MFA/RBAC checks for writes
5. Bind to localhost by default

**Deliverables:**
- MCP server binary/process
- Read/write tool definitions
- Documentation in `docs/operator-mcp.md`

---

### #5. Kubernetes Helm + operator path

| Aspect | Detail |
|--------|--------|
| **Priority** | High (enterprise) |
| **Demo value** | K8s deployment required for many enterprises |
| **Dependencies** | Docker deployment (complete) |
| **Risk** | Medium — new deployment surface |

**Implementation phases:**
1. Create Helm chart structure
2. Add templates (Deployment, Service, Ingress, etc.)
3. Configure health/readiness probes
4. Add CronJobs for retention and backup
5. Write `docs/kubernetes.md`

**Deliverables:**
- `deploy/helm/phaseone/` chart
- Kustomize overlays for dev/staging/prod
- Kubernetes documentation

---

### #6. Multi-tenant org controls

| Aspect | Detail |
|--------|--------|
| **Priority** | High (SaaS) |
| **Demo value** | SaaS readiness; enterprise isolation |
| **Dependencies** | RBAC (complete), audit (complete) |
| **Risk** | High — data isolation critical |

**Implementation phases:**
1. Add `orgs` table and data model
2. Add `org_id` to agents, events, sessions
3. Implement per-org policy loading
4. Extend RBAC with `org_admin` role
5. Add `/v1/orgs/:orgId/...` endpoints

**Deliverables:**
- Org data model and migrations
- Scoped policy/playbooks
- Org admin dashboard

---

## Sequencing and dependencies

```
                    ┌─────────────┐
                    │   v0.7.0    │
                    │  (shipped)  │
                    └──────┬──────┘
                           │
           ┌───────────────┼───────────────┐
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  Wave A     │ │  Wave B     │ │  Wave C     │
    │ #1 OIDC     │ │ #2 Learn    │ │ #4 Op MCP   │
    │ #9 Sim      │ │ #3 MCP Prxy │ │ #5 Helm     │
    │ #8 SDKs     │ │ #7 Signed   │ │ #6 Multi-T  │
    └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
           │               │               │
           └───────────────┼───────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │   v0.8.0    │
                    └─────────────┘
```

**Within each wave, items can be parallelized:**
- Wave A: #1, #9, #8 have no inter-dependencies
- Wave B: #2, #3, #7 have no inter-dependencies
- Wave C: #5 and #6 can start in parallel; #4 can start anytime

**Cross-wave dependencies:**
- Wave C #6 (multi-tenant) benefits from Wave A #1 (OIDC) for org-scoped IdP
- Wave C #4 (operator MCP) benefits from Wave B #3 (MCP proxy) for consistency

---

## Risk assessment

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| IdP integration complexity | Medium | Medium | Test with multiple IdPs early |
| MCP proxy security surface | Medium | High | Strict allowlist; audit all calls |
| Multi-tenant data leakage | Low | Critical | Strict isolation; security review |
| SDK version compatibility | Medium | Medium | Semantic versioning; deprecation policy |
| Helm chart complexity | Medium | Medium | Test in CI with minikube/kind |

---

## Success criteria

Phase 8 is complete when:

1. All nine items reach **Done** status in `RECOMMENDATIONS_STATUS.md`
2. All features have passing tests
3. Documentation updated for each feature
4. Demo script covers Wave A features
5. Security review completed for Wave C #6 (multi-tenant)

---

## Version notes

- **v0.7.0:** Phase 7 shipped (gatekeeper, playbooks, runtime overrides)
- **v0.8.0:** Phase 8 complete (Waves A–C — all nine recommendations)

---

DEFENSIVE ONLY — no exploit tooling, no secrets, no attack payloads.
