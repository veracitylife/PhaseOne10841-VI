# PhaseOne10841 — Phase 8 Approved Recommendations (1–9)

**Veracity Integrity LLC** · https://VeracityIntegrity.com
Product: PhaseOne10841ME · **v0.1.2** (Phase 8 complete)
All nine items below are **Approved** by Ryan (2026-09-17). Implementation **complete**.

---

> **Archive note:** Phase 1–7 ops recommendations 1–9 are **complete** and shipped in v0.7.0.
> See git history for the prior checklist. This document now tracks Phase 8 approved backlog.

---

## 1. Finish real IdP for OIDC/SSO

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Concrete IdP implementation with callback, session management, and logout — enterprise auth demoable end-to-end beside email OTP.

### Acceptance criteria
- Full OIDC callback flow with state/nonce validation
- Session binding (IdP session ↔ PhaseOne session)
- Logout endpoint with IdP session termination
- Works alongside email OTP (never weakens MFA)
- Demo-ready with at least one real IdP (Okta, Azure AD, or Auth0)
- Documentation for operator IdP configuration

### Suggested approach
1. Extend `shared/src/oidc.ts` with full callback handler
2. Add `/auth/oidc/callback` and `/auth/oidc/logout` routes
3. Store IdP tokens securely (encrypted at rest if persisted)
4. Add dashboard IdP connection status / test button
5. Create `docs/oidc-setup.md` with IdP configuration guides

### Risks / safety notes (DEFENSIVE ONLY)
- Token storage must use secure defaults (httpOnly, Secure cookies)
- State parameter must be cryptographically random to prevent CSRF
- Never log tokens or IdP secrets
- Graceful fallback to email OTP if IdP unavailable

---

## 2. Playbook effectiveness / learn loop

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Track false positives, hit rates, and suggested YAML tweaks from confirm/deny actions — still human-gated.

### Acceptance criteria
- Record playbook trigger outcomes (confirmed, denied, auto-resolved)
- Dashboard view of playbook effectiveness metrics
- False positive rate per rule/playbook
- Suggested threshold/condition tweaks based on patterns
- All suggestions require human review before applying
- Export effectiveness data for offline analysis

### Suggested approach
1. Add `playbook_outcomes` table (playbook_id, outcome, timestamp, admin_notes)
2. Extend gatekeeper worker to record outcomes on confirm/deny
3. Add `/v1/phaseone/gatekeeper/effectiveness` API
4. Dashboard "Learn" tab with effectiveness charts
5. Simple heuristic: if deny rate > 50% over 7 days, suggest threshold increase

### Risks / safety notes (DEFENSIVE ONLY)
- Never auto-apply suggestions — human confirmation required
- Retain outcome history for audit (subject to retention policy)
- Rate limit suggestion generation to prevent alert fatigue

---

## 3. Full MCP wire proxy (selective)

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Thin wire proxy for trusted MCP servers with same policy/approval/audit as tools.

### Acceptance criteria
- Proxy MCP JSON-RPC calls through gateway
- Apply tool policy to MCP tool invocations
- Audit all MCP calls with full request/response
- Selective: only proxied MCP servers (allowlist)
- Approval flow for destructive MCP tools
- Injection scanning on MCP results

### Suggested approach
1. Add `/v1/mcp/proxy` endpoint accepting JSON-RPC
2. Parse MCP tool calls, map to policy rules
3. Reuse existing tool enforce logic for MCP tools
4. Add `mcp_servers` allowlist in policy YAML
5. Record MCP calls in event store with `event_type: mcp_proxy`

### Risks / safety notes (DEFENSIVE ONLY)
- Only proxy to explicitly allowlisted MCP servers
- Never auto-trust MCP server responses
- Timeout MCP calls to prevent hanging
- Sanitize MCP responses before returning to agent

---

## 4. Operator MCP (read-mostly)

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Management MCP for trusted operator agents: health, gatekeeper status, pending confirmations, metrics; mutations only with MFA/RBAC + human confirm.

### Acceptance criteria
- MCP server exposing PhaseOne management tools
- Read tools: health, gatekeeper status, pending confirmations, metrics, recent events
- Write tools: confirm/deny actions, runtime overrides
- Write tools require MFA-authenticated session + RBAC check
- Write tools require explicit human confirmation dialog
- Full audit trail for all MCP management calls

### Suggested approach
1. Create `mcp-server/` with JSON-RPC handler
2. Implement read tools: `phaseone_health`, `phaseone_gatekeeper_status`, `phaseone_pending`, `phaseone_metrics`
3. Implement write tools: `phaseone_confirm`, `phaseone_deny`, `phaseone_override`
4. Bind MCP server to localhost only by default
5. Require `X-PhaseOne-Admin-Token` header for write operations

### Risks / safety notes (DEFENSIVE ONLY)
- Default to localhost binding (no external exposure)
- Write operations must verify MFA session is active
- Rate limit MCP management calls
- Log all management MCP calls to audit

---

## 5. Kubernetes Helm + operator path

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Helm/Kustomize deployment: Postgres, gateway, dashboard, ingress, secrets, retention CronJobs.

### Acceptance criteria
- Helm chart in `deploy/helm/phaseone/`
- Configurable values for all env vars
- Kubernetes Secrets for sensitive values
- Ingress with TLS termination
- CronJob for retention cleanup
- CronJob for backups (optional PVC)
- Health/readiness probes configured
- Resource limits documented

### Suggested approach
1. Create Helm chart structure with templates for Deployment, Service, Ingress, ConfigMap, Secret, CronJob
2. Add `values.yaml` with sensible defaults
3. Kustomize overlays for dev/staging/prod
4. Document in `docs/kubernetes.md`
5. Test with minikube/kind in CI

### Risks / safety notes (DEFENSIVE ONLY)
- Secrets must use Kubernetes Secrets (not ConfigMaps)
- Default to ClusterIP services (no external exposure without Ingress)
- Resource limits prevent noisy-neighbor issues
- PodSecurityPolicy / SecurityContext for non-root

---

## 6. Multi-tenant org controls

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Orgs, agent fleets, per-tenant policy/playbooks, scoped audit beyond email allowlists.

### Acceptance criteria
- Org entity with unique identifier
- Agents belong to orgs
- Per-org policy YAML
- Per-org playbooks directory
- Scoped audit queries (org filter)
- Org admin vs global admin roles
- Org-scoped API keys

### Suggested approach
1. Add `orgs` table (id, name, created_at, settings_json)
2. Add `org_id` foreign key to agents, events, sessions
3. Policy loader checks org-specific path first, falls back to global
4. Extend RBAC: `org_admin` role scoped to org
5. API: `/v1/orgs/:orgId/...` namespaced endpoints

### Risks / safety notes (DEFENSIVE ONLY)
- Strict tenant isolation — org A cannot see org B data
- Global admin can see all orgs (for platform ops)
- Org deletion must be soft-delete with retention
- Validate org_id on every scoped request

---

## 7. Signed canary packages

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Signed rotatable production canaries with integrity checks and SIEM provenance.

### Acceptance criteria
- Canary packages signed with Ed25519 or similar
- Signature verification on canary load
- Rotation preserves signature chain (old sig + new sig)
- SIEM export includes canary signature metadata
- CLI command to verify canary integrity
- Tamper detection alert if signature invalid

### Suggested approach
1. Generate Ed25519 keypair during onboard (private key encrypted at rest)
2. Sign canary JSON with `canary.signature` field
3. Add `npm run phaseone -- canary verify` command
4. On canary rotate, sign new canary, archive old signature
5. SIEM export includes `canary_signature` for provenance

### Risks / safety notes (DEFENSIVE ONLY)
- Private signing key must be protected (file permissions, encryption)
- Key rotation procedure documented
- Signature verification must not block startup (warn only on first run)
- Never expose private key in logs or API

---

## 8. Packaged SDKs (npm + PyPI)

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Official clients for OpenAI/LangChain/CrewAI with headers, enforce helpers, versioned docs.

### Acceptance criteria
- `@phaseone/client` npm package
- `phaseone-client` PyPI package
- Automatic `X-PhaseOne-*` header injection
- `enforce()` wrapper for tool calls
- TypeScript types / Python type hints
- Versioned documentation matching package version
- CI publish to npm/PyPI on release

### Suggested approach
1. Create `packages/sdk-js/` with TypeScript client
2. Create `packages/sdk-python/` with Python client
3. Wrap OpenAI client with header injection
4. Add `enforce(tool, args)` that calls `/v1/phaseone/tools/enforce`
5. Publish workflow: tag → build → publish

### Risks / safety notes (DEFENSIVE ONLY)
- SDK must not embed secrets (use env vars)
- SDK must validate gateway URL (no open redirect)
- Version must match gateway compatibility
- Clear deprecation policy for breaking changes

---

## 9. Gatekeeper blast-radius & simulation

| | |
|--|--|
| **Approved** | Yes |
| **Status** | **Done** |

**Goal:** Pre-flight "what would this playbook do?" over a time window; rate caps/cooldowns so contain/harden cannot thrash a fleet.

### Acceptance criteria
- Simulation API: given playbook + time window, return projected actions
- Historical replay: "if this playbook existed last 24h, what would it have done?"
- Blast-radius estimate: count of agents/sessions affected
- Rate caps: max N contain actions per hour per agent
- Cooldowns: after harden action, wait M minutes before next
- Dashboard simulation UI with dry-run visualization

### Suggested approach
1. Add `/v1/phaseone/gatekeeper/simulate` endpoint
2. Query historical events matching playbook conditions
3. Return `{ projected_actions: [...], blast_radius: { agents: N, sessions: M } }`
4. Add `rate_caps` and `cooldowns` to gatekeeper config
5. Dashboard "Simulate" button on playbook detail

### Risks / safety notes (DEFENSIVE ONLY)
- Simulation must be read-only (no side effects)
- Rate caps prevent runaway automation
- Cooldowns prevent flip-flopping between contain/release
- Alert if simulation shows high blast radius

---

## Suggested implementation order

See [PHASE8_PLAN.md](PHASE8_PLAN.md) for detailed waves and sequencing.

**Wave A (sales/demo leverage):**
1. #1 Finish real IdP for OIDC/SSO
2. #9 Gatekeeper blast-radius & simulation
3. #8 Packaged SDKs (npm + PyPI)

**Wave B (defense depth):**
4. #2 Playbook effectiveness / learn loop
5. #3 Full MCP wire proxy (selective)
6. #7 Signed canary packages

**Wave C (platform scale):**
7. #4 Operator MCP (read-mostly)
8. #5 Kubernetes Helm + operator path
9. #6 Multi-tenant org controls

---

DEFENSIVE ONLY — no exploit tooling, no secrets, no attack payloads.
