# PhaseOne10841 Gatekeeper — Automated Defense Orchestration

**Phase 7 Feature** · phaseone-core v0.7.0  
**Veracity Integrity LLC** · https://VeracityIntegrity.com

---

## Overview

The **Gatekeeper** is PhaseOne10841's automated defense orchestration system. It implements a **Sense → Decide → Act → Learn** loop that responds to security events with pre-defined, auditable playbooks.

**Key principles:**

- **DEFENSIVE ONLY** — No exploit PoCs, attack payloads, or offensive tooling
- **Outside the model** — Enforcement stays in the gateway control plane, not as LLM prompts
- **Human-in-the-loop** — High-impact/irreversible actions require confirmation
- **Dry-run by default** — Safe to enable and observe before activating live responses
- **Auditable** — Every automated action is logged with actor `gatekeeper`

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│    SENSE    │ ──► │   DECIDE    │ ──► │     ACT     │ ──► │    LEARN    │
│  Rule hits  │     │  Playbooks  │     │   Actions   │     │   Audit     │
│  Events     │     │  Matching   │     │  Execution  │     │   Metrics   │
│  Metrics    │     │  Conditions │     │  Overrides  │     │   Dashboard │
└─────────────┘     └─────────────┘     └─────────────┘     └─────────────┘
```

### 1. Sense

The gatekeeper consumes signals from existing PhaseOne systems:

- **Rule hits** — Detection rules in `rules/*.yaml` (aggregation, time windows)
- **Event types** — `canary.trigger`, `injection_blocked`, `a2a.blocked`, `approval.timeout`
- **Severity levels** — info, low, medium, high, critical
- **Decisions** — allow, deny, quarantine
- **A2A trust changes** — Trust level modifications
- **Metrics counters** — Prometheus metrics thresholds

### 2. Decide

YAML playbooks under `playbooks/*.yaml` define automated responses:

```yaml
id: canary-response
name: Canary Trigger Response
tier: contain

match:
  event_type: canary.trigger
  severity:
    - high
    - critical

actions:
  - type: emit_alert
    params:
      message: "Canary marker detected"
  - type: force_approval
    params:
      tools: ["*"]
      duration_ms: 300000
```

### 3. Act

Actions execute through existing gateway APIs and shared modules:

| Tier | Actions | Description |
|------|---------|-------------|
| **observe** | `emit_alert`, `write_audit`, `dashboard_notify` | No mutations |
| **contain** | + `tighten_rate_limit`, `force_approval`, `lower_a2a_trust`, `deny_tool`, `deny_domain` | Temporary restrictions |
| **harden** | + `rotate_canary`, `reload_rules` | Persistent changes (require confirmation) |

### 4. Learn

- All actions logged to admin audit with actor `gatekeeper`
- Dashboard notifications visible in Gatekeeper strip
- Recent actions tracked and queryable
- Pending confirmations for human review

---

## Playbook Schema

```yaml
# Required
id: string          # Unique identifier
name: string        # Human-readable name
tier: observe | contain | harden
match: object       # Conditions to trigger
actions: array      # Actions to execute

# Optional
description: string
enabled: boolean    # Default: true
cooldown_ms: number # Minimum time between executions (default: 60000)
max_executions_per_window: number # Rate limit (default: 10)
```

### Match Conditions

```yaml
match:
  # Any of these can be string or string[]
  rule_id: "brute-force-attempt"        # Match specific rule
  event_type:                           # Match event types
    - canary.trigger
    - a2a.blocked
  severity: ">=medium"                  # Threshold with >= prefix
  decision: deny                        # Match decision outcome
  agent_id: "specific-agent"            # Target specific agent
  
  # Aggregation
  count: 3           # Require N events in window
  window_ms: 60000   # Time window for count
```

### Action Types

#### Observe Tier

```yaml
- type: emit_alert
  params:
    message: "Alert message"

- type: write_audit
  params:
    action: "gatekeeper.custom_action"

- type: dashboard_notify
  params:
    message: "Dashboard notification"
```

#### Contain Tier

```yaml
- type: tighten_rate_limit
  params:
    factor: 0.5          # Reduce limit by factor
    duration_ms: 300000  # Duration in ms

- type: force_approval
  params:
    tools: ["*"]         # Tools requiring approval
    duration_ms: 600000

- type: lower_a2a_trust
  params:
    agent_id: "target"   # Optional, defaults to event agent
    trust_level: "LOCAL-UNTRUSTED"

- type: deny_tool
  params:
    tool: "dangerous_tool"
    duration_ms: 600000

- type: deny_domain
  params:
    domain: "suspicious.com"
    duration_ms: 600000
```

#### Harden Tier

```yaml
- type: rotate_canary
  requires_confirmation: true  # Default: true for harden actions
  params:
    canary_id: "api-key"

- type: reload_rules
  requires_confirmation: true
```

---

## Configuration

### Environment Variables

```bash
# Enable/disable gatekeeper
PHASEONE_GATEKEEPER_ENABLED=false    # Default: false (safe start)

# Dry-run mode (no mutations)
PHASEONE_GATEKEEPER_DRY_RUN=true     # Default: true

# Playbooks directory
PHASEONE_PLAYBOOKS_DIR=./playbooks   # Default: ./playbooks

# Optional: separate webhook for gatekeeper alerts
PHASEONE_GATEKEEPER_WEBHOOK_URL=

# Polling interval for event processing
PHASEONE_GATEKEEPER_POLL_MS=5000     # Default: 5000

# Event window for aggregation
PHASEONE_GATEKEEPER_EVENT_WINDOW_MS=60000  # Default: 60000

# Confirmation timeout for harden actions
PHASEONE_GATEKEEPER_CONFIRM_TIMEOUT_MS=600000  # Default: 600000
```

### Onboarding

The `npm run onboard` script includes gatekeeper configuration:

```bash
npm run onboard  # Interactive setup includes Phase 7 settings
```

---

## CLI Commands

```bash
# Show gatekeeper status
npm run phaseone -- gatekeeper status

# List available playbooks
npm run phaseone -- gatekeeper list-playbooks

# Run cycle (process queued events)
npm run phaseone -- gatekeeper run

# Dry-run cycle (no mutations)
npm run phaseone -- gatekeeper dry-run

# Process single event
npm run phaseone -- gatekeeper run --event '{"event_type":"canary.trigger","severity":"high"}'

# Confirm pending action
npm run phaseone -- gatekeeper confirm <confirmation-id>

# Deny pending action
npm run phaseone -- gatekeeper deny <confirmation-id>

# JSON output
npm run phaseone -- gatekeeper status --json
```

---

## API Endpoints

### Status & Configuration

```bash
# Get gatekeeper status
GET /v1/phaseone/gatekeeper/status

# Get configuration
GET /v1/phaseone/gatekeeper/config

# Update configuration
POST /v1/phaseone/gatekeeper/config
{
  "enabled": true,
  "dry_run": false,
  "actor_email": "admin@example.com"
}
```

### Playbooks

```bash
# List playbooks
GET /v1/phaseone/gatekeeper/playbooks

# Validate playbook
POST /v1/phaseone/gatekeeper/playbooks/validate
{
  "playbook": { ... }
}
```

### Event Processing

```bash
# Queue events
POST /v1/phaseone/gatekeeper/queue
{
  "event": { "event_type": "canary.trigger", "severity": "high" }
}

# Process single event
POST /v1/phaseone/gatekeeper/process
{
  "event": { "event_type": "test", "rule_id": "brute-force" },
  "dry_run": true
}

# Run processing cycle
POST /v1/phaseone/gatekeeper/run
{
  "dry_run": false,
  "actor_email": "admin@example.com"
}

# Process rule hit through gatekeeper
POST /v1/phaseone/gatekeeper/rules-event
{
  "event": {
    "event_type": "tool.call",
    "decision": "deny",
    "tool_name": "run_shell"
  }
}
```

### Confirmations

```bash
# List pending confirmations
GET /v1/phaseone/gatekeeper/pending

# Confirm action
POST /v1/phaseone/gatekeeper/confirm/:id
{
  "actor_email": "admin@example.com"
}

# Deny action
POST /v1/phaseone/gatekeeper/deny/:id
{
  "actor_email": "admin@example.com"
}
```

### Runtime State

```bash
# Get recent actions
GET /v1/phaseone/gatekeeper/recent?limit=50

# Get runtime overrides (temporary policy changes)
GET /v1/phaseone/gatekeeper/overrides

# Cleanup expired overrides
POST /v1/phaseone/gatekeeper/overrides/cleanup

# Get dashboard notifications
GET /v1/phaseone/gatekeeper/notifications
```

---

## Dashboard Integration

The dashboard includes a **Gatekeeper strip** showing:

- Enabled/disabled status
- Dry-run toggle
- Last execution time
- Pending confirmations count
- Recent actions
- Active runtime overrides

API endpoints for dashboard:

```
GET  /api/gatekeeper/status
GET  /api/gatekeeper/playbooks
GET  /api/gatekeeper/pending
GET  /api/gatekeeper/recent
POST /api/gatekeeper/config
POST /api/gatekeeper/run
POST /api/gatekeeper/confirm/:id
POST /api/gatekeeper/deny/:id
```

---

## Shipped Playbooks

PhaseOne10841 ships with these default playbooks:

| Playbook | Tier | Trigger | Actions |
|----------|------|---------|---------|
| `canary-response` | contain | canary.trigger (high+) | Alert, notify, force approval |
| `injection-blocked-response` | observe | rule: injection-blocked | Alert, audit, notify |
| `brute-force-response` | contain | rule: brute-force × 3 | Alert, tighten rate limit |
| `a2a-quarantine-response` | contain | a2a.quarantined | Alert, lower trust |
| `approval-timeout-burst` | observe | rule × 3 in 5min | Alert, notify |
| `high-severity-harden` | harden | critical × 5 | Alert, rotate canary*, reload rules* |

\* Requires human confirmation

---

## Security Considerations

### What Gatekeeper DOES NOT Do

- **No shell execution** — Never shells out to arbitrary commands
- **No prompt injection** — Stays outside the LLM agent prompt path
- **No attack simulation** — No exploit PoCs or offensive tooling
- **No autonomous policy writing** — Decisions from playbooks, not LLM

### Human Confirmation Required

Actions in the `harden` tier that make persistent changes require explicit human confirmation:

- `rotate_canary` — Changes canary markers
- `reload_rules` — Reloads detection rules

Pending confirmations expire after `PHASEONE_GATEKEEPER_CONFIRM_TIMEOUT_MS` (default: 10 minutes).

### Audit Trail

Every gatekeeper action is logged to admin audit with:

- `actor_email: "gatekeeper"`
- Action type and parameters
- Triggering event details
- Dry-run status
- Timestamp

---

## Example: Custom Playbook

Create `playbooks/custom-response.yaml`:

```yaml
# PhaseOne10841 Gatekeeper Playbook
# Custom response for specific tool abuse
# DEFENSIVE ONLY

id: custom-tool-abuse
name: Custom Tool Abuse Response
description: Respond to repeated denials of sensitive tool

enabled: true
tier: contain

match:
  event_type: tool.call
  decision: deny
  count: 5
  window_ms: 120000

actions:
  - type: emit_alert
    params:
      message: "Repeated tool denials detected — possible automated probing"
  
  - type: write_audit
    params:
      action: gatekeeper.tool_abuse_detected
  
  - type: dashboard_notify
    params:
      message: "🚨 Tool abuse pattern — agent restricted"
  
  - type: force_approval
    params:
      tools:
        - "run_shell"
        - "write_file"
      duration_ms: 900000

cooldown_ms: 300000
max_executions_per_window: 2
```

---

## Testing

```bash
# Run gatekeeper tests
npm test -- tests/gatekeeper.test.ts

# Test playbook validation
npm run phaseone -- gatekeeper list-playbooks --dir ./playbooks

# Test event matching in dry-run
npm run phaseone -- gatekeeper dry-run --event '{"event_type":"canary.trigger","severity":"high"}'
```

---

## What Works vs Stubbed

| Feature | Status |
|---------|--------|
| Playbook loading/validation | **Works** |
| Event matching (single + count) | **Works** |
| Observe tier actions | **Works** |
| Contain tier actions | **Works** |
| Harden tier with confirmation | **Works** |
| Runtime overrides | **Works** |
| CLI commands | **Works** |
| Dashboard routes | **Works** |
| Audit logging | **Works** |
| LLM advisor for suggestions | **Stubbed** — Roadmap item |
| Auto-remediation learning | **Stubbed** — Roadmap item |

---

## Roadmap

- LLM advisor for summarizing events and suggesting playbook improvements (advisory only)
- Machine learning for anomaly detection thresholds
- Playbook effectiveness scoring
- Cross-playbook coordination
- Kubernetes operator integration

---

**Veracity Integrity LLC** · https://VeracityIntegrity.com  
MIT License · DEFENSIVE ONLY
