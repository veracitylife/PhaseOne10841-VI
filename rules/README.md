# PhaseOne10841 Detection Rules

Lightweight Sigma-ish YAML rules evaluated against gateway/recorder event fields.

**DEFENSIVE ONLY** — match and count; no exploit content.

**Veracity Integrity LLC** · https://VeracityIntegrity.com

---

## Quick Start

Configure directory: `PHASEONE_RULES_DIR` (default: this folder).

```bash
# List rules via CLI
npm run phaseone -- rules

# Evaluate rules against an event
npm run phaseone -- rules evaluate --event '{"tool_name":"run_shell","decision":"deny"}'

# View rules via API
curl http://localhost:8080/v1/phaseone/rules

# Dashboard view
# → Detection rules section
```

---

## Rule Structure

Each rule is a YAML file with the following structure:

```yaml
id: phaseone.category.rule_name          # Unique identifier
title: Human-readable rule name          # Display name
description: Detailed explanation        # Optional
status: stable | experimental            # Rule maturity
level: info | low | medium | high | critical
enabled: true | false                    # Default: true

logsource:
  product: PhaseOne10841                 # Always PhaseOne10841

detection:
  selection:                             # Field matching
    field_name: value
    field_name:
      - value1
      - value2
  condition: selection                   # Logic expression

falsepositives:                          # Documentation
  - Expected benign trigger scenario
```

---

## Selection Matchers

### Exact Match

```yaml
detection:
  selection:
    tool_name: run_shell
    decision: deny
```

### Multiple Values (OR)

```yaml
detection:
  selection:
    tool_name:
      - run_shell
      - shell_exec
      - bash
```

### Multiple Selections (OR conditions)

```yaml
detection:
  selection_any:
    - tool_name: run_shell
      decision: deny
    - tool_name: raw_shell
      decision: deny
```

### Numeric Comparisons

```yaml
detection:
  selection:
    field_gte:
      injection_score: 0.7    # >= 0.7
    field_lte:
      response_time_ms: 1000  # <= 1000
    field_gt:
      retry_count: 3          # > 3
    field_lt:
      confidence: 0.5         # < 0.5
```

### String Operations

```yaml
detection:
  selection:
    field_contains:
      command: "rm -rf"       # Case-insensitive substring
    field_regex:
      url: "^https?://.*\\.exe$"  # Regex match
    field_not:
      status: success         # Exclude matches
```

---

## Aggregation Rules (Phase 6)

Aggregation rules match based on counts, sums, or averages over a time window.

### Count Aggregation

Detect N events matching selection in a time window:

```yaml
id: phaseone.auth.brute_force
title: Brute force login attempt detected
detection:
  selection:
    event_type: auth_failure
  aggregation:
    type: count
    group_by:
      - source_ip
    threshold: 5
    comparison: gte
  timewindow:
    duration_ms: 300000  # 5 minutes
  condition: selection and aggregation
```

### Distinct Count

Detect N distinct values of a field:

```yaml
id: phaseone.network.multi_domain
title: Agent accessing multiple distinct domains
detection:
  selection:
    event_type: http_request
  aggregation:
    type: distinct_count
    field: domain
    group_by:
      - agent_id
    threshold: 10
    comparison: gte
  timewindow:
    duration_ms: 300000
```

### Average Aggregation

Detect when average of a numeric field exceeds threshold:

```yaml
id: phaseone.injection.high_average
title: Elevated average injection scores
detection:
  selection:
    event_type: chat_completion
  aggregation:
    type: avg
    field: injection_score
    group_by:
      - agent_id
      - session_id
    threshold: 0.5
    comparison: gte
  timewindow:
    duration_ms: 600000  # 10 minutes
```

### Sum Aggregation

```yaml
detection:
  aggregation:
    type: sum
    field: bytes_sent
    group_by:
      - agent_id
    threshold: 10000000  # 10MB
    comparison: gte
  timewindow:
    duration_ms: 60000
```

### Aggregation Options

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | `count` \| `distinct_count` \| `sum` \| `avg` |
| `field` | string | Field to aggregate (required for sum/avg/distinct_count) |
| `group_by` | string[] | Group events by these fields |
| `threshold` | number | Trigger threshold |
| `comparison` | string | `gte` \| `gt` \| `lte` \| `lt` \| `eq` |

### Time Window Options

| Field | Type | Description |
|-------|------|-------------|
| `duration_ms` | number | Window duration in milliseconds |
| `slide_ms` | number | (Future) Sliding window interval |

---

## Included Rules

### Simple Matching Rules

| File | ID | Level | Description |
|------|-----|-------|-------------|
| `shell-denied.yaml` | phaseone.shell.denied | medium | Shell tool calls denied by policy |
| `domain-denied.yaml` | phaseone.domain.denied | medium | Domain access denied by policy |
| `injection-blocked.yaml` | phaseone.injection.blocked | high | Prompt injection blocked |
| `a2a-untrusted.yaml` | phaseone.a2a.untrusted | medium | Untrusted A2A source |
| `canary-trigger.yaml` | phaseone.canary.triggered | critical | Canary token triggered |
| `high-injection-score.yaml` | phaseone.injection.score.high | high | High injection score on event |

### Aggregation Rules (Phase 6)

| File | ID | Level | Description |
|------|-----|-------|-------------|
| `brute-force-attempt.yaml` | phaseone.auth.brute_force | high | 5+ auth failures in 5 min |
| `rapid-tool-calls.yaml` | phaseone.agent.rapid_tools | medium | 50+ tool calls in 1 min |
| `multi-domain-access.yaml` | phaseone.network.multi_domain | medium | 10+ distinct domains in 5 min |
| `high-injection-average.yaml` | phaseone.injection.high_average | high | Avg injection score > 0.5 |
| `approval-timeout-burst.yaml` | phaseone.approval.timeout_burst | high | 3+ approval timeouts in 10 min |

---

## Event Fields

Common fields available for matching:

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | Event category |
| `tool_name` | string | Tool being called |
| `decision` | string | `allow` \| `deny` \| `approval_required` |
| `decision_reason` | string | Why decision was made |
| `domain` | string | Target domain for network calls |
| `destination` | string | Target destination |
| `injection_score` | number | 0-1 injection likelihood |
| `canary` | boolean/string | Canary trigger info |
| `a2a_trust` | string | A2A trust level |
| `agent_id` | string | Agent identifier |
| `session_id` | string | Session identifier |
| `timestamp` | number | Event timestamp (ms) |
| `metadata.*` | various | Additional event metadata |

---

## CLI Commands

```bash
# List all rules
npm run phaseone -- rules

# List rules as JSON
npm run phaseone -- rules --json

# Evaluate rules against an event
npm run phaseone -- rules evaluate --event '{"tool_name":"run_shell","decision":"deny"}'

# Evaluate from a file
npm run phaseone -- rules evaluate --file event.json

# Custom rules directory
npm run phaseone -- rules --dir ./custom-rules
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/phaseone/rules` | List all rules with hit counts |
| POST | `/v1/phaseone/rules/evaluate` | Evaluate rules against event |

---

## Custom Rules

Create new rule files in the rules directory:

1. Create `rules/my-custom-rule.yaml`
2. Follow the rule structure above
3. Restart gateway or call `resetRulesCache()` to reload

---

## Tuning Guide

See [`docs/rules-tuning.md`](../docs/rules-tuning.md) for:
- Adjusting thresholds
- Handling false positives
- Creating organization-specific rules
- Integration with SIEM exports

---

**DEFENSIVE ONLY** — no exploit content, attack patterns, or offensive tooling.

**Veracity Integrity LLC** · https://VeracityIntegrity.com
