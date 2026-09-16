# Detection rules tuning (PhaseOne10841)

**Veracity Integrity LLC** · https://VeracityIntegrity.com

Walk `rules/*.yaml` against **your real agent tool names** before production alerting.

## Built-in rules

| Rule file | Fires when | Tune by |
|-----------|------------|---------|
| `shell-denied.yaml` | Shell tool blocked / attempted | Default matches `run_shell`, `shell_exec`, `unrestricted_shell`, `raw_shell`, `bash`, `Shell` — add your ids |
| `domain-denied.yaml` | Egress domain denied | Align with policy allowlist domains |
| `injection-blocked.yaml` / `high-injection-score.yaml` | Prompt-injection scanner | Raise `injection_score` threshold if RAG docs are noisy |
| `canary-trigger.yaml` | Canary marker seen | Keep canary values unique to this deploy |
| `a2a-untrusted.yaml` | Untrusted/quarantined A2A | Map to your agent id naming |

Sample rules live in `/rules/*.yaml`. The engine accepts a **list** for `tool_name` (any match).

## Process

1. Point one real agent through the gateway with `UPSTREAM_PROVIDER=mock` (or Ollama after health green).
2. Exercise normal tools; note false positives in dashboard → Detection rules / Audit.
3. Edit rule `match` / `tool_name` fields to your tool names; keep severity high only for canary + secret egress.
4. Only then enable alert webhooks (`PHASEONE_ALERT_WEBHOOK_URL`).

Do **not** weaken canary or secret-egress rules to silence noise — fix tool naming matches instead.

## Related

- Operator checklist: [`RECOMMENDATIONS.md`](./RECOMMENDATIONS.md) item 8
- Policy defaults: `policy/default-policy.yaml` (`run_shell` deny-by-default)
