# Detection rules tuning (PhaseOne10841)

Walk `rules/*.yaml` against **your real agent tool names** before production alerting.

## Built-in rules
| Rule file | Fires when | Tune by |
|-----------|------------|---------|
| `shell-denied.yaml` | Shell tool blocked / attempted | Match your shell tool ids (`run_terminal`, `bash`, `Shell`, …) |
| `domain-denied.yaml` | Egress domain denied | Align with policy allowlist domains |
| `injection-blocked.yaml` / `high-injection-score.yaml` | Prompt-injection scanner | Raise threshold if RAG docs are noisy |
| `canary-trigger.yaml` | Canary marker seen | Keep canary values unique to this deploy |
| `a2a-untrusted.yaml` | Untrusted/quarantined A2A | Map to your agent id naming |

## Process
1. Point one real agent through the gateway with `UPSTREAM_PROVIDER=mock` or Ollama.
2. Exercise normal tools; note false positives in dashboard → Detection rules / Audit.
3. Edit rule `match` fields to your tool names; keep severity high only for canary + secret egress.
4. Only then enable alert webhooks.

Do **not** weaken canary or secret-egress rules to silence noise — fix tool naming matches instead.
