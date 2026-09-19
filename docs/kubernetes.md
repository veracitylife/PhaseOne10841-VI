# Kubernetes deployment — PhaseOne10841

**PhaseOne10841** is a Defensive Agent Security Gateway (Agent EDR) by [Veracity Integrity LLC](https://VeracityIntegrity.com).

This guide covers Helm and Kustomize manifests under `deploy/`. All defaults are **DEFENSIVE ONLY**: no real credentials ship in chart values or base manifests. Secrets must be supplied at deploy time via `kubectl create secret` or `existingSecret` references.

---

## Prerequisites

| Requirement | Notes |
|-------------|--------|
| Kubernetes | 1.25+ recommended |
| `kubectl` | Configured for your cluster |
| Helm | 3.10+ (optional; Kustomize-only path available) |
| Container image | Build or pull `phaseone:0.1.1` from this repository (`Dockerfile` at repo root) |
| Postgres | **Production:** managed/external Postgres via `DATABASE_URL`. **Lab:** optional embedded Postgres in Helm (`postgres.enabled: true`) |

Build the image locally:

```bash
docker build -t phaseone:0.1.1 .
# Push to your registry and set image.repository / image.tag in values
```

---

## Helm install

Chart path: `deploy/helm/phaseone`

```bash
# Review rendered manifests
helm template phaseone deploy/helm/phaseone --namespace phaseone

# Install with defaults (ClusterIP, ingress disabled, lab Postgres optional)
helm upgrade --install phaseone deploy/helm/phaseone \
  --namespace phaseone \
  --create-namespace
```

### Key values (`values.yaml`)

| Area | Default | Notes |
|------|---------|--------|
| `replicaCount.gateway` / `dashboard` | `1` | Scale per environment |
| `image.repository` / `tag` | `phaseone` / `0.1.1` | Point at your registry in prod |
| `service.gateway` | ClusterIP `:8080` | Gateway API |
| `service.dashboard` | ClusterIP `:3000` | Admin console |
| `ingress.enabled` | `false` | Enable with TLS placeholder secret |
| `postgres.enabled` | `true` | **Lab only** — disable for external DB |
| `existingSecret.name` | `""` | Set to skip chart-created placeholder Secret |
| `retention.enabled` | `true` | Nightly cleanup CronJob |
| `backup.enabled` | `false` | Weekly backup CronJob (enable in prod) |
| `securityContext.runAsNonRoot` | `true` | UID/GID `1000` (node user in image) |

Production example (external Postgres, no embedded DB, ingress off until TLS ready):

```bash
helm upgrade --install phaseone deploy/helm/phaseone \
  --namespace phaseone \
  --set postgres.enabled=false \
  --set existingSecret.name=phaseone-secrets \
  --set backup.enabled=true
```

---

## Secrets (required before production)

**Never commit real secrets to Git or Helm values.**

Create the application secret with `kubectl`:

```bash
kubectl create namespace phaseone

kubectl -n phaseone create secret generic phaseone-secrets \
  --from-literal=PHASEONE_SESSION_SECRET="$(openssl rand -hex 32)" \
  --from-literal=PHASEONE_ADMIN_EMAILS='ops@yourcompany.com' \
  --from-literal=DATABASE_URL='postgres://USER:PASS@your-postgres-host:5432/phaseone' \
  --from-literal=OPENROUTER_API_KEY='' \
  --dry-run=client -o yaml | kubectl apply -f -
```

If using Helm placeholder Secret (`existingSecret.create: true`), patch keys in place:

```bash
kubectl -n phaseone patch secret phaseone-secrets -p '{
  "stringData": {
    "PHASEONE_SESSION_SECRET": "REPLACE",
    "DATABASE_URL": "postgres://USER:PASS@host:5432/phaseone"
  }
}'
```

Reference an existing secret in Helm:

```yaml
existingSecret:
  create: false
  name: phaseone-secrets
```

### Secret keys (via `secretKeyRef`)

| Key | Component | Purpose |
|-----|-----------|---------|
| `DATABASE_URL` | Gateway, CronJobs | Postgres connection |
| `PHASEONE_SESSION_SECRET` | Dashboard | Session signing (run `npm run onboard` locally to generate) |
| `PHASEONE_ADMIN_EMAILS` | Dashboard | MFA admin allowlist |
| `PHASEONE_VIEWER_EMAILS` | Dashboard | Read-only operators |
| `OPENAI_API_KEY` / `OPENROUTER_API_KEY` | Gateway | Upstream LLM (when not `mock`) |
| `SMTP_*` | Dashboard | Email OTP (leave empty for lab fallback file) |
| `PHASEONE_OIDC_*` | Dashboard | Enterprise SSO (optional) |
| `PHASEONE_SIEM_WEBHOOK_URL` / `PHASEONE_ALERT_WEBHOOK_URL` | Gateway | Outbound webhooks |

Non-secret config lives in the ConfigMap (`config` in values / `phaseone-config` in Kustomize).

---

## External Postgres (recommended for production)

Disable embedded Postgres and provide `DATABASE_URL`:

```yaml
postgres:
  enabled: false

database:
  externalUrlSecret:
    name: phaseone-secrets
    key: DATABASE_URL
```

Run migrations after the database is reachable:

```bash
kubectl -n phaseone run migrate --rm -it --restart=Never \
  --image=phaseone:0.1.1 \
  --env="DATABASE_URL=postgres://..." \
  --command -- tsx db/migrate.ts
```

Embedded Postgres (`postgres.enabled: true`) is a single-replica StatefulSet for **lab/dev only**. Patch the `*-postgres` secret password and matching `DATABASE_URL` before use.

---

## Ingress and TLS

Ingress is disabled by default. Enable in values:

```yaml
ingress:
  enabled: true
  className: nginx
  tls:
    - secretName: phaseone-tls-placeholder
      hosts:
        - phaseone.example.com
        - dashboard.phaseone.example.com
```

Create the TLS secret (placeholder name in chart — replace with cert-manager or your CA):

```bash
kubectl -n phaseone create secret tls phaseone-tls-placeholder \
  --cert=fullchain.pem \
  --key=privkey.pem
```

When serving the dashboard over HTTPS, set `PHASEONE_SECURE_COOKIES=true` in the ConfigMap.

---

## Health probes

Gateway liveness/readiness use **`GET /health`** (JSON status including DB check).

Dashboard uses **`GET /healthz`**.

Port-forward to verify:

```bash
kubectl -n phaseone port-forward svc/phaseone-gateway 8080:8080
curl -s http://127.0.0.1:8080/health | jq .
```

---

## CronJobs

| Job | Schedule (default) | Command | Enable |
|-----|-------------------|---------|--------|
| Retention | `0 3 * * *` | `tsx scripts/retention-cleanup.ts --execute` | `retention.enabled: true` |
| Backup | `0 2 * * 0` | `bash scripts/backup.sh` | `backup.enabled: true` |

Both jobs read `DATABASE_URL` from secrets only. Tune `PHASEONE_RETENTION_DAYS` via ConfigMap.

---

## Resource limits

Starting limits (adjust per load):

| Workload | CPU limit | Memory limit |
|----------|-----------|--------------|
| Gateway | 1 | 512Mi |
| Dashboard | 500m | 256Mi |
| Postgres (lab) | 500m | 512Mi |
| CronJobs | 200m | 256Mi |

Set in `values.yaml` under `gateway.resources`, `dashboard.resources`, etc.

---

## Kustomize overlays

Base manifests: `deploy/kustomize/base`  
Overlays: `dev`, `staging`, `prod`

```bash
# Dev (single replica, mock upstream)
kubectl apply -k deploy/kustomize/overlays/dev

# Staging (2 replicas, ingress placeholder)
kubectl apply -k deploy/kustomize/overlays/staging

# Production (3 gateway / 2 dashboard, backup CronJob, external DB patch)
kubectl apply -k deploy/kustomize/overlays/prod
```

Create secrets in each namespace before workloads become ready:

```bash
kubectl -n phaseone create secret generic phaseone-secrets \
  --from-literal=DATABASE_URL='...' \
  --from-literal=PHASEONE_SESSION_SECRET='...' \
  --from-literal=PHASEONE_ADMIN_EMAILS='...'
```

Kustomize base mirrors the Helm output pattern; use `helm template` and `kubectl kustomize` diff when validating changes.

---

## DEFENSIVE ONLY reminder

- PhaseOne10841 is a **defensive** agent security gateway — policy enforcement, audit, canaries, MFA dashboard, and human approval.
- Do not store upstream API keys, SMTP passwords, or session secrets in `values.yaml`, ConfigMaps, or Git.
- Use `existingSecret` / `secretKeyRef` exclusively for sensitive material.
- Replace all `REPLACE_VIA_KUBECTL` placeholders before accepting traffic.

---

## Support

- Product: [PhaseOne10841 on GitHub](https://github.com/veracitylife/PhaseOne10841-VI)
- Company: [Veracity Integrity LLC](https://VeracityIntegrity.com)
- Local ops checklist: `docs/LOCAL_OPS_CHECKLIST.md`
- Operations runbook: `docs/operations.md`

Commercial deployment and hardening assistance: https://VeracityIntegrity.com
