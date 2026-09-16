# Reverse proxy + TLS (Caddy)

**Veracity Integrity LLC** · https://VeracityIntegrity.com

Do **not** expose gateway `:8080` or dashboard `:3000` beyond localhost on a shared network. Put TLS in front.

## Quick start (local)

After the base stack is healthy (`GET /healthz`, `GET /readyz`):

```bash
docker compose -f docker-compose.yml -f docker-compose.proxy.yml up -d
```

Then open:

| URL | Backend |
|-----|---------|
| https://phaseone.localhost | Dashboard (MFA UI) |
| https://gateway.phaseone.localhost | Gateway API |

Caddy uses an **internal CA** for `*.localhost`. Trust the local CA once in your OS/browser (Caddy prints guidance on first TLS handshake).

Set when serving over HTTPS:

```bash
PHASEONE_SECURE_COOKIES=true
```

Recreate the dashboard container after changing that env var.

## Files

| File | Role |
|------|------|
| `docker-compose.proxy.yml` | Adds `caddy` service (ports 80/443) |
| `deploy/caddy/Caddyfile` | Routes + `tls internal` for lab |

## Production notes

1. Replace `phaseone.localhost` with your real hostname in `deploy/caddy/Caddyfile`.
2. Uncomment the global `email …` block for Let's Encrypt ACME.
3. Keep origin ports bound to `127.0.0.1` (or remove host port publishes) so only Caddy is public.
4. Prefer SMTP MFA (`SMTP_FROM=noreply@clovisstar.com`) before exposing the dashboard.

## Verify

```bash
curl -sk https://phaseone.localhost/healthz
curl -sk https://gateway.phaseone.localhost/healthz
```
