/**
 * PhaseOne10841 Admin Console — Veracity Integrity LLC
 * MFA (email OTP) gated proxy + RBAC lite (admin vs viewer).
 */
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  loadAuthConfig,
  requestOtp,
  verifyOtp,
  getSession,
  destroySession,
  parseCookies,
  sessionCookieHeader,
  csrfCookieHeader,
  clearSessionCookies,
  validateCsrf,
  __testGetLastOtp,
} from './auth.js';
import { canMutate, type DashboardRole } from '../../shared/src/rbac.js';
import { warnIfWeakSessionSecret } from '../../shared/src/session-secret.js';
import { recordAudit } from '../../shared/src/audit.js';
import {
  SECURITY_HEADERS,
  dashboardContentSecurityPolicy,
  describeCookieDefaults,
} from '../../shared/src/security-headers.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GATEWAY_URL = process.env.GATEWAY_URL ?? 'http://gateway:8080';
const PORT = Number(process.env.DASHBOARD_PORT ?? 3000);
const VERSION = '0.5.1';

const app = new Hono();
const authCfg = loadAuthConfig();

app.use('*', async (c, next) => {
  await next();
  for (const [k, v] of Object.entries(SECURITY_HEADERS)) c.header(k, v);
  c.header('Content-Security-Policy', dashboardContentSecurityPolicy());
  if (c.req.path.startsWith('/api/')) c.header('Cache-Control', 'no-store');
});


async function gw(path: string, init?: RequestInit) {
  const res = await fetch(`${GATEWAY_URL}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  const ct = res.headers.get('content-type') ?? '';
  if (ct.includes('json')) {
    const data = await res.json().catch(() => ({}));
    return { status: res.status, data, raw: null as string | null, contentType: ct };
  }
  const raw = await res.text();
  return { status: res.status, data: null, raw, contentType: ct };
}

type AuthOk = { ok: true; email: string; csrf: string; sessionId: string; role: DashboardRole };
type AuthFail = { ok: false; status: 401 | 403; error: string };

function requireAuth(c: { req: { header: (n: string) => string | undefined } }): AuthOk | AuthFail {
  if (!authCfg.enabled) {
    return { ok: true, email: 'auth-disabled@local', csrf: 'disabled', sessionId: 'disabled', role: 'admin' };
  }
  const cookies = parseCookies(c.req.header('cookie'));
  const session = getSession(cookies[authCfg.cookieName]);
  if (!session) return { ok: false, status: 401, error: 'authentication required' };
  return {
    ok: true,
    email: session.email,
    csrf: session.csrfToken,
    sessionId: session.id,
    role: session.role ?? 'admin',
  };
}

function requireMutatingAuth(c: {
  req: { header: (n: string) => string | undefined };
}): AuthOk | AuthFail {
  const auth = requireAuth(c);
  if (!auth.ok) return auth;
  if (!authCfg.enabled) return auth;
  if (!canMutate(auth.role)) {
    return { ok: false, status: 403, error: 'viewer role is read-only' };
  }
  const cookies = parseCookies(c.req.header('cookie'));
  const session = getSession(cookies[authCfg.cookieName]);
  if (!session) return { ok: false, status: 401, error: 'authentication required' };
  const headerToken = c.req.header('x-csrf-token') ?? c.req.header('x-phaseone-csrf');
  if (!validateCsrf(session, headerToken, cookies[authCfg.csrfCookieName])) {
    return { ok: false, status: 401, error: 'invalid CSRF token' };
  }
  return auth;
}

app.get('/healthz', (c) =>
  c.json({
    status: 'ok',
    service: 'phaseone-dashboard',
    version: VERSION,
    product: 'PhaseOne10841',
    vendor: 'Veracity Integrity LLC',
  })
);

app.get('/readyz', async (c) => {
  try {
    const { status, data } = await gw('/readyz');
    const ready = status === 200 && (data as { status?: string })?.status === 'ready';
    return c.json(
      {
        status: ready ? 'ready' : 'not_ready',
        dashboard: 'ok',
        gateway: data,
        version: VERSION,
      },
      ready ? 200 : 503
    );
  } catch (err) {
    return c.json(
      {
        status: 'not_ready',
        dashboard: 'ok',
        gateway: { error: err instanceof Error ? err.message : 'unreachable' },
        version: VERSION,
      },
      503
    );
  }
});

app.get('/api/health', async (c) => {
  const { status, data } = await gw('/health');
  return c.json(
    {
      dashboard: 'ok',
      version: VERSION,
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
      site: 'https://VeracityIntegrity.com',
      auth_enabled: authCfg.enabled,
      gateway: data,
    },
    status as 200
  );
});

app.get('/api/auth/status', (c) => {
  const auth = requireAuth(c);
  return c.json({
    enabled: authCfg.enabled,
    authenticated: auth.ok,
    email: auth.ok ? auth.email : null,
    role: auth.ok ? auth.role : null,
    csrf: auth.ok ? auth.csrf : null,
    can_mutate: auth.ok ? canMutate(auth.role) : false,
    vendor: 'Veracity Integrity LLC',
  });
});

app.post('/api/auth/request-otp', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { email?: string };
  if (!body.email) return c.json({ ok: false, error: 'email required' }, 400);
  const result = await requestOtp(body.email, authCfg);
  if (!result.ok) {
    return c.json(result, result.retryAfterMs ? 429 : 403);
  }
  return c.json({
    ok: true,
    channel: result.channel,
    message:
      result.channel === 'fallback'
        ? 'OTP logged to server console/fallback file (SMTP not configured)'
        : 'OTP sent to email',
  });
});

app.post('/api/auth/login', async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { email?: string; code?: string };
  if (!body.email || !body.code) return c.json({ ok: false, error: 'email and code required' }, 400);
  const result = verifyOtp(body.email, body.code, authCfg);
  if (!result.ok || !result.session) {
    return c.json({ ok: false, error: result.error }, 401);
  }
  await recordAudit({
    actor_email: result.session.email,
    action: 'login',
    detail: { role: result.session.role },
    ip: c.req.header('x-forwarded-for') ?? undefined,
  }).catch(() => undefined);
  const headers = new Headers({ 'content-type': 'application/json' });
  headers.append('set-cookie', sessionCookieHeader(result.session, authCfg));
  headers.append('set-cookie', csrfCookieHeader(result.session, authCfg));
  return new Response(
    JSON.stringify({
      ok: true,
      email: result.session.email,
      role: result.session.role,
      csrf: result.session.csrfToken,
      can_mutate: canMutate(result.session.role),
    }),
    { status: 200, headers }
  );
});

app.post('/api/auth/logout', async (c) => {
  const cookies = parseCookies(c.req.header('cookie'));
  const sid = cookies[authCfg.cookieName];
  const session = getSession(sid);
  if (session) {
    await recordAudit({ actor_email: session.email, action: 'logout' }).catch(() => undefined);
  }
  if (sid) destroySession(sid);
  const headers = new Headers({ 'content-type': 'application/json' });
  for (const h of clearSessionCookies(authCfg)) headers.append('set-cookie', h);
  return new Response(JSON.stringify({ ok: true }), { status: 200, headers });
});

app.get('/api/auth/test/last-otp', (c) => {
  if (!authCfg.testMode) return c.json({ error: 'not available' }, 404);
  return c.json({ otp: __testGetLastOtp() });
});

function gate(c: Parameters<typeof requireAuth>[0]) {
  return requireAuth(c);
}

const proxyGet = (
  apiPath: string,
  gwPath: string | ((c: { req: { param: (n: string) => string; query: (n: string) => string | undefined } }) => string)
) => {
  app.get(apiPath, async (c) => {
    const auth = gate(c);
    if (!auth.ok) return c.json({ error: auth.error }, 401);
    const path = typeof gwPath === 'function' ? gwPath(c as never) : gwPath;
    const q = c.req.url.includes('?') ? '?' + c.req.url.split('?')[1] : '';
    const { status, data, raw, contentType } = await gw(path.includes('?') ? path : path + q);
    if (raw != null && contentType && !contentType.includes('json')) {
      return c.body(raw, status as 200, { 'content-type': contentType });
    }
    return c.json(data, status as 200);
  });
};

proxyGet('/api/stats', '/v1/phaseone/stats');
proxyGet('/api/incidents', '/v1/phaseone/incidents');
proxyGet('/api/approvals', (c) => {
  const s = c.req.query('status');
  return `/v1/phaseone/approvals${s ? `?status=${s}` : '?status=pending'}`;
});
proxyGet('/api/agents', '/v1/phaseone/agents');
proxyGet('/api/sessions', '/v1/phaseone/sessions');
proxyGet('/api/canaries', '/v1/phaseone/canaries/manage');
proxyGet('/api/policy', '/v1/phaseone/policy');
proxyGet('/api/policy/raw', '/v1/phaseone/policy/raw');
proxyGet('/api/secrets/patterns', '/v1/phaseone/secrets/patterns');
proxyGet('/api/health/detail', '/v1/phaseone/health/detail');
proxyGet('/api/export/preview', '/v1/phaseone/export/preview');
proxyGet('/api/permissions', '/v1/phaseone/permissions/analyze?agent_id=policy-default');
proxyGet('/api/audit', '/v1/phaseone/audit');
proxyGet('/api/rules', '/v1/phaseone/rules');
proxyGet('/api/a2a/trust', '/v1/phaseone/a2a/trust');
proxyGet('/api/alerts/config', '/v1/phaseone/alerts/config');
proxyGet('/api/metrics', '/v1/phaseone/metrics');
proxyGet('/api/ops', '/v1/phaseone/ops');
proxyGet('/api/retention', '/v1/phaseone/retention');
proxyGet('/api/rate-limits', '/v1/phaseone/rate-limits');

app.get('/api/security/cookies', (c) => {
  const auth = gate(c);
  if (!auth.ok) return c.json({ error: auth.error }, 401);
  return c.json(describeCookieDefaults(authCfg.secureCookies));
});


app.get('/api/sessions/:id/timeline', async (c) => {
  const auth = gate(c);
  if (!auth.ok) return c.json({ error: auth.error }, 401);
  const agent = c.req.query('agent_id');
  const q = agent ? `?agent_id=${encodeURIComponent(agent)}` : '';
  const { status, data } = await gw(`/v1/phaseone/sessions/${c.req.param('id')}/timeline${q}`);
  return c.json(data, status as 200);
});

app.get('/api/sessions/:id/replay', async (c) => {
  const auth = gate(c);
  if (!auth.ok) return c.json({ error: auth.error }, 401);
  const agent = c.req.query('agent_id');
  const q = agent ? `?agent_id=${encodeURIComponent(agent)}` : '';
  const { status, data } = await gw(`/v1/phaseone/sessions/${c.req.param('id')}/replay${q}`);
  return c.json(data, status as 200);
});

app.get('/api/sessions/:id/export.jsonl', async (c) => {
  const auth = gate(c);
  if (!auth.ok) return c.json({ error: auth.error }, 401);
  await recordAudit({
    actor_email: auth.email,
    action: 'export',
    resource: `session:${c.req.param('id')}`,
  }).catch(() => undefined);
  const { status, raw, contentType } = await gw(`/v1/phaseone/sessions/${c.req.param('id')}/export.jsonl`);
  return c.body(raw ?? '', status as 200, {
    'content-type': contentType || 'application/x-ndjson',
    'content-disposition': `attachment; filename="session-${c.req.param('id')}.jsonl"`,
  });
});

app.get('/api/export/events.jsonl', async (c) => {
  const auth = gate(c);
  if (!auth.ok) return c.json({ error: auth.error }, 401);
  await recordAudit({ actor_email: auth.email, action: 'export', resource: 'events.jsonl' }).catch(
    () => undefined
  );
  const q = c.req.url.includes('?') ? '?' + c.req.url.split('?')[1] : '';
  const { status, raw, contentType } = await gw(`/v1/phaseone/export/events.jsonl${q}`);
  return c.body(raw ?? '', status as 200, {
    'content-type': contentType || 'application/x-ndjson',
    'content-disposition': 'attachment; filename="phaseone-events.jsonl"',
  });
});

app.get('/api/events', async (c) => {
  const auth = gate(c);
  if (!auth.ok) return c.json({ error: auth.error }, 401);
  const q = c.req.url.includes('?') ? '?' + c.req.url.split('?')[1] : '';
  const { status, data } = await gw(`/v1/phaseone/events${q}`);
  return c.json(data, status as 200);
});

app.post('/api/approvals/:id/approve', async (c) => {
  const auth = requireMutatingAuth(c);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  const body = await c.req.json().catch(() => ({}));
  const { status, data } = await gw(`/v1/phaseone/approvals/${c.req.param('id')}/approve`, {
    method: 'POST',
    body: JSON.stringify({ ...body, resolved_by: auth.email }),
  });
  await recordAudit({
    actor_email: auth.email,
    action: 'approve',
    resource: c.req.param('id'),
  }).catch(() => undefined);
  return c.json(data, status as 200);
});

app.post('/api/approvals/:id/deny', async (c) => {
  const auth = requireMutatingAuth(c);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  const body = await c.req.json().catch(() => ({}));
  const { status, data } = await gw(`/v1/phaseone/approvals/${c.req.param('id')}/deny`, {
    method: 'POST',
    body: JSON.stringify({ ...body, resolved_by: auth.email }),
  });
  await recordAudit({
    actor_email: auth.email,
    action: 'deny',
    resource: c.req.param('id'),
  }).catch(() => undefined);
  return c.json(data, status as 200);
});

app.post('/api/export/webhook', async (c) => {
  const auth = requireMutatingAuth(c);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  const body = await c.req.json().catch(() => ({}));
  const { status, data } = await gw('/v1/phaseone/export/webhook', {
    method: 'POST',
    body: JSON.stringify(body),
  });
  await recordAudit({ actor_email: auth.email, action: 'export', resource: 'webhook' }).catch(
    () => undefined
  );
  return c.json(data, status as 200);
});

app.put('/api/policy', async (c) => {
  const auth = requireMutatingAuth(c);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const { status, data } = await gw('/v1/phaseone/policy', {
    method: 'PUT',
    body: JSON.stringify({ ...body, actor_email: auth.email }),
  });
  return c.json(data, status as 200);
});

app.post('/api/a2a/trust', async (c) => {
  const auth = requireMutatingAuth(c);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  const body = await c.req.json().catch(() => ({}));
  const { status, data } = await gw('/v1/phaseone/a2a/trust', {
    method: 'POST',
    body: JSON.stringify(body),
  });
  await recordAudit({
    actor_email: auth.email,
    action: 'a2a.trust',
    detail: body as Record<string, unknown>,
  }).catch(() => undefined);
  return c.json(data, status as 200);
});

app.post('/api/canaries/rotate', async (c) => {
  const auth = requireMutatingAuth(c);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const { status, data } = await gw('/v1/phaseone/canaries/rotate', {
    method: 'POST',
    body: JSON.stringify({ ...body, actor_email: auth.email }),
  });
  return c.json(data, status as 200);
});

app.post('/api/alerts/test', async (c) => {
  const auth = requireMutatingAuth(c);
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);
  const body = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
  const { status, data } = await gw('/v1/phaseone/alerts/test', {
    method: 'POST',
    body: JSON.stringify({ ...body, actor_email: auth.email }),
  });
  return c.json(data, status as 200);
});

app.get('/', (c) => {
  const html = readFileSync(join(__dirname, '../public/index.html'), 'utf8');
  return c.html(html);
});

warnIfWeakSessionSecret(process.env.PHASEONE_SESSION_SECRET);
if (!process.env.SMTP_HOST) {
  console.warn(
    '[PhaseOne MFA] ⚠ LAB-ONLY: SMTP_HOST unset — OTP falls back to console/file. '
      + 'Set SMTP_* (From: noreply@clovisstar.com) before shared/production use.'
  );
}
console.log(`PhaseOne10841 Admin Console v${VERSION} — Veracity Integrity LLC`);
console.log(
  `Dashboard on :${PORT} (gateway=${GATEWAY_URL}) auth=${authCfg.enabled} · https://VeracityIntegrity.com`
);
serve({ fetch: app.fetch, port: PORT, hostname: '0.0.0.0' });
