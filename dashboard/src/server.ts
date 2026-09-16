import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { serveStatic } from '@hono/node-server/serve-static';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const GATEWAY_URL = process.env.GATEWAY_URL ?? 'http://gateway:8080';
const PORT = Number(process.env.DASHBOARD_PORT ?? 3000);

const app = new Hono();

async function gw(path: string, init?: RequestInit) {
  const res = await fetch(`${GATEWAY_URL}${path}`, {
    ...init,
    headers: {
      'content-type': 'application/json',
      ...(init?.headers ?? {}),
    },
  });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

app.get('/api/stats', async (c) => {
  const { status, data } = await gw('/v1/phaseone/stats');
  return c.json(data, status as 200);
});

app.get('/api/incidents', async (c) => {
  const { status, data } = await gw('/v1/phaseone/incidents');
  return c.json(data, status as 200);
});

app.get('/api/approvals', async (c) => {
  const q = c.req.query('status') ? `?status=${c.req.query('status')}` : '?status=pending';
  const { status, data } = await gw(`/v1/phaseone/approvals${q}`);
  return c.json(data, status as 200);
});

app.post('/api/approvals/:id/approve', async (c) => {
  const { status, data } = await gw(`/v1/phaseone/approvals/${c.req.param('id')}/approve`, {
    method: 'POST',
    body: JSON.stringify({ resolved_by: 'dashboard-ui' }),
  });
  return c.json(data, status as 200);
});

app.post('/api/approvals/:id/deny', async (c) => {
  const { status, data } = await gw(`/v1/phaseone/approvals/${c.req.param('id')}/deny`, {
    method: 'POST',
    body: JSON.stringify({ resolved_by: 'dashboard-ui' }),
  });
  return c.json(data, status as 200);
});

app.get('/api/sessions/:id/timeline', async (c) => {
  const { status, data } = await gw(`/v1/phaseone/sessions/${c.req.param('id')}/timeline`);
  return c.json(data, status as 200);
});

app.get('/', (c) => {
  const html = readFileSync(join(__dirname, '../public/index.html'), 'utf8');
  return c.html(html);
});

app.use('/static/*', serveStatic({ root: join(__dirname, '../public') }));

console.log(`PhaseOne10841 dashboard on :${PORT} (gateway=${GATEWAY_URL})`);
serve({ fetch: app.fetch, port: PORT, hostname: '0.0.0.0' });
