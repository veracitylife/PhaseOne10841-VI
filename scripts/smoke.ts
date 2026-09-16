#!/usr/bin/env npx tsx
/**
 * PhaseOne10841 post-compose smoke tests (defensive).
 * Usage: npm run smoke
 * Env: GATEWAY_URL (default http://localhost:8080), DASHBOARD_URL (http://localhost:3000)
 *
 * Checks: healthz/readyz/metrics, mock chat path, policy deny, canary detect.
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */
import { randomUUID } from 'node:crypto';

const GATEWAY = (process.env.GATEWAY_URL ?? 'http://localhost:8080').replace(/\/$/, '');
const DASHBOARD = (process.env.DASHBOARD_URL ?? 'http://localhost:3000').replace(/\/$/, '');

interface Check {
  name: string;
  ok: boolean;
  detail?: string;
}

async function fetchJson(
  url: string,
  init?: RequestInit
): Promise<{ status: number; data: unknown; text: string }> {
  const res = await fetch(url, init);
  const text = await res.text();
  let data: unknown = null;
  try {
    data = JSON.parse(text);
  } catch {
    data = null;
  }
  return { status: res.status, data, text };
}

export async function runSmoke(): Promise<{ ok: boolean; checks: Check[] }> {
  const checks: Check[] = [];
  const sessionId = randomUUID();
  const agentId = 'smoke-agent';

  // 1) Gateway healthz
  try {
    const { status, data } = await fetchJson(`${GATEWAY}/healthz`);
    const body = data as { status?: string };
    checks.push({
      name: 'gateway /healthz',
      ok: status === 200 && body?.status === 'ok',
      detail: `status=${status}`,
    });
  } catch (err) {
    checks.push({
      name: 'gateway /healthz',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 2) Gateway readyz
  try {
    const { status, data } = await fetchJson(`${GATEWAY}/readyz`);
    const body = data as { status?: string };
    checks.push({
      name: 'gateway /readyz',
      ok: status === 200 && body?.status === 'ready',
      detail: `status=${status} body=${body?.status}`,
    });
  } catch (err) {
    checks.push({
      name: 'gateway /readyz',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 3) Metrics
  try {
    const { status, text } = await fetchJson(`${GATEWAY}/metrics`);
    checks.push({
      name: 'gateway /metrics',
      ok: status === 200 && text.includes('phaseone_'),
      detail: `status=${status} bytes=${text.length}`,
    });
  } catch (err) {
    checks.push({
      name: 'gateway /metrics',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 4) Dashboard healthz
  try {
    const { status, data } = await fetchJson(`${DASHBOARD}/healthz`);
    const body = data as { status?: string };
    checks.push({
      name: 'dashboard /healthz',
      ok: status === 200 && body?.status === 'ok',
      detail: `status=${status}`,
    });
  } catch (err) {
    checks.push({
      name: 'dashboard /healthz',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 5) MFA-less / mock upstream chat path
  try {
    const { status, data } = await fetchJson(`${GATEWAY}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'X-PhaseOne-Agent-Id': agentId,
        'X-PhaseOne-Session-Id': sessionId,
      },
      body: JSON.stringify({
        model: 'phaseone-mock',
        messages: [{ role: 'user', content: 'PhaseOne smoke hello' }],
      }),
    });
    const body = data as { phaseone?: { gateway?: string }; choices?: unknown[]; error?: unknown };
    const ok =
      status === 200 &&
      (Boolean(body?.phaseone) || Array.isArray(body?.choices)) &&
      !body?.error;
    checks.push({
      name: 'mock chat /v1/chat/completions',
      ok,
      detail: `status=${status}`,
    });
  } catch (err) {
    checks.push({
      name: 'mock chat /v1/chat/completions',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 6) Policy deny path — shell that should be denied by default
  try {
    const { status, data } = await fetchJson(`${GATEWAY}/v1/phaseone/tools/enforce`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        agent_id: agentId,
        session_id: sessionId,
        tool_name: 'run_shell',
        arguments: { command: 'rm -rf /' },
        wait_for_approval: false,
      }),
    });
    const body = data as { allowed?: boolean; decision?: { action?: string } };
    const denied = status === 403 || body?.allowed === false;
    checks.push({
      name: 'policy deny (dangerous shell)',
      ok: denied,
      detail: `status=${status} allowed=${body?.allowed}`,
    });
  } catch (err) {
    checks.push({
      name: 'policy deny (dangerous shell)',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 7) Canary detect — match endpoint with known marker substring
  try {
    const canaryMarker = 'AKIA_PHASEONE_CANARY_NOTREAL01';
    const { status, data } = await fetchJson(`${GATEWAY}/v1/phaseone/canaries/match`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        text: `uploading key ${canaryMarker} to exfil`,
        session_id: sessionId,
        agent_id: agentId,
      }),
    });
    const body = data as { count?: number; hits?: unknown[] };
    const ok = status === 200 && (body?.count ?? 0) > 0;
    checks.push({
      name: 'canary detect',
      ok,
      detail: `status=${status} count=${body?.count ?? 0}`,
    });
  } catch (err) {
    checks.push({
      name: 'canary detect',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  // 8) Ops endpoint (Phase 5)
  try {
    const { status, data } = await fetchJson(`${GATEWAY}/v1/phaseone/ops`);
    const body = data as { phase?: number; version?: string };
    checks.push({
      name: 'phase5 /v1/phaseone/ops',
      ok: status === 200 && body?.phase === 5,
      detail: `status=${status} version=${body?.version}`,
    });
  } catch (err) {
    checks.push({
      name: 'phase5 /v1/phaseone/ops',
      ok: false,
      detail: err instanceof Error ? err.message : String(err),
    });
  }

  const ok = checks.every((c) => c.ok);
  return { ok, checks };
}

async function main(): Promise<number> {
  console.log('PhaseOne10841 smoke — Veracity Integrity LLC');
  console.log(`Gateway: ${GATEWAY}`);
  console.log(`Dashboard: ${DASHBOARD}`);
  console.log('');
  const { ok, checks } = await runSmoke();
  for (const c of checks) {
    console.log(`${c.ok ? '✓' : '✗'} ${c.name}${c.detail ? ` — ${c.detail}` : ''}`);
  }
  console.log('');
  console.log(ok ? 'SMOKE PASS' : 'SMOKE FAIL');
  console.log('https://VeracityIntegrity.com');
  return ok ? 0 : 1;
}

const isDirect = process.argv[1]?.endsWith('smoke.ts');
if (isDirect) {
  main()
    .then((c) => process.exit(c))
    .catch((err) => {
      console.error(err);
      process.exit(1);
    });
}
