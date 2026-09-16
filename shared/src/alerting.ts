/**
 * High-severity webhook alerting with retry/backoff.
 * Events: canary, injection blocked, approval timeout.
 * DEFENSIVE notifications only.
 */

import { Metrics } from './metrics.js';

export type AlertSeverity = 'high' | 'critical';

export interface AlertPayload {
  event: 'canary' | 'injection_blocked' | 'approval_timeout' | string;
  severity: AlertSeverity;
  message: string;
  agent_id?: string;
  session_id?: string;
  detail?: Record<string, unknown>;
  product?: string;
  vendor?: string;
  site?: string;
  timestamp?: string;
}

export interface AlertConfig {
  webhookUrl?: string;
  maxRetries: number;
  baseDelayMs: number;
  enabled: boolean;
}

export function loadAlertConfig(): AlertConfig {
  const url = process.env.PHASEONE_ALERT_WEBHOOK_URL ?? process.env.ALERT_WEBHOOK_URL ?? '';
  return {
    webhookUrl: url || undefined,
    maxRetries: Number(process.env.PHASEONE_ALERT_MAX_RETRIES ?? 3),
    baseDelayMs: Number(process.env.PHASEONE_ALERT_BASE_DELAY_MS ?? 250),
    enabled: (process.env.PHASEONE_ALERTS_ENABLED ?? (url ? 'true' : 'false')).toLowerCase() !== 'false',
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export async function sendAlert(
  payload: AlertPayload,
  cfg = loadAlertConfig(),
  fetchImpl: typeof fetch = fetch
): Promise<{ ok: boolean; attempts: number; status?: number; error?: string }> {
  if (!cfg.enabled || !cfg.webhookUrl) {
    return { ok: false, attempts: 0, error: 'alerts not configured' };
  }

  const body = {
    ...payload,
    product: payload.product ?? 'PhaseOne10841',
    vendor: payload.vendor ?? 'Veracity Integrity LLC',
    site: payload.site ?? 'https://VeracityIntegrity.com',
    timestamp: payload.timestamp ?? new Date().toISOString(),
  };

  let lastStatus: number | undefined;
  let lastError: string | undefined;
  const max = Math.max(1, cfg.maxRetries);

  for (let attempt = 1; attempt <= max; attempt++) {
    try {
      const res = await fetchImpl(cfg.webhookUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'user-agent': 'PhaseOne10841-Alert/0.4',
        },
        body: JSON.stringify(body),
      });
      lastStatus = res.status;
      if (res.ok) {
        Metrics.alert('sent');
        return { ok: true, attempts: attempt, status: res.status };
      }
      lastError = `HTTP ${res.status}`;
    } catch (err) {
      lastError = err instanceof Error ? err.message : 'fetch failed';
    }
    if (attempt < max) {
      const delay = cfg.baseDelayMs * Math.pow(2, attempt - 1);
      await sleep(delay);
    }
  }

  Metrics.alert('failed');
  return { ok: false, attempts: max, status: lastStatus, error: lastError };
}

/** Fire-and-forget helper for gateway paths */
export function notifyHighSeverity(payload: AlertPayload): void {
  void sendAlert(payload).catch(() => undefined);
}
