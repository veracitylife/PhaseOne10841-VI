/**
 * SIEM / export hooks — JSONL + optional webhook sink.
 * ECS-ish field shape for Splunk/Elastic-friendly ingestion.
 * DEFENSIVE: exports telemetry only; no attack content.
 */

import type { AgentEvent } from '../../shared/src/types.js';
import { redactSecretsDeep } from '../../shared/src/secrets.js';

export interface EcsLikeEvent {
  '@timestamp': string;
  event: {
    id?: string;
    kind: string;
    category: string[];
    type: string[];
    action: string;
    outcome?: string;
    severity?: number;
    reason?: string | null;
  };
  agent: { id: string; type: string; name: string };
  labels: {
    session_id: string;
    product: string;
    vendor: string;
    version: string;
  };
  phaseone: {
    session_id: string;
    agent_id: string;
    event_type: string;
    tool_name?: string | null;
    destination?: string | null;
    decision?: string | null;
    decision_reason?: string | null;
    tool_args?: unknown;
    result?: unknown;
    metadata?: Record<string, unknown>;
    parent_event_id?: string | null;
    canary_signature?: string | null;
  };
  url?: { full?: string; domain?: string };
  message: string;
}

const SEVERITY_MAP: Record<string, number> = {
  info: 1,
  low: 2,
  medium: 4,
  high: 7,
  critical: 9,
};

function outcomeFromDecision(decision?: string | null): string | undefined {
  if (!decision) return undefined;
  if (decision === 'allow') return 'success';
  if (decision === 'deny' || decision === 'quarantine') return 'failure';
  if (decision === 'require_approval') return 'unknown';
  return undefined;
}

function hostFromDest(dest?: string | null): string | undefined {
  if (!dest) return undefined;
  try {
    if (dest.includes('://')) return new URL(dest).hostname;
  } catch {
    /* ignore */
  }
  return dest.split('/')[0] || undefined;
}

/** Map a PhaseOne event to an ECS-ish document (secrets redacted). */
export function toEcsLike(event: AgentEvent, opts?: { version?: string }): EcsLikeEvent {
  const version = opts?.version ?? '0.1.1';
  const ts = event.timestamp ?? new Date().toISOString();
  const args = event.tool_args != null ? redactSecretsDeep(event.tool_args) : undefined;
  const result = event.result != null ? redactSecretsDeep(event.result) : undefined;
  const meta = event.metadata ? redactSecretsDeep(event.metadata) : undefined;
  const canarySignature =
    (meta && typeof meta === 'object' && 'canary_signature' in meta
      ? String((meta as { canary_signature?: unknown }).canary_signature ?? '')
      : '') ||
    (typeof event.metadata?.canary_signature === 'string'
      ? event.metadata.canary_signature
      : null);

  return {
    '@timestamp': ts,
    event: {
      id: event.id,
      kind: 'event',
      category: ['intrusion_detection', 'process'],
      type: [event.event_type.includes('block') || event.decision === 'deny' ? 'denied' : 'info'],
      action: event.event_type,
      outcome: outcomeFromDecision(event.decision),
      severity: SEVERITY_MAP[event.severity] ?? 1,
      reason: event.decision_reason ?? null,
    },
    agent: {
      id: event.agent_id,
      type: 'ai-agent',
      name: event.agent_id,
    },
    labels: {
      session_id: event.session_id,
      product: 'PhaseOne10841',
      vendor: 'Veracity Integrity LLC',
      version,
    },
    phaseone: {
      session_id: event.session_id,
      agent_id: event.agent_id,
      event_type: event.event_type,
      tool_name: event.tool_name ?? null,
      destination: event.destination ?? null,
      decision: event.decision ?? null,
      decision_reason: event.decision_reason ?? null,
      tool_args: args,
      result,
      metadata: meta,
      parent_event_id: event.parent_event_id ?? null,
      canary_signature: canarySignature || null,
    },
    url: event.destination
      ? { full: event.destination, domain: hostFromDest(event.destination) }
      : undefined,
    message: [
      event.event_type,
      event.tool_name,
      event.decision,
      event.decision_reason,
    ]
      .filter(Boolean)
      .join(' · '),
  };
}

/** Serialize events as JSONL (one ECS-ish doc per line). */
export function eventsToJsonl(events: AgentEvent[], opts?: { version?: string }): string {
  return events.map((e) => JSON.stringify(toEcsLike(e, opts))).join('\n') + (events.length ? '\n' : '');
}

export interface WebhookSinkResult {
  ok: boolean;
  status?: number;
  error?: string;
  sent: number;
}

/**
 * POST events to a webhook URL as JSON body:
 * { product, vendor, format: "ecs-ish", events: [...] }
 */
export async function sendWebhookSink(
  url: string,
  events: AgentEvent[],
  opts?: { version?: string; timeoutMs?: number; fetchImpl?: typeof fetch }
): Promise<WebhookSinkResult> {
  if (!url) return { ok: false, error: 'webhook URL not configured', sent: 0 };
  const fetchFn = opts?.fetchImpl ?? fetch;
  const docs = events.map((e) => toEcsLike(e, opts));
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts?.timeoutMs ?? 10_000);
  try {
    const res = await fetchFn(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'user-agent': 'PhaseOne10841-SIEM/0.3 (+https://VeracityIntegrity.com)',
        'x-phaseone-product': 'PhaseOne10841',
        'x-phaseone-vendor': 'Veracity Integrity LLC',
      },
      body: JSON.stringify({
        product: 'PhaseOne10841',
        vendor: 'Veracity Integrity LLC',
        site: 'https://VeracityIntegrity.com',
        format: 'ecs-ish',
        count: docs.length,
        events: docs,
      }),
      signal: controller.signal,
    });
    return { ok: res.ok, status: res.status, sent: docs.length, error: res.ok ? undefined : `HTTP ${res.status}` };
  } catch (err) {
    return {
      ok: false,
      sent: 0,
      error: err instanceof Error ? err.message : 'webhook failed',
    };
  } finally {
    clearTimeout(timer);
  }
}
