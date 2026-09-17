/**
 * PhaseOne10841 Gatekeeper Action Executors
 * Execute allowlisted defensive actions — NEVER shell out arbitrarily.
 * 
 * DEFENSIVE ONLY — no exploit tooling.
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

import type {
  GatekeeperActionType,
  PlaybookAction,
  GatekeeperActionResult,
  GatekeeperEvent,
} from './types.js';
import { recordAudit } from '../../shared/src/audit.js';
import { sendAlert, type AlertPayload } from '../../shared/src/alerting.js';
import { rotateCanary } from '../../canaries/src/manager.js';
import { resetRulesCache } from '../../rules/src/engine.js';

const runtimeOverrides = new Map<string, unknown>();
const dashboardNotifications: Array<{
  id: string;
  message: string;
  severity: string;
  playbook_id: string;
  created_at: string;
}> = [];
const MAX_NOTIFICATIONS = 100;

type ActionExecutor = (
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
) => Promise<GatekeeperActionResult>;

async function executeEmitAlert(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const payload: AlertPayload = {
    event: `gatekeeper.${event.event_type}`,
    severity: (event.severity as 'high' | 'critical') ?? 'high',
    message: (action.params?.message as string) ?? `Gatekeeper triggered: ${event.event_type}`,
    agent_id: event.agent_id,
    session_id: event.session_id,
    detail: {
      rule_id: event.rule_id,
      playbook_action: 'emit_alert',
      dry_run: dryRun,
      ...event.metadata,
    },
  };
  
  if (dryRun) {
    return {
      action_type: 'emit_alert',
      ok: true,
      dry_run: true,
      detail: `Would send alert: ${payload.message}`,
    };
  }
  
  const result = await sendAlert(payload);
  return {
    action_type: 'emit_alert',
    ok: result.ok,
    dry_run: false,
    detail: result.ok ? 'Alert sent' : `Alert failed: ${result.error}`,
    error: result.error,
  };
}

async function executeWriteAudit(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const entry = {
    actor_email: 'gatekeeper',
    action: (action.params?.action as string) ?? 'gatekeeper.auto_action',
    resource: event.rule_id ?? event.event_type,
    detail: {
      event_type: event.event_type,
      rule_id: event.rule_id,
      severity: event.severity,
      agent_id: event.agent_id,
      dry_run: dryRun,
      ...event.metadata,
    },
  };
  
  if (dryRun) {
    return {
      action_type: 'write_audit',
      ok: true,
      dry_run: true,
      detail: `Would write audit: ${entry.action}`,
    };
  }
  
  await recordAudit(entry);
  return {
    action_type: 'write_audit',
    ok: true,
    dry_run: false,
    detail: `Audit recorded: ${entry.action}`,
  };
}

async function executeDashboardNotify(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const notification = {
    id: `notif-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    message: (action.params?.message as string) ?? `Gatekeeper: ${event.event_type}`,
    severity: event.severity ?? 'medium',
    playbook_id: (action.params?.playbook_id as string) ?? 'unknown',
    created_at: new Date().toISOString(),
  };
  
  if (dryRun) {
    return {
      action_type: 'dashboard_notify',
      ok: true,
      dry_run: true,
      detail: `Would notify dashboard: ${notification.message}`,
    };
  }
  
  dashboardNotifications.unshift(notification);
  if (dashboardNotifications.length > MAX_NOTIFICATIONS) {
    dashboardNotifications.length = MAX_NOTIFICATIONS;
  }
  
  return {
    action_type: 'dashboard_notify',
    ok: true,
    dry_run: false,
    detail: `Dashboard notified: ${notification.message}`,
  };
}

async function executeTightenRateLimit(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const factor = (action.params?.factor as number) ?? 0.5;
  const duration_ms = (action.params?.duration_ms as number) ?? 300000;
  const target = event.agent_id ?? 'global';
  
  const key = `rate_limit:${target}`;
  
  if (dryRun) {
    return {
      action_type: 'tighten_rate_limit',
      ok: true,
      dry_run: true,
      detail: `Would tighten rate limit for ${target} by factor ${factor} for ${duration_ms}ms`,
    };
  }
  
  runtimeOverrides.set(key, {
    factor,
    expires_at: Date.now() + duration_ms,
    set_at: Date.now(),
  });
  
  await recordAudit({
    actor_email: 'gatekeeper',
    action: 'rate_limit.tighten',
    resource: target,
    detail: { factor, duration_ms, event_type: event.event_type },
  });
  
  return {
    action_type: 'tighten_rate_limit',
    ok: true,
    dry_run: false,
    detail: `Rate limit tightened for ${target} by factor ${factor}`,
  };
}

async function executeForceApproval(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const tools = (action.params?.tools as string[]) ?? ['*'];
  const duration_ms = (action.params?.duration_ms as number) ?? 600000;
  const target = event.agent_id ?? 'global';
  
  const key = `force_approval:${target}`;
  
  if (dryRun) {
    return {
      action_type: 'force_approval',
      ok: true,
      dry_run: true,
      detail: `Would force approval for tools ${tools.join(',')} on ${target}`,
    };
  }
  
  runtimeOverrides.set(key, {
    tools,
    expires_at: Date.now() + duration_ms,
    set_at: Date.now(),
  });
  
  await recordAudit({
    actor_email: 'gatekeeper',
    action: 'approval.force',
    resource: target,
    detail: { tools, duration_ms, event_type: event.event_type },
  });
  
  return {
    action_type: 'force_approval',
    ok: true,
    dry_run: false,
    detail: `Forced approval enabled for ${target} on tools: ${tools.join(',')}`,
  };
}

async function executeLowerA2ATrust(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const target = (action.params?.agent_id as string) ?? event.agent_id;
  const newTrust = (action.params?.trust_level as string) ?? 'LOCAL-UNTRUSTED';
  
  if (!target) {
    return {
      action_type: 'lower_a2a_trust',
      ok: false,
      dry_run: dryRun,
      error: 'No agent_id specified',
    };
  }
  
  const key = `a2a_trust:${target}`;
  
  if (dryRun) {
    return {
      action_type: 'lower_a2a_trust',
      ok: true,
      dry_run: true,
      detail: `Would lower A2A trust for ${target} to ${newTrust}`,
    };
  }
  
  runtimeOverrides.set(key, {
    trust_level: newTrust,
    set_at: Date.now(),
  });
  
  await recordAudit({
    actor_email: 'gatekeeper',
    action: 'a2a.trust_lowered',
    resource: target,
    detail: { new_trust: newTrust, event_type: event.event_type },
  });
  
  return {
    action_type: 'lower_a2a_trust',
    ok: true,
    dry_run: false,
    detail: `A2A trust for ${target} lowered to ${newTrust}`,
  };
}

async function executeDenyTool(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const tool = (action.params?.tool as string) ?? event.metadata?.tool_name;
  const duration_ms = (action.params?.duration_ms as number) ?? 600000;
  
  if (!tool) {
    return {
      action_type: 'deny_tool',
      ok: false,
      dry_run: dryRun,
      error: 'No tool specified',
    };
  }
  
  const key = `deny_tool:${tool}`;
  
  if (dryRun) {
    return {
      action_type: 'deny_tool',
      ok: true,
      dry_run: true,
      detail: `Would deny tool ${tool} for ${duration_ms}ms`,
    };
  }
  
  runtimeOverrides.set(key, {
    denied: true,
    expires_at: Date.now() + duration_ms,
    set_at: Date.now(),
  });
  
  await recordAudit({
    actor_email: 'gatekeeper',
    action: 'tool.deny',
    resource: tool,
    detail: { duration_ms, event_type: event.event_type },
  });
  
  return {
    action_type: 'deny_tool',
    ok: true,
    dry_run: false,
    detail: `Tool ${tool} denied for ${duration_ms}ms`,
  };
}

async function executeDenyDomain(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const domain = (action.params?.domain as string) ?? event.metadata?.domain;
  const duration_ms = (action.params?.duration_ms as number) ?? 600000;
  
  if (!domain) {
    return {
      action_type: 'deny_domain',
      ok: false,
      dry_run: dryRun,
      error: 'No domain specified',
    };
  }
  
  const key = `deny_domain:${domain}`;
  
  if (dryRun) {
    return {
      action_type: 'deny_domain',
      ok: true,
      dry_run: true,
      detail: `Would deny domain ${domain} for ${duration_ms}ms`,
    };
  }
  
  runtimeOverrides.set(key, {
    denied: true,
    expires_at: Date.now() + duration_ms,
    set_at: Date.now(),
  });
  
  await recordAudit({
    actor_email: 'gatekeeper',
    action: 'domain.deny',
    resource: domain,
    detail: { duration_ms, event_type: event.event_type },
  });
  
  return {
    action_type: 'deny_domain',
    ok: true,
    dry_run: false,
    detail: `Domain ${domain} denied for ${duration_ms}ms`,
  };
}

async function executeRotateCanary(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const canaryId = (action.params?.canary_id as string) ?? 'api-key';
  
  if (action.requires_confirmation) {
    return {
      action_type: 'rotate_canary',
      ok: false,
      dry_run: dryRun,
      requires_confirmation: true,
      detail: `Canary rotation for ${canaryId} requires human confirmation`,
    };
  }
  
  if (dryRun) {
    return {
      action_type: 'rotate_canary',
      ok: true,
      dry_run: true,
      detail: `Would rotate canary ${canaryId}`,
    };
  }
  
  const result = rotateCanary(canaryId);
  
  if (result.ok) {
    await recordAudit({
      actor_email: 'gatekeeper',
      action: 'canary.rotate',
      resource: canaryId,
      detail: { event_type: event.event_type },
    });
  }
  
  return {
    action_type: 'rotate_canary',
    ok: result.ok,
    dry_run: false,
    detail: result.ok ? `Canary ${canaryId} rotated` : undefined,
    error: result.error,
    confirmed: true,
  };
}

async function executeReloadRules(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  if (action.requires_confirmation) {
    return {
      action_type: 'reload_rules',
      ok: false,
      dry_run: dryRun,
      requires_confirmation: true,
      detail: 'Rules reload requires human confirmation',
    };
  }
  
  if (dryRun) {
    return {
      action_type: 'reload_rules',
      ok: true,
      dry_run: true,
      detail: 'Would reload detection rules',
    };
  }
  
  resetRulesCache();
  
  await recordAudit({
    actor_email: 'gatekeeper',
    action: 'rules.reload',
    detail: { event_type: event.event_type },
  });
  
  return {
    action_type: 'reload_rules',
    ok: true,
    dry_run: false,
    detail: 'Detection rules reloaded',
    confirmed: true,
  };
}

const ACTION_EXECUTORS: Record<GatekeeperActionType, ActionExecutor> = {
  emit_alert: executeEmitAlert,
  write_audit: executeWriteAudit,
  dashboard_notify: executeDashboardNotify,
  tighten_rate_limit: executeTightenRateLimit,
  force_approval: executeForceApproval,
  lower_a2a_trust: executeLowerA2ATrust,
  deny_tool: executeDenyTool,
  deny_domain: executeDenyDomain,
  rotate_canary: executeRotateCanary,
  reload_rules: executeReloadRules,
};

export async function executeAction(
  action: PlaybookAction,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<GatekeeperActionResult> {
  const executor = ACTION_EXECUTORS[action.type];
  if (!executor) {
    return {
      action_type: action.type,
      ok: false,
      dry_run: dryRun,
      error: `Unknown action type: ${action.type}`,
    };
  }
  
  try {
    return await executor(action, event, dryRun);
  } catch (err) {
    return {
      action_type: action.type,
      ok: false,
      dry_run: dryRun,
      error: err instanceof Error ? err.message : 'Unknown error',
    };
  }
}

export function getRuntimeOverride(key: string): unknown | null {
  const override = runtimeOverrides.get(key);
  if (!override) return null;
  
  const data = override as { expires_at?: number };
  if (data.expires_at && Date.now() > data.expires_at) {
    runtimeOverrides.delete(key);
    return null;
  }
  
  return override;
}

export function listRuntimeOverrides(): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  const now = Date.now();
  
  for (const [key, value] of runtimeOverrides) {
    const data = value as { expires_at?: number };
    if (!data.expires_at || now <= data.expires_at) {
      result[key] = value;
    }
  }
  
  return result;
}

export function getDashboardNotifications(limit = 50): typeof dashboardNotifications {
  return dashboardNotifications.slice(0, limit);
}

export function clearExpiredOverrides(): number {
  const now = Date.now();
  let cleared = 0;
  
  for (const [key, value] of runtimeOverrides) {
    const data = value as { expires_at?: number };
    if (data.expires_at && now > data.expires_at) {
      runtimeOverrides.delete(key);
      cleared++;
    }
  }
  
  return cleared;
}

export function __testResetActions(): void {
  runtimeOverrides.clear();
  dashboardNotifications.length = 0;
}
