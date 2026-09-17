/**
 * PhaseOne10841 Gatekeeper Worker
 * Main orchestration service — evaluates playbooks, executes actions.
 * 
 * DEFENSIVE ONLY — no exploit tooling.
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

import type {
  GatekeeperConfig,
  GatekeeperEvent,
  GatekeeperState,
  PlaybookExecution,
  PendingConfirmation,
  Playbook,
} from './types.js';
import { loadPlaybooks, resetPlaybooksCache } from './playbooks.js';
import { matchAllPlaybooks, recordPlaybookExecution, __testResetMatcher } from './matcher.js';
import {
  executeAction,
  listRuntimeOverrides,
  getDashboardNotifications,
  clearExpiredOverrides,
  __testResetActions,
} from './actions.js';
import { recordAudit } from '../../shared/src/audit.js';

const MAX_RECENT_ACTIONS = 100;

interface WorkerState {
  enabled: boolean;
  dryRun: boolean;
  lastRunAt: string | null;
  executionsCount: number;
  recentActions: PlaybookExecution[];
  pendingConfirmations: PendingConfirmation[];
  eventQueue: GatekeeperEvent[];
  isRunning: boolean;
}

const state: WorkerState = {
  enabled: false,
  dryRun: true,
  lastRunAt: null,
  executionsCount: 0,
  recentActions: [],
  pendingConfirmations: [],
  eventQueue: [],
  isRunning: false,
};

export function loadGatekeeperConfig(): GatekeeperConfig {
  return {
    enabled: (process.env.PHASEONE_GATEKEEPER_ENABLED ?? 'false').toLowerCase() === 'true',
    dry_run: (process.env.PHASEONE_GATEKEEPER_DRY_RUN ?? 'true').toLowerCase() !== 'false',
    playbooks_dir: process.env.PHASEONE_PLAYBOOKS_DIR ?? './playbooks',
    poll_interval_ms: Number(process.env.PHASEONE_GATEKEEPER_POLL_MS ?? 5000),
    event_window_ms: Number(process.env.PHASEONE_GATEKEEPER_EVENT_WINDOW_MS ?? 60000),
    webhook_url: process.env.PHASEONE_GATEKEEPER_WEBHOOK_URL ?? process.env.PHASEONE_ALERT_WEBHOOK_URL,
    max_recent_actions: Number(process.env.PHASEONE_GATEKEEPER_MAX_ACTIONS ?? MAX_RECENT_ACTIONS),
    confirmation_timeout_ms: Number(process.env.PHASEONE_GATEKEEPER_CONFIRM_TIMEOUT_MS ?? 600000),
  };
}

export function getGatekeeperState(): GatekeeperState {
  return {
    enabled: state.enabled,
    dry_run: state.dryRun,
    last_run_at: state.lastRunAt ?? undefined,
    executions_count: state.executionsCount,
    pending_confirmations: [...state.pendingConfirmations],
    recent_actions: [...state.recentActions],
  };
}

export function setGatekeeperEnabled(enabled: boolean): void {
  state.enabled = enabled;
}

export function setGatekeeperDryRun(dryRun: boolean): void {
  state.dryRun = dryRun;
}

export function queueEvent(event: GatekeeperEvent): void {
  state.eventQueue.push(event);
  if (state.eventQueue.length > 1000) {
    state.eventQueue.shift();
  }
}

export async function processEvent(
  event: GatekeeperEvent,
  opts?: { dryRunOverride?: boolean; playbooksDir?: string }
): Promise<PlaybookExecution[]> {
  const cfg = loadGatekeeperConfig();
  const dryRun = opts?.dryRunOverride ?? state.dryRun;
  const playbooks = loadPlaybooks(opts?.playbooksDir ?? cfg.playbooks_dir);
  
  const matches = matchAllPlaybooks(playbooks, event);
  const executions: PlaybookExecution[] = [];
  
  for (const { playbook, eventsInWindow } of matches) {
    const execution = await executePlaybook(playbook, event, dryRun);
    execution.trigger_event.metadata = {
      ...execution.trigger_event.metadata,
      events_in_window: eventsInWindow,
    };
    executions.push(execution);
    recordPlaybookExecution(playbook.id);
  }
  
  state.recentActions.unshift(...executions);
  if (state.recentActions.length > cfg.max_recent_actions) {
    state.recentActions.length = cfg.max_recent_actions;
  }
  
  state.executionsCount += executions.length;
  state.lastRunAt = new Date().toISOString();
  
  return executions;
}

async function executePlaybook(
  playbook: Playbook,
  event: GatekeeperEvent,
  dryRun: boolean
): Promise<PlaybookExecution> {
  const execution: PlaybookExecution = {
    playbook_id: playbook.id,
    playbook_name: playbook.name,
    tier: playbook.tier,
    trigger_event: event,
    matched_at: new Date().toISOString(),
    dry_run: dryRun,
    actions: [],
    actor: 'gatekeeper',
  };
  
  for (const action of playbook.actions) {
    const actionWithPlaybookId = {
      ...action,
      params: {
        ...action.params,
        playbook_id: playbook.id,
      },
    };
    
    const result = await executeAction(actionWithPlaybookId, event, dryRun);
    execution.actions.push(result);
    
    if (result.requires_confirmation && !result.confirmed) {
      const pending: PendingConfirmation = {
        id: `confirm-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        playbook_id: playbook.id,
        action_type: action.type,
        params: action.params,
        created_at: new Date().toISOString(),
        expires_at: new Date(Date.now() + (loadGatekeeperConfig().confirmation_timeout_ms)).toISOString(),
        trigger_event: event,
      };
      state.pendingConfirmations.push(pending);
    }
  }
  
  if (!dryRun) {
    await recordAudit({
      actor_email: 'gatekeeper',
      action: 'playbook.executed',
      resource: playbook.id,
      detail: {
        playbook_name: playbook.name,
        tier: playbook.tier,
        event_type: event.event_type,
        rule_id: event.rule_id,
        actions_count: execution.actions.length,
        success_count: execution.actions.filter(a => a.ok).length,
      },
    });
  }
  
  return execution;
}

export async function confirmPendingAction(
  confirmationId: string,
  approvedBy: string
): Promise<{ ok: boolean; execution?: PlaybookExecution; error?: string }> {
  const idx = state.pendingConfirmations.findIndex(p => p.id === confirmationId);
  if (idx === -1) {
    return { ok: false, error: 'Confirmation not found' };
  }
  
  const pending = state.pendingConfirmations[idx];
  
  if (new Date(pending.expires_at) < new Date()) {
    state.pendingConfirmations.splice(idx, 1);
    return { ok: false, error: 'Confirmation expired' };
  }
  
  state.pendingConfirmations.splice(idx, 1);
  
  const playbook = loadPlaybooks().find(p => p.id === pending.playbook_id);
  if (!playbook) {
    return { ok: false, error: 'Playbook not found' };
  }
  
  const action = playbook.actions.find(a => a.type === pending.action_type);
  if (!action) {
    return { ok: false, error: 'Action not found in playbook' };
  }
  
  const confirmedAction = {
    ...action,
    requires_confirmation: false,
    params: pending.params,
  };
  
  const result = await executeAction(confirmedAction, pending.trigger_event, false);
  
  const execution: PlaybookExecution = {
    playbook_id: playbook.id,
    playbook_name: playbook.name,
    tier: playbook.tier,
    trigger_event: pending.trigger_event,
    matched_at: new Date().toISOString(),
    dry_run: false,
    actions: [{ ...result, confirmed: true }],
    actor: approvedBy,
  };
  
  state.recentActions.unshift(execution);
  state.executionsCount++;
  
  await recordAudit({
    actor_email: approvedBy,
    action: 'gatekeeper.confirm',
    resource: confirmationId,
    detail: {
      playbook_id: playbook.id,
      action_type: pending.action_type,
      ok: result.ok,
    },
  });
  
  return { ok: result.ok, execution };
}

export async function denyPendingAction(
  confirmationId: string,
  deniedBy: string
): Promise<{ ok: boolean; error?: string }> {
  const idx = state.pendingConfirmations.findIndex(p => p.id === confirmationId);
  if (idx === -1) {
    return { ok: false, error: 'Confirmation not found' };
  }
  
  const pending = state.pendingConfirmations[idx];
  state.pendingConfirmations.splice(idx, 1);
  
  await recordAudit({
    actor_email: deniedBy,
    action: 'gatekeeper.deny_confirm',
    resource: confirmationId,
    detail: {
      playbook_id: pending.playbook_id,
      action_type: pending.action_type,
    },
  });
  
  return { ok: true };
}

export async function runGatekeeperCycle(
  opts?: { dryRunOverride?: boolean; playbooksDir?: string }
): Promise<{ processed: number; executions: PlaybookExecution[] }> {
  if (state.isRunning) {
    return { processed: 0, executions: [] };
  }
  
  state.isRunning = true;
  const allExecutions: PlaybookExecution[] = [];
  
  try {
    const events = [...state.eventQueue];
    state.eventQueue = [];
    
    for (const event of events) {
      const executions = await processEvent(event, opts);
      allExecutions.push(...executions);
    }
    
    cleanupExpiredConfirmations();
    clearExpiredOverrides();
    
    return { processed: events.length, executions: allExecutions };
  } finally {
    state.isRunning = false;
  }
}

function cleanupExpiredConfirmations(): void {
  const now = new Date();
  state.pendingConfirmations = state.pendingConfirmations.filter(
    p => new Date(p.expires_at) > now
  );
}

export function getGatekeeperStatus(): {
  state: GatekeeperState;
  config: GatekeeperConfig;
  overrides: Record<string, unknown>;
  notifications: typeof getDashboardNotifications extends () => infer R ? R : never;
  queue_size: number;
} {
  return {
    state: getGatekeeperState(),
    config: loadGatekeeperConfig(),
    overrides: listRuntimeOverrides(),
    notifications: getDashboardNotifications(),
    queue_size: state.eventQueue.length,
  };
}

export function convertRuleHitToEvent(hit: {
  rule_id: string;
  title: string;
  level: string;
  matched: Record<string, unknown>;
}, context: {
  event_type?: string;
  agent_id?: string;
  session_id?: string;
  decision?: string;
}): GatekeeperEvent {
  return {
    id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    event_type: context.event_type ?? 'rule.hit',
    rule_id: hit.rule_id,
    rule_title: hit.title,
    severity: hit.level,
    agent_id: context.agent_id,
    session_id: context.session_id,
    decision: context.decision,
    timestamp: Date.now(),
    metadata: hit.matched,
  };
}

export function __testResetWorker(): void {
  state.enabled = false;
  state.dryRun = true;
  state.lastRunAt = null;
  state.executionsCount = 0;
  state.recentActions = [];
  state.pendingConfirmations = [];
  state.eventQueue = [];
  state.isRunning = false;
  resetPlaybooksCache();
  __testResetMatcher();
  __testResetActions();
}
