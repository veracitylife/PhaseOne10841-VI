/**
 * PhaseOne10841 Gatekeeper Types
 * Automated agentic defense orchestration — DEFENSIVE ONLY.
 * 
 * Veracity Integrity LLC · https://VeracityIntegrity.com
 */

export type PlaybookTier = 'observe' | 'contain' | 'harden';

export type GatekeeperActionType =
  // Observe tier — no mutation
  | 'emit_alert'
  | 'write_audit'
  | 'dashboard_notify'
  // Contain tier — temporary restrictions
  | 'tighten_rate_limit'
  | 'force_approval'
  | 'lower_a2a_trust'
  | 'deny_tool'
  | 'deny_domain'
  // Harden tier — persistent changes (may require confirmation)
  | 'rotate_canary'
  | 'reload_rules';

export interface PlaybookMatch {
  rule_id?: string | string[];
  event_type?: string | string[];
  severity?: 'info' | 'low' | 'medium' | 'high' | 'critical' | string[];
  count?: number;
  window_ms?: number;
  agent_id?: string;
  decision?: 'allow' | 'deny' | 'quarantine' | string[];
}

export interface PlaybookAction {
  type: GatekeeperActionType;
  params?: Record<string, unknown>;
  requires_confirmation?: boolean;
}

export interface Playbook {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  tier: PlaybookTier;
  match: PlaybookMatch;
  actions: PlaybookAction[];
  cooldown_ms?: number;
  max_executions_per_window?: number;
}

export interface GatekeeperEvent {
  id: string;
  event_type: string;
  rule_id?: string;
  rule_title?: string;
  severity?: string;
  agent_id?: string;
  session_id?: string;
  decision?: string;
  decision_reason?: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface GatekeeperActionResult {
  action_type: GatekeeperActionType;
  ok: boolean;
  dry_run: boolean;
  detail?: string;
  error?: string;
  requires_confirmation?: boolean;
  confirmed?: boolean;
}

export interface PlaybookExecution {
  playbook_id: string;
  playbook_name: string;
  tier: PlaybookTier;
  trigger_event: GatekeeperEvent;
  matched_at: string;
  dry_run: boolean;
  actions: GatekeeperActionResult[];
  actor: string;
}

export interface GatekeeperState {
  enabled: boolean;
  dry_run: boolean;
  last_run_at?: string;
  executions_count: number;
  pending_confirmations: PendingConfirmation[];
  recent_actions: PlaybookExecution[];
}

export interface PendingConfirmation {
  id: string;
  playbook_id: string;
  action_type: GatekeeperActionType;
  params?: Record<string, unknown>;
  created_at: string;
  expires_at: string;
  trigger_event: GatekeeperEvent;
}

export interface GatekeeperConfig {
  enabled: boolean;
  dry_run: boolean;
  playbooks_dir: string;
  poll_interval_ms: number;
  event_window_ms: number;
  webhook_url?: string;
  max_recent_actions: number;
  confirmation_timeout_ms: number;
}
