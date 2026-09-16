/** Shared event and policy types for PhaseOne10841 gateway */

export type EventSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export type EventType =
  | 'chat.completion'
  | 'tool.call'
  | 'tool.result'
  | 'http.request'
  | 'filesystem.access'
  | 'shell.exec'
  | 'mcp.call'
  | 'mcp.denied'
  | 'policy.decision'
  | 'canary.trigger'
  | 'secret.detected'
  | 'secret.blocked'
  | 'prompt_injection.detected'
  | 'prompt_injection.blocked'
  | 'approval.requested'
  | 'approval.resolved'
  | 'approval.expired'
  | 'agent.spawn'
  | 'a2a.message'
  | 'a2a.blocked'
  | 'a2a.quarantined'
  | 'permission.findings'
  | 'lab.detector_hit'
  | 'siem.export'
  | 'siem.webhook'
  | 'session.start'
  | 'session.end';

export type PolicyAction = 'allow' | 'deny' | 'require_approval' | 'quarantine';

export type A2ATrustLevel =
  | 'LOCAL-TRUSTED'
  | 'LOCAL-UNTRUSTED'
  | 'REMOTE-VERIFIED'
  | 'REMOTE-UNKNOWN'
  | 'QUARANTINED';

export type ApprovalRisk = 'low' | 'medium' | 'high' | 'critical';

export interface AgentEvent {
  id?: string;
  session_id: string;
  agent_id: string;
  event_type: EventType;
  severity: EventSeverity;
  timestamp?: string;
  tool_name?: string | null;
  tool_args?: unknown;
  destination?: string | null;
  result?: unknown;
  decision?: PolicyAction | null;
  decision_reason?: string | null;
  metadata?: Record<string, unknown>;
  parent_event_id?: string | null;
}

export interface ApprovalRequest {
  id?: string;
  session_id: string;
  agent_id: string;
  action_type: string;
  payload: unknown;
  status: 'pending' | 'approved' | 'denied' | 'expired';
  reason?: string | null;
  risk?: ApprovalRisk | null;
  note?: string | null;
  resolution_note?: string | null;
  expires_at?: string | null;
  created_at?: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
}

/** Ordered chain step for session replay (Phase 3) */
export interface TimelineStep {
  index: number;
  event_id: string;
  timestamp?: string;
  agent_id: string;
  event_type: EventType;
  severity: EventSeverity;
  tool_name?: string | null;
  /** Redacted args safe for UI/export */
  args_redacted?: unknown;
  destination?: string | null;
  result?: unknown;
  decision?: PolicyAction | null;
  decision_reason?: string | null;
  next_event_id?: string | null;
  parent_event_id?: string | null;
  chain: {
    agent: string;
    tool?: string | null;
    args?: unknown;
    dest?: string | null;
    result?: unknown;
    next?: string | null;
  };
}

export interface PolicyCheckContext {
  agentId: string;
  sessionId: string;
  toolName?: string;
  toolArgs?: unknown;
  domain?: string;
  url?: string;
  method?: string;
  path?: string;
  shellCommand?: string;
  mcpServer?: string;
  mcpTool?: string;
  egressBody?: string;
  spawnDepth?: number;
  actionHint?: string;
}

export interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  ruleId?: string;
  matchedCanaries?: string[];
  matchedSecrets?: string[];
  requireApproval?: boolean;
  risk?: ApprovalRisk;
}
