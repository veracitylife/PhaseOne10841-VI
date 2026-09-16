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
  | 'policy.decision'
  | 'canary.trigger'
  | 'secret.detected'
  | 'prompt_injection.detected'
  | 'approval.requested'
  | 'approval.resolved'
  | 'agent.spawn'
  | 'a2a.message'
  | 'session.start'
  | 'session.end';

export type PolicyAction = 'allow' | 'deny' | 'require_approval';

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
  status: 'pending' | 'approved' | 'denied';
  reason?: string | null;
  created_at?: string;
  resolved_at?: string | null;
  resolved_by?: string | null;
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
}
