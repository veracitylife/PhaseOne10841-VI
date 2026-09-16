import { randomUUID } from 'node:crypto';
import { evaluateToolCall, evaluatePolicy } from '../../policy/src/engine.js';
import { matchCanaries } from '../../canaries/src/detector.js';
import {
  detectSecrets,
  redactSecrets,
  redactSecretsDeep,
} from '../../shared/src/secrets.js';
import {
  recordEvent,
  createApproval,
} from '../../recorder/src/recorder.js';
import type { PolicyDecision } from '../../shared/src/types.js';
import { scanMessagesWithPolicy, scanUntrustedPayload } from './scanner.js';
import {
  waitForApprovalDecision,
  riskForTool,
  approvalExpiresAt,
  getApprovalTimeoutMs,
} from './approval.js';
import { Metrics } from '../../shared/src/metrics.js';
import { notifyHighSeverity } from '../../shared/src/alerting.js';
import { noteCanaryTrigger } from '../../canaries/src/manager.js';
import { evaluateEventRules } from './routes/phase4.js';

export interface EnforceResult {
  allowed: boolean;
  pendingApproval?: boolean;
  approvalId?: string;
  decision: PolicyDecision;
  blockedResponse?: Record<string, unknown>;
}

function blockedPayload(decision: PolicyDecision, extra?: Record<string, unknown>) {
  return {
    error: {
      message: `PhaseOne10841 policy blocked request: ${decision.reason}`,
      type: 'phaseone_policy_violation',
      code: decision.ruleId ?? 'policy_deny',
      phaseone: {
        action: decision.action,
        reason: decision.reason,
        matched_canaries: decision.matchedCanaries ?? [],
        matched_secrets: decision.matchedSecrets ?? [],
        ...extra,
      },
    },
  };
}

/**
 * Scan chat messages for prompt-injection / canaries with source classification.
 * Returns whether untrusted content should hard-block the request (policy.block_mode).
 */
export async function scanMessagesForThreats(
  sessionId: string,
  agentId: string,
  messages: Array<{ role?: string; content?: unknown }>
): Promise<{ blocked: boolean; reason?: string }> {
  const inj = await scanMessagesWithPolicy(sessionId, agentId, messages);

  for (const msg of messages) {
    if (msg.role === 'system') continue;
    const text = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content ?? '');
    const canaries = matchCanaries(text);
    for (const c of canaries) {
      noteCanaryTrigger(c.canaryId, { session_id: sessionId, agent_id: agentId, name: c.name });
      Metrics.canary();
      await recordEvent({
        session_id: sessionId,
        agent_id: agentId,
        event_type: 'canary.trigger',
        severity: 'critical',
        decision: 'deny',
        decision_reason: `canary ${c.name} seen in message content`,
        metadata: { canary_id: c.canaryId, marker_preview: c.marker.slice(0, 12) + '…' },
      });
      notifyHighSeverity({
        event: 'canary',
        severity: 'critical',
        message: `Canary ${c.name} observed in message content`,
        agent_id: agentId,
        session_id: sessionId,
        detail: { canary_id: c.canaryId },
      });
      evaluateEventRules({ event_type: 'canary.trigger', canary: true, agent_id: agentId } as never);
    }
  }

  if (inj.blocked) {
    Metrics.injection('blocked');
    Metrics.block('prompt_injection');
    notifyHighSeverity({
      event: 'injection_blocked',
      severity: 'high',
      message: inj.reason ?? 'prompt injection blocked',
      agent_id: agentId,
      session_id: sessionId,
    });
    evaluateEventRules({ event_type: 'prompt_injection.blocked' });
    return { blocked: true, reason: inj.reason };
  }
  return { blocked: false };
}

/** Scan a tool/MCP/RAG result blob as untrusted content */
export async function scanToolResultContent(
  sessionId: string,
  agentId: string,
  payload: unknown,
  channel = 'tool_result'
): Promise<EnforceResult> {
  const result = await scanUntrustedPayload(sessionId, agentId, payload, channel);
  if (result.blocked) {
    const decision: PolicyDecision = {
      action: 'deny',
      reason: `untrusted content blocked: ${result.scan.blockedRules.join(', ')}`,
      ruleId: 'prompt_injection.block',
    };
    return { allowed: false, decision, blockedResponse: blockedPayload(decision) };
  }
  return {
    allowed: true,
    decision: { action: 'allow', reason: 'untrusted content scan clean or detect-only', ruleId: 'prompt_injection.ok' },
  };
}

export async function enforceToolCall(opts: {
  sessionId: string;
  agentId: string;
  toolName: string;
  toolArgs: unknown;
  waitForApproval?: boolean;
}): Promise<EnforceResult> {
  const decision = evaluateToolCall(opts.agentId, opts.sessionId, opts.toolName, opts.toolArgs);

  const destination =
    typeof opts.toolArgs === 'object' && opts.toolArgs && 'url' in (opts.toolArgs as object)
      ? String((opts.toolArgs as { url: string }).url)
      : typeof opts.toolArgs === 'object' && opts.toolArgs && 'path' in (opts.toolArgs as object)
        ? String((opts.toolArgs as { path: string }).path)
        : null;

  await recordEvent({
    session_id: opts.sessionId,
    agent_id: opts.agentId,
    event_type: 'tool.call',
    severity: decision.action === 'deny' ? 'high' : decision.action === 'require_approval' ? 'medium' : 'info',
    tool_name: opts.toolName,
    tool_args: redactSecretsDeep(opts.toolArgs),
    destination,
    decision: decision.action === 'require_approval' ? 'require_approval' : decision.action === 'deny' ? 'deny' : 'allow',
    decision_reason: decision.reason,
    metadata: {
      rule_id: decision.ruleId,
      matched_canaries: decision.matchedCanaries,
      matched_secrets: decision.matchedSecrets,
    },
  });

  evaluateEventRules({
    event_type: 'tool.call',
    tool_name: opts.toolName,
    decision: decision.action === 'deny' ? 'deny' : decision.action === 'require_approval' ? 'require_approval' : 'allow',
    decision_reason: decision.reason,
    destination: destination ?? undefined,
    canary: Boolean(decision.matchedCanaries?.length),
    metadata: { rule_id: decision.ruleId },
  });

  if (decision.action === 'deny') {
    Metrics.block(decision.ruleId ?? 'policy');
  }

  if (decision.matchedCanaries && decision.matchedCanaries.length > 0) {
    for (const cid of decision.matchedCanaries) {
      noteCanaryTrigger(cid, { session_id: opts.sessionId, agent_id: opts.agentId });
    }
    Metrics.canary();
    notifyHighSeverity({
      event: 'canary',
      severity: 'critical',
      message: `Canary trigger on tool ${opts.toolName}`,
      agent_id: opts.agentId,
      session_id: opts.sessionId,
      detail: { canaries: decision.matchedCanaries },
    });
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: 'canary.trigger',
      severity: 'critical',
      tool_name: opts.toolName,
      tool_args: { note: 'canary markers redacted from log' },
      decision: 'deny',
      decision_reason: `canary trigger: ${decision.matchedCanaries.join(', ')}`,
      metadata: { canaries: decision.matchedCanaries },
    });
  }

  if (decision.matchedSecrets && decision.matchedSecrets.length > 0) {
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: decision.action === 'deny' ? 'secret.blocked' : 'secret.detected',
      severity: 'high',
      tool_name: opts.toolName,
      decision: decision.action === 'deny' ? 'deny' : 'allow',
      decision_reason: `secret patterns: ${decision.matchedSecrets.join(', ')}`,
      metadata: { secrets: decision.matchedSecrets },
    });
  }

  // Specialized monitoring hooks
  if (opts.toolName === 'run_shell') {
    const cmd =
      typeof opts.toolArgs === 'object' && opts.toolArgs && 'command' in (opts.toolArgs as object)
        ? String((opts.toolArgs as { command: string }).command)
        : '';
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: 'shell.exec',
      severity: decision.action === 'allow' ? 'info' : 'high',
      tool_name: 'run_shell',
      tool_args: { command: redactSecrets(cmd) },
      decision: decision.action === 'require_approval' ? 'require_approval' : decision.action === 'deny' ? 'deny' : 'allow',
      decision_reason: decision.reason,
    });
  }

  if (opts.toolName === 'http_request' || opts.toolName === 'fetch') {
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: 'http.request',
      severity: decision.action === 'allow' ? 'info' : 'high',
      tool_name: opts.toolName,
      destination,
      tool_args: redactSecretsDeep(opts.toolArgs),
      decision: decision.action === 'require_approval' ? 'require_approval' : decision.action === 'deny' ? 'deny' : 'allow',
      decision_reason: decision.reason,
    });
  }

  if (['read_file', 'write_file', 'list_files', 'delete_file'].includes(opts.toolName)) {
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: 'filesystem.access',
      severity: decision.action === 'allow' ? 'info' : 'high',
      tool_name: opts.toolName,
      destination,
      decision: decision.action === 'require_approval' ? 'require_approval' : decision.action === 'deny' ? 'deny' : 'allow',
      decision_reason: decision.reason,
    });
  }

  if (opts.toolName === 'mcp_call') {
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: decision.action === 'deny' ? 'mcp.denied' : 'mcp.call',
      severity: decision.action === 'allow' ? 'info' : 'high',
      tool_name: opts.toolName,
      tool_args: redactSecretsDeep(opts.toolArgs),
      decision: decision.action === 'require_approval' ? 'require_approval' : decision.action === 'deny' ? 'deny' : 'allow',
      decision_reason: decision.reason,
    });
  }

  if (opts.toolName === 'spawn_agent') {
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: 'agent.spawn',
      severity: decision.action === 'allow' ? 'info' : 'high',
      tool_name: opts.toolName,
      tool_args: opts.toolArgs,
      decision: decision.action === 'require_approval' ? 'require_approval' : decision.action === 'deny' ? 'deny' : 'allow',
      decision_reason: decision.reason,
    });
  }

  if (decision.action === 'deny') {
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: 'policy.decision',
      severity: 'high',
      tool_name: opts.toolName,
      decision: 'deny',
      decision_reason: decision.reason,
      metadata: { rule_id: decision.ruleId },
    });
    return {
      allowed: false,
      decision,
      blockedResponse: blockedPayload(decision),
    };
  }

  if (decision.action === 'require_approval') {
    const risk = decision.risk ?? riskForTool(opts.toolName, decision.reason);
    const expiresAt = approvalExpiresAt();
    Metrics.approval('requested');
    const approval = await createApproval({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      action_type: opts.toolName,
      payload: {
        tool: opts.toolName,
        args: redactSecretsDeep(opts.toolArgs),
        destination,
      },
      status: 'pending',
      reason: decision.reason,
      risk,
      expires_at: expiresAt,
    });
    await recordEvent({
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      event_type: 'approval.requested',
      severity: risk === 'critical' || risk === 'high' ? 'high' : 'medium',
      tool_name: opts.toolName,
      tool_args: redactSecretsDeep(opts.toolArgs),
      destination,
      decision: 'require_approval',
      decision_reason: decision.reason,
      metadata: {
        approval_id: approval.id,
        risk,
        expires_at: expiresAt,
        timeout_ms: getApprovalTimeoutMs(),
      },
    });

    if (opts.waitForApproval && approval.id) {
      const wait = await waitForApprovalDecision({ approvalId: approval.id });
      if (wait.status === 'approved') {
        Metrics.approval('approved');
        return { allowed: true, approvalId: approval.id, decision: wait.decision };
      }
      if (wait.status === 'expired' || wait.status === 'timeout') {
        Metrics.approval('expired');
        notifyHighSeverity({
          event: 'approval_timeout',
          severity: 'high',
          message: `Approval timed out for ${opts.toolName}`,
          agent_id: opts.agentId,
          session_id: opts.sessionId,
          detail: { approval_id: approval.id },
        });
      } else {
        Metrics.approval('denied');
      }
      return {
        allowed: false,
        approvalId: approval.id,
        decision: wait.decision,
        blockedResponse: blockedPayload(wait.decision),
      };
    }

    return {
      allowed: false,
      pendingApproval: true,
      approvalId: approval.id,
      decision,
      blockedResponse: {
        error: {
          message: 'PhaseOne10841: destructive action queued for human approval',
          type: 'phaseone_approval_required',
          code: 'approval_required',
          phaseone: {
            approval_id: approval.id,
            reason: decision.reason,
            risk,
            status: 'pending',
            expires_at: expiresAt,
            poll_hint: 'GET /v1/phaseone/approvals/:id or wait_for_approval=true',
          },
        },
      },
    };
  }

  return { allowed: true, decision };
}

export async function enforceEgressText(
  sessionId: string,
  agentId: string,
  text: string,
  destination?: string
): Promise<EnforceResult> {
  const decision = evaluatePolicy({
    agentId,
    sessionId,
    toolName: 'http_request',
    egressBody: text,
    domain: destination,
    url: destination,
    method: 'POST',
  });

  const secrets = detectSecrets(text);
  const canaries = matchCanaries(text);
  if (canaries.length) {
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'canary.trigger',
      severity: 'critical',
      destination: destination ?? null,
      decision: 'deny',
      decision_reason: `canary in egress: ${canaries.map((c) => c.name).join(', ')}`,
    });
  }
  if (secrets.length) {
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'secret.detected',
      severity: 'high',
      destination: destination ?? null,
      decision: decision.action === 'deny' ? 'deny' : 'allow',
      decision_reason: secrets.map((s) => s.type).join(', '),
    });
  }

  if (decision.action === 'deny') {
    return { allowed: false, decision, blockedResponse: blockedPayload(decision) };
  }
  return { allowed: true, decision };
}

export function newSessionId(): string {
  return randomUUID();
}
