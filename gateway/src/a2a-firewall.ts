/**
 * Agent-to-Agent (A2A) Firewall — DEFENSIVE middleware path.
 * Flow: A → gateway → policy / injection-scan → B
 * Trust levels: LOCAL-TRUSTED | LOCAL-UNTRUSTED | REMOTE-VERIFIED | REMOTE-UNKNOWN | QUARANTINED
 */

import type { A2ATrustLevel, PolicyAction } from '../../shared/src/types.js';
import { scanPromptInjection } from '../../shared/src/prompt-injection.js';
import { getPolicy } from '../../policy/src/engine.js';
import { recordEvent, ensureSession } from '../../recorder/src/recorder.js';
import { newSessionId } from './enforce.js';
import { Metrics } from '../../shared/src/metrics.js';
import { evaluateEventRules } from './routes/phase4.js';

export interface A2AMessage {
  from_agent_id: string;
  to_agent_id: string;
  session_id?: string;
  content: string;
  /** Declared trust of the sender (gateway may downgrade) */
  trust_level?: A2ATrustLevel;
  metadata?: Record<string, unknown>;
}

export interface A2ADecision {
  action: PolicyAction;
  trust_level: A2ATrustLevel;
  reason: string;
  session_id: string;
  injection_hits: Array<{ rule: string; severity: string }>;
  quarantined?: boolean;
}

const TRUST_RANK: Record<A2ATrustLevel, number> = {
  'LOCAL-TRUSTED': 4,
  'REMOTE-VERIFIED': 3,
  'LOCAL-UNTRUSTED': 2,
  'REMOTE-UNKNOWN': 1,
  QUARANTINED: 0,
};

function normalizeTrust(raw?: string): A2ATrustLevel {
  const allowed: A2ATrustLevel[] = [
    'LOCAL-TRUSTED',
    'LOCAL-UNTRUSTED',
    'REMOTE-VERIFIED',
    'REMOTE-UNKNOWN',
    'QUARANTINED',
  ];
  if (raw && (allowed as string[]).includes(raw)) return raw as A2ATrustLevel;
  return 'REMOTE-UNKNOWN';
}

function resolveEffectiveTrust(
  declared: A2ATrustLevel,
  fromAgent: string,
  policyTrust: {
    default_remote: A2ATrustLevel;
    local_trusted_agents: string[];
    local_untrusted_agents: string[];
    verified_remote_agents: string[];
    quarantined_agents: string[];
  }
): A2ATrustLevel {
  if (policyTrust.quarantined_agents.includes(fromAgent)) return 'QUARANTINED';
  if (policyTrust.local_trusted_agents.includes(fromAgent)) return 'LOCAL-TRUSTED';
  if (policyTrust.verified_remote_agents.includes(fromAgent)) return 'REMOTE-VERIFIED';
  if (policyTrust.local_untrusted_agents.includes(fromAgent)) return 'LOCAL-UNTRUSTED';

  // Do not allow clients to self-assert higher than policy default for unknown agents
  const defaultTrust = policyTrust.default_remote ?? 'REMOTE-UNKNOWN';
  if (TRUST_RANK[declared] > TRUST_RANK[defaultTrust] && declared !== 'LOCAL-TRUSTED') {
    // Cap self-asserted trust at default for unknowns
    return defaultTrust;
  }
  if (declared === 'LOCAL-TRUSTED' && !policyTrust.local_trusted_agents.includes(fromAgent)) {
    return 'LOCAL-UNTRUSTED';
  }
  return declared === 'REMOTE-UNKNOWN' ? defaultTrust : declared;
}

/**
 * Evaluate and optionally record an A2A message through the firewall.
 */
export async function processA2AMessage(msg: A2AMessage): Promise<A2ADecision> {
  const policy = getPolicy();
  const a2a = policy.a2a ?? {
    enabled: true,
    default_remote: 'REMOTE-UNKNOWN' as A2ATrustLevel,
    local_trusted_agents: [] as string[],
    local_untrusted_agents: [] as string[],
    verified_remote_agents: [] as string[],
    quarantined_agents: [] as string[],
    block_quarantined: true,
    block_unknown_remote: false,
    scan_injection: true,
    block_on_injection: true,
    allow_from_to_same: true,
  };

  const sessionId = msg.session_id ?? newSessionId();
  const agentId = msg.from_agent_id;
  await ensureSession(sessionId, agentId, { metadata: { a2a: true, to: msg.to_agent_id } });

  const declared = normalizeTrust(msg.trust_level);
  const trust = resolveEffectiveTrust(declared, msg.from_agent_id, {
    default_remote: a2a.default_remote,
    local_trusted_agents: a2a.local_trusted_agents,
    local_untrusted_agents: a2a.local_untrusted_agents,
    verified_remote_agents: a2a.verified_remote_agents,
    quarantined_agents: a2a.quarantined_agents,
  });

  let action: PolicyAction = 'allow';
  let reason = 'a2a allowed';
  let quarantined = false;
  const injection_hits: Array<{ rule: string; severity: string }> = [];

  if (!a2a.enabled) {
    action = 'allow';
    reason = 'a2a firewall disabled';
  } else if (trust === 'QUARANTINED' || (a2a.block_quarantined && a2a.quarantined_agents.includes(msg.from_agent_id))) {
    action = 'quarantine';
    quarantined = true;
    reason = `sender trust=QUARANTINED`;
  } else if (a2a.block_unknown_remote && trust === 'REMOTE-UNKNOWN') {
    action = 'deny';
    reason = 'REMOTE-UNKNOWN senders blocked by policy';
  } else if (!a2a.allow_from_to_same && msg.from_agent_id === msg.to_agent_id) {
    action = 'deny';
    reason = 'self-addressed A2A messages blocked';
  }

  // Injection scan on message content (treat as untrusted except LOCAL-TRUSTED)
  if (a2a.scan_injection && action === 'allow') {
    const source = trust === 'LOCAL-TRUSTED' ? 'user' : 'untrusted';
    const scan = scanPromptInjection(msg.content, {
      source,
      blockMode: a2a.block_on_injection,
      blockUser: false,
      minBlockSeverity: 'medium',
    });
    for (const h of scan.hits) {
      injection_hits.push({ rule: h.rule, severity: h.severity });
    }
    if (scan.shouldBlock) {
      action = trust === 'LOCAL-UNTRUSTED' || trust === 'REMOTE-UNKNOWN' ? 'quarantine' : 'deny';
      if (action === 'quarantine') quarantined = true;
      reason = `a2a injection blocked: ${scan.blockedRules.join(', ')}`;
    } else if (scan.hits.length) {
      reason = `a2a allowed with injection warnings: ${scan.hits.map((h) => h.rule).join(', ')}`;
    }
  }

  // Record path: A → gateway → decision
  await recordEvent({
    session_id: sessionId,
    agent_id: agentId,
    event_type: 'a2a.message',
    severity: action === 'allow' ? (injection_hits.length ? 'medium' : 'info') : 'high',
    destination: msg.to_agent_id,
    decision: action === 'quarantine' ? 'quarantine' : action === 'deny' ? 'deny' : 'allow',
    decision_reason: reason,
    tool_args: {
      from: msg.from_agent_id,
      to: msg.to_agent_id,
      trust_declared: declared,
      trust_effective: trust,
      content_preview: msg.content.slice(0, 200),
    },
    metadata: {
      trust_level: trust,
      injection_hits,
      ...(msg.metadata ?? {}),
    },
  });

  if (action === 'deny') {
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'a2a.blocked',
      severity: 'high',
      destination: msg.to_agent_id,
      decision: 'deny',
      decision_reason: reason,
      metadata: { trust_level: trust, injection_hits },
    });
  }

  if (quarantined || action === 'quarantine') {
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'a2a.quarantined',
      severity: 'high',
      destination: msg.to_agent_id,
      decision: 'quarantine',
      decision_reason: reason,
      metadata: { trust_level: trust, injection_hits },
    });
  }

  for (const hit of injection_hits) {
    await recordEvent({
      session_id: sessionId,
      agent_id: agentId,
      event_type: 'prompt_injection.detected',
      severity: hit.severity === 'high' ? 'high' : 'medium',
      decision: action === 'allow' ? 'allow' : 'deny',
      decision_reason: `a2a scan: ${hit.rule}`,
      metadata: { rule: hit.rule, channel: 'a2a', trust_level: trust },
    });
  }

  Metrics.a2a(action === 'quarantine' ? 'quarantine' : action === 'deny' ? 'deny' : 'allow');
  evaluateEventRules({
    event_type: action === 'deny' ? 'a2a.blocked' : action === 'quarantine' ? 'a2a.quarantined' : 'a2a.message',
    a2a_trust: trust,
    decision: action === 'allow' ? 'allow' : action === 'quarantine' ? 'quarantine' : 'deny',
    decision_reason: reason,
  });

  return {
    action,
    trust_level: trust,
    reason,
    session_id: sessionId,
    injection_hits,
    quarantined,
  };
}

/** Synchronous evaluate (no DB) for unit tests */
export function evaluateA2AMessageSync(
  msg: A2AMessage,
  policyOverrides?: Partial<NonNullable<ReturnType<typeof getPolicy>['a2a']>>
): Omit<A2ADecision, 'session_id'> & { session_id?: string } {
  const policy = getPolicy();
  const a2a = { ...(policy.a2a ?? {
    enabled: true,
    default_remote: 'REMOTE-UNKNOWN' as A2ATrustLevel,
    local_trusted_agents: [] as string[],
    local_untrusted_agents: [] as string[],
    verified_remote_agents: [] as string[],
    quarantined_agents: [] as string[],
    block_quarantined: true,
    block_unknown_remote: false,
    scan_injection: true,
    block_on_injection: true,
    allow_from_to_same: true,
  }), ...policyOverrides };

  const declared = normalizeTrust(msg.trust_level);
  const trust = resolveEffectiveTrust(declared, msg.from_agent_id, {
    default_remote: a2a.default_remote,
    local_trusted_agents: a2a.local_trusted_agents,
    local_untrusted_agents: a2a.local_untrusted_agents,
    verified_remote_agents: a2a.verified_remote_agents,
    quarantined_agents: a2a.quarantined_agents,
  });

  let action: PolicyAction = 'allow';
  let reason = 'a2a allowed';
  let quarantined = false;
  const injection_hits: Array<{ rule: string; severity: string }> = [];

  if (trust === 'QUARANTINED' || (a2a.block_quarantined && a2a.quarantined_agents.includes(msg.from_agent_id))) {
    action = 'quarantine';
    quarantined = true;
    reason = 'sender trust=QUARANTINED';
  } else if (a2a.block_unknown_remote && trust === 'REMOTE-UNKNOWN') {
    action = 'deny';
    reason = 'REMOTE-UNKNOWN senders blocked by policy';
  }

  if (a2a.scan_injection && action === 'allow') {
    const source = trust === 'LOCAL-TRUSTED' ? 'user' : 'untrusted';
    const scan = scanPromptInjection(msg.content, {
      source,
      blockMode: a2a.block_on_injection,
      minBlockSeverity: 'medium',
    });
    for (const h of scan.hits) injection_hits.push({ rule: h.rule, severity: h.severity });
    if (scan.shouldBlock) {
      action = trust === 'LOCAL-UNTRUSTED' || trust === 'REMOTE-UNKNOWN' ? 'quarantine' : 'deny';
      if (action === 'quarantine') quarantined = true;
      reason = `a2a injection blocked: ${scan.blockedRules.join(', ')}`;
    }
  }

  return { action, trust_level: trust, reason, injection_hits, quarantined };
}
