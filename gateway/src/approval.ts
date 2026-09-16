/**
 * Human approval wait/poll + timeout policy (Phase 3).
 * DEFENSIVE: gates destructive actions; does not execute them.
 */

import type { ApprovalRequest, ApprovalRisk, PolicyDecision } from '../../shared/src/types.js';
import { getApproval, resolveApproval } from '../../recorder/src/recorder.js';
import { getPolicy } from '../../policy/src/engine.js';

export interface ApprovalWaitOptions {
  approvalId: string;
  timeoutMs?: number;
  pollIntervalMs?: number;
  expireOnTimeout?: boolean;
}

export interface ApprovalWaitResult {
  status: 'approved' | 'denied' | 'expired' | 'timeout' | 'pending';
  approval?: ApprovalRequest | null;
  decision: PolicyDecision;
  waitedMs: number;
}

export function getApprovalTimeoutMs(): number {
  const env = process.env.PHASEONE_APPROVAL_TIMEOUT_MS;
  if (env && Number.isFinite(Number(env))) return Number(env);
  try {
    return getPolicy().approval?.timeout_ms ?? 120_000;
  } catch {
    return 120_000;
  }
}

export function getApprovalPollIntervalMs(): number {
  const env = process.env.PHASEONE_APPROVAL_POLL_MS;
  if (env && Number.isFinite(Number(env))) return Number(env);
  try {
    return getPolicy().approval?.poll_interval_ms ?? 500;
  } catch {
    return 500;
  }
}

export function riskForTool(toolName: string, reason?: string): ApprovalRisk {
  const destructive = ['delete_file', 'force_push', 'drop_database', 'send_email_blast', 'wipe'];
  if (destructive.includes(toolName)) return 'high';
  if (/drop|destroy|wipe|force/i.test(toolName) || /drop|destroy|wipe|force/i.test(reason ?? '')) {
    return 'critical';
  }
  if (/write|email|mcp|shell/i.test(toolName)) return 'medium';
  return 'low';
}

export function approvalExpiresAt(from = new Date(), timeoutMs?: number): string {
  const ms = timeoutMs ?? getApprovalTimeoutMs();
  return new Date(from.getTime() + ms).toISOString();
}

export async function waitForApprovalDecision(opts: ApprovalWaitOptions): Promise<ApprovalWaitResult> {
  let timeoutMs = opts.timeoutMs ?? getApprovalTimeoutMs();
  let pollMs = opts.pollIntervalMs ?? getApprovalPollIntervalMs();
  let expireOnTimeout = opts.expireOnTimeout;
  try {
    const p = getPolicy();
    if (expireOnTimeout === undefined) expireOnTimeout = p.approval?.expire_on_timeout ?? true;
  } catch {
    if (expireOnTimeout === undefined) expireOnTimeout = true;
  }

  const started = Date.now();

  while (Date.now() - started < timeoutMs) {
    const current = await getApproval(opts.approvalId);
    if (!current) {
      return {
        status: 'pending',
        approval: null,
        waitedMs: Date.now() - started,
        decision: { action: 'deny', reason: 'approval not found', ruleId: 'approval.missing' },
      };
    }

    if (current.status === 'approved') {
      return {
        status: 'approved',
        approval: current,
        waitedMs: Date.now() - started,
        decision: {
          action: 'allow',
          reason: current.resolution_note
            ? `approved by human: ${current.resolution_note}`
            : 'approved by human',
          ruleId: 'approval.approved',
        },
      };
    }

    if (current.status === 'denied') {
      return {
        status: 'denied',
        approval: current,
        waitedMs: Date.now() - started,
        decision: {
          action: 'deny',
          reason: current.resolution_note
            ? `denied by human: ${current.resolution_note}`
            : 'denied by human',
          ruleId: 'approval.denied',
        },
      };
    }

    if (current.status === 'expired') {
      return {
        status: 'expired',
        approval: current,
        waitedMs: Date.now() - started,
        decision: { action: 'deny', reason: 'approval expired', ruleId: 'approval.expired' },
      };
    }

    if (current.expires_at && Date.parse(current.expires_at) <= Date.now()) {
      if (expireOnTimeout) await resolveApproval(opts.approvalId, 'expired', 'timeout-policy');
      return {
        status: 'expired',
        approval: current,
        waitedMs: Date.now() - started,
        decision: {
          action: 'deny',
          reason: 'approval timed out (expires_at)',
          ruleId: 'approval.timeout',
        },
      };
    }

    await sleep(Math.min(pollMs, Math.max(0, timeoutMs - (Date.now() - started))));
  }

  if (expireOnTimeout) {
    await resolveApproval(opts.approvalId, 'expired', 'timeout-policy');
  }

  return {
    status: 'timeout',
    waitedMs: Date.now() - started,
    decision: {
      action: 'deny',
      reason: `approval wait timed out after ${timeoutMs}ms`,
      ruleId: 'approval.timeout',
    },
  };
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, Math.max(0, ms)));
}
