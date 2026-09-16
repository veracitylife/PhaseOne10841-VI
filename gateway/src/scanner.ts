/**
 * Prompt-injection scanner service — wires shared scanner into gateway policy/events.
 * Scans untrusted content: tool results, retrieved context, MCP-ish payloads.
 */

import {
  scanPromptInjection,
  classifyMessageSource,
  type ContentSource,
  type ScanResult,
} from '../../shared/src/prompt-injection.js';
import { getPolicy } from '../../policy/src/engine.js';
import { recordEvent } from '../../recorder/src/recorder.js';

export interface ScannerInput {
  sessionId: string;
  agentId: string;
  text: string;
  source?: ContentSource;
  /** e.g. tool_result | retrieved_context | mcp_payload | message */
  channel?: string;
}

export interface ScannerServiceResult {
  scan: ScanResult;
  blocked: boolean;
  eventsRecorded: number;
}

export function getInjectionPolicy() {
  const p = getPolicy();
  return (
    p.prompt_injection ?? {
      block_mode: false,
      block_user: false,
      scan_untrusted: true,
      scan_user: true,
      scan_system: false,
      min_block_severity: 'medium' as const,
    }
  );
}

export async function runInjectionScan(input: ScannerInput): Promise<ScannerServiceResult> {
  const inj = getInjectionPolicy();
  const source = input.source ?? 'untrusted';

  if (source === 'system' && !inj.scan_system) {
    return {
      scan: { source: 'system', hits: [], maxSeverity: null, shouldBlock: false, blockedRules: [] },
      blocked: false,
      eventsRecorded: 0,
    };
  }
  if (source === 'user' && !inj.scan_user) {
    return {
      scan: { source: 'user', hits: [], maxSeverity: null, shouldBlock: false, blockedRules: [] },
      blocked: false,
      eventsRecorded: 0,
    };
  }
  if (source === 'untrusted' && !inj.scan_untrusted) {
    return {
      scan: { source: 'untrusted', hits: [], maxSeverity: null, shouldBlock: false, blockedRules: [] },
      blocked: false,
      eventsRecorded: 0,
    };
  }

  const scan = scanPromptInjection(input.text, {
    source,
    blockMode: inj.block_mode,
    blockUser: inj.block_user,
    minBlockSeverity: inj.min_block_severity ?? 'medium',
  });

  let eventsRecorded = 0;
  for (const hit of scan.hits) {
    await recordEvent({
      session_id: input.sessionId,
      agent_id: input.agentId,
      event_type: scan.shouldBlock ? 'prompt_injection.blocked' : 'prompt_injection.detected',
      severity: hit.severity === 'high' ? 'high' : 'medium',
      decision: scan.shouldBlock ? 'deny' : 'allow',
      decision_reason: `${scan.shouldBlock ? 'blocked' : 'detected'}: ${hit.rule}`,
      metadata: {
        rule: hit.rule,
        excerpt: hit.excerpt,
        source: scan.source,
        channel: input.channel ?? 'content',
      },
    });
    eventsRecorded++;
  }

  return { scan, blocked: scan.shouldBlock, eventsRecorded };
}

export async function scanMessagesWithPolicy(
  sessionId: string,
  agentId: string,
  messages: Array<{ role?: string; content?: unknown }>
): Promise<{ blocked: boolean; reason?: string; scans: ScanResult[] }> {
  const scans: ScanResult[] = [];
  for (const msg of messages) {
    const source = classifyMessageSource(msg.role);
    const text = typeof msg.content === 'string' ? msg.content : JSON.stringify(msg.content ?? '');
    const result = await runInjectionScan({
      sessionId,
      agentId,
      text,
      source,
      channel: msg.role === 'tool' ? 'tool_result' : 'message',
    });
    scans.push(result.scan);
    if (result.blocked) {
      return {
        blocked: true,
        reason: `prompt injection blocked (${result.scan.blockedRules.join(', ')}) from ${result.scan.source}`,
        scans,
      };
    }
  }
  return { blocked: false, scans };
}

/** Scan tool result / MCP / RAG blob explicitly as untrusted */
export async function scanUntrustedPayload(
  sessionId: string,
  agentId: string,
  payload: unknown,
  channel: string
): Promise<ScannerServiceResult> {
  const text = typeof payload === 'string' ? payload : JSON.stringify(payload ?? '');
  return runInjectionScan({
    sessionId,
    agentId,
    text,
    source: 'untrusted',
    channel,
  });
}
