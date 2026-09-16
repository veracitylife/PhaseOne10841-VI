/**
 * Claude-style tool proxy stub — enforce tools via PhaseOne before execution.
 * DEFENSIVE ONLY. No Anthropic SDK dependency required.
 */

export interface ClaudeToolProxyHint {
  enforceUrl: string;
  scanUrl: string;
  notes: string[];
}

export function claudeToolProxyHint(gatewayUrl = 'http://localhost:8080'): ClaudeToolProxyHint {
  const base = gatewayUrl.replace(/\/$/, '');
  return {
    enforceUrl: `${base}/v1/phaseone/tools/enforce`,
    scanUrl: `${base}/v1/phaseone/scan/untrusted`,
    notes: [
      'Before executing a tool_use block, POST name+arguments to enforceUrl',
      'If allowed=false and pending_approval, poll approvals or wait_for_approval',
      'Scan tool results / MCP payloads via scanUrl as untrusted content',
      'Optionally map Anthropic messages to OpenAI chat and use /v1/chat/completions',
      'PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com',
    ],
  };
}
