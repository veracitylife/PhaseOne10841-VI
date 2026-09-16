/**
 * CrewAI stub — how to route crew LLMs and A2A through PhaseOne.
 * DEFENSIVE ONLY.
 */

export function crewaiPhaseOneHint(gatewayUrl = 'http://localhost:8080'): {
  openai_base_url: string;
  a2a_endpoint: string;
  notes: string[];
} {
  const base = gatewayUrl.replace(/\/$/, '');
  return {
    openai_base_url: `${base}/v1`,
    a2a_endpoint: `${base}/v1/phaseone/a2a/message`,
    notes: [
      'Configure CrewAI LLM provider to OpenAI-compatible base URL above',
      'Set distinct X-PhaseOne-Agent-Id per crew agent',
      'Peer messages should pass through the A2A firewall endpoint',
      'Veracity Integrity LLC · https://VeracityIntegrity.com',
    ],
  };
}
