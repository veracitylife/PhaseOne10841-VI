/**
 * LangChain stub — documentation helper for pointing ChatOpenAI at PhaseOne.
 * Does not import LangChain (optional peer). DEFENSIVE ONLY.
 */

export interface LangChainPhaseOneHint {
  baseURL: string;
  model: string;
  headers: Record<string, string>;
  notes: string[];
}

export function langchainPhaseOneHint(gatewayUrl = 'http://localhost:8080'): LangChainPhaseOneHint {
  const base = gatewayUrl.replace(/\/$/, '');
  return {
    baseURL: `${base}/v1`,
    model: 'phaseone-mock',
    headers: {
      'X-PhaseOne-Agent-Id': 'langchain-agent',
      'X-PhaseOne-Session-Id': 'set-per-run',
    },
    notes: [
      'Use ChatOpenAI configuration.baseURL = gateway /v1',
      'Wrap tool calls with POST /v1/phaseone/tools/enforce before side effects',
      'Scan retrieved context with POST /v1/phaseone/scan/untrusted',
      'Product: PhaseOne10841 by Veracity Integrity LLC',
    ],
  };
}
