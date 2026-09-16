/**
 * CrewAI adapter — route crew agents and A2A messages through PhaseOne gateway.
 * DEFENSIVE ONLY.
 * 
 * PhaseOne10841 · Veracity Integrity LLC · https://VeracityIntegrity.com
 */

export interface CrewAIPhaseOneConfig {
  openai_base_url: string;
  api_key: string;
  a2a_endpoint: string;
  tool_enforce_endpoint: string;
  scan_untrusted_endpoint: string;
  model: string;
  notes: string[];
}

export interface A2AMessagePayload {
  source_agent_id: string;
  target_agent_id: string;
  message: string;
  metadata?: Record<string, unknown>;
}

export interface A2AMessageResult {
  allowed: boolean;
  scanned: boolean;
  injection_score?: number;
  trust_level?: 'trusted' | 'semi-trusted' | 'untrusted';
  reason?: string;
}

export interface ToolEnforcePayload {
  agent_id: string;
  tool_name: string;
  arguments: Record<string, unknown>;
  wait_for_approval?: boolean;
}

export interface ToolEnforceResult {
  allowed: boolean;
  pending_approval?: boolean;
  approval_id?: string;
  reason?: string;
}

/**
 * Generate configuration for routing CrewAI through PhaseOne.
 * 
 * @example Python usage with CrewAI:
 * ```python
 * from crewai import Agent, Crew, Task
 * from langchain_openai import ChatOpenAI
 * 
 * # Point LLM at PhaseOne gateway
 * llm = ChatOpenAI(
 *     base_url="http://localhost:8080/v1",
 *     api_key="phaseone-unused",
 *     model="phaseone-mock",
 *     default_headers={
 *         "X-PhaseOne-Agent-Id": "crewai-researcher",
 *         "X-PhaseOne-Session-Id": str(uuid.uuid4()),
 *     }
 * )
 * 
 * researcher = Agent(
 *     role='Senior Researcher',
 *     llm=llm,
 *     # ...
 * )
 * ```
 */
export function crewaiPhaseOneConfig(
  gatewayUrl = 'http://localhost:8080',
  apiKey = 'phaseone-unused'
): CrewAIPhaseOneConfig {
  const base = gatewayUrl.replace(/\/$/, '');
  return {
    openai_base_url: `${base}/v1`,
    api_key: apiKey,
    a2a_endpoint: `${base}/v1/phaseone/a2a/message`,
    tool_enforce_endpoint: `${base}/v1/phaseone/tools/enforce`,
    scan_untrusted_endpoint: `${base}/v1/phaseone/scan/untrusted`,
    model: 'phaseone-mock',
    notes: [
      'Configure CrewAI LLM provider to OpenAI-compatible base URL above',
      'Set distinct X-PhaseOne-Agent-Id per crew agent',
      'Route inter-agent messages through the A2A firewall endpoint',
      'Wrap tool calls with tool_enforce_endpoint before side effects',
      'Scan tool results with scan_untrusted_endpoint',
      'Veracity Integrity LLC · https://VeracityIntegrity.com',
    ],
  };
}

/**
 * Route an agent-to-agent message through PhaseOne A2A firewall.
 * Use this when crew agents communicate with each other.
 * 
 * @example
 * ```ts
 * const result = await sendA2AMessage(config.a2a_endpoint, {
 *   source_agent_id: 'crewai-researcher',
 *   target_agent_id: 'crewai-writer',
 *   message: 'Here are my research findings...',
 * });
 * if (!result.allowed) {
 *   console.error('A2A message blocked:', result.reason);
 * }
 * ```
 */
export async function sendA2AMessage(
  a2aEndpoint: string,
  payload: A2AMessagePayload
): Promise<A2AMessageResult> {
  const res = await fetch(a2aEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json() as A2AMessageResult;
  return data;
}

/**
 * Enforce a tool call through PhaseOne before execution.
 * 
 * @example
 * ```ts
 * const result = await enforceToolCall(config.tool_enforce_endpoint, {
 *   agent_id: 'crewai-researcher',
 *   tool_name: 'web_search',
 *   arguments: { query: 'AI safety research papers' },
 * });
 * if (!result.allowed) {
 *   throw new Error(`Tool blocked: ${result.reason}`);
 * }
 * ```
 */
export async function enforceToolCall(
  enforceEndpoint: string,
  payload: ToolEnforcePayload
): Promise<ToolEnforceResult> {
  const res = await fetch(enforceEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json() as ToolEnforceResult;
  return data;
}

/**
 * Generate agent-specific headers for PhaseOne tracking.
 * Use distinct agent IDs for each crew member.
 * 
 * @example
 * ```python
 * # Python usage
 * headers = get_agent_headers("crewai-researcher", session_id)
 * llm = ChatOpenAI(default_headers=headers, ...)
 * ```
 */
export function getAgentHeaders(
  agentId: string,
  sessionId?: string
): Record<string, string> {
  return {
    'X-PhaseOne-Agent-Id': agentId,
    'X-PhaseOne-Session-Id': sessionId ?? crypto.randomUUID(),
  };
}

/**
 * Python code snippet for CrewAI integration.
 * Copy-paste this into your CrewAI project.
 */
export const CREWAI_PYTHON_SNIPPET = `
# CrewAI + PhaseOne10841 Integration
# Veracity Integrity LLC · https://VeracityIntegrity.com
# DEFENSIVE ONLY — no exploit tooling

import os
import uuid
import requests
from crewai import Agent, Crew, Task
from langchain_openai import ChatOpenAI

PHASEONE_GATEWAY = os.getenv("PHASEONE_GATEWAY_URL", "http://localhost:8080")
SESSION_ID = str(uuid.uuid4())

def create_phaseone_llm(agent_id: str) -> ChatOpenAI:
    """Create a ChatOpenAI instance routed through PhaseOne."""
    return ChatOpenAI(
        base_url=f"{PHASEONE_GATEWAY}/v1",
        api_key=os.getenv("OPENAI_API_KEY", "phaseone-unused"),
        model=os.getenv("PHASEONE_MODEL", "phaseone-mock"),
        default_headers={
            "X-PhaseOne-Agent-Id": agent_id,
            "X-PhaseOne-Session-Id": SESSION_ID,
        }
    )

def enforce_tool(agent_id: str, tool_name: str, arguments: dict) -> dict:
    """Check if a tool call is allowed by PhaseOne policy."""
    response = requests.post(
        f"{PHASEONE_GATEWAY}/v1/phaseone/tools/enforce",
        json={
            "agent_id": agent_id,
            "tool_name": tool_name,
            "arguments": arguments,
            "wait_for_approval": False,
        }
    )
    return response.json()

def send_a2a_message(source_id: str, target_id: str, message: str) -> dict:
    """Route inter-agent messages through PhaseOne A2A firewall."""
    response = requests.post(
        f"{PHASEONE_GATEWAY}/v1/phaseone/a2a/message",
        json={
            "source_agent_id": source_id,
            "target_agent_id": target_id,
            "message": message,
        }
    )
    return response.json()

# Example crew setup
researcher = Agent(
    role='Senior Researcher',
    goal='Find accurate information',
    backstory='Expert researcher with attention to detail',
    llm=create_phaseone_llm("crewai-researcher"),
    verbose=True,
)

writer = Agent(
    role='Technical Writer',
    goal='Create clear documentation',
    backstory='Skilled at explaining complex topics',
    llm=create_phaseone_llm("crewai-writer"),
    verbose=True,
)
`.trim();

export const crewaiPhaseOneHint = crewaiPhaseOneConfig;
