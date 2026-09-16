import type { A2ATrustLevel } from '../../shared/src/types.js';

export interface PolicyConfig {
  version: string;
  name: string;
  domains: {
    mode: 'allowlist' | 'denylist';
    allow: string[];
    deny: string[];
  };
  tools: {
    mode: 'allowlist' | 'denylist';
    allow: string[];
    deny: string[];
  };
  shell: {
    mode: 'deny_by_default' | 'allow_by_default';
    allow_patterns: string[];
    deny_patterns: string[];
  };
  filesystem: {
    allowed_roots: string[];
    blocked_paths: string[];
  };
  http: {
    allowed_methods: string[];
    denied_methods: string[];
  };
  mcp: {
    mode: 'allowlist' | 'denylist';
    allow_servers: string[];
    allow_tools: string[];
  };
  destructive: {
    patterns: string[];
    tools: string[];
  };
  agent_spawn: {
    max_depth: number;
    max_children_per_agent: number;
  };
  secret_egress: {
    block: boolean;
  };
  canary: {
    block_on_detect: boolean;
    severity: string;
  };
  /** Phase 2: prompt-injection controls */
  prompt_injection?: {
    block_mode: boolean;
    block_user: boolean;
    scan_untrusted: boolean;
    scan_user: boolean;
    scan_system: boolean;
    min_block_severity: 'low' | 'medium' | 'high';
  };
  /** Phase 2: agent-to-agent firewall */
  a2a?: {
    enabled: boolean;
    default_remote: A2ATrustLevel;
    local_trusted_agents: string[];
    local_untrusted_agents: string[];
    verified_remote_agents: string[];
    quarantined_agents: string[];
    block_quarantined: boolean;
    block_unknown_remote: boolean;
    scan_injection: boolean;
    block_on_injection: boolean;
    allow_from_to_same: boolean;
  };
  /** Phase 2: permission analyzer hooks */
  permission_analyzer?: {
    enabled: boolean;
    warn_on_excessive: boolean;
    record_findings_on_session_start: boolean;
  };
}

