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
}
