/**
 * Secret pattern detection — defensive egress scanning only.
 * Patterns match common credential shapes; canary tokens are handled separately.
 * Phase 3: broader patterns + deep object redaction for recorder/logs.
 */

export interface SecretMatch {
  type: string;
  preview: string;
}

const SECRET_PATTERNS: Array<{ type: string; re: RegExp }> = [
  { type: 'aws_access_key_id', re: /\b(AKIA[0-9A-Z]{16})\b/g },
  { type: 'aws_secret_access_key', re: /\b(aws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+=]{40})/gi },
  { type: 'github_pat', re: /\b(ghp_[A-Za-z0-9]{36})\b/g },
  { type: 'github_fine_grained', re: /\b(github_pat_[A-Za-z0-9_]{20,})\b/g },
  { type: 'github_oauth', re: /\b(gho_[A-Za-z0-9]{36})\b/g },
  { type: 'github_app', re: /\b(ghs_[A-Za-z0-9]{36})\b/g },
  { type: 'openai_key', re: /\b(sk-[A-Za-z0-9]{20,})\b/g },
  { type: 'openai_proj_key', re: /\b(sk-proj-[A-Za-z0-9_-]{20,})\b/g },
  { type: 'anthropic_key', re: /\b(sk-ant-[A-Za-z0-9\-_]{20,})\b/g },
  { type: 'slack_token', re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  { type: 'stripe_key', re: /\b(sk_live_[A-Za-z0-9]{20,}|rk_live_[A-Za-z0-9]{20,})\b/g },
  { type: 'google_api_key', re: /\b(AIza[0-9A-Za-z\-_]{35})\b/g },
  { type: 'jwt_token', re: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g },
  { type: 'private_key_block', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
  { type: 'generic_api_key_assignment', re: /\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[=:]\s*["']?[^\s"']{16,}/gi },
  { type: 'bearer_token', re: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/gi },
  { type: 'basic_auth_header', re: /\bAuthorization:\s*Basic\s+[A-Za-z0-9+/=]{16,}/gi },
  { type: 'connection_string_password', re: /\b(postgres|mysql|mongodb|redis|amqp).*?:\/\/[^:]+:([^@\s]+)@/gi },
  { type: 'npm_token', re: /\b(npm_[A-Za-z0-9]{36})\b/g },
  { type: 'telegram_bot', re: /\b(\d{8,10}:[A-Za-z0-9_-]{35})\b/g },
];

/** Tools treated as outbound egress channels for secret_egress.block */
export const OUTBOUND_TOOL_NAMES = new Set([
  'http_request',
  'fetch',
  'web_search',
  'mcp_call',
  'send_email',
  'send_email_blast',
  'webhook',
  'post_message',
]);

export function detectSecrets(text: string): SecretMatch[] {
  if (!text || typeof text !== 'string') return [];
  const matches: SecretMatch[] = [];
  const seen = new Set<string>();

  for (const { type, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const raw = m[1] ?? m[0];
      const key = `${type}:${raw.slice(0, 16)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      matches.push({
        type,
        preview: redactPreview(raw),
      });
    }
  }
  return matches;
}

/** Flatten tool args / HTTP bodies into scannable text (headers, body, url, nested). */
export function collectEgressText(value: unknown, depth = 0): string {
  if (value == null) return '';
  if (depth > 8) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  if (Array.isArray(value)) {
    return value.map((v) => collectEgressText(v, depth + 1)).join('\n');
  }
  if (typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const [k, v] of Object.entries(obj)) {
      parts.push(k);
      // Prefer scanning high-risk fields first but scan all
      parts.push(collectEgressText(v, depth + 1));
    }
    return parts.join('\n');
  }
  return '';
}

export function detectSecretsInValue(value: unknown): SecretMatch[] {
  return detectSecrets(collectEgressText(value));
}

function redactPreview(value: string): string {
  if (value.length <= 8) return '****';
  return `${value.slice(0, 4)}…${value.slice(-4)}`;
}

/** Strip likely secrets from logged prompts / payloads for storage. */
export function redactSecrets(text: string): string {
  if (!text) return text;
  let out = text;
  for (const { re } of SECRET_PATTERNS) {
    const flags = re.flags.includes('g') ? re.flags : re.flags + 'g';
    const global = new RegExp(re.source, flags);
    out = out.replace(global, '[REDACTED]');
  }
  return out;
}

/** Deep-redact secrets in objects/arrays for recorder storage. */
export function redactSecretsDeep<T>(value: T, depth = 0): T {
  if (value == null || depth > 10) return value;
  if (typeof value === 'string') return redactSecrets(value) as T;
  if (typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    return value.map((v) => redactSecretsDeep(v, depth + 1)) as T;
  }
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    const keyLower = k.toLowerCase();
    if (
      /(password|secret|token|api[_-]?key|authorization|private[_-]?key|credential)/i.test(keyLower) &&
      typeof v === 'string' &&
      v.length > 4
    ) {
      out[k] = '[REDACTED]';
    } else {
      out[k] = redactSecretsDeep(v, depth + 1);
    }
  }
  return out as T;
}

export function listSecretPatternTypes(): string[] {
  return SECRET_PATTERNS.map((p) => p.type);
}
