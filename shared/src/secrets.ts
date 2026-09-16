/**
 * Secret pattern detection — defensive egress scanning only.
 * Patterns match common credential shapes; canary tokens are handled separately.
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
  { type: 'openai_key', re: /\b(sk-[A-Za-z0-9]{20,})\b/g },
  { type: 'slack_token', re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g },
  { type: 'private_key_block', re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { type: 'generic_api_key_assignment', re: /\b(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[=:]\s*["']?[^\s"']{16,}/gi },
  { type: 'bearer_token', re: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/g },
  { type: 'connection_string_password', re: /\b(postgres|mysql|mongodb).*?:\/\/[^:]+:([^@\s]+)@/gi },
];

export function detectSecrets(text: string): SecretMatch[] {
  if (!text || typeof text !== 'string') return [];
  const matches: SecretMatch[] = [];
  const seen = new Set<string>();

  for (const { type, re } of SECRET_PATTERNS) {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const raw = m[1] ?? m[0];
      const key = `${type}:${raw.slice(0, 12)}`;
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
