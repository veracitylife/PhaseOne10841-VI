/**
 * Light prompt-injection detector — heuristics only, detection not generation.
 * Flags untrusted content that attempts to override system/developer instructions.
 */

export interface InjectionHit {
  rule: string;
  severity: 'low' | 'medium' | 'high';
  excerpt: string;
}

const RULES: Array<{ rule: string; severity: InjectionHit['severity']; re: RegExp }> = [
  {
    rule: 'ignore_previous_instructions',
    severity: 'high',
    re: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)/i,
  },
  {
    rule: 'system_override',
    severity: 'high',
    re: /(?:you\s+are\s+now|new\s+system\s+prompt|disregard\s+your\s+(?:system|safety))/i,
  },
  {
    rule: 'role_hijack',
    severity: 'medium',
    re: /(?:act\s+as|pretend\s+to\s+be|jailbreak|DAN\s+mode)/i,
  },
  {
    rule: 'hidden_instruction_markers',
    severity: 'medium',
    re: /(?:<<\s*SYS\s*>>|\[INST\]|<\|system\|>|###\s*Instruction)/i,
  },
  {
    rule: 'exfiltrate_secrets',
    severity: 'high',
    re: /(?:exfiltrat|send\s+(?:me\s+)?(?:all\s+)?(?:secrets|credentials|api\s*keys)|dump\s+(?:env|\.env))/i,
  },
];

export function detectPromptInjection(text: string): InjectionHit[] {
  if (!text || typeof text !== 'string') return [];
  const hits: InjectionHit[] = [];
  for (const { rule, severity, re } of RULES) {
    const m = text.match(re);
    if (m) {
      const start = Math.max(0, (m.index ?? 0) - 20);
      const excerpt = text.slice(start, start + 80).replace(/\s+/g, ' ');
      hits.push({ rule, severity, excerpt });
    }
  }
  return hits;
}
