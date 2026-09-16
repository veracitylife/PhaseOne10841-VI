/**
 * Prompt-injection scanner — DEFENSIVE detection only.
 * Classifies content source and flags untrusted payloads that attempt to
 * override system/developer instructions. Does NOT generate attack content.
 */

export type ContentSource = 'user' | 'system' | 'untrusted';

export type InjectionSeverity = 'low' | 'medium' | 'high';

export interface InjectionHit {
  rule: string;
  severity: InjectionSeverity;
  excerpt: string;
  source?: ContentSource;
}

export interface ScanOptions {
  /** Provenance of the text being scanned */
  source?: ContentSource;
  /** When true, treat user content with the same scrutiny as untrusted */
  scanUserAsUntrusted?: boolean;
}

export interface ScanResult {
  source: ContentSource;
  hits: InjectionHit[];
  /** Highest severity among hits, or null if clean */
  maxSeverity: InjectionSeverity | null;
  /** Policy may block when true (untrusted/high, or configured) */
  shouldBlock: boolean;
  blockedRules: string[];
}

const RULES: Array<{ rule: string; severity: InjectionSeverity; re: RegExp }> = [
  {
    rule: 'ignore_previous_instructions',
    severity: 'high',
    re: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules)/i,
  },
  {
    rule: 'system_override',
    severity: 'high',
    re: /(?:you\s+are\s+now|new\s+system\s+prompt|disregard\s+your\s+(?:system|safety)|override\s+(?:your\s+)?(?:system|developer)\s+(?:prompt|instructions))/i,
  },
  {
    rule: 'role_hijack',
    severity: 'medium',
    re: /(?:act\s+as|pretend\s+to\s+be|jailbreak|DAN\s+mode|developer\s+mode\s+enabled)/i,
  },
  {
    rule: 'hidden_instruction_markers',
    severity: 'medium',
    re: /(?:<<\s*SYS\s*>>|\[INST\]|<\|system\|>|###\s*Instruction|<\/?system>)/i,
  },
  {
    rule: 'exfiltrate_secrets',
    severity: 'high',
    re: /(?:exfiltrat|send\s+(?:me\s+)?(?:all\s+)?(?:secrets|credentials|api\s*keys)|dump\s+(?:env|\.env)|reveal\s+(?:your\s+)?(?:system\s+)?prompt)/i,
  },
  {
    rule: 'tool_misuse_coercion',
    severity: 'high',
    re: /(?:call\s+the\s+\w+\s+tool\s+with|must\s+invoke\s+tool|bypass\s+(?:policy|approval|sandbox)|disable\s+(?:safety|guardrails|filters))/i,
  },
  {
    rule: 'indirect_injection_marker',
    severity: 'high',
    // Lab / detector fixture marker — clearly labeled TEST content only
    re: /PHASEONE_TEST_INJECTION[_A-Z0-9]*/i,
  },
  {
    rule: 'encoded_instruction_hint',
    severity: 'medium',
    re: /(?:base64\s*[:=]\s*[A-Za-z0-9+/=]{40,}|decode\s+and\s+execute\s+the\s+following)/i,
  },
  {
    rule: 'authority_spoof',
    severity: 'medium',
    re: /(?:as\s+(?:your\s+)?(?:admin|root|developer|system\s+operator)|this\s+is\s+an?\s+authorized\s+override)/i,
  },
];

const SEVERITY_RANK: Record<InjectionSeverity, number> = {
  low: 1,
  medium: 2,
  high: 3,
};

export function detectPromptInjection(text: string, options?: ScanOptions): InjectionHit[] {
  if (!text || typeof text !== 'string') return [];
  const source = options?.source ?? 'untrusted';
  const hits: InjectionHit[] = [];
  for (const { rule, severity, re } of RULES) {
    const m = text.match(re);
    if (m) {
      const start = Math.max(0, (m.index ?? 0) - 20);
      const excerpt = text.slice(start, start + 80).replace(/\s+/g, ' ');
      hits.push({ rule, severity, excerpt, source });
    }
  }
  return hits;
}

/**
 * Full scan with source classification and block recommendation.
 * - system: never blocks (trusted control plane)
 * - user: detect; block only if policy says so (default: detect-only unless high + block_user)
 * - untrusted: tool results / RAG / MCP / retrieved context — block on medium+ when policy.block
 */
export function scanPromptInjection(
  text: string,
  options: ScanOptions & {
    blockMode?: boolean;
    blockUser?: boolean;
    minBlockSeverity?: InjectionSeverity;
  } = {}
): ScanResult {
  const source = options.source ?? 'untrusted';
  const effectiveSource: ContentSource =
    source === 'user' && options.scanUserAsUntrusted ? 'untrusted' : source;

  const hits = detectPromptInjection(text, { source: effectiveSource });
  let maxSeverity: InjectionSeverity | null = null;
  for (const h of hits) {
    if (!maxSeverity || SEVERITY_RANK[h.severity] > SEVERITY_RANK[maxSeverity]) {
      maxSeverity = h.severity;
    }
  }

  const minBlock = options.minBlockSeverity ?? 'medium';
  const blockMode = options.blockMode ?? false;
  let shouldBlock = false;
  const blockedRules: string[] = [];

  if (blockMode && hits.length > 0 && effectiveSource !== 'system') {
    if (effectiveSource === 'untrusted') {
      for (const h of hits) {
        if (SEVERITY_RANK[h.severity] >= SEVERITY_RANK[minBlock]) {
          shouldBlock = true;
          blockedRules.push(h.rule);
        }
      }
    } else if (effectiveSource === 'user' && (options.blockUser ?? false)) {
      for (const h of hits) {
        if (SEVERITY_RANK[h.severity] >= SEVERITY_RANK['high']) {
          shouldBlock = true;
          blockedRules.push(h.rule);
        }
      }
    }
  }

  return {
    source: effectiveSource,
    hits,
    maxSeverity,
    shouldBlock,
    blockedRules,
  };
}

/** Classify a chat message role into ContentSource */
export function classifyMessageSource(role?: string): ContentSource {
  if (!role) return 'untrusted';
  const r = role.toLowerCase();
  if (r === 'system' || r === 'developer') return 'system';
  if (r === 'user' || r === 'assistant') return r === 'assistant' ? 'untrusted' : 'user';
  // tool, function, retrieved, mcp, context → untrusted
  return 'untrusted';
}

export function listInjectionRules(): Array<{ rule: string; severity: InjectionSeverity }> {
  return RULES.map(({ rule, severity }) => ({ rule, severity }));
}
