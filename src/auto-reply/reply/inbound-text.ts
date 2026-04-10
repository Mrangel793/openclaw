export type InjectionDetectionResult =
  | { detected: false }
  | { detected: true; reason: string; pattern: string };

const INJECTION_PATTERNS: ReadonlyArray<{ pattern: RegExp; reason: string }> = [
  // --- Instruction override (EN) ---
  {
    pattern: /ignore\s+(all\s+|previous\s+|above\s+)?instructions?/i,
    reason: "instruction override attempt",
  },
  {
    pattern: /forget\s+(everything|the\s+above|all\s+previous)/i,
    reason: "instruction override attempt",
  },
  {
    pattern: /disregard\s+(?:all\s+)?(?:previous\s+|your\s+)?instructions?/i,
    reason: "instruction override attempt",
  },
  // --- Instruction override (ES) ---
  {
    pattern: /ignora\s+(las\s+|todas\s+(las\s+)?)?instrucciones/i,
    reason: "instruction override attempt (es)",
  },
  {
    pattern: /olvida\s+(todo|lo\s+anterior|tus\s+instrucciones)/i,
    reason: "instruction override attempt (es)",
  },
  {
    pattern: /nueva\s+instrucci[oó]n/i,
    reason: "instruction override attempt (es)",
  },
  {
    pattern: /a\s+partir\s+de\s+ahora\s+(eres|debes|act[uú]a)/i,
    reason: "instruction override attempt (es)",
  },
  // --- Role injection (EN) ---
  {
    pattern: /you\s+are\s+now\s+/i,
    reason: "role injection attempt",
  },
  {
    pattern: /pretend\s+(to\s+be|you\s+are)/i,
    reason: "role injection attempt",
  },
  {
    pattern: /act\s+as\s+(if\s+you\s+are|a\s+)/i,
    reason: "role injection attempt",
  },
  {
    pattern: /your\s+new\s+(role|persona|identity)\s+is/i,
    reason: "role injection attempt",
  },
  // --- Role injection (ES) ---
  {
    pattern: /act[uú]a\s+como/i,
    reason: "role injection attempt (es)",
  },
  {
    pattern: /ahora\s+eres\s+/i,
    reason: "role injection attempt (es)",
  },
  {
    pattern: /fin(ge|gir)\s+(ser|que\s+eres)/i,
    reason: "role injection attempt (es)",
  },
  // --- System prompt / context injection ---
  {
    pattern: /<system>/i,
    reason: "system prompt injection attempt",
  },
  {
    pattern: /###\s*(system|instruction)/i,
    reason: "system prompt injection attempt",
  },
  {
    pattern: /new\s+system\s+prompt/i,
    reason: "system prompt injection attempt",
  },
  {
    pattern: /\[system\]/i,
    reason: "system prompt injection attempt",
  },
  {
    pattern: /---(END|BEGIN)\s*(SYSTEM|PROMPT|INSTRUCTION)---/i,
    reason: "system prompt injection attempt",
  },
  // --- Jailbreak triggers ---
  {
    pattern: /jailbreak/i,
    reason: "jailbreak keyword",
  },
  {
    pattern: /developer\s+mode\s+(enabled|on|activated)/i,
    reason: "jailbreak keyword",
  },
  {
    pattern: /DAN\s+(mode|prompt)/i,
    reason: "jailbreak keyword",
  },
  // --- RTL override and invisible / zero-width unicode ---
  {
    pattern: /[\u202e\u200f\u200b\ufeff\u2060]/,
    reason: "suspicious unicode character",
  },
];

/**
 * Keywords that must appear in a base64-decoded string for it to trigger a
 * base64 injection alert. Chosen to minimise false positives on legitimate
 * base64 payloads (images, documents) while catching hidden instruction text.
 */
const BASE64_INJECTION_KEYWORDS =
  /ignore|instructions?|forget|system\s+prompt|pretend|jailbreak|instrucciones|olvida|ignora|act\s+as/i;

/**
 * Matches candidate base64 chunks: at least 40 chars of base64 alphabet,
 * optionally followed by one or two `=` padding chars.
 * The surrounding context anchors prevent matching hex hashes, UUIDs, etc.
 * embedded mid-word, but allows chunks that start at a word boundary.
 */
const BASE64_CHUNK_RE =
  /(?:^|[\s"'`([{,;])([A-Za-z0-9+/]{40,}={0,2})(?=$|[\s"'`)\]},;.])/gm;

/**
 * Decode a base64 candidate string and check whether it contains injection
 * keywords. Returns true if the chunk looks like a hidden instruction.
 */
function isBase64InjectionChunk(candidate: string): boolean {
  // Padding: base64 strings must have length divisible by 4 (allow 1-2 missing)
  const padded =
    candidate.length % 4 === 0
      ? candidate
      : candidate + "=".repeat(4 - (candidate.length % 4));
  let decoded: string;
  try {
    decoded = Buffer.from(padded, "base64").toString("utf-8");
  } catch {
    return false;
  }
  // Reject if decoded output contains many non-printable bytes (binary data)
  const nonPrintable = (decoded.match(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g) ?? []).length;
  if (nonPrintable > decoded.length * 0.1) {
    return false;
  }
  return BASE64_INJECTION_KEYWORDS.test(decoded);
}

/**
 * Scan text for base64 chunks that, when decoded, contain injection keywords.
 */
function detectBase64Injection(text: string): InjectionDetectionResult {
  BASE64_CHUNK_RE.lastIndex = 0;
  let match: RegExpExecArray | null;
  while ((match = BASE64_CHUNK_RE.exec(text)) !== null) {
    const candidate = match[1];
    if (candidate && isBase64InjectionChunk(candidate)) {
      return {
        detected: true,
        reason: "base64-encoded injection attempt",
        pattern: "base64",
      };
    }
  }
  return { detected: false };
}

export function detectPromptInjection(
  text: string,
  additionalPatterns?: string[],
): InjectionDetectionResult {
  for (const { pattern, reason } of INJECTION_PATTERNS) {
    if (pattern.test(text)) {
      return { detected: true, reason, pattern: pattern.source };
    }
  }

  const base64Result = detectBase64Injection(text);
  if (base64Result.detected) {
    return base64Result;
  }

  if (additionalPatterns) {
    for (const raw of additionalPatterns) {
      try {
        const re = new RegExp(raw, "i");
        if (re.test(text)) {
          return { detected: true, reason: "custom pattern", pattern: raw };
        }
      } catch {
        // invalid regex — skip
      }
    }
  }
  return { detected: false };
}

export function normalizeInboundTextNewlines(input: string): string {
  // Normalize actual newline characters (CR+LF and CR to LF).
  // Do NOT replace literal backslash-n sequences (\\n) as they may be part of
  // Windows paths like C:\Work\nxxx\README.md or user-intended escape sequences.
  return input.replaceAll("\r\n", "\n").replaceAll("\r", "\n");
}

const BRACKETED_SYSTEM_TAG_RE = /\[\s*(System\s*Message|System|Assistant|Internal)\s*\]/gi;
const LINE_SYSTEM_PREFIX_RE = /^(\s*)System:(?=\s|$)/gim;

/**
 * Neutralize user-controlled strings that spoof internal system markers.
 */
export function sanitizeInboundSystemTags(input: string): string {
  return input
    .replace(BRACKETED_SYSTEM_TAG_RE, (_match, tag: string) => `(${tag})`)
    .replace(LINE_SYSTEM_PREFIX_RE, "$1System (untrusted):");
}
