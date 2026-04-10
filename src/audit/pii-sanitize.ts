/**
 * PII sanitization for audit log entries.
 *
 * Masks personally identifiable information before entries are written to the
 * audit log, complying with Colombian Ley 1581 de 2012 (Habeas Data).
 *
 * Patterns covered:
 *   - Email addresses
 *   - Colombian mobile phone numbers (10 digits, starting with 3; +57 prefix)
 *   - Colombian cédula numbers (dot-formatted: 1.234.567 / 12.345.678.901;
 *     or following explicit labels: "CC:", "cédula", "documento", "NIT")
 */

import type { AuditEntryInput } from "./audit-types.js";

// ---------------------------------------------------------------------------
// Patterns
// ---------------------------------------------------------------------------

/** Standard email address (RFC-5321 local-part, up to 64 chars). */
const EMAIL_RE = /[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]{1,255}\.[a-zA-Z]{2,}/g;

/**
 * Colombian mobile phone numbers.
 * Matches 10-digit numbers starting with 3 (Colombian mobile prefix),
 * optionally preceded by the +57 country code.
 * Spaces and dashes between digit groups are accepted.
 *
 * Two branches via alternation:
 *   1. `+57` prefixed  — explicit country code, no lookbehind needed.
 *   2. Standalone      — `3` must not be preceded by a hex/digit/dot char
 *                        (avoids false positives inside hashes or decimals).
 *
 * Examples: 3001234567 | 300 123 4567 | 300-123-4567 | +57 300 123 4567 | +573001234567
 */
const PHONE_RE =
  /(?:\+57[\s\-]?3\d{2}|(?<![0-9a-fA-F.])3\d{2})[\s\-]?\d{3}[\s\-]?\d{4}(?!\d)/g;

/**
 * Dot-formatted Colombian cédula numbers (thousands separator = ".").
 * Requires at least two dot-separated groups of exactly 3 digits.
 *
 * Examples: 1.234.567 | 12.345.678 | 1.234.567.890
 */
const CEDULA_DOT_RE = /\b\d{1,3}(?:\.\d{3}){2,3}\b/g;

/**
 * Plain cédula numbers that follow an explicit label (CC, cédula, documento, NIT).
 * Uses lookbehind to replace only the number, preserving the label in the log.
 *
 * Examples: "CC: 12345678" → "CC: [CEDULA]"
 *           "Cédula: 1234567890" → "Cédula: [CEDULA]"
 */
const CEDULA_CONTEXTUAL_RE =
  /(?<=\b(?:c\.?\s*c\.?|c[eé]dula|documento|identificaci[oó]n|nit)\s*[:#\s]\s*)[1-9]\d{6,9}\b/gi;

// ---------------------------------------------------------------------------
// Mask tokens — distinct tokens so log consumers can count / alert on PII hits.
// ---------------------------------------------------------------------------

export const MASK_EMAIL = "[EMAIL]";
export const MASK_PHONE = "[PHONE]";
export const MASK_CEDULA = "[CEDULA]";

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/**
 * Sanitize a single string value.
 * Patterns are applied in order: email → cédula (contextual) → cédula (dot) → phone.
 * Order matters: email must fire before phone to avoid mangling local-part digits.
 */
export function sanitizeString(text: string): string {
  // Reset lastIndex before each call (global regexes are stateful).
  EMAIL_RE.lastIndex = 0;
  CEDULA_CONTEXTUAL_RE.lastIndex = 0;
  CEDULA_DOT_RE.lastIndex = 0;
  PHONE_RE.lastIndex = 0;

  return text
    .replace(EMAIL_RE, MASK_EMAIL)
    .replace(CEDULA_CONTEXTUAL_RE, MASK_CEDULA)
    .replace(CEDULA_DOT_RE, MASK_CEDULA)
    .replace(PHONE_RE, MASK_PHONE);
}

/**
 * Deep-traverse an arbitrary value, sanitizing all string leaves.
 * Non-string primitives (numbers, booleans, null, undefined) pass through unchanged.
 */
export function sanitizeValue(value: unknown): unknown {
  if (typeof value === "string") {
    return sanitizeString(value);
  }
  if (Array.isArray(value)) {
    return value.map(sanitizeValue);
  }
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = sanitizeValue(v);
    }
    return out;
  }
  return value;
}

/**
 * Return a copy of an `AuditEntryInput` with PII fields sanitized.
 *
 * Fields sanitized:
 *   - `actor`   — may contain an email or name
 *   - `role`    — may contain an email used as role identifier
 *   - `tool`    — unlikely, but sanitized for safety
 *   - `details` — free-form; most likely to carry PII from message content
 *
 * Fields NOT sanitized (intentionally):
 *   - `ip`      — system-level network address, not personal data under Ley 1581
 *   - `session` — opaque token, no structured PII
 *   - `kind`    — enum value, never PII
 */
export function sanitizeAuditInput(input: AuditEntryInput): AuditEntryInput {
  return {
    ...input,
    ...(input.actor !== undefined && { actor: sanitizeString(input.actor) }),
    ...(input.role !== undefined && { role: sanitizeString(input.role) }),
    ...(input.tool !== undefined && { tool: sanitizeString(input.tool) }),
    ...(input.details !== undefined && {
      details: sanitizeValue(input.details) as Record<string, unknown>,
    }),
  };
}
