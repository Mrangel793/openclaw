/**
 * Audit log types for MSPI Colombia compliance.
 *
 * Each entry is chained via SHA-256 (prevHash → hash) so any tampering with
 * historical records is detectable. An optional HMAC-SHA-256 signature field
 * (`sig`) proves entry authenticity when a signing key is configured.
 */

export type AuditEventKind =
  /** MCP tool invoked successfully through the gateway. */
  | "tool_call"
  /** Tool call blocked by gateway policy (deny list, role restriction, network policy). */
  | "tool_blocked"
  /** Successful gateway authentication. */
  | "auth_success"
  /** Failed gateway authentication attempt. */
  | "auth_failure"
  /** Rate-limited authentication attempt. */
  | "auth_rate_limited"
  /** Inbound message rejected due to prompt injection detection. */
  | "injection_blocked"
  /** Gateway configuration file written. */
  | "config_change"
  /** Skill installed. */
  | "skill_install"
  /** Skill updated. */
  | "skill_update"
  /** Gateway process started. */
  | "gateway_start"
  /** Gateway process stopping. */
  | "gateway_stop";

export type AuditEntry = {
  /** Sequential index starting at 1. Monotonically increasing within a log file. */
  seq: number;
  /** ISO-8601 timestamp in UTC (e.g. "2026-04-08T21:30:00.000Z"). */
  ts: string;
  /** Event kind. */
  kind: AuditEventKind;
  /** Actor identifier: role name, authenticated user, client IP, or "system". */
  actor?: string;
  /** Client IP address (when available). */
  ip?: string;
  /** Authenticated role name (for role-token requests). */
  role?: string;
  /** Tool name (for tool_call / tool_blocked events). */
  tool?: string;
  /** Session key (for tool_call events). */
  session?: string;
  /** Additional structured details (sanitized — no secret values). */
  details?: Record<string, unknown>;
  /**
   * SHA-256 hex digest of the previous entry's `hash` field.
   * The genesis entry uses 64 zero characters ("000...000").
   */
  prevHash: string;
  /**
   * SHA-256 hex digest of this entry serialized without the `hash` and `sig` fields.
   * Used to verify the integrity of the hash chain.
   */
  hash: string;
  /**
   * HMAC-SHA-256 hex digest of this entry's `hash` field, signed with the configured
   * audit signing key. Present only when `audit.signingKey` is configured.
   * Used to prove that entries were written by an authorized gateway process.
   */
  sig?: string;
};

/** Input to the audit logger — seq / ts / prevHash / hash / sig are computed internally. */
export type AuditEntryInput = Omit<AuditEntry, "seq" | "ts" | "prevHash" | "hash" | "sig">;

export type AuditConfig = {
  /**
   * Enable the audit log.
   * Automatically true when `logPath` is explicitly configured.
   * Default: false.
   */
  enabled?: boolean;
  /**
   * Absolute or home-relative path for the JSONL audit log file.
   * Default: `~/.openclaw/audit/audit.jsonl`.
   */
  logPath?: string;
  /**
   * Signing key for HMAC-SHA-256 entry signatures (plaintext or `${ENV_VAR}`).
   * When omitted, entries include only the SHA-256 hash chain (no HMAC).
   * Recommended: at least 32 random bytes, base64-encoded.
   */
  signingKey?: string;
  /**
   * Rotate the log file after this many entries.
   * The current file is renamed to `audit.<timestamp>.jsonl` and a new file is started.
   * Default: 0 (no rotation).
   */
  rotateAfterEntries?: number;
  /**
   * Sanitize PII (emails, phone numbers, cédulas) from log entries before writing.
   * Complies with Colombian Ley 1581 de 2012 (Habeas Data).
   * Default: true.
   */
  piiSanitize?: boolean;
};
