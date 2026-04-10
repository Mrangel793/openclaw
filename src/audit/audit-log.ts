/**
 * Append-only audit log with SHA-256 hash chain and optional HMAC-SHA-256 signing.
 *
 * Each entry written to the JSONL file includes:
 *   - `prevHash`: SHA-256 of the previous entry's hash (chain integrity)
 *   - `hash`:     SHA-256 of the entry content (without hash/sig fields)
 *   - `sig`:      HMAC-SHA-256 of the hash, signed with the configured key (authenticity)
 *
 * A detached verifier (`src/audit/audit-verify.ts`) can replay the log and
 * confirm that no entries were added, removed, or modified.
 */

import { createHash, createHmac } from "node:crypto";
import { appendFile, mkdir, readFile, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { resolveConfigDir, resolveUserPath } from "../utils.js";
import type { AuditConfig, AuditEntry, AuditEntryInput } from "./audit-types.js";
import { sanitizeAuditInput } from "./pii-sanitize.js";

const GENESIS_PREV_HASH = "0".repeat(64);
const DEFAULT_LOG_SUBPATH = "audit/audit.jsonl";

/** Fields excluded when computing the entry hash. */
const HASH_EXCLUDED_FIELDS: ReadonlySet<string> = new Set(["hash", "sig"]);

/**
 * Serialize an entry to canonical JSON, excluding `hash` and `sig`.
 * Field order is deterministic (sorted by key name) so the digest is stable.
 */
function canonicalEntryJson(entry: Partial<AuditEntry>): string {
  const keys = Object.keys(entry).filter((k) => !HASH_EXCLUDED_FIELDS.has(k)).sort();
  const obj: Record<string, unknown> = {};
  for (const key of keys) {
    const value = (entry as Record<string, unknown>)[key];
    if (value !== undefined) {
      obj[key] = value;
    }
  }
  return JSON.stringify(obj);
}

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function hmacSha256Hex(data: string, key: string): string {
  return createHmac("sha256", key).update(data, "utf8").digest("hex");
}

/**
 * Resolve the signing key from a config value.
 * Supports plaintext strings and `${ENV_VAR}` templates.
 */
function resolveSigningKey(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const envMatch = /^\$\{([A-Z][A-Z0-9_]{0,127})\}$/.exec(value.trim());
  if (envMatch) {
    const envValue = process.env[envMatch[1]];
    return envValue?.trim() || undefined;
  }
  return value.trim() || undefined;
}

export function resolveDefaultAuditLogPath(): string {
  return join(resolveConfigDir(), DEFAULT_LOG_SUBPATH);
}

function resolveLogPath(config: AuditConfig): string {
  const raw = config.logPath?.trim();
  if (!raw) {
    return resolveDefaultAuditLogPath();
  }
  return raw.startsWith("~") ? resolveUserPath(raw) : raw;
}

type AuditLogState = {
  seq: number;
  lastHash: string;
};

/**
 * Read the last line of the log file to restore the hash chain state.
 * Returns genesis state when the file is absent or empty.
 */
async function loadLastState(logPath: string): Promise<AuditLogState> {
  let raw: string;
  try {
    raw = await readFile(logPath, "utf8");
  } catch {
    return { seq: 0, lastHash: GENESIS_PREV_HASH };
  }
  const lines = raw.trimEnd().split("\n");
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i].trim();
    if (!line) {
      continue;
    }
    try {
      const entry = JSON.parse(line) as Partial<AuditEntry>;
      if (typeof entry.seq === "number" && typeof entry.hash === "string") {
        return { seq: entry.seq, lastHash: entry.hash };
      }
    } catch {
      // malformed line — keep looking
    }
  }
  return { seq: 0, lastHash: GENESIS_PREV_HASH };
}

async function ensureLogDir(logPath: string): Promise<void> {
  await mkdir(dirname(logPath), { recursive: true });
}

async function rotateLog(logPath: string): Promise<void> {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const rotated = logPath.replace(/\.jsonl$/, `.${ts}.jsonl`);
  try {
    await rename(logPath, rotated);
  } catch {
    // If rename fails (file doesn't exist etc.) just continue
  }
}

export class AuditLogger {
  private readonly logPath: string;
  private readonly signingKey: string | undefined;
  private readonly rotateAfterEntries: number;
  private readonly piiSanitize: boolean;
  private state: AuditLogState | null = null;
  private initPromise: Promise<void> | null = null;
  private writeQueue: Promise<void> = Promise.resolve();

  constructor(config: AuditConfig) {
    this.logPath = resolveLogPath(config);
    this.signingKey = resolveSigningKey(config.signingKey);
    this.rotateAfterEntries = config.rotateAfterEntries ?? 0;
    this.piiSanitize = config.piiSanitize !== false; // default true
  }

  private async init(): Promise<void> {
    await ensureLogDir(this.logPath);
    this.state = await loadLastState(this.logPath);
  }

  private ensureInit(): Promise<void> {
    if (!this.initPromise) {
      this.initPromise = this.init();
    }
    return this.initPromise;
  }

  /**
   * Append an audit entry to the log. Returns the written entry.
   * Writes are serialized (queued) so concurrent callers never interleave.
   */
  append(input: AuditEntryInput): Promise<AuditEntry> {
    const result = new Promise<AuditEntry>((resolve, reject) => {
      this.writeQueue = this.writeQueue.then(async () => {
        try {
          const entry = await this.writeEntry(input);
          resolve(entry);
        } catch (err) {
          reject(err);
        }
      });
    });
    return result;
  }

  private async writeEntry(rawInput: AuditEntryInput): Promise<AuditEntry> {
    await this.ensureInit();
    const state = this.state!;

    const input = this.piiSanitize ? sanitizeAuditInput(rawInput) : rawInput;;

    // Rotate if threshold reached.
    if (this.rotateAfterEntries > 0 && state.seq >= this.rotateAfterEntries) {
      await rotateLog(this.logPath);
      state.seq = 0;
      state.lastHash = GENESIS_PREV_HASH;
    }

    const seq = state.seq + 1;
    const ts = new Date().toISOString();
    const prevHash = state.lastHash;

    // Build entry without hash/sig fields.
    const partial: Omit<AuditEntry, "hash" | "sig"> = {
      seq,
      ts,
      prevHash,
      kind: input.kind,
      ...(input.actor !== undefined && { actor: input.actor }),
      ...(input.ip !== undefined && { ip: input.ip }),
      ...(input.role !== undefined && { role: input.role }),
      ...(input.tool !== undefined && { tool: input.tool }),
      ...(input.session !== undefined && { session: input.session }),
      ...(input.details !== undefined && { details: input.details }),
    };

    const canonical = canonicalEntryJson(partial);
    const hash = sha256Hex(canonical);
    const sig = this.signingKey ? hmacSha256Hex(hash, this.signingKey) : undefined;

    const entry: AuditEntry = {
      ...partial,
      hash,
      ...(sig !== undefined && { sig }),
    };

    const line = JSON.stringify(entry) + "\n";
    await appendFile(this.logPath, line, "utf8");

    // Advance state.
    state.seq = seq;
    state.lastHash = hash;

    return entry;
  }

  /** Log path used by this instance (for display / diagnostics). */
  getLogPath(): string {
    return this.logPath;
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton — shared across the gateway process lifetime.
// ---------------------------------------------------------------------------

let activeLogger: AuditLogger | null = null;

/**
 * Initialize the module-level audit logger from config.
 * Must be called before `auditLog()`. Safe to call multiple times
 * (subsequent calls replace the active logger).
 */
export function initAuditLogger(config: AuditConfig): AuditLogger {
  activeLogger = new AuditLogger(config);
  return activeLogger;
}

/**
 * Append an entry to the active audit logger.
 * If no logger has been initialized, the call is silently dropped.
 */
export async function auditLog(input: AuditEntryInput): Promise<void> {
  if (!activeLogger) {
    return;
  }
  try {
    await activeLogger.append(input);
  } catch {
    // Audit log failures must never crash the gateway.
  }
}

/**
 * Return the active logger instance, or null if not initialized.
 */
export function getActiveAuditLogger(): AuditLogger | null {
  return activeLogger;
}
