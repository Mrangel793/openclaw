/**
 * Audit log integrity verifier.
 *
 * Reads a JSONL audit log and checks:
 * 1. Hash chain continuity (prevHash of entry N == hash of entry N-1).
 * 2. Hash correctness (recompute SHA-256 and compare).
 * 3. HMAC signature validity (when a signing key is provided).
 */

import { createHash, createHmac } from "node:crypto";
import { createReadStream } from "node:fs";
import { createInterface } from "node:readline";
import type { AuditEntry } from "./audit-types.js";

const GENESIS_PREV_HASH = "0".repeat(64);
const HASH_EXCLUDED_FIELDS: ReadonlySet<string> = new Set(["hash", "sig"]);

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

export type VerifyResult = {
  ok: boolean;
  totalEntries: number;
  errors: VerifyError[];
};

export type VerifyError = {
  lineNumber: number;
  seq?: number;
  kind: "parse_error" | "seq_gap" | "prev_hash_mismatch" | "hash_mismatch" | "sig_mismatch";
  message: string;
};

/**
 * Verify the integrity of an audit log file.
 *
 * @param logPath - Path to the JSONL audit log file.
 * @param signingKey - Optional HMAC signing key to verify `sig` fields.
 * @returns Verification result with error list.
 */
export async function verifyAuditLog(
  logPath: string,
  signingKey?: string,
): Promise<VerifyResult> {
  const errors: VerifyError[] = [];
  let totalEntries = 0;
  let expectedPrevHash = GENESIS_PREV_HASH;
  let expectedSeq = 1;
  let lineNumber = 0;

  const stream = createReadStream(logPath, "utf8");
  const rl = createInterface({ input: stream, crlfDelay: Infinity });

  for await (const line of rl) {
    lineNumber++;
    const trimmed = line.trim();
    if (!trimmed) {
      continue;
    }

    let entry: Partial<AuditEntry>;
    try {
      entry = JSON.parse(trimmed) as Partial<AuditEntry>;
    } catch {
      errors.push({
        lineNumber,
        kind: "parse_error",
        message: `Line ${lineNumber}: failed to parse JSON`,
      });
      continue;
    }

    totalEntries++;

    // Check sequential integrity.
    if (typeof entry.seq === "number" && entry.seq !== expectedSeq) {
      errors.push({
        lineNumber,
        seq: entry.seq,
        kind: "seq_gap",
        message: `Line ${lineNumber}: expected seq=${expectedSeq}, got seq=${entry.seq}`,
      });
    }

    // Check prevHash chain.
    if (typeof entry.prevHash === "string") {
      if (entry.prevHash !== expectedPrevHash) {
        errors.push({
          lineNumber,
          seq: entry.seq,
          kind: "prev_hash_mismatch",
          message: `Line ${lineNumber} seq=${entry.seq}: prevHash mismatch (chain broken)`,
        });
      }
    }

    // Recompute and verify hash.
    if (typeof entry.hash === "string") {
      const recomputed = sha256Hex(canonicalEntryJson(entry));
      if (recomputed !== entry.hash) {
        errors.push({
          lineNumber,
          seq: entry.seq,
          kind: "hash_mismatch",
          message: `Line ${lineNumber} seq=${entry.seq}: hash mismatch — entry may have been tampered`,
        });
      }

      // Verify HMAC signature if key is provided.
      if (signingKey && typeof entry.sig === "string") {
        const expectedSig = hmacSha256Hex(entry.hash, signingKey);
        if (expectedSig !== entry.sig) {
          errors.push({
            lineNumber,
            seq: entry.seq,
            kind: "sig_mismatch",
            message: `Line ${lineNumber} seq=${entry.seq}: HMAC signature mismatch — entry may be inauthentic`,
          });
        }
      }

      // Advance expected state for next iteration.
      expectedPrevHash = entry.hash;
    }

    expectedSeq = (entry.seq ?? expectedSeq) + 1;
  }

  return { ok: errors.length === 0, totalEntries, errors };
}
