import { createHash, createHmac } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditLogger } from "./audit-log.js";
import { verifyAuditLog } from "./audit-verify.js";

const GENESIS_HASH = "0".repeat(64);

function sha256Hex(data: string): string {
  return createHash("sha256").update(data, "utf8").digest("hex");
}

function hmacSha256Hex(data: string, key: string): string {
  return createHmac("sha256", key).update(data, "utf8").digest("hex");
}

function tmpLog(suffix = ""): string {
  return join(tmpdir(), `audit-test-${Date.now()}-${Math.random().toString(36).slice(2)}${suffix}.jsonl`);
}

describe("AuditLogger", () => {
  let logPath: string;

  beforeEach(() => {
    logPath = tmpLog();
  });

  afterEach(async () => {
    try {
      await rm(logPath, { force: true });
    } catch {
      // best-effort cleanup
    }
  });

  it("creates the log file and writes a valid first entry", async () => {
    const logger = new AuditLogger({ logPath });
    const entry = await logger.append({ kind: "gateway_start", actor: "system" });

    expect(entry.seq).toBe(1);
    expect(entry.kind).toBe("gateway_start");
    expect(entry.actor).toBe("system");
    expect(entry.prevHash).toBe(GENESIS_HASH);
    expect(entry.hash).toHaveLength(64);
    expect(entry.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(entry.sig).toBeUndefined();

    const raw = await readFile(logPath, "utf8");
    const parsed = JSON.parse(raw.trim());
    expect(parsed.hash).toBe(entry.hash);
  });

  it("sequences entries monotonically", async () => {
    const logger = new AuditLogger({ logPath });
    const e1 = await logger.append({ kind: "gateway_start" });
    const e2 = await logger.append({ kind: "tool_call", tool: "web_fetch" });
    const e3 = await logger.append({ kind: "auth_success", actor: "user" });

    expect(e1.seq).toBe(1);
    expect(e2.seq).toBe(2);
    expect(e3.seq).toBe(3);
  });

  it("chains hashes correctly (prevHash of N equals hash of N-1)", async () => {
    const logger = new AuditLogger({ logPath });
    const e1 = await logger.append({ kind: "gateway_start" });
    const e2 = await logger.append({ kind: "tool_call", tool: "web_fetch" });
    const e3 = await logger.append({ kind: "auth_success" });

    expect(e1.prevHash).toBe(GENESIS_HASH);
    expect(e2.prevHash).toBe(e1.hash);
    expect(e3.prevHash).toBe(e2.hash);
  });

  it("hash is deterministic: recomputing matches stored hash", async () => {
    const logger = new AuditLogger({ logPath });
    const entry = await logger.append({ kind: "tool_call", tool: "sessions_spawn", session: "s1" });

    // Recompute canonical JSON (sorted keys, excluding hash/sig).
    const { hash: _hash, sig: _sig, ...rest } = entry;
    const keys = Object.keys(rest).sort();
    const obj: Record<string, unknown> = {};
    for (const k of keys) {
      if ((rest as Record<string, unknown>)[k] !== undefined) {
        obj[k] = (rest as Record<string, unknown>)[k];
      }
    }
    const recomputed = sha256Hex(JSON.stringify(obj));
    expect(recomputed).toBe(entry.hash);
  });

  it("includes HMAC sig when signingKey is configured", async () => {
    const signingKey = "test-signing-key-for-unit-tests";
    const logger = new AuditLogger({ logPath, signingKey });
    const entry = await logger.append({ kind: "gateway_start", actor: "system" });

    expect(entry.sig).toBeDefined();
    expect(entry.sig).toHaveLength(64);
    // Verify HMAC manually.
    const expectedSig = hmacSha256Hex(entry.hash, signingKey);
    expect(entry.sig).toBe(expectedSig);
  });

  it("does not include sig when no signingKey", async () => {
    const logger = new AuditLogger({ logPath });
    const entry = await logger.append({ kind: "gateway_start" });
    expect(entry.sig).toBeUndefined();
  });

  it("resumes hash chain correctly after restart (reads last entry from file)", async () => {
    // First logger session.
    const logger1 = new AuditLogger({ logPath });
    const e1 = await logger1.append({ kind: "gateway_start" });
    const e2 = await logger1.append({ kind: "tool_call", tool: "web_fetch" });

    // Second logger session — simulates gateway restart.
    const logger2 = new AuditLogger({ logPath });
    const e3 = await logger2.append({ kind: "gateway_start" });

    expect(e3.seq).toBe(3);
    expect(e3.prevHash).toBe(e2.hash);
    // Ensure e1 is still there.
    expect(e3.prevHash).not.toBe(e1.hash);
  });

  it("includes all provided optional fields in the entry", async () => {
    const logger = new AuditLogger({ logPath });
    const entry = await logger.append({
      kind: "tool_blocked",
      actor: "analista",
      ip: "192.168.1.50",
      role: "analista",
      tool: "sessions_spawn",
      session: "agent:main:main",
      details: { reason: "role_deny_list" },
    });

    expect(entry.actor).toBe("analista");
    expect(entry.ip).toBe("192.168.1.50");
    expect(entry.role).toBe("analista");
    expect(entry.tool).toBe("sessions_spawn");
    expect(entry.session).toBe("agent:main:main");
    expect(entry.details).toEqual({ reason: "role_deny_list" });
  });

  it("writes valid JSON lines to the file", async () => {
    const logger = new AuditLogger({ logPath });
    await logger.append({ kind: "gateway_start" });
    await logger.append({ kind: "tool_call", tool: "web_fetch" });

    const raw = await readFile(logPath, "utf8");
    const lines = raw.trim().split("\n");
    expect(lines).toHaveLength(2);
    for (const line of lines) {
      expect(() => JSON.parse(line)).not.toThrow();
    }
  });
});

describe("verifyAuditLog", () => {
  let logPath: string;

  beforeEach(() => {
    logPath = tmpLog("-verify");
  });

  afterEach(async () => {
    try {
      await rm(logPath, { force: true });
    } catch {
      // best-effort
    }
  });

  it("returns ok:true for a valid unmodified log", async () => {
    const logger = new AuditLogger({ logPath });
    await logger.append({ kind: "gateway_start" });
    await logger.append({ kind: "tool_call", tool: "web_fetch" });
    await logger.append({ kind: "auth_success", actor: "admin" });

    const result = await verifyAuditLog(logPath);
    expect(result.ok).toBe(true);
    expect(result.totalEntries).toBe(3);
    expect(result.errors).toHaveLength(0);
  });

  it("detects a tampered hash field", async () => {
    const logger = new AuditLogger({ logPath });
    await logger.append({ kind: "gateway_start" });
    await logger.append({ kind: "tool_call", tool: "web_fetch" });

    // Tamper: overwrite the first entry's hash with a wrong value.
    const raw = await readFile(logPath, "utf8");
    const lines = raw.trim().split("\n");
    const entry1 = JSON.parse(lines[0]);
    entry1.hash = "a".repeat(64); // wrong hash
    lines[0] = JSON.stringify(entry1);
    const { writeFile } = await import("node:fs/promises");
    await writeFile(logPath, lines.join("\n") + "\n");

    const result = await verifyAuditLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.kind === "hash_mismatch")).toBe(true);
    // Entry 2's prevHash should also fail since entry 1's hash was changed.
    expect(result.errors.some((e) => e.kind === "prev_hash_mismatch")).toBe(true);
  });

  it("detects a modified entry field (tampered content)", async () => {
    const logger = new AuditLogger({ logPath });
    await logger.append({ kind: "tool_call", tool: "web_fetch", actor: "user" });

    const raw = await readFile(logPath, "utf8");
    const entry = JSON.parse(raw.trim());
    // Tamper: change actor but keep original hash (hash will not match now).
    entry.actor = "attacker";
    const { writeFile } = await import("node:fs/promises");
    await writeFile(logPath, JSON.stringify(entry) + "\n");

    const result = await verifyAuditLog(logPath);
    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.kind === "hash_mismatch")).toBe(true);
  });

  it("verifies HMAC sig when signing key is provided", async () => {
    const signingKey = "test-hmac-key";
    const logger = new AuditLogger({ logPath, signingKey });
    await logger.append({ kind: "gateway_start" });

    // Verify with correct key.
    const result = await verifyAuditLog(logPath, signingKey);
    expect(result.ok).toBe(true);
    expect(result.errors).toHaveLength(0);
  });

  it("detects HMAC sig mismatch when wrong key is used for verification", async () => {
    const logger = new AuditLogger({ logPath, signingKey: "correct-key" });
    await logger.append({ kind: "gateway_start" });

    const result = await verifyAuditLog(logPath, "wrong-key");
    expect(result.ok).toBe(false);
    expect(result.errors.some((e) => e.kind === "sig_mismatch")).toBe(true);
  });

  it("returns ok:true with no errors on an empty file", async () => {
    const { writeFile } = await import("node:fs/promises");
    await writeFile(logPath, "");
    const result = await verifyAuditLog(logPath);
    expect(result.ok).toBe(true);
    expect(result.totalEntries).toBe(0);
  });
});
