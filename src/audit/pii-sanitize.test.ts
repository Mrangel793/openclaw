import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditLogger } from "./audit-log.js";
import {
  MASK_CEDULA,
  MASK_EMAIL,
  MASK_PHONE,
  sanitizeAuditInput,
  sanitizeString,
  sanitizeValue,
} from "./pii-sanitize.js";

// ---------------------------------------------------------------------------
// sanitizeString
// ---------------------------------------------------------------------------

describe("sanitizeString — emails", () => {
  it("masks a plain email", () => {
    expect(sanitizeString("usuario@entidad.gov.co")).toBe(MASK_EMAIL);
  });

  it("masks an email embedded in text", () => {
    const result = sanitizeString("Contactar a juan.perez@correo.com para info");
    expect(result).toBe(`Contactar a ${MASK_EMAIL} para info`);
  });

  it("masks multiple emails in one string", () => {
    const result = sanitizeString("De: a@b.co Para: c@d.org");
    expect(result).toBe(`De: ${MASK_EMAIL} Para: ${MASK_EMAIL}`);
  });

  it("does not mask plain text without @", () => {
    expect(sanitizeString("analista-principal")).toBe("analista-principal");
  });

  it("does not mask a lone @ sign", () => {
    expect(sanitizeString("error @ line 42")).toBe("error @ line 42");
  });
});

describe("sanitizeString — Colombian mobile phones", () => {
  it("masks a plain 10-digit mobile number", () => {
    expect(sanitizeString("3001234567")).toBe(MASK_PHONE);
  });

  it("masks mobile with spaces", () => {
    expect(sanitizeString("300 123 4567")).toBe(MASK_PHONE);
  });

  it("masks mobile with dashes", () => {
    expect(sanitizeString("300-123-4567")).toBe(MASK_PHONE);
  });

  it("masks mobile with +57 country code", () => {
    expect(sanitizeString("+57 300 123 4567")).toBe(MASK_PHONE);
  });

  it("masks mobile with +57 no spaces", () => {
    expect(sanitizeString("+573001234567")).toBe(MASK_PHONE);
  });

  it("masks phone embedded in a sentence", () => {
    const result = sanitizeString("Llame al 3109876543 para confirmar");
    expect(result).toBe(`Llame al ${MASK_PHONE} para confirmar`);
  });

  it("does not mask a number that starts with 1", () => {
    // 1234567890 starts with 1 — not a Colombian mobile
    expect(sanitizeString("ID 1234567890")).toBe("ID 1234567890");
  });

  it("does not mask a port number like 3000", () => {
    // Only 4 digits after the 3 → does not match 3 + 9 more digits
    expect(sanitizeString("localhost:3000")).toBe("localhost:3000");
  });

  it("does not mask a sequence inside a SHA-256 hash", () => {
    // A 64-char hex hash has no word boundaries mid-string
    const hash = "a".repeat(32) + "3" + "b".repeat(31);
    expect(sanitizeString(hash)).toBe(hash);
  });
});

describe("sanitizeString — cédulas colombianas (dot-formatted)", () => {
  it("masks a 7-digit cédula formatted with dots (1.234.567)", () => {
    expect(sanitizeString("1.234.567")).toBe(MASK_CEDULA);
  });

  it("masks a 10-digit cédula (1.234.567.890)", () => {
    expect(sanitizeString("1.234.567.890")).toBe(MASK_CEDULA);
  });

  it("masks cédula embedded in text", () => {
    const result = sanitizeString("Ciudadano 12.345.678 solicita trámite");
    expect(result).toBe(`Ciudadano ${MASK_CEDULA} solicita trámite`);
  });

  it("does not mask a decimal number like 12.34", () => {
    // Only 2 digits after dot — does not satisfy the 3-digit group pattern
    expect(sanitizeString("precio: 12.34")).toBe("precio: 12.34");
  });

  it("does not mask a version like 1.2.3", () => {
    expect(sanitizeString("v1.2.3")).toBe("v1.2.3");
  });
});

describe("sanitizeString — cédulas colombianas (contextual)", () => {
  it("masks plain digits after 'CC:'", () => {
    const result = sanitizeString("CC: 12345678");
    expect(result).toBe(`CC: ${MASK_CEDULA}`);
  });

  it("masks after 'cédula' label (with accent)", () => {
    const result = sanitizeString("cédula 1234567890");
    expect(result).toBe(`cédula ${MASK_CEDULA}`);
  });

  it("masks after 'cedula' label (no accent)", () => {
    const result = sanitizeString("cedula: 87654321");
    expect(result).toBe(`cedula: ${MASK_CEDULA}`);
  });

  it("masks after 'documento' label", () => {
    const result = sanitizeString("documento #123456789");
    expect(result).toBe(`documento #${MASK_CEDULA}`);
  });

  it("masks after 'NIT' label (uppercase)", () => {
    const result = sanitizeString("NIT: 900123456");
    expect(result).toBe(`NIT: ${MASK_CEDULA}`);
  });

  it("does not mask a 5-digit number after CC (too short for cédula)", () => {
    expect(sanitizeString("CC: 12345")).toBe("CC: 12345");
  });

  it("does not mask an 11-digit number after CC (too long)", () => {
    expect(sanitizeString("CC: 12345678901")).toBe("CC: 12345678901");
  });
});

describe("sanitizeString — no false positives on system fields", () => {
  it("does not alter a tool name", () => {
    expect(sanitizeString("sessions_spawn")).toBe("sessions_spawn");
  });

  it("does not alter an RFC-1918 IP address", () => {
    expect(sanitizeString("192.168.1.50")).toBe("192.168.1.50");
  });

  it("does not alter a role name like 'analista'", () => {
    expect(sanitizeString("analista")).toBe("analista");
  });

  it("does not alter an event kind like 'tool_call'", () => {
    expect(sanitizeString("tool_call")).toBe("tool_call");
  });

  it("does not alter a reason string", () => {
    expect(sanitizeString("role_deny_list")).toBe("role_deny_list");
  });
});

// ---------------------------------------------------------------------------
// sanitizeValue
// ---------------------------------------------------------------------------

describe("sanitizeValue", () => {
  it("sanitizes a top-level string", () => {
    expect(sanitizeValue("3001234567")).toBe(MASK_PHONE);
  });

  it("passes through numbers unchanged", () => {
    expect(sanitizeValue(42)).toBe(42);
  });

  it("passes through booleans unchanged", () => {
    expect(sanitizeValue(true)).toBe(true);
  });

  it("passes through null unchanged", () => {
    expect(sanitizeValue(null)).toBeNull();
  });

  it("sanitizes string items inside an array", () => {
    const result = sanitizeValue(["clean", "3001234567", "also clean"]);
    expect(result).toEqual(["clean", MASK_PHONE, "also clean"]);
  });

  it("sanitizes string values inside a flat object", () => {
    const result = sanitizeValue({ name: "CC: 12345678", count: 3 });
    expect(result).toEqual({ name: `CC: ${MASK_CEDULA}`, count: 3 });
  });

  it("sanitizes string values in a nested object", () => {
    const result = sanitizeValue({
      user: { contact: "ana@gobernacion.co", phone: "300 987 6543" },
    });
    expect(result).toEqual({
      user: { contact: MASK_EMAIL, phone: MASK_PHONE },
    });
  });

  it("sanitizes strings inside arrays inside objects", () => {
    const result = sanitizeValue({ tags: ["ok", "email:x@y.com", 1] });
    expect(result).toEqual({ tags: ["ok", `email:${MASK_EMAIL}`, 1] });
  });
});

// ---------------------------------------------------------------------------
// sanitizeAuditInput
// ---------------------------------------------------------------------------

describe("sanitizeAuditInput", () => {
  it("sanitizes actor when it contains an email", () => {
    const result = sanitizeAuditInput({ kind: "auth_success", actor: "ana@entidad.gov.co" });
    expect(result.actor).toBe(MASK_EMAIL);
  });

  it("sanitizes role when it contains an email", () => {
    const result = sanitizeAuditInput({ kind: "tool_call", role: "admin@sistema.co" });
    expect(result.role).toBe(MASK_EMAIL);
  });

  it("sanitizes details deeply", () => {
    const result = sanitizeAuditInput({
      kind: "tool_blocked",
      details: {
        message: "Solicitante CC: 87654321 llama al 3109876543",
        nested: { doc: "1.234.567.890" },
      },
    });
    expect((result.details as Record<string, unknown>)["message"]).toBe(
      `Solicitante CC: ${MASK_CEDULA} llama al ${MASK_PHONE}`,
    );
    expect(
      ((result.details as Record<string, unknown>)["nested"] as Record<string, unknown>)["doc"],
    ).toBe(MASK_CEDULA);
  });

  it("does NOT sanitize the ip field", () => {
    const result = sanitizeAuditInput({ kind: "auth_success", ip: "203.0.113.5" });
    // IP is preserved as-is (it's a system field, not personal data under Ley 1581)
    expect(result.ip).toBe("203.0.113.5");
  });

  it("does NOT sanitize the session field", () => {
    const result = sanitizeAuditInput({ kind: "tool_call", session: "agent:main:main" });
    expect(result.session).toBe("agent:main:main");
  });

  it("passes through entries with no PII unchanged", () => {
    const input = { kind: "gateway_start" as const, actor: "system" };
    const result = sanitizeAuditInput(input);
    expect(result).toEqual(input);
  });
});

// ---------------------------------------------------------------------------
// AuditLogger integration — PII sanitization is applied before hashing
// ---------------------------------------------------------------------------

describe("AuditLogger PII integration", () => {
  let logPath: string;

  beforeEach(() => {
    logPath = join(tmpdir(), `pii-test-${Date.now()}-${Math.random().toString(36).slice(2)}.jsonl`);
  });

  afterEach(async () => {
    await rm(logPath, { force: true });
  });

  it("sanitizes PII in details before writing (default piiSanitize:true)", async () => {
    const logger = new AuditLogger({ logPath });
    const entry = await logger.append({
      kind: "tool_blocked",
      details: { message: "Ciudadano 1.234.567.890 llamó a 3001234567" },
    });

    const msg = (entry.details as Record<string, unknown>)["message"] as string;
    expect(msg).not.toContain("1.234.567.890");
    expect(msg).not.toContain("3001234567");
    expect(msg).toContain(MASK_CEDULA);
    expect(msg).toContain(MASK_PHONE);
  });

  it("sanitizes actor email before writing", async () => {
    const logger = new AuditLogger({ logPath });
    const entry = await logger.append({
      kind: "auth_success",
      actor: "funcionario@entidad.gov.co",
    });
    expect(entry.actor).toBe(MASK_EMAIL);
  });

  it("does NOT sanitize when piiSanitize:false", async () => {
    const logger = new AuditLogger({ logPath, piiSanitize: false });
    const entry = await logger.append({
      kind: "auth_success",
      actor: "funcionario@entidad.gov.co",
      details: { cedula: "1.234.567.890" },
    });
    expect(entry.actor).toBe("funcionario@entidad.gov.co");
    expect((entry.details as Record<string, unknown>)["cedula"]).toBe("1.234.567.890");
  });

  it("hash chain remains valid after sanitization", async () => {
    const logger = new AuditLogger({ logPath });
    const e1 = await logger.append({ kind: "gateway_start" });
    const e2 = await logger.append({
      kind: "tool_call",
      actor: "ana@corp.co",
      details: { phone: "3109876543" },
    });

    expect(e2.prevHash).toBe(e1.hash);
    expect(e2.actor).toBe(MASK_EMAIL);
  });
});
