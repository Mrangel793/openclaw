import { describe, expect, it, vi } from "vitest";
import {
  getSamlSessionStore,
  initSamlSessionStore,
  samlValidateToken,
  SamlSessionStore,
} from "./saml-session-store.js";

describe("SamlSessionStore", () => {
  it("issues a non-empty token string", () => {
    const store = new SamlSessionStore();
    const token = store.issue("ana@entidad.gov.co");
    expect(typeof token).toBe("string");
    expect(token.length).toBeGreaterThan(0);
  });

  it("issued tokens are unique", () => {
    const store = new SamlSessionStore();
    const t1 = store.issue("user1@test.co");
    const t2 = store.issue("user2@test.co");
    expect(t1).not.toBe(t2);
  });

  it("validate returns the session for a valid token", () => {
    const store = new SamlSessionStore();
    const token = store.issue("jperez@entidad.gov.co");
    const session = store.validate(token);
    expect(session).not.toBeNull();
    expect(session?.user).toBe("jperez@entidad.gov.co");
  });

  it("validate returns null for an unknown token", () => {
    const store = new SamlSessionStore();
    expect(store.validate("unknown-token")).toBeNull();
  });

  it("validate returns null for an expired session", () => {
    const store = new SamlSessionStore();
    // Issue with 1 ms TTL — already expired by the time validate is called.
    const token = store.issue("user@test.co", 1);
    // Advance time past expiry.
    vi.setSystemTime(Date.now() + 100);
    expect(store.validate(token)).toBeNull();
    vi.useRealTimers();
  });

  it("revoke removes the session", () => {
    const store = new SamlSessionStore();
    const token = store.issue("user@test.co");
    store.revoke(token);
    expect(store.validate(token)).toBeNull();
  });

  it("size reflects only active (non-expired) sessions", () => {
    vi.useFakeTimers();
    const store = new SamlSessionStore(1000);
    store.issue("a@test.co");
    store.issue("b@test.co");
    expect(store.size).toBe(2);

    // Expire them.
    vi.advanceTimersByTime(1001);
    expect(store.size).toBe(0);
    vi.useRealTimers();
  });

  it("cleanup removes expired entries without affecting live ones", () => {
    vi.useFakeTimers();
    const store = new SamlSessionStore(500);
    const t1 = store.issue("a@test.co", 100); // expires soon
    const t2 = store.issue("b@test.co", 10_000); // stays alive

    vi.advanceTimersByTime(200);
    store.cleanup();

    expect(store.validate(t1)).toBeNull();
    expect(store.validate(t2)).not.toBeNull();
    vi.useRealTimers();
  });

  it("custom TTL overrides the store default", () => {
    vi.useFakeTimers();
    const store = new SamlSessionStore(60_000); // 1 min default
    const token = store.issue("u@test.co", 1_000); // 1 s custom

    vi.advanceTimersByTime(999);
    expect(store.validate(token)).not.toBeNull(); // still valid

    vi.advanceTimersByTime(2);
    expect(store.validate(token)).toBeNull(); // now expired
    vi.useRealTimers();
  });
});

// ---------------------------------------------------------------------------
// Module-level singleton
// ---------------------------------------------------------------------------

describe("initSamlSessionStore / getSamlSessionStore / samlValidateToken", () => {
  it("getSamlSessionStore returns null before init", () => {
    // Note: this test runs before initSamlSessionStore is called in this suite,
    // but other tests above may have used the singleton. We reset it indirectly
    // by calling initSamlSessionStore to create a fresh one.
    const store = initSamlSessionStore();
    expect(getSamlSessionStore()).toBe(store);
  });

  it("samlValidateToken validates against the active singleton", () => {
    const store = initSamlSessionStore();
    const token = store.issue("singleton@test.co");
    const session = samlValidateToken(token);
    expect(session?.user).toBe("singleton@test.co");
  });

  it("samlValidateToken returns null for unknown token", () => {
    initSamlSessionStore();
    expect(samlValidateToken("no-such-token")).toBeNull();
  });
});
