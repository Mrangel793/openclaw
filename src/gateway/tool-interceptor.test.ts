import { describe, expect, it } from "vitest";
import { runGatewayToolInterceptor } from "./tool-interceptor.js";

function invoke(
  toolArgs: Record<string, unknown>,
  policy: Parameters<typeof runGatewayToolInterceptor>[0]["networkPolicy"],
) {
  return runGatewayToolInterceptor({ toolName: "test_tool", toolArgs, networkPolicy: policy });
}

describe("runGatewayToolInterceptor", () => {
  describe("no-op conditions", () => {
    it("passes when networkPolicy is undefined", () => {
      expect(invoke({ url: "https://evil.com" }, undefined).ok).toBe(true);
    });

    it("passes when policy is empty object (no allowedHosts, no blockExternalUrls)", () => {
      expect(invoke({ url: "https://evil.com" }, {}).ok).toBe(true);
    });

    it("passes when allowedHosts is empty array and blockExternalUrls is false", () => {
      expect(invoke({ url: "https://evil.com" }, { allowedHosts: [], blockExternalUrls: false }).ok).toBe(true);
    });
  });

  describe("allowedHosts only", () => {
    const policy = { allowedHosts: ["api.empresa.com", "*.internal.empresa.com"] };

    it("allows URL matching exact host", () => {
      expect(invoke({ url: "https://api.empresa.com/data" }, policy).ok).toBe(true);
    });

    it("allows URL matching wildcard subdomain", () => {
      expect(invoke({ url: "https://db.internal.empresa.com/query" }, policy).ok).toBe(true);
    });

    it("blocks URL not in allowedHosts", () => {
      const result = invoke({ url: "https://evil.com/exfil" }, policy);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toContain("allowedHosts");
        expect(result.value).toBe("https://evil.com/exfil");
      }
    });

    it("blocks URL on different subdomain level", () => {
      expect(invoke({ url: "https://empresa.com/data" }, policy).ok).toBe(false);
    });

    it("passes non-URL strings without inspection", () => {
      expect(invoke({ query: "SELECT * FROM users" }, policy).ok).toBe(true);
    });

    it("inspects nested objects recursively", () => {
      const result = invoke({ nested: { deep: { url: "https://evil.com" } } }, policy);
      expect(result.ok).toBe(false);
    });

    it("inspects array values recursively", () => {
      const result = invoke({ urls: ["https://api.empresa.com", "https://evil.com"] }, policy);
      expect(result.ok).toBe(false);
    });

    it("does not flag the first URL if it is allowed but blocks the second", () => {
      const result = invoke(
        { first: "https://api.empresa.com/ok", second: "https://evil.com/bad" },
        policy,
      );
      expect(result.ok).toBe(false);
    });
  });

  describe("blockExternalUrls only (no allowedHosts)", () => {
    const policy = { blockExternalUrls: true };

    it("allows RFC-1918 10.x address", () => {
      expect(invoke({ url: "http://10.0.0.5/api" }, policy).ok).toBe(true);
    });

    it("allows RFC-1918 192.168.x address", () => {
      expect(invoke({ url: "https://192.168.1.100/resource" }, policy).ok).toBe(true);
    });

    it("allows RFC-1918 172.16.x address", () => {
      expect(invoke({ url: "http://172.16.0.1/data" }, policy).ok).toBe(true);
    });

    it("allows localhost", () => {
      expect(invoke({ url: "http://localhost:8080/health" }, policy).ok).toBe(true);
    });

    it("allows .internal hostname", () => {
      expect(invoke({ url: "https://api.empresa.internal/v1" }, policy).ok).toBe(true);
    });

    it("allows .local hostname", () => {
      expect(invoke({ url: "http://printer.local/status" }, policy).ok).toBe(true);
    });

    it("blocks public IP address", () => {
      const result = invoke({ url: "https://8.8.8.8/query" }, policy);
      expect(result.ok).toBe(false);
      if (!result.ok) {
        expect(result.reason).toContain("blockExternalUrls");
      }
    });

    it("blocks public hostname", () => {
      const result = invoke({ url: "https://google.com/exfil" }, policy);
      expect(result.ok).toBe(false);
    });

    it("blocks any external HTTPS URL", () => {
      expect(invoke({ endpoint: "https://attacker.io/steal" }, policy).ok).toBe(false);
    });

    it("passes non-URL strings", () => {
      expect(invoke({ key: "some plain text value" }, policy).ok).toBe(true);
    });
  });

  describe("blockExternalUrls + allowedHosts (combined)", () => {
    const policy = {
      blockExternalUrls: true,
      allowedHosts: ["api.trusted.com"],
    };

    it("allows private network addresses", () => {
      expect(invoke({ url: "http://192.168.1.5/data" }, policy).ok).toBe(true);
    });

    it("allows explicitly allowlisted public host", () => {
      expect(invoke({ url: "https://api.trusted.com/endpoint" }, policy).ok).toBe(true);
    });

    it("blocks public URL not in allowedHosts", () => {
      const result = invoke({ url: "https://google.com/exfil" }, policy);
      expect(result.ok).toBe(false);
    });

    it("blocks unlisted public URL even if blockExternalUrls would allow internal ones", () => {
      const result = invoke({ url: "https://untrusted.com/data" }, policy);
      expect(result.ok).toBe(false);
    });
  });

  describe("edge cases", () => {
    it("does not crash on malformed URL-like strings", () => {
      const policy = { blockExternalUrls: true };
      expect(() => invoke({ url: "https://[::invalid" }, policy)).not.toThrow();
    });

    it("limits recursion depth to avoid stack overflow on deeply nested objects", () => {
      const deep: Record<string, unknown> = {};
      let current = deep;
      for (let i = 0; i < 10; i++) {
        current.next = {};
        current = current.next as Record<string, unknown>;
      }
      current.url = "https://evil.com";
      // Should not crash; deeply nested URL may or may not be caught depending on depth limit
      expect(() => invoke(deep, { blockExternalUrls: true })).not.toThrow();
    });

    it("ignores ftp:// and other non-HTTP schemes", () => {
      expect(invoke({ url: "ftp://evil.com/file" }, { blockExternalUrls: true }).ok).toBe(true);
    });
  });
});
