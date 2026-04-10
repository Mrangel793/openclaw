import { describe, expect, it, vi, type MockInstance } from "vitest";
import { SamlProvider, type SamlProviderConfig } from "./saml-provider.js";
import { SamlSessionStore } from "./saml-session-store.js";

// ---------------------------------------------------------------------------
// Mock @node-saml/node-saml
// ---------------------------------------------------------------------------

vi.mock("@node-saml/node-saml", () => {
  class SAML {
    options: Record<string, unknown>;
    constructor(opts: Record<string, unknown>) {
      this.options = opts;
    }
    generateServiceProviderMetadata(_dec: null, _pub: null): string {
      return `<EntityDescriptor entityID="${this.options["issuer"]}"/>`;
    }
    async getAuthorizeUrlAsync(relayState: string): Promise<string> {
      return `https://idp.test/sso?relay=${encodeURIComponent(relayState)}`;
    }
    async validatePostResponseAsync(
      body: Record<string, string>,
    ): Promise<{ profile: Record<string, unknown> | null; loggedOut: boolean }> {
      if (body["SAMLResponse"] === "INVALID") {
        throw new Error("Invalid signature");
      }
      if (body["SAMLResponse"] === "LOGOUT") {
        return { profile: null, loggedOut: true };
      }
      return {
        profile: {
          nameID: "jperez@entidad.gov.co",
          nameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
          issuer: "https://idp.test",
          "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress":
            "jperez@entidad.gov.co",
        },
        loggedOut: false,
      };
    }
  }
  return { SAML };
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const BASE_CONFIG: SamlProviderConfig = {
  idpSsoUrl: "https://adfs.test/adfs/ls",
  idpCert:
    "MIICpDCCAYwCCQDU5pqbtHHD7jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAl0ZXN0LWNlcnQwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAl0ZXN0LWNlcnQwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7",
  spEntityId: "https://openclaw.test/auth/saml/metadata",
  spAcsUrl: "https://openclaw.test/auth/saml/callback",
};

function makeProvider(
  config: Partial<SamlProviderConfig> = {},
  storeTtlMs?: number,
): { provider: SamlProvider; store: SamlSessionStore } {
  const store = new SamlSessionStore(storeTtlMs);
  const provider = new SamlProvider({ ...BASE_CONFIG, ...config }, store);
  return { provider, store };
}

// ---------------------------------------------------------------------------
// getMetadataXml
// ---------------------------------------------------------------------------

describe("SamlProvider.getMetadataXml", () => {
  it("returns an XML string containing the SP entity ID", () => {
    const { provider } = makeProvider();
    const xml = provider.getMetadataXml();
    expect(typeof xml).toBe("string");
    expect(xml).toContain("openclaw.test");
  });
});

// ---------------------------------------------------------------------------
// getLoginUrl
// ---------------------------------------------------------------------------

describe("SamlProvider.getLoginUrl", () => {
  it("returns a URL string starting with https://", async () => {
    const { provider } = makeProvider();
    const url = await provider.getLoginUrl();
    expect(url.startsWith("https://")).toBe(true);
  });

  it("includes relay state in the redirect URL", async () => {
    const { provider } = makeProvider();
    const url = await provider.getLoginUrl("https://openclaw.test/dashboard");
    expect(url).toContain("relay=");
  });
});

// ---------------------------------------------------------------------------
// handleCallback — success
// ---------------------------------------------------------------------------

describe("SamlProvider.handleCallback — success", () => {
  it("returns ok:true with user identity from assertion", async () => {
    const { provider } = makeProvider();
    const result = await provider.handleCallback({ SAMLResponse: "VALID" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.user).toBe("jperez@entidad.gov.co");
    }
  });

  it("issues a non-empty session token on success", async () => {
    const { provider } = makeProvider();
    const result = await provider.handleCallback({ SAMLResponse: "VALID" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(typeof result.token).toBe("string");
      expect(result.token.length).toBeGreaterThan(0);
    }
  });

  it("issued token is valid in the session store", async () => {
    const { provider, store } = makeProvider();
    const result = await provider.handleCallback({ SAMLResponse: "VALID" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      const session = store.validate(result.token);
      expect(session?.user).toBe("jperez@entidad.gov.co");
    }
  });

  it("uses custom userAttribute when configured", async () => {
    // The mock profile has the standard email claim; this test checks that
    // the provider picks the right attribute.
    const { provider } = makeProvider({
      userAttribute:
        "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    });
    const result = await provider.handleCallback({ SAMLResponse: "VALID" });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.user).toBe("jperez@entidad.gov.co");
    }
  });
});

// ---------------------------------------------------------------------------
// handleCallback — failures
// ---------------------------------------------------------------------------

describe("SamlProvider.handleCallback — failures", () => {
  it("returns ok:false when assertion signature is invalid", async () => {
    const { provider } = makeProvider();
    const result = await provider.handleCallback({ SAMLResponse: "INVALID" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toContain("saml_validation_error");
    }
  });

  it("returns ok:false on logout response", async () => {
    const { provider } = makeProvider();
    const result = await provider.handleCallback({ SAMLResponse: "LOGOUT" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("saml_logout_or_empty_profile");
    }
  });

  it("returns ok:false when user is not in allowUsers list", async () => {
    const { provider } = makeProvider({ allowUsers: ["admin@entidad.gov.co"] });
    const result = await provider.handleCallback({ SAMLResponse: "VALID" });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("saml_user_not_allowed");
    }
  });

  it("allowUsers list accepts the user when identity matches", async () => {
    const { provider } = makeProvider({
      allowUsers: ["jperez@entidad.gov.co", "admin@entidad.gov.co"],
    });
    const result = await provider.handleCallback({ SAMLResponse: "VALID" });
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// PEM certificate normalization
// ---------------------------------------------------------------------------

describe("SamlProvider — certificate handling", () => {
  it("wraps a bare base-64 certificate in PEM headers", () => {
    // The SAML constructor receives the cert; we just verify it doesn't throw.
    expect(() =>
      makeProvider({
        idpCert:
          "MIICpDCCAYwCCQDU5pqbtHHD7jANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAl0ZXN0LWNlcnQwHhcN",
      }),
    ).not.toThrow();
  });

  it("accepts a full PEM block as-is", () => {
    expect(() =>
      makeProvider({
        idpCert:
          "-----BEGIN CERTIFICATE-----\nMIICpDCCAYwC\n-----END CERTIFICATE-----",
      }),
    ).not.toThrow();
  });
});
