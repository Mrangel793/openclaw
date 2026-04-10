/**
 * SAML 2.0 Service Provider (SP) for Active Directory Federation Services (ADFS)
 * and other SAML IdPs (Entra ID / Azure AD, Okta, etc.).
 *
 * Wraps `@node-saml/node-saml` and connects the assertion exchange to the
 * in-memory `SamlSessionStore`.
 *
 * Typical flow:
 *   1. Client navigates to `GET /auth/saml/login`.
 *   2. Gateway redirects to IdP SSO URL with a signed AuthnRequest.
 *   3. IdP authenticates the user and POSTs a SAMLResponse to
 *      `POST /auth/saml/callback` (the ACS URL).
 *   4. Provider validates the assertion, extracts the user identity,
 *      issues a session token via `SamlSessionStore`, and redirects
 *      the browser to the Control UI with `?token=<token>` in the URL.
 */

import { SAML } from "@node-saml/node-saml";
import { type SamlSessionStore } from "./saml-session-store.js";

export type SamlProviderConfig = {
  /** IdP SSO redirect URL (e.g. ADFS: https://adfs.entidad.gov.co/adfs/ls). */
  idpSsoUrl: string;
  /**
   * IdP X.509 certificate in PEM format (without `-----BEGIN CERTIFICATE-----` header)
   * or full PEM string. Used to verify the assertion signature.
   */
  idpCert: string;
  /**
   * SP Entity ID / Issuer.
   * Must match the Relying Party Trust identifier configured in ADFS.
   * Example: `https://openclaw.entidad.gov.co/auth/saml/metadata`
   */
  spEntityId: string;
  /**
   * SP Assertion Consumer Service URL where ADFS will POST the SAMLResponse.
   * Example: `https://openclaw.entidad.gov.co/auth/saml/callback`
   */
  spAcsUrl: string;
  /**
   * SAML attribute name containing the user identity (returned as `user` in the session).
   * Falls back to `nameID` when the attribute is absent.
   * Default: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   */
  userAttribute?: string;
  /**
   * Optional allowlist of authenticated user identities (e.g. emails).
   * When non-empty, users not in the list are rejected even after a valid assertion.
   */
  allowUsers?: string[];
  /** Session token TTL in milliseconds. Default: 28800000 (8 h). */
  sessionTtlMs?: number;
  /** SP private key for signing AuthnRequest (PEM). Optional. */
  spPrivateKey?: string;
};

const DEFAULT_USER_ATTRIBUTE =
  "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress";

export type SamlCallbackResult =
  | { ok: true; user: string; token: string }
  | { ok: false; reason: string };

export class SamlProvider {
  private readonly saml: SAML;
  private readonly config: SamlProviderConfig;
  private readonly store: SamlSessionStore;

  constructor(config: SamlProviderConfig, store: SamlSessionStore) {
    this.config = config;
    this.store = store;

    this.saml = new SAML({
      entryPoint: config.idpSsoUrl,
      idpCert: normalizeCert(config.idpCert),
      issuer: config.spEntityId,
      callbackUrl: config.spAcsUrl,
      ...(config.spPrivateKey ? { privateKey: config.spPrivateKey } : {}),
      wantAssertionsSigned: true,
      // Disable in-response-to validation for broad compatibility with ADFS.
      validateInResponseTo: "never",
    });
  }

  /**
   * Generate the SP SAML metadata XML.
   * Expose this at `GET /auth/saml/metadata`.
   */
  getMetadataXml(): string {
    return this.saml.generateServiceProviderMetadata(null, null);
  }

  /**
   * Build the redirect URL for the IdP login page.
   * The browser should be redirected here to initiate SSO.
   *
   * @param relayState Optional relay-state value (e.g. the original request URL).
   */
  async getLoginUrl(relayState = ""): Promise<string> {
    return this.saml.getAuthorizeUrlAsync(relayState, undefined, {});
  }

  /**
   * Validate a SAMLResponse POST body and issue a session token.
   *
   * @param body The parsed POST body from the ACS endpoint (must contain `SAMLResponse`).
   * @returns `ok:true` with user identifier and session token, or `ok:false` with reason.
   */
  async handleCallback(body: Record<string, string>): Promise<SamlCallbackResult> {
    try {
      const { profile, loggedOut } = await this.saml.validatePostResponseAsync(body);

      if (loggedOut || !profile) {
        return { ok: false, reason: "saml_logout_or_empty_profile" };
      }

      // Extract user identity from the preferred attribute, fall back to nameID.
      const userAttr = this.config.userAttribute ?? DEFAULT_USER_ATTRIBUTE;
      const rawUser =
        (profile[userAttr] as string | undefined)?.trim() ||
        profile.nameID?.trim() ||
        "";

      if (!rawUser) {
        return { ok: false, reason: "saml_user_identity_missing" };
      }

      // Optional allowlist check.
      const allowUsers = this.config.allowUsers ?? [];
      if (allowUsers.length > 0 && !allowUsers.includes(rawUser)) {
        return { ok: false, reason: "saml_user_not_allowed" };
      }

      const token = this.store.issue(rawUser, this.config.sessionTtlMs);
      return { ok: true, user: rawUser, token };
    } catch (err) {
      return {
        ok: false,
        reason: `saml_validation_error: ${err instanceof Error ? err.message : String(err)}`,
      };
    }
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton
// ---------------------------------------------------------------------------

let activeProvider: SamlProvider | null = null;

export function initSamlProvider(
  config: SamlProviderConfig,
  store: SamlSessionStore,
): SamlProvider {
  activeProvider = new SamlProvider(config, store);
  return activeProvider;
}

export function getSamlProvider(): SamlProvider | null {
  return activeProvider;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Accept either a bare base-64 certificate or a full PEM block.
 * @node-saml/node-saml requires the full PEM format.
 */
function normalizeCert(cert: string): string {
  const trimmed = cert.trim();
  if (trimmed.startsWith("-----")) {
    return trimmed;
  }
  // Bare base-64 — wrap in PEM header/footer.
  const body = trimmed.replace(/\s+/g, "").replace(/.{64}/g, "$&\n");
  return `-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
}
