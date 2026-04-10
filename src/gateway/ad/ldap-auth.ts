/**
 * LDAP / Active Directory authentication for the gateway.
 *
 * Supports direct user-bind authentication against an LDAP or LDAPS server.
 * The caller injects a `LdapClientFactory` so unit tests can mock the network
 * without a real directory server.
 *
 * Flow:
 *   1. Connect and bind with the service account (search/read permissions).
 *   2. Search for the user entry by username / email.
 *   3. Rebind using the discovered user DN and the supplied password.
 *   4. Optionally verify group membership.
 *   5. Return the canonical user identifier.
 */

export type LdapAuthOptions = {
  /** LDAP server URL: `ldap://` or `ldaps://`. */
  url: string;
  /** Base DN for the user search (e.g. "DC=entidad,DC=gov,DC=co"). */
  baseDn: string;
  /**
   * Service-account DN used to search the directory.
   * When omitted, an anonymous bind is attempted.
   */
  bindDn?: string;
  /** Service-account password. */
  bindPassword?: string;
  /**
   * LDAP filter used to locate the user entry.
   * Use `{{username}}` as placeholder — it is LDAP-escaped before substitution.
   * Default: `(sAMAccountName={{username}})`
   */
  userSearchFilter?: string;
  /**
   * Entry attribute returned as the canonical user identifier in auth results.
   * Default: `sAMAccountName`
   */
  userAttribute?: string;
  /**
   * Distinguished Names of groups the user must belong to (at least one).
   * When empty or absent, group membership is not checked.
   */
  allowedGroups?: string[];
  /** Skip TLS certificate validation. Use only in development environments. */
  tlsSkipVerify?: boolean;
  /** TCP connection timeout in milliseconds. Default: 5000. */
  connectTimeoutMs?: number;
};

export type LdapAuthResult =
  | { ok: true; user: string }
  | {
      ok: false;
      reason:
        | "credentials_missing"
        | "invalid_credentials"
        | "user_not_found"
        | "not_in_group"
        | "ldap_error";
      message?: string;
    };

// ---------------------------------------------------------------------------
// Client abstraction — allows injection of mock clients in tests
// ---------------------------------------------------------------------------

export type LdapSearchEntry = {
  dn: string;
  [attr: string]: string | string[] | undefined;
};

export type LdapClientHandle = {
  bind(dn: string, password: string): Promise<void>;
  unbind(): Promise<void>;
  search(
    baseDn: string,
    opts: { scope: "sub"; filter: string; attributes: string[] },
  ): Promise<{ searchEntries: LdapSearchEntry[] }>;
};

export type LdapClientFactory = (opts: {
  url: string;
  connectTimeout: number;
  tlsOptions?: { rejectUnauthorized: boolean };
}) => LdapClientHandle;

/** Default factory that uses ldapts. Loaded lazily to avoid import-time side effects. */
export const defaultLdapClientFactory: LdapClientFactory = (opts) => {
  // ldapts is loaded lazily; its import is deferred until first use.
  // This allows the module to load even if ldapts is absent in minimal test setups.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { Client } = require("ldapts") as typeof import("ldapts");
  return new Client({
    url: opts.url,
    connectTimeout: opts.connectTimeout,
    tlsOptions: opts.tlsOptions,
  }) as unknown as LdapClientHandle;
};

// ---------------------------------------------------------------------------
// LDAP filter injection prevention
// ---------------------------------------------------------------------------

/**
 * Escape a string for safe inclusion in an LDAP search filter (RFC 4515).
 * Characters escaped: NUL, `(`, `)`, `*`, `\`.
 */
export function ldapEscapeFilter(value: string): string {
  return value.replace(/[\\\0()*]/g, (ch) => {
    const hex = ch.charCodeAt(0).toString(16).padStart(2, "0");
    return `\\${hex}`;
  });
}

// ---------------------------------------------------------------------------
// LdapAuthenticator
// ---------------------------------------------------------------------------

export class LdapAuthenticator {
  private readonly opts: LdapAuthOptions;
  private readonly createClient: LdapClientFactory;

  constructor(opts: LdapAuthOptions, createClient: LdapClientFactory = defaultLdapClientFactory) {
    this.opts = opts;
    this.createClient = createClient;
  }

  async authenticate(username: string, password: string): Promise<LdapAuthResult> {
    if (!username || !password) {
      return { ok: false, reason: "credentials_missing" };
    }

    const client = this.createClient({
      url: this.opts.url,
      connectTimeout: this.opts.connectTimeoutMs ?? 5000,
      tlsOptions: this.opts.tlsSkipVerify ? { rejectUnauthorized: false } : undefined,
    });

    try {
      // Step 1 — service account bind (or anonymous).
      if (this.opts.bindDn && this.opts.bindPassword) {
        await client.bind(this.opts.bindDn, this.opts.bindPassword);
      }

      // Step 2 — find the user DN.
      const userAttribute = this.opts.userAttribute ?? "sAMAccountName";
      const filterTemplate = this.opts.userSearchFilter ?? `(${userAttribute}={{username}})`;
      const filter = filterTemplate.replace(/\{\{username\}\}/g, ldapEscapeFilter(username));

      const { searchEntries } = await client.search(this.opts.baseDn, {
        scope: "sub",
        filter,
        attributes: [userAttribute, "memberOf"],
      });

      if (searchEntries.length === 0) {
        return { ok: false, reason: "user_not_found" };
      }

      const userEntry = searchEntries[0];
      const userDn = userEntry.dn;

      // Step 3 — unbind service account, rebind as user to verify password.
      await client.unbind();
      try {
        await client.bind(userDn, password);
      } catch {
        return { ok: false, reason: "invalid_credentials" };
      }

      // Step 4 — optional group membership check.
      const allowedGroups = this.opts.allowedGroups ?? [];
      if (allowedGroups.length > 0) {
        const memberOfRaw = userEntry["memberOf"];
        const memberOf: string[] = Array.isArray(memberOfRaw)
          ? (memberOfRaw as string[])
          : typeof memberOfRaw === "string"
            ? [memberOfRaw]
            : [];

        const inGroup = memberOf.some((g) =>
          allowedGroups.some(
            (allowed) => normalizeDn(g) === normalizeDn(allowed),
          ),
        );

        if (!inGroup) {
          return { ok: false, reason: "not_in_group" };
        }
      }

      // Step 5 — determine canonical user identifier.
      const attrValue = userEntry[userAttribute];
      const user =
        typeof attrValue === "string"
          ? attrValue
          : Array.isArray(attrValue) && attrValue.length > 0
            ? (attrValue[0] as string)
            : username;

      return { ok: true, user };
    } catch (err) {
      return {
        ok: false,
        reason: "ldap_error",
        message: err instanceof Error ? err.message : String(err),
      };
    } finally {
      try {
        await client.unbind();
      } catch {
        // best-effort cleanup
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Case-insensitive DN comparison (spaces around `=` and `,` are normalized). */
function normalizeDn(dn: string): string {
  return dn
    .trim()
    .toLowerCase()
    .replace(/\s*=\s*/g, "=")
    .replace(/\s*,\s*/g, ",");
}
