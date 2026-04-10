import { describe, expect, it } from "vitest";
import {
  ldapEscapeFilter,
  LdapAuthenticator,
  type LdapClientFactory,
  type LdapClientHandle,
  type LdapSearchEntry,
} from "./ldap-auth.js";

// ---------------------------------------------------------------------------
// Mock LDAP client factory
// ---------------------------------------------------------------------------

type MockConfig = {
  /** Entries returned by search(). */
  searchEntries?: LdapSearchEntry[];
  /** If set, bind() throws this error when called with the user DN + any password. */
  userBindError?: Error;
  /** If set, service-account bind() throws this error. */
  serviceBindError?: Error;
  /** If set, search() throws this error. */
  searchError?: Error;
};

function makeMockFactory(config: MockConfig = {}): LdapClientFactory {
  return (_opts) => {
    const client: LdapClientHandle = {
      async bind(dn: string, _password: string) {
        // First bind is the service account (bindDn starts with "CN=svc").
        if (dn.toLowerCase().startsWith("cn=svc") && config.serviceBindError) {
          throw config.serviceBindError;
        }
        // Subsequent binds are user binds.
        if (!dn.toLowerCase().startsWith("cn=svc") && config.userBindError) {
          throw config.userBindError;
        }
      },
      async unbind() {
        // no-op
      },
      async search(_baseDn, _opts) {
        if (config.searchError) {
          throw config.searchError;
        }
        return { searchEntries: config.searchEntries ?? [] };
      },
    };
    return client;
  };
}

const VALID_ENTRY: LdapSearchEntry = {
  dn: "CN=Juan Perez,OU=Funcionarios,DC=entidad,DC=gov,DC=co",
  sAMAccountName: "jperez",
  memberOf: "CN=Funcionarios,OU=Groups,DC=entidad,DC=gov,DC=co",
};

// ---------------------------------------------------------------------------
// ldapEscapeFilter
// ---------------------------------------------------------------------------

describe("ldapEscapeFilter", () => {
  it("passes through a plain username unchanged", () => {
    expect(ldapEscapeFilter("jperez")).toBe("jperez");
  });

  it("escapes backslash", () => {
    expect(ldapEscapeFilter("a\\b")).toBe("a\\5cb");
  });

  it("escapes parentheses", () => {
    expect(ldapEscapeFilter("(bad)")).toBe("\\28bad\\29");
  });

  it("escapes asterisk", () => {
    expect(ldapEscapeFilter("*")).toBe("\\2a");
  });

  it("escapes NUL byte", () => {
    expect(ldapEscapeFilter("\0")).toBe("\\00");
  });

  it("prevents LDAP filter injection in username", () => {
    const malicious = "admin)(uid=*))(|(uid=*";
    const escaped = ldapEscapeFilter(malicious);
    expect(escaped).not.toContain(")(");
    expect(escaped).not.toContain("*");
  });
});

// ---------------------------------------------------------------------------
// LdapAuthenticator — successful authentication
// ---------------------------------------------------------------------------

describe("LdapAuthenticator — success", () => {
  it("returns ok:true with user from sAMAccountName", async () => {
    const auth = new LdapAuthenticator(
      { url: "ldaps://dc01.test:636", baseDn: "DC=test,DC=co" },
      makeMockFactory({ searchEntries: [VALID_ENTRY] }),
    );
    const result = await auth.authenticate("jperez", "secret");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.user).toBe("jperez");
    }
  });

  it("returns ok:true with custom userAttribute", async () => {
    const entry: LdapSearchEntry = {
      dn: "CN=Ana,OU=Users,DC=test,DC=co",
      mail: "ana@entidad.gov.co",
    };
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test", userAttribute: "mail" },
      makeMockFactory({ searchEntries: [entry] }),
    );
    const result = await auth.authenticate("ana@entidad.gov.co", "pass");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.user).toBe("ana@entidad.gov.co");
    }
  });

  it("falls back to the supplied username when attribute is absent from entry", async () => {
    const entry: LdapSearchEntry = { dn: "CN=Unknown,DC=test" };
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test" },
      makeMockFactory({ searchEntries: [entry] }),
    );
    const result = await auth.authenticate("fallback_user", "pass");
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.user).toBe("fallback_user");
    }
  });

  it("accepts multi-value memberOf as array", async () => {
    const entry: LdapSearchEntry = {
      dn: "CN=User,DC=test",
      sAMAccountName: "analyst",
      memberOf: [
        "CN=Analistas,OU=Groups,DC=test",
        "CN=AllUsers,OU=Groups,DC=test",
      ],
    };
    const auth = new LdapAuthenticator(
      {
        url: "ldap://dc:389",
        baseDn: "DC=test",
        allowedGroups: ["CN=Analistas,OU=Groups,DC=test"],
      },
      makeMockFactory({ searchEntries: [entry] }),
    );
    const result = await auth.authenticate("analyst", "pass");
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// LdapAuthenticator — failure cases
// ---------------------------------------------------------------------------

describe("LdapAuthenticator — failures", () => {
  it("returns credentials_missing when username is empty", async () => {
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test" },
      makeMockFactory(),
    );
    const result = await auth.authenticate("", "pass");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("credentials_missing");
    }
  });

  it("returns credentials_missing when password is empty", async () => {
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test" },
      makeMockFactory(),
    );
    const result = await auth.authenticate("jperez", "");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("credentials_missing");
    }
  });

  it("returns user_not_found when search returns no entries", async () => {
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test" },
      makeMockFactory({ searchEntries: [] }),
    );
    const result = await auth.authenticate("ghost", "pass");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("user_not_found");
    }
  });

  it("returns invalid_credentials when user bind fails", async () => {
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test" },
      makeMockFactory({
        searchEntries: [VALID_ENTRY],
        userBindError: new Error("Invalid credentials"),
      }),
    );
    const result = await auth.authenticate("jperez", "wrongpass");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("invalid_credentials");
    }
  });

  it("returns not_in_group when user is not a member of any allowed group", async () => {
    const entry: LdapSearchEntry = {
      dn: "CN=User,DC=test",
      sAMAccountName: "outsider",
      memberOf: "CN=OtherGroup,OU=Groups,DC=test",
    };
    const auth = new LdapAuthenticator(
      {
        url: "ldap://dc:389",
        baseDn: "DC=test",
        allowedGroups: ["CN=Funcionarios,OU=Groups,DC=test"],
      },
      makeMockFactory({ searchEntries: [entry] }),
    );
    const result = await auth.authenticate("outsider", "pass");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("not_in_group");
    }
  });

  it("returns ldap_error when search throws", async () => {
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test" },
      makeMockFactory({ searchError: new Error("Network timeout") }),
    );
    const result = await auth.authenticate("jperez", "pass");
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.reason).toBe("ldap_error");
      expect(result.message).toContain("Network timeout");
    }
  });

  it("group check is case-insensitive for DN comparison", async () => {
    const entry: LdapSearchEntry = {
      dn: "CN=User,DC=test",
      sAMAccountName: "user",
      memberOf: "CN=FUNCIONARIOS,OU=GROUPS,DC=TEST",
    };
    const auth = new LdapAuthenticator(
      {
        url: "ldap://dc:389",
        baseDn: "DC=test",
        allowedGroups: ["cn=funcionarios,ou=groups,dc=test"],
      },
      makeMockFactory({ searchEntries: [entry] }),
    );
    const result = await auth.authenticate("user", "pass");
    expect(result.ok).toBe(true);
  });

  it("skips group check when allowedGroups is empty", async () => {
    const entry: LdapSearchEntry = {
      dn: "CN=User,DC=test",
      sAMAccountName: "anyone",
      // memberOf intentionally absent
    };
    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test", allowedGroups: [] },
      makeMockFactory({ searchEntries: [entry] }),
    );
    const result = await auth.authenticate("anyone", "pass");
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// LDAP filter substitution
// ---------------------------------------------------------------------------

describe("LdapAuthenticator — filter injection prevention", () => {
  it("escapes injection characters in the username before embedding in filter", async () => {
    let capturedFilter = "";
    const spyFactory: LdapClientFactory = (_opts) => ({
      async bind(_dn, _pw) {},
      async unbind() {},
      async search(_base, opts) {
        capturedFilter = opts.filter;
        return { searchEntries: [] }; // user not found — that's fine
      },
    });

    const auth = new LdapAuthenticator(
      { url: "ldap://dc:389", baseDn: "DC=test" },
      spyFactory,
    );
    await auth.authenticate("*)(uid=*))(|(uid=*", "pass");
    // The dangerous unescaped injection sequence must not appear in the filter.
    expect(capturedFilter).not.toContain("*)(uid=*)");
    // Each special character must appear as its hex escape, not raw.
    expect(capturedFilter).not.toContain("uid=*"); // asterisk must be escaped
    expect(capturedFilter).toContain("\\2a"); // escaped *
    expect(capturedFilter).toContain("\\29"); // escaped )
  });
});
