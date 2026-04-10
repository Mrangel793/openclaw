/**
 * In-memory session store for SAML-issued gateway tokens.
 *
 * After a successful SAML assertion exchange the provider issues a short-lived
 * opaque token (UUID v4). Subsequent gateway connections present this token as
 * a standard Bearer credential. The store validates and tracks expiry.
 *
 * The store is backed by a plain `Map` — no persistence. On gateway restart
 * all SAML sessions are invalidated and users must re-authenticate via SSO.
 */

import { randomUUID } from "node:crypto";

export type SamlSession = {
  /** Authenticated user identifier (e.g. email from the SAML NameID). */
  user: string;
  /** Absolute expiry timestamp in milliseconds since Unix epoch. */
  expiresAt: number;
};

/** Default session lifetime: 8 hours (matching a typical working day). */
const DEFAULT_TTL_MS = 8 * 60 * 60 * 1000;

export class SamlSessionStore {
  private readonly sessions = new Map<string, SamlSession>();
  private readonly defaultTtlMs: number;

  constructor(defaultTtlMs = DEFAULT_TTL_MS) {
    this.defaultTtlMs = defaultTtlMs;
  }

  /**
   * Issue a new session token for the given user.
   * @returns The opaque Bearer token the client should use.
   */
  issue(user: string, ttlMs?: number): string {
    this.cleanup(); // prune stale entries before adding new ones
    const token = randomUUID();
    const expiresAt = Date.now() + (ttlMs ?? this.defaultTtlMs);
    this.sessions.set(token, { user, expiresAt });
    return token;
  }

  /**
   * Validate a token. Returns the session if valid and not expired, or null.
   */
  validate(token: string): SamlSession | null {
    const session = this.sessions.get(token);
    if (!session) {
      return null;
    }
    if (Date.now() >= session.expiresAt) {
      this.sessions.delete(token);
      return null;
    }
    return session;
  }

  /**
   * Explicitly revoke a session (e.g. on logout).
   */
  revoke(token: string): void {
    this.sessions.delete(token);
  }

  /**
   * Remove all expired entries. Called automatically on `issue`.
   */
  cleanup(): void {
    const now = Date.now();
    for (const [token, session] of this.sessions) {
      if (now >= session.expiresAt) {
        this.sessions.delete(token);
      }
    }
  }

  /** Total number of active (not yet expired) sessions. */
  get size(): number {
    this.cleanup();
    return this.sessions.size;
  }
}

// ---------------------------------------------------------------------------
// Module-level singleton
// ---------------------------------------------------------------------------

let activeStore: SamlSessionStore | null = null;

export function initSamlSessionStore(defaultTtlMs?: number): SamlSessionStore {
  activeStore = new SamlSessionStore(defaultTtlMs);
  return activeStore;
}

export function getSamlSessionStore(): SamlSessionStore | null {
  return activeStore;
}

/** Validate a token against the active store. Returns null if store not initialized or token invalid. */
export function samlValidateToken(token: string): SamlSession | null {
  return activeStore?.validate(token) ?? null;
}
