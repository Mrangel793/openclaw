import type { GatewayNetworkPolicy } from "../config/types.gateway.js";
import { isBlockedHostnameOrIp } from "../infra/net/ssrf.js";

export type ToolInterceptorResult =
  | { ok: true }
  | { ok: false; reason: string; value?: string };

function isHostnameAllowedByPattern(hostname: string, pattern: string): boolean {
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    if (!suffix || hostname === suffix) {
      return false;
    }
    return hostname.endsWith(`.${suffix}`);
  }
  return hostname === pattern;
}

function hostnameInAllowlist(hostname: string, allowlist: string[]): boolean {
  return allowlist.some((pattern) => isHostnameAllowedByPattern(hostname, pattern));
}

/**
 * Returns true when `hostname` is a private/internal address:
 * RFC-1918 ranges (10.x, 172.16-31.x, 192.168.x), loopback, link-local,
 * special-use IPs, and internal hostnames (.local, .internal, localhost).
 *
 * Delegates to the shared SSRF library so IP range logic is in one place.
 * "Blocked" in the SSRF context means "private/internal" — exactly the
 * addresses we want to *allow* when blockExternalUrls is active.
 */
function isInternalHostname(hostname: string): boolean {
  return isBlockedHostnameOrIp(hostname);
}

function collectStringValues(value: unknown, depth = 0): string[] {
  if (depth > 5) return [];
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) {
    return value.flatMap((item) => collectStringValues(item, depth + 1));
  }
  if (value !== null && typeof value === "object") {
    return Object.values(value as Record<string, unknown>).flatMap((v) =>
      collectStringValues(v, depth + 1),
    );
  }
  return [];
}

/**
 * Determines whether a URL hostname should be blocked given the network policy.
 *
 * Decision order:
 * 1. Explicit allowlist match → always allowed (trumps blockExternalUrls).
 * 2. blockExternalUrls + internal hostname → allowed (private network is safe).
 * 3. Explicit allowlist present but hostname not in it → blocked.
 * 4. blockExternalUrls true but hostname is public → blocked.
 * 5. No policy active → allowed.
 */
function isHostnameBlocked(
  hostname: string,
  allowedHosts: string[],
  blockExternalUrls: boolean,
): boolean {
  // Step 1: explicit allowlist match always permits.
  if (allowedHosts.length > 0 && hostnameInAllowlist(hostname, allowedHosts)) {
    return false;
  }
  // Step 2: when blocking external URLs, private/internal addresses are always safe.
  if (blockExternalUrls && isInternalHostname(hostname)) {
    return false;
  }
  // Step 3: hostname not in an explicit allowlist → block.
  if (allowedHosts.length > 0) {
    return true;
  }
  // Step 4: blockExternalUrls active and hostname is not internal → block.
  if (blockExternalUrls) {
    return true;
  }
  // Step 5: no policy active.
  return false;
}

/**
 * Validates tool arguments against the gateway network policy.
 *
 * Extracts all string values from toolArgs recursively and blocks any
 * HTTP/HTTPS URL whose hostname violates the configured policy:
 *
 * - `allowedHosts`: explicit hostname allowlist (supports `*.example.com` wildcards).
 * - `blockExternalUrls`: block any URL outside RFC-1918 / internal ranges.
 *
 * When neither option is configured the interceptor is a no-op.
 */
export function runGatewayToolInterceptor(params: {
  toolName: string;
  toolArgs: Record<string, unknown>;
  networkPolicy: GatewayNetworkPolicy | undefined;
}): ToolInterceptorResult {
  const { networkPolicy, toolArgs } = params;
  if (!networkPolicy) {
    return { ok: true };
  }

  const allowedHosts = networkPolicy.allowedHosts ?? [];
  const blockExternalUrls = networkPolicy.blockExternalUrls === true;

  // No-op when neither policy is active.
  if (allowedHosts.length === 0 && !blockExternalUrls) {
    return { ok: true };
  }

  for (const candidate of collectStringValues(toolArgs)) {
    if (!/^https?:\/\//i.test(candidate)) {
      continue;
    }
    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      continue;
    }
    const hostname = parsed.hostname.toLowerCase();
    if (isHostnameBlocked(hostname, allowedHosts, blockExternalUrls)) {
      const reason =
        allowedHosts.length > 0
          ? "URL blocked by gateway network policy (host not in allowedHosts)"
          : "URL blocked: external URLs are not allowed (blockExternalUrls=true)";
      return { ok: false, reason, value: candidate };
    }
  }
  return { ok: true };
}
