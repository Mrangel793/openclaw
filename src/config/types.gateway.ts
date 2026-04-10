import type { SecretInput } from "./types.secrets.js";

export type GatewayBindMode = "auto" | "lan" | "loopback" | "custom" | "tailnet";

export type GatewayTlsConfig = {
  /** Enable TLS for the gateway server. */
  enabled?: boolean;
  /** Auto-generate a self-signed cert if cert/key are missing (default: true). */
  autoGenerate?: boolean;
  /** PEM certificate path for the gateway server. */
  certPath?: string;
  /** PEM private key path for the gateway server. */
  keyPath?: string;
  /** Optional PEM CA bundle for TLS clients (mTLS or custom roots). */
  caPath?: string;
};

export type WideAreaDiscoveryConfig = {
  enabled?: boolean;
  /** Optional unicast DNS-SD domain (e.g. "openclaw.internal"). */
  domain?: string;
};

export type MdnsDiscoveryMode = "off" | "minimal" | "full";

export type MdnsDiscoveryConfig = {
  /**
   * mDNS/Bonjour discovery broadcast mode (default: minimal).
   * - off: disable mDNS entirely
   * - minimal: omit cliPath/sshPort from TXT records
   * - full: include cliPath/sshPort in TXT records
   */
  mode?: MdnsDiscoveryMode;
};

export type DiscoveryConfig = {
  wideArea?: WideAreaDiscoveryConfig;
  mdns?: MdnsDiscoveryConfig;
};

export type CanvasHostConfig = {
  enabled?: boolean;
  /** Directory to serve (default: ~/.openclaw/workspace/canvas). */
  root?: string;
  /** HTTP port to listen on (default: 18793). */
  port?: number;
  /** Enable live-reload file watching + WS reloads (default: true). */
  liveReload?: boolean;
};

export type TalkProviderConfig = {
  /** Default voice ID for the provider's Talk mode implementation. */
  voiceId?: string;
  /** Optional voice name -> provider voice ID map. */
  voiceAliases?: Record<string, string>;
  /** Default provider model ID for Talk mode. */
  modelId?: string;
  /** Default provider output format (for example pcm_44100). */
  outputFormat?: string;
  /** Provider API key (optional; provider-specific env fallback may apply). */
  apiKey?: SecretInput;
  /** Provider-specific extensions. */
  [key: string]: unknown;
};

export type ResolvedTalkConfig = {
  /** Active Talk TTS provider resolved from the current config payload. */
  provider: string;
  /** Provider config for the active Talk provider. */
  config: TalkProviderConfig;
};

export type TalkConfig = {
  /** Active Talk TTS provider (for example "elevenlabs"). */
  provider?: string;
  /** Provider-specific Talk config keyed by provider id. */
  providers?: Record<string, TalkProviderConfig>;
  /** Stop speaking when user starts talking (default: true). */
  interruptOnSpeech?: boolean;
  /** Milliseconds of user silence before Talk mode sends the transcript after a pause. */
  silenceTimeoutMs?: number;

  /**
   * Legacy ElevenLabs compatibility fields.
   * Kept during rollout while older clients migrate to provider/providers.
   */
  voiceId?: string;
  voiceAliases?: Record<string, string>;
  modelId?: string;
  outputFormat?: string;
  apiKey?: SecretInput;
};

export type TalkConfigResponse = TalkConfig & {
  /** Canonical active Talk payload for clients. */
  resolved?: ResolvedTalkConfig;
};

export type GatewayControlUiConfig = {
  /** If false, the Gateway will not serve the Control UI (default /). */
  enabled?: boolean;
  /** Optional base path prefix for the Control UI (e.g. "/openclaw"). */
  basePath?: string;
  /** Optional filesystem root for Control UI assets (defaults to dist/control-ui). */
  root?: string;
  /** Allowed browser origins for Control UI/WebChat websocket connections. */
  allowedOrigins?: string[];
  /**
   * DANGEROUS: Keep Host-header origin fallback behavior.
   * Supported long-term for deployments that intentionally rely on this policy.
   */
  dangerouslyAllowHostHeaderOriginFallback?: boolean;
  /**
   * Insecure-auth toggle.
   * Control UI still requires secure context + device identity unless
   * dangerouslyDisableDeviceAuth is enabled.
   */
  allowInsecureAuth?: boolean;
  /** DANGEROUS: Disable device identity checks for the Control UI (default: false). */
  dangerouslyDisableDeviceAuth?: boolean;
};

export type GatewayAuthMode = "none" | "token" | "password" | "trusted-proxy" | "ldap" | "saml";

/**
 * LDAP / Active Directory authentication configuration.
 * Required when `gateway.auth.mode` is `"ldap"`.
 */
export type GatewayLdapConfig = {
  /**
   * LDAP server URL. Use `ldaps://` for LDAPS (recommended for production).
   * Example: `ldaps://dc01.entidad.gov.co:636`
   */
  url: string;
  /**
   * Base Distinguished Name for user searches.
   * Example: `"DC=entidad,DC=gov,DC=co"`
   */
  baseDn: string;
  /**
   * Service-account DN used to search the directory before verifying user credentials.
   * Example: `"CN=svc-openclaw,OU=ServiceAccounts,DC=entidad,DC=gov,DC=co"`
   * When omitted, an anonymous bind is attempted (requires anonymous read access).
   */
  bindDn?: SecretInput;
  /** Service-account password (plaintext or `${ENV_VAR}`). */
  bindPassword?: SecretInput;
  /**
   * LDAP search filter to locate the user entry.
   * Use `{{username}}` as the placeholder; it will be LDAP-escaped.
   * Default: `"(sAMAccountName={{username}})"` (standard AD attribute).
   * For UPN-based login use: `"(userPrincipalName={{username}})"`.
   */
  userSearchFilter?: string;
  /**
   * Entry attribute used as the canonical user identifier in audit logs and session info.
   * Default: `"sAMAccountName"`.
   */
  userAttribute?: string;
  /**
   * Optional allowlist of AD group DNs. The authenticating user must be a member of
   * at least one of these groups.
   * Example: `["CN=Funcionarios,OU=Groups,DC=entidad,DC=gov,DC=co"]`
   */
  allowedGroups?: string[];
  /**
   * Skip TLS certificate validation.
   * **Do not use in production.** Only for internal test environments with self-signed certs.
   * Default: false.
   */
  tlsSkipVerify?: boolean;
  /** TCP connection timeout in milliseconds. Default: 5000. */
  connectTimeoutMs?: number;
};

/**
 * SAML 2.0 Service Provider configuration.
 * Required when `gateway.auth.mode` is `"saml"`.
 *
 * Compatible with ADFS, Entra ID (Azure AD), Okta, and any standard SAML 2.0 IdP.
 */
export type GatewaySamlConfig = {
  /**
   * IdP Single Sign-On URL (HTTP-Redirect binding).
   * ADFS example: `https://adfs.entidad.gov.co/adfs/ls`
   * Entra ID example: `https://login.microsoftonline.com/<tenant>/saml2`
   */
  idpSsoUrl: string;
  /**
   * IdP signing certificate in PEM format (with or without `-----BEGIN CERTIFICATE-----` header).
   * Obtain this from the IdP's federation metadata or admin console.
   */
  idpCert: string;
  /**
   * SP Entity ID — must match the identifier configured in the IdP Relying Party Trust.
   * Convention: use the SP metadata URL.
   * Example: `https://openclaw.entidad.gov.co/auth/saml/metadata`
   */
  spEntityId: string;
  /**
   * SP Assertion Consumer Service (ACS) URL — where the IdP will POST the SAMLResponse.
   * Example: `https://openclaw.entidad.gov.co/auth/saml/callback`
   */
  spAcsUrl: string;
  /**
   * SAML attribute name that contains the authenticated user identity.
   * Falls back to `nameID` when absent.
   * Default: `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress`
   */
  userAttribute?: string;
  /**
   * Optional allowlist of SAML user identities (e.g. emails).
   * When empty or absent, all users authenticated by the IdP are allowed.
   */
  allowUsers?: string[];
  /**
   * Session token lifetime in milliseconds.
   * Default: 28800000 (8 hours).
   */
  sessionTtlMs?: number;
  /**
   * SP private key (PEM) for signing AuthnRequest messages.
   * Supports plaintext PEM or `${ENV_VAR}`.
   * Optional — most IdPs do not require signed requests.
   */
  spPrivateKey?: SecretInput;
};

/**
 * Configuration for trusted reverse proxy authentication.
 * Used when Clawdbot runs behind an identity-aware proxy (Pomerium, Caddy + OAuth, etc.)
 * that handles authentication and passes user identity via headers.
 */
export type GatewayTrustedProxyConfig = {
  /**
   * Header name containing the authenticated user identity (required).
   * Common values: "x-forwarded-user", "x-remote-user", "x-pomerium-claim-email"
   */
  userHeader: string;
  /**
   * Additional headers that MUST be present for the request to be trusted.
   * Use this to verify the request actually came through the proxy.
   * Example: ["x-forwarded-proto", "x-forwarded-host"]
   */
  requiredHeaders?: string[];
  /**
   * Optional allowlist of user identities that can access the gateway.
   * If empty or omitted, all authenticated users from the proxy are allowed.
   * Example: ["nick@example.com", "admin@company.org"]
   */
  allowUsers?: string[];
};

export type GatewayAuthConfig = {
  /** Authentication mode for Gateway connections. Defaults to token when unset. */
  mode?: GatewayAuthMode;
  /** Shared token for token mode (plaintext or SecretRef). */
  token?: SecretInput;
  /** Shared password for password mode (consider env instead). */
  password?: SecretInput;
  /** Allow Tailscale identity headers when serve mode is enabled. */
  allowTailscale?: boolean;
  /** Rate-limit configuration for failed authentication attempts. */
  rateLimit?: GatewayAuthRateLimitConfig;
  /**
   * Configuration for trusted-proxy auth mode.
   * Required when mode is "trusted-proxy".
   */
  trustedProxy?: GatewayTrustedProxyConfig;
  /**
   * LDAP / Active Directory configuration.
   * Required when mode is "ldap".
   */
  ldap?: GatewayLdapConfig;
  /**
   * SAML 2.0 Service Provider configuration.
   * Required when mode is "saml".
   */
  saml?: GatewaySamlConfig;
};

export type GatewayAuthRateLimitConfig = {
  /** Maximum failed attempts per IP before blocking.  @default 5 */
  maxAttempts?: number;
  /** Sliding window duration in milliseconds.  @default 60000 (1 min) */
  windowMs?: number;
  /** Lockout duration in milliseconds after the limit is exceeded.  @default 300000 (5 min) */
  lockoutMs?: number;
  /** Exempt localhost/loopback addresses from auth rate limiting.  @default true */
  exemptLoopback?: boolean;
};

export type GatewayTailscaleMode = "off" | "serve" | "funnel";

export type GatewayTailscaleConfig = {
  /** Tailscale exposure mode for the Gateway control UI. */
  mode?: GatewayTailscaleMode;
  /** Reset serve/funnel configuration on shutdown. */
  resetOnExit?: boolean;
};

export type GatewayRemoteConfig = {
  /** Whether remote gateway surfaces are enabled. Default: true when absent. */
  enabled?: boolean;
  /** Remote Gateway WebSocket URL (ws:// or wss://). */
  url?: string;
  /** Transport for macOS remote connections (ssh tunnel or direct WS). */
  transport?: "ssh" | "direct";
  /** Token for remote auth (when the gateway requires token auth). */
  token?: SecretInput;
  /** Password for remote auth (when the gateway requires password auth). */
  password?: SecretInput;
  /** Expected TLS certificate fingerprint (sha256) for remote gateways. */
  tlsFingerprint?: string;
  /** SSH target for tunneling remote Gateway (user@host). */
  sshTarget?: string;
  /** SSH identity file path for tunneling remote Gateway. */
  sshIdentity?: string;
};

export type GatewayReloadMode = "off" | "restart" | "hot" | "hybrid";

export type GatewayReloadConfig = {
  /** Reload strategy for config changes (default: hybrid). */
  mode?: GatewayReloadMode;
  /** Debounce window for config reloads (ms). Default: 300. */
  debounceMs?: number;
  /**
   * Maximum time (ms) to wait for in-flight operations to complete before
   * forcing a SIGUSR1 restart. Default: 300000 (5 minutes).
   * Lower values risk aborting active subagent LLM calls.
   * @see https://github.com/openclaw/openclaw/issues/47711
   */
  deferralTimeoutMs?: number;
};

export type GatewayHttpChatCompletionsConfig = {
  /**
   * If false, the Gateway will not serve `POST /v1/chat/completions`.
   * Default: false when absent.
   */
  enabled?: boolean;
  /**
   * Max request body size in bytes for `/v1/chat/completions`.
   * Default: 20MB.
   */
  maxBodyBytes?: number;
  /**
   * Max number of `image_url` parts processed from the latest user message.
   * Default: 8.
   */
  maxImageParts?: number;
  /**
   * Max cumulative decoded image bytes for all `image_url` parts in one request.
   * Default: 20MB.
   */
  maxTotalImageBytes?: number;
  /** Image input controls for `image_url` parts. */
  images?: GatewayHttpChatCompletionsImagesConfig;
};

export type GatewayHttpChatCompletionsImagesConfig = {
  /** Allow URL fetches for `image_url` parts. Default: false. */
  allowUrl?: boolean;
  /**
   * Optional hostname allowlist for URL fetches.
   * Supports exact hosts and `*.example.com` wildcards.
   */
  urlAllowlist?: string[];
  /** Allowed MIME types (case-insensitive). */
  allowedMimes?: string[];
  /** Max bytes per image. Default: 10MB. */
  maxBytes?: number;
  /** Max redirects when fetching a URL. Default: 3. */
  maxRedirects?: number;
  /** Fetch timeout in ms. Default: 10s. */
  timeoutMs?: number;
};

export type GatewayHttpResponsesConfig = {
  /**
   * If false, the Gateway will not serve `POST /v1/responses` (OpenResponses API).
   * Default: false when absent.
   */
  enabled?: boolean;
  /**
   * Max request body size in bytes for `/v1/responses`.
   * Default: 20MB.
   */
  maxBodyBytes?: number;
  /**
   * Max number of URL-based `input_file` + `input_image` parts per request.
   * Default: 8.
   */
  maxUrlParts?: number;
  /** File inputs (input_file). */
  files?: GatewayHttpResponsesFilesConfig;
  /** Image inputs (input_image). */
  images?: GatewayHttpResponsesImagesConfig;
};

export type GatewayHttpResponsesFilesConfig = {
  /** Allow URL fetches for input_file. Default: true. */
  allowUrl?: boolean;
  /**
   * Optional hostname allowlist for URL fetches.
   * Supports exact hosts and `*.example.com` wildcards.
   */
  urlAllowlist?: string[];
  /** Allowed MIME types (case-insensitive). */
  allowedMimes?: string[];
  /** Max bytes per file. Default: 5MB. */
  maxBytes?: number;
  /** Max decoded characters per file. Default: 200k. */
  maxChars?: number;
  /** Max redirects when fetching a URL. Default: 3. */
  maxRedirects?: number;
  /** Fetch timeout in ms. Default: 10s. */
  timeoutMs?: number;
  /** PDF handling (application/pdf). */
  pdf?: GatewayHttpResponsesPdfConfig;
};

export type GatewayHttpResponsesPdfConfig = {
  /** Max pages to parse/render. Default: 4. */
  maxPages?: number;
  /** Max pixels per rendered page. Default: 4M. */
  maxPixels?: number;
  /** Minimum extracted text length to skip rasterization. Default: 200 chars. */
  minTextChars?: number;
};

export type GatewayHttpResponsesImagesConfig = {
  /** Allow URL fetches for input_image. Default: true. */
  allowUrl?: boolean;
  /**
   * Optional hostname allowlist for URL fetches.
   * Supports exact hosts and `*.example.com` wildcards.
   */
  urlAllowlist?: string[];
  /** Allowed MIME types (case-insensitive). */
  allowedMimes?: string[];
  /** Max bytes per image. Default: 10MB. */
  maxBytes?: number;
  /** Max redirects when fetching a URL. Default: 3. */
  maxRedirects?: number;
  /** Fetch timeout in ms. Default: 10s. */
  timeoutMs?: number;
};

export type GatewayHttpEndpointsConfig = {
  chatCompletions?: GatewayHttpChatCompletionsConfig;
  responses?: GatewayHttpResponsesConfig;
};

export type GatewayHttpSecurityHeadersConfig = {
  /**
   * Value for the Strict-Transport-Security response header.
   * Set to false to disable explicitly.
   *
   * Example: "max-age=31536000; includeSubDomains"
   */
  strictTransportSecurity?: string | false;
};

export type GatewayHttpConfig = {
  endpoints?: GatewayHttpEndpointsConfig;
  securityHeaders?: GatewayHttpSecurityHeadersConfig;
};

export type GatewayPushApnsRelayConfig = {
  /** Base HTTPS URL for the external iOS APNs relay service. */
  baseUrl?: string;
  /** Timeout in milliseconds for relay send requests (default: 10000). */
  timeoutMs?: number;
};

export type GatewayPushApnsConfig = {
  relay?: GatewayPushApnsRelayConfig;
};

export type GatewayPushConfig = {
  apns?: GatewayPushApnsConfig;
};

export type GatewayNodesConfig = {
  /** Browser routing policy for node-hosted browser proxies. */
  browser?: {
    /** Routing mode (default: auto). */
    mode?: "auto" | "manual" | "off";
    /** Pin to a specific node id/name (optional). */
    node?: string;
  };
  /** Additional node.invoke commands to allow on the gateway. */
  allowCommands?: string[];
  /** Commands to deny even if they appear in the defaults or node claims. */
  denyCommands?: string[];
};

export type GatewaySecurityConfig = {
  /**
   * Global WebSocket origin allowlist. When set, any WebSocket connection that
   * presents an Origin header must match one of the listed origins (exact,
   * case-insensitive) or be from a local loopback address. Use "*" to allow any
   * origin. Connections without an Origin header (e.g. native CLI clients) are
   * not affected by this list.
   *
   * Example: ["https://control.empresa.com", "https://app.empresa.com"]
   */
  wsOriginAllowlist?: string[];
};

export type GatewayNetworkPolicy = {
  /**
   * Hostnames/patterns allowed for HTTP/HTTPS URLs found in tool call arguments.
   * Supports exact hosts ("api.empresa.com") and subdomain wildcards ("*.empresa.com").
   * When defined, any URL not matching the list is blocked with HTTP 403.
   * If empty or omitted, no URL-based blocking is applied (unless blockExternalUrls is set).
   */
  allowedHosts?: string[];
  /**
   * When true, block any URL whose hostname resolves to a public (non-private) address.
   * Only RFC-1918 private ranges (10.x, 172.16-31.x, 192.168.x), loopback, link-local,
   * and internal hostnames (.local, .internal, localhost) are allowed through.
   * Use `allowedHosts` to add explicit exceptions for trusted public endpoints.
   * Default: false.
   */
  blockExternalUrls?: boolean;
};

export type GatewayToolsConfig = {
  /** Tools to deny via gateway HTTP /tools/invoke (extends defaults). */
  deny?: string[];
  /** Tools to explicitly allow (removes from default deny list). */
  allow?: string[];
  /**
   * Network policy for tool call argument inspection.
   * Blocks tool calls that include URLs pointing to hosts outside the allowlist.
   */
  networkPolicy?: GatewayNetworkPolicy;
};

export type GatewayRoleToolsConfig = {
  /** Tool names allowed for this role (applied after global deny list). */
  allow?: string[];
  /** Additional tool names denied for this role. */
  deny?: string[];
};

export type GatewayRoleMcpConfig = {
  /**
   * MCP server or plugin IDs this role can access.
   * When set, only tools whose plugin/server ID appears in this list are accessible
   * for this role. Native (built-in) tools without a plugin ID are not affected.
   * Supports exact matches (case-insensitive).
   * Example: ["filesystem", "web-search-plugin"]
   */
  allow?: string[];
  /**
   * MCP server or plugin IDs blocked for this role.
   * Applied in addition to the global deny list and any per-role tool deny list.
   * Example: ["filesystem"]
   */
  deny?: string[];
};

export type GatewayRoleConfig = {
  /** Identifier for this role (e.g. "admin", "analista", "funcionario"). */
  name: string;
  /**
   * Bearer token that grants this role.
   * Accepts plaintext strings, `${ENV_VAR}` template syntax, or a SecretRef object.
   * For env-based refs at gateway bootstrap, prefer `${ENV_VAR}` or
   * `{ source: "env", provider: "default", id: "MY_ROLE_TOKEN" }`.
   */
  token: SecretInput;
  /** Tool-name–level access restrictions applied to requests with this role's token. */
  tools?: GatewayRoleToolsConfig;
  /**
   * MCP server / plugin–level access restrictions for this role.
   * Use this to allow or deny entire MCP servers or plugin groups.
   * Applied in addition to `tools` restrictions.
   */
  mcps?: GatewayRoleMcpConfig;
};

export type GatewayConfig = {
  /** Single multiplexed port for Gateway WS + HTTP (default: 18789). */
  port?: number;
  /**
   * Explicit gateway mode. When set to "remote", local gateway start is disabled.
   * When set to "local", the CLI may start the gateway locally.
   */
  mode?: "local" | "remote";
  /**
   * Bind address policy for the Gateway WebSocket + Control UI HTTP server.
   * - auto: Loopback (127.0.0.1) if available, else 0.0.0.0 (fallback to all interfaces)
   * - lan: 0.0.0.0 (all interfaces, no fallback)
   * - loopback: 127.0.0.1 (local-only)
   * - tailnet: Tailnet IPv4 if available (100.64.0.0/10), else loopback
   * - custom: User-specified IP, fallback to 0.0.0.0 if unavailable (requires customBindHost)
   * Default: loopback (127.0.0.1).
   */
  bind?: GatewayBindMode;
  /** Custom IP address for bind="custom" mode. Fallback: 0.0.0.0. */
  customBindHost?: string;
  controlUi?: GatewayControlUiConfig;
  auth?: GatewayAuthConfig;
  tailscale?: GatewayTailscaleConfig;
  remote?: GatewayRemoteConfig;
  reload?: GatewayReloadConfig;
  tls?: GatewayTlsConfig;
  http?: GatewayHttpConfig;
  push?: GatewayPushConfig;
  nodes?: GatewayNodesConfig;
  /**
   * IPs of trusted reverse proxies (e.g. Traefik, nginx). When a connection
   * arrives from one of these IPs, the Gateway trusts `x-forwarded-for`
   * to determine the client IP for local pairing and HTTP checks.
   */
  trustedProxies?: string[];
  /**
   * Allow `x-real-ip` as a fallback only when `x-forwarded-for` is missing.
   * Default: false (safer fail-closed behavior).
   */
  allowRealIpFallback?: boolean;
  /** Tool access restrictions for HTTP /tools/invoke endpoint. */
  tools?: GatewayToolsConfig;
  /**
   * Role-based access control: multiple tokens, each granting different tool permissions.
   * Requests authenticated with a role token are subject to that role's tool restrictions.
   * Requests using the main gateway.auth.token have unrestricted access (admin role).
   */
  roles?: GatewayRoleConfig[];
  /**
   * Disable installation or updates of skills from ClawHub (third-party marketplace).
   * When true, only locally-audited skills are allowed.
   * Default: false.
   */
  /** Global WebSocket and connection-level security settings. */
  security?: GatewaySecurityConfig;
  disableClawHub?: boolean;
  /**
   * Channel health monitor interval in minutes.
   * Periodically checks channel health and restarts unhealthy channels.
   * Set to 0 to disable. Default: 5.
   */
  channelHealthCheckMinutes?: number;
  /**
   * Stale event threshold in minutes for the channel health monitor.
   * A connected channel that receives no events for this duration is treated
   * as a stale socket and restarted. Default: 30.
   */
  channelStaleEventThresholdMinutes?: number;
  /**
   * Maximum number of health-monitor-initiated channel restarts per hour.
   * Once this limit is reached, the monitor skips further restarts until
   * the rolling window expires. Default: 10.
   */
  channelMaxRestartsPerHour?: number;
};
