import type { IncomingMessage, ServerResponse } from "node:http";
import { auditLog } from "../audit/audit-log.js";
import { createOpenClawTools } from "../agents/openclaw-tools.js";
import { runBeforeToolCallHook } from "../agents/pi-tools.before-tool-call.js";
import { resolveToolLoopDetectionConfig } from "../agents/pi-tools.js";
import {
  resolveEffectiveToolPolicy,
  resolveGroupToolPolicy,
  resolveSubagentToolPolicy,
} from "../agents/pi-tools.policy.js";
import {
  applyToolPolicyPipeline,
  buildDefaultToolPolicyPipelineSteps,
} from "../agents/tool-policy-pipeline.js";
import {
  collectExplicitAllowlist,
  mergeAlsoAllowPolicy,
  resolveToolProfilePolicy,
} from "../agents/tool-policy.js";
import { ToolInputError } from "../agents/tools/common.js";
import { loadConfig } from "../config/config.js";
import { resolveMainSessionKey } from "../config/sessions.js";
import type { GatewayRoleConfig } from "../config/types.gateway.js";
import {
  coerceSecretRef,
  normalizeSecretInputString,
} from "../config/types.secrets.js";
import { logWarn } from "../logger.js";
import { isTestDefaultMemorySlotDisabled } from "../plugins/config-state.js";
import { getPluginToolMeta } from "../plugins/tools.js";
import { isSubagentSessionKey } from "../routing/session-key.js";
import { DEFAULT_GATEWAY_HTTP_TOOL_DENY } from "../security/dangerous-tools.js";
import { safeEqualSecret } from "../security/secret-equal.js";
import { normalizeMessageChannel } from "../utils/message-channel.js";
import type { AuthRateLimiter } from "./auth-rate-limit.js";
import type { ResolvedGatewayAuth } from "./auth.js";
import { runGatewayToolInterceptor } from "./tool-interceptor.js";
import { authorizeGatewayBearerRequestOrReply } from "./http-auth-helpers.js";
import { resolveRequestClientIp } from "./net.js";
import {
  readJsonBodyOrError,
  sendInvalidRequest,
  sendJson,
  sendMethodNotAllowed,
} from "./http-common.js";
import { getBearerToken, getHeader } from "./http-utils.js";

/**
 * Resolves a role token from a SecretInput value at gateway-bootstrap level.
 * Supports plaintext strings, `${ENV_VAR}` templates, and env-source SecretRef objects.
 * Vault and exec-source refs are not supported at this layer.
 */
function resolveRoleTokenAtGateway(
  token: unknown,
  env: NodeJS.ProcessEnv = process.env,
): string | undefined {
  const plain = normalizeSecretInputString(token);
  if (plain) {
    return plain;
  }
  const ref = coerceSecretRef(token);
  if (!ref) {
    return undefined;
  }
  if (ref.source === "env") {
    const value = env[ref.id];
    return typeof value === "string" && value.trim() ? value.trim() : undefined;
  }
  // file, exec, hcvault: not resolvable synchronously at HTTP request time
  return undefined;
}

/**
 * Finds the first role from gateway.roles[] whose token matches the bearer token.
 * Handles SecretInput token values (plaintext, env refs).
 */
function matchRoleByBearerToken(
  roles: GatewayRoleConfig[],
  bearerToken: string,
): GatewayRoleConfig | undefined {
  for (const role of roles) {
    const resolved = resolveRoleTokenAtGateway(role.token);
    if (resolved && safeEqualSecret(bearerToken, resolved)) {
      return role;
    }
  }
  return undefined;
}

const DEFAULT_BODY_BYTES = 2 * 1024 * 1024;
const MEMORY_TOOL_NAMES = new Set(["memory_search", "memory_get"]);

type ToolsInvokeBody = {
  tool?: unknown;
  action?: unknown;
  args?: unknown;
  sessionKey?: unknown;
  dryRun?: unknown;
};

function resolveSessionKeyFromBody(body: ToolsInvokeBody): string | undefined {
  if (typeof body.sessionKey === "string" && body.sessionKey.trim()) {
    return body.sessionKey.trim();
  }
  return undefined;
}

function resolveMemoryToolDisableReasons(cfg: ReturnType<typeof loadConfig>): string[] {
  if (!process.env.VITEST) {
    return [];
  }
  const reasons: string[] = [];
  const plugins = cfg.plugins;
  const slotRaw = plugins?.slots?.memory;
  const slotDisabled =
    slotRaw === null || (typeof slotRaw === "string" && slotRaw.trim().toLowerCase() === "none");
  const pluginsDisabled = plugins?.enabled === false;
  const defaultDisabled = isTestDefaultMemorySlotDisabled(cfg);

  if (pluginsDisabled) {
    reasons.push("plugins.enabled=false");
  }
  if (slotDisabled) {
    reasons.push(slotRaw === null ? "plugins.slots.memory=null" : 'plugins.slots.memory="none"');
  }
  if (!pluginsDisabled && !slotDisabled && defaultDisabled) {
    reasons.push("memory plugin disabled by test default");
  }
  return reasons;
}

function mergeActionIntoArgsIfSupported(params: {
  toolSchema: unknown;
  action: string | undefined;
  args: Record<string, unknown>;
}): Record<string, unknown> {
  const { toolSchema, action, args } = params;
  if (!action) {
    return args;
  }
  if (args.action !== undefined) {
    return args;
  }
  // TypeBox schemas are plain objects; many tools define an `action` property.
  const schemaObj = toolSchema as { properties?: Record<string, unknown> } | null;
  const hasAction = Boolean(
    schemaObj &&
    typeof schemaObj === "object" &&
    schemaObj.properties &&
    "action" in schemaObj.properties,
  );
  if (!hasAction) {
    return args;
  }
  return { ...args, action };
}

function getErrorMessage(err: unknown): string {
  if (err instanceof Error) {
    return err.message || String(err);
  }
  if (typeof err === "string") {
    return err;
  }
  return String(err);
}

function resolveToolInputErrorStatus(err: unknown): number | null {
  if (err instanceof ToolInputError) {
    const status = (err as { status?: unknown }).status;
    return typeof status === "number" ? status : 400;
  }
  if (typeof err !== "object" || err === null || !("name" in err)) {
    return null;
  }
  const name = (err as { name?: unknown }).name;
  if (name !== "ToolInputError" && name !== "ToolAuthorizationError") {
    return null;
  }
  const status = (err as { status?: unknown }).status;
  if (typeof status === "number") {
    return status;
  }
  return name === "ToolAuthorizationError" ? 403 : 400;
}

export async function handleToolsInvokeHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  opts: {
    auth: ResolvedGatewayAuth;
    maxBodyBytes?: number;
    trustedProxies?: string[];
    allowRealIpFallback?: boolean;
    rateLimiter?: AuthRateLimiter;
  },
): Promise<boolean> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (url.pathname !== "/tools/invoke") {
    return false;
  }

  if (req.method !== "POST") {
    sendMethodNotAllowed(res, "POST");
    return true;
  }

  const cfg = loadConfig();

  // When gateway.roles are configured, check if the bearer token matches a role token.
  // If so, synthesize auth against that role's resolved token so the shared-secret check
  // passes. This allows role tokens (including SecretInput refs) to be used in place of
  // the main gateway token.
  const preAuthBearerToken =
    opts.auth.mode === "token" || opts.auth.mode === "none"
      ? getBearerToken(req)
      : undefined;
  const matchedRole = preAuthBearerToken
    ? matchRoleByBearerToken(cfg.gateway?.roles ?? [], preAuthBearerToken)
    : undefined;
  // Use the resolved plaintext token for the downstream auth check.
  const matchedRoleResolvedToken = matchedRole
    ? resolveRoleTokenAtGateway(matchedRole.token)
    : undefined;
  const effectiveAuth: ResolvedGatewayAuth = matchedRole && matchedRoleResolvedToken
    ? { ...opts.auth, mode: "token", token: matchedRoleResolvedToken }
    : opts.auth;

  const ok = await authorizeGatewayBearerRequestOrReply({
    req,
    res,
    auth: effectiveAuth,
    trustedProxies: opts.trustedProxies ?? cfg.gateway?.trustedProxies,
    allowRealIpFallback: opts.allowRealIpFallback ?? cfg.gateway?.allowRealIpFallback,
    rateLimiter: opts.rateLimiter,
  });
  if (!ok) {
    return true;
  }

  const bodyUnknown = await readJsonBodyOrError(req, res, opts.maxBodyBytes ?? DEFAULT_BODY_BYTES);
  if (bodyUnknown === undefined) {
    return true;
  }
  const body = (bodyUnknown ?? {}) as ToolsInvokeBody;

  const toolName = typeof body.tool === "string" ? body.tool.trim() : "";
  if (!toolName) {
    sendInvalidRequest(res, "tools.invoke requires body.tool");
    return true;
  }

  if (process.env.VITEST && MEMORY_TOOL_NAMES.has(toolName)) {
    const reasons = resolveMemoryToolDisableReasons(cfg);
    if (reasons.length > 0) {
      const suffix = reasons.length > 0 ? ` (${reasons.join(", ")})` : "";
      sendJson(res, 400, {
        ok: false,
        error: {
          type: "invalid_request",
          message:
            `memory tools are disabled in tests${suffix}. ` +
            'Enable by setting plugins.slots.memory="memory-core" (and ensure plugins.enabled is not false).',
        },
      });
      return true;
    }
  }

  const action = typeof body.action === "string" ? body.action.trim() : undefined;

  const argsRaw = body.args;
  const args =
    argsRaw && typeof argsRaw === "object" && !Array.isArray(argsRaw)
      ? (argsRaw as Record<string, unknown>)
      : {};

  const rawSessionKey = resolveSessionKeyFromBody(body);
  const sessionKey =
    !rawSessionKey || rawSessionKey === "main" ? resolveMainSessionKey(cfg) : rawSessionKey;

  // Resolve message channel/account hints (optional headers) for policy inheritance.
  const messageChannel = normalizeMessageChannel(
    getHeader(req, "x-openclaw-message-channel") ?? "",
  );
  const accountId = getHeader(req, "x-openclaw-account-id")?.trim() || undefined;
  const agentTo = getHeader(req, "x-openclaw-message-to")?.trim() || undefined;
  const agentThreadId = getHeader(req, "x-openclaw-thread-id")?.trim() || undefined;

  const {
    agentId,
    globalPolicy,
    globalProviderPolicy,
    agentPolicy,
    agentProviderPolicy,
    profile,
    providerProfile,
    profileAlsoAllow,
    providerProfileAlsoAllow,
  } = resolveEffectiveToolPolicy({ config: cfg, sessionKey });
  const profilePolicy = resolveToolProfilePolicy(profile);
  const providerProfilePolicy = resolveToolProfilePolicy(providerProfile);

  const profilePolicyWithAlsoAllow = mergeAlsoAllowPolicy(profilePolicy, profileAlsoAllow);
  const providerProfilePolicyWithAlsoAllow = mergeAlsoAllowPolicy(
    providerProfilePolicy,
    providerProfileAlsoAllow,
  );
  const groupPolicy = resolveGroupToolPolicy({
    config: cfg,
    sessionKey,
    messageProvider: messageChannel ?? undefined,
    accountId: accountId ?? null,
  });
  const subagentPolicy = isSubagentSessionKey(sessionKey)
    ? resolveSubagentToolPolicy(cfg)
    : undefined;

  // Build tool list (core + plugin tools).
  const allTools = createOpenClawTools({
    agentSessionKey: sessionKey,
    agentChannel: messageChannel ?? undefined,
    agentAccountId: accountId,
    agentTo,
    agentThreadId,
    allowGatewaySubagentBinding: true,
    // HTTP callers consume tool output directly; preserve raw media invoke payloads.
    allowMediaInvokeCommands: true,
    config: cfg,
    pluginToolAllowlist: collectExplicitAllowlist([
      profilePolicy,
      providerProfilePolicy,
      globalPolicy,
      globalProviderPolicy,
      agentPolicy,
      agentProviderPolicy,
      groupPolicy,
      subagentPolicy,
    ]),
  });

  const subagentFiltered = applyToolPolicyPipeline({
    // oxlint-disable-next-line typescript/no-explicit-any
    tools: allTools as any,
    // oxlint-disable-next-line typescript/no-explicit-any
    toolMeta: (tool) => getPluginToolMeta(tool as any),
    warn: logWarn,
    steps: [
      ...buildDefaultToolPolicyPipelineSteps({
        profilePolicy: profilePolicyWithAlsoAllow,
        profile,
        profileAlsoAllow,
        providerProfilePolicy: providerProfilePolicyWithAlsoAllow,
        providerProfile,
        providerProfileAlsoAllow,
        globalPolicy,
        globalProviderPolicy,
        agentPolicy,
        agentProviderPolicy,
        groupPolicy,
        agentId,
      }),
      { policy: subagentPolicy, label: "subagent tools.allow" },
    ],
  });

  // matchedRole is already resolved above from the bearer token pre-auth check.
  const activeRole = matchedRole;

  // Gateway HTTP-specific deny list — applies to ALL sessions via HTTP.
  const gatewayToolsCfg = cfg.gateway?.tools;
  const defaultGatewayDeny: string[] = DEFAULT_GATEWAY_HTTP_TOOL_DENY.filter(
    (name) => !gatewayToolsCfg?.allow?.includes(name),
  );
  const gatewayDenyNames = defaultGatewayDeny.concat(
    Array.isArray(gatewayToolsCfg?.deny) ? gatewayToolsCfg.deny : [],
  );
  // Apply role-specific tool deny list on top of the gateway-level deny list.
  if (activeRole?.tools?.deny?.length) {
    for (const name of activeRole.tools.deny) {
      gatewayDenyNames.push(name);
    }
  }
  const gatewayDenySet = new Set(gatewayDenyNames);

  // When a role defines an explicit tool allow list, restrict to only those tools.
  const roleAllowSet =
    activeRole?.tools?.allow?.length ? new Set(activeRole.tools.allow) : undefined;

  // MCP server / plugin–level sets for this role.
  // Matches against getPluginToolMeta(tool).pluginId (case-insensitive).
  const roleMcpAllowSet = activeRole?.mcps?.allow?.length
    ? new Set(activeRole.mcps.allow.map((s) => s.trim().toLowerCase()).filter(Boolean))
    : undefined;
  const roleMcpDenySet = activeRole?.mcps?.deny?.length
    ? new Set(activeRole.mcps.deny.map((s) => s.trim().toLowerCase()).filter(Boolean))
    : undefined;

  const gatewayFiltered = subagentFiltered.filter((t) => {
    // Tool-name–level filters.
    if (gatewayDenySet.has(t.name)) return false;
    if (roleAllowSet !== undefined && !roleAllowSet.has(t.name)) return false;

    // MCP server / plugin–level filters (only applies to plugin tools with metadata).
    // oxlint-disable-next-line typescript/no-explicit-any
    const meta = getPluginToolMeta(t as any);
    if (meta) {
      const pluginId = meta.pluginId.trim().toLowerCase();
      if (roleMcpDenySet?.has(pluginId)) return false;
      if (roleMcpAllowSet !== undefined && !roleMcpAllowSet.has(pluginId)) return false;
    }

    return true;
  });

  // Resolve client IP once for audit logging.
  const clientIp =
    resolveRequestClientIp(
      req,
      opts.trustedProxies ?? cfg.gateway?.trustedProxies,
      opts.allowRealIpFallback ?? cfg.gateway?.allowRealIpFallback,
    ) ?? req.socket?.remoteAddress;

  const auditActor = matchedRole?.name ?? "gateway-token";
  const auditRole = matchedRole?.name;

  const tool = gatewayFiltered.find((t) => t.name === toolName);
  if (!tool) {
    void auditLog({
      kind: "tool_blocked",
      actor: auditActor,
      ip: clientIp,
      role: auditRole,
      tool: toolName,
      session: sessionKey,
      details: { reason: "tool_not_available" },
    });
    sendJson(res, 404, {
      ok: false,
      error: { type: "not_found", message: `Tool not available: ${toolName}` },
    });
    return true;
  }

  try {
    const toolCallId = `http-${Date.now()}`;
    const toolArgs = mergeActionIntoArgsIfSupported({
      // oxlint-disable-next-line typescript/no-explicit-any
      toolSchema: (tool as any).parameters,
      action,
      args,
    });

    const interceptorResult = runGatewayToolInterceptor({
      toolName,
      toolArgs,
      networkPolicy: gatewayToolsCfg?.networkPolicy,
    });
    if (!interceptorResult.ok) {
      void auditLog({
        kind: "tool_blocked",
        actor: auditActor,
        ip: clientIp,
        role: auditRole,
        tool: toolName,
        session: sessionKey,
        details: { reason: "network_policy", blockedUrl: interceptorResult.value },
      });
      sendJson(res, 403, {
        ok: false,
        error: { type: "blocked", message: interceptorResult.reason },
      });
      return true;
    }

    const hookResult = await runBeforeToolCallHook({
      toolName,
      params: toolArgs,
      toolCallId,
      ctx: {
        agentId,
        sessionKey,
        loopDetection: resolveToolLoopDetectionConfig({ cfg, agentId }),
      },
    });
    if (hookResult.blocked) {
      void auditLog({
        kind: "tool_blocked",
        actor: auditActor,
        ip: clientIp,
        role: auditRole,
        tool: toolName,
        session: sessionKey,
        details: { reason: "hook_blocked", hookReason: hookResult.reason },
      });
      sendJson(res, 403, {
        ok: false,
        error: { type: "tool_call_blocked", message: hookResult.reason },
      });
      return true;
    }

    // oxlint-disable-next-line typescript/no-explicit-any
    const result = await (tool as any).execute?.(toolCallId, hookResult.params);

    void auditLog({
      kind: "tool_call",
      actor: auditActor,
      ip: clientIp,
      role: auditRole,
      tool: toolName,
      session: sessionKey,
    });

    sendJson(res, 200, { ok: true, result });
  } catch (err) {
    const inputStatus = resolveToolInputErrorStatus(err);
    if (inputStatus !== null) {
      sendJson(res, inputStatus, {
        ok: false,
        error: { type: "tool_error", message: getErrorMessage(err) || "invalid tool arguments" },
      });
      return true;
    }
    logWarn(`tools-invoke: tool execution failed: ${String(err)}`);
    sendJson(res, 500, {
      ok: false,
      error: { type: "tool_error", message: "tool execution failed" },
    });
  }

  return true;
}
