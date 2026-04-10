/**
 * HTTP request handler for SAML 2.0 SP endpoints.
 *
 * Mounts three routes under `/auth/saml/`:
 *   GET  /auth/saml/metadata  — SP metadata XML (for IdP registration)
 *   GET  /auth/saml/login     — redirect to IdP SSO page
 *   POST /auth/saml/callback  — ACS endpoint; validates assertion, issues token
 *
 * Returns `false` for any path that is not a SAML path (so the caller can
 * continue to the next handler stage).
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import type { SamlProvider } from "./saml-provider.js";

const SAML_PATH_PREFIX = "/auth/saml";

function sendXml(res: ServerResponse, status: number, body: string): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/xml; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

function sendHtml(res: ServerResponse, status: number, body: string): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(body);
}

function sendError(res: ServerResponse, status: number, message: string): void {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  res.end(JSON.stringify({ error: message }));
}

function redirect(res: ServerResponse, url: string): void {
  res.statusCode = 302;
  res.setHeader("Location", url);
  res.setHeader("Cache-Control", "no-store");
  res.end();
}

/** Read the full body of a POST request as a UTF-8 string. */
async function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf-8")));
    req.on("error", reject);
  });
}

/** Parse `application/x-www-form-urlencoded` body into a string-only record. */
function parseFormBody(raw: string): Record<string, string> {
  const params = new URLSearchParams(raw);
  const result: Record<string, string> = {};
  for (const [key, value] of params.entries()) {
    result[key] = value;
  }
  return result;
}

/**
 * Handle an incoming HTTP request for the `/auth/saml/*` path space.
 *
 * @param req  Incoming Node.js HTTP request.
 * @param res  Outgoing Node.js HTTP response.
 * @param provider  Active SAML provider (must be non-null when mode is "saml").
 * @param controlUiBasePath  Base path of the Control UI for post-login redirect. Default: "/".
 * @returns `true` if the request was handled (response sent), `false` if not a SAML path.
 */
export async function handleSamlHttpRequest(
  req: IncomingMessage,
  res: ServerResponse,
  provider: SamlProvider,
  controlUiBasePath = "/",
): Promise<boolean> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const pathname = url.pathname;

  if (!pathname.startsWith(SAML_PATH_PREFIX)) {
    return false;
  }

  const subPath = pathname.slice(SAML_PATH_PREFIX.length); // e.g. "/metadata", "/login", "/callback"

  // ── GET /auth/saml/metadata ────────────────────────────────────────────
  if (req.method === "GET" && (subPath === "/metadata" || subPath === "")) {
    try {
      const xml = provider.getMetadataXml();
      sendXml(res, 200, xml);
    } catch (err) {
      sendError(res, 500, `metadata_error: ${err instanceof Error ? err.message : String(err)}`);
    }
    return true;
  }

  // ── GET /auth/saml/login ───────────────────────────────────────────────
  if (req.method === "GET" && subPath === "/login") {
    try {
      const relayState = url.searchParams.get("relay") ?? "";
      const loginUrl = await provider.getLoginUrl(relayState);
      redirect(res, loginUrl);
    } catch (err) {
      sendError(res, 500, `login_error: ${err instanceof Error ? err.message : String(err)}`);
    }
    return true;
  }

  // ── POST /auth/saml/callback ───────────────────────────────────────────
  if (req.method === "POST" && subPath === "/callback") {
    try {
      const rawBody = await readBody(req);
      const contentType = (req.headers["content-type"] ?? "").toLowerCase();

      let body: Record<string, string>;
      if (contentType.includes("application/x-www-form-urlencoded")) {
        body = parseFormBody(rawBody);
      } else {
        sendError(res, 415, "expected_form_encoded_body");
        return true;
      }

      const result = await provider.handleCallback(body);

      if (!result.ok) {
        sendHtml(
          res,
          403,
          `<!doctype html><html><body><h1>Authentication failed</h1><p>${escapeHtml(result.reason)}</p></body></html>`,
        );
        return true;
      }

      // Redirect to the Control UI with the session token in the query string.
      // The UI is expected to store it and use it as a Bearer token.
      const base = controlUiBasePath.endsWith("/")
        ? controlUiBasePath
        : `${controlUiBasePath}/`;
      const returnUrl = `${base}?saml_token=${encodeURIComponent(result.token)}`;
      redirect(res, returnUrl);
    } catch (err) {
      sendError(res, 500, `callback_error: ${err instanceof Error ? err.message : String(err)}`);
    }
    return true;
  }

  // Unknown SAML sub-path.
  sendError(res, 404, "saml_path_not_found");
  return true;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
