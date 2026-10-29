import http from "node:http";
import { timingSafeEqual } from "node:crypto";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { configuredOptions, createServer, SERVER_INFO, TOOLSETS, type ServerOptions } from "./server.js";
import { envValue } from "./env.js";
import { describeCredentialSource, runWithAuth } from "./google.js";
import { loadHosted } from "./hosted/index.js";
import { loadOAuth } from "./oauth.js";
import { startDigestSchedule } from "./digest.js";

const PORT = Number(envValue("MCP_PORT") ?? 8080);
const HOST = envValue("MCP_HOST") ?? "127.0.0.1";
const PATH = envValue("MCP_PATH") ?? "/mcp";

/** Apply a request's `?toolsets=` / `?readOnly=` narrowing. Intersects with what the instance already allows, so it can only ever remove access. */
export function narrowOptions(base: ServerOptions, url: URL): ServerOptions {
  const out: ServerOptions = { ...base };
  const raw = url.searchParams.get("toolsets");
  if (raw !== null) {
    const asked = raw.split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
    const unknown = asked.filter((x) => !(TOOLSETS as readonly string[]).includes(x));
    if (unknown.length) throw new Error(`unknown toolset(s): ${unknown.join(", ")}. Valid: ${TOOLSETS.join(", ")}`);
    if (!asked.length) throw new Error(`toolsets must name at least one of: ${TOOLSETS.join(", ")}`);
    out.toolsets = base.toolsets ? base.toolsets.filter((t) => asked.includes(t)) : asked;
  }
  if (/^(1|true|yes)$/i.test(url.searchParams.get("readOnly") ?? "")) out.readOnly = true;
  return out;
}
const TOKEN = envValue("MCP_AUTH_TOKEN");
/** Tools only the operator's own token may see: they manage access to this server itself. */
const OPERATOR_ONLY_TOOLS = ["oauth_list_grants", "oauth_revoke_grant"];

function bearer(req: http.IncomingMessage): string {
  const header = req.headers.authorization ?? "";
  return header.startsWith("Bearer ") ? header.slice(7) : "";
}

/** Missing configuration never grants operator privileges. */
function authorized(req: http.IncomingMessage): boolean {
  if (!TOKEN) return false;
  const a = Buffer.from(bearer(req));
  const b = Buffer.from(TOKEN);
  return a.length === b.length && timingSafeEqual(a, b);
}

function json(res: http.ServerResponse, status: number, body: unknown) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

export function startHttp() {
  if (!TOKEN) throw new Error("HTTP mode requires MCP_AUTH_TOKEN. Use stdio for credential-free local development.");
  const publicUrl = envValue("SEO_MCP_PUBLIC_URL");
  const hosts = new Set([`127.0.0.1:${PORT}`, `localhost:${PORT}`, `[::1]:${PORT}`]);
  if (!["0.0.0.0", "::"].includes(HOST)) hosts.add(`${HOST.includes(":") && !HOST.startsWith("[") ? `[${HOST}]` : HOST}:${PORT}`);
  const origins = new Set([...hosts].map((host) => `http://${host}`));
  if (publicUrl) { const u = new URL(publicUrl); hosts.add(u.host); origins.add(u.origin); }
  for (const host of (envValue("MCP_ALLOWED_HOSTS") ?? "").split(",").filter(Boolean)) hosts.add(host.trim().toLowerCase());
  for (const origin of (envValue("MCP_ALLOWED_ORIGINS") ?? "").split(",").filter(Boolean)) origins.add(new URL(origin.trim()).origin);
  const hosted = loadHosted();
  // Optional OAuth layer (SEO_MCP_OAUTH=1) for clients that cannot send a static bearer token.
  const oauth = loadOAuth();
  // Optional weekly Search Console digest (SEO_MCP_DIGEST_SITES), so a drop reports itself.
  const digest = startDigestSchedule();
  const handle = async (req: http.IncomingMessage, res: http.ServerResponse) => {
    const host = req.headers.host?.toLowerCase();
    if (!host || !hosts.has(host)) { json(res, 403, { error: "invalid host" }); return; }
    if (req.headers.origin && !origins.has(req.headers.origin)) { json(res, 403, { error: "invalid origin" }); return; }
    if (!req.url?.startsWith("/") || req.url.startsWith("//")) { json(res, 400, { error: "invalid request target" }); return; }
    const url = new URL(req.url, `http://${host}`);

    if (url.pathname === "/healthz") {
      // Liveness for proxies and deploy scripts; version and credential source only for callers that hold the token.
      json(res, 200, authorized(req) ? { ok: true, version: SERVER_INFO.version, credentials: describeCredentialSource() } : { ok: true });
      return;
    }
    if (url.pathname !== PATH) {
      // These handlers read request bodies and talk to Google and GitHub; a throw here must not
      // become an unhandled rejection, which would take the whole process down.
      try {
        if (oauth && (await oauth.handle(req, res, url))) return;
        if (hosted && (await hosted.handle(req, res, url))) return;
      } catch (err) {
        console.error("web request failed:", err);
        if (!res.headersSent) json(res, 400, { error: "bad request" });
        return;
      }
      json(res, 404, { error: "not found" });
      return;
    }
    // Operator token → full server with the operator's credentials; an OAuth grant is the same
    // access (the browser form asked for that very token), narrowed to read-only for `mcp:read`;
    // a hosted user token → read-only server on that user's own Google grant.
    const operator = authorized(req);
    const grant = operator ? null : oauth?.resolve(bearer(req)) ?? null;
    const tenant = operator || grant ? null : hosted?.resolve(bearer(req)) ?? null;
    if (!operator && !grant && !tenant) {
      // RFC 9728: point unauthenticated clients at the metadata so they can start the OAuth flow.
      res.setHeader("WWW-Authenticate", oauth ? `Bearer resource_metadata="${oauth.metadataUrl(req)}"` : "Bearer");
      json(res, 401, { error: "unauthorized" });
      return;
    }
    if (req.method !== "POST") {
      // Stateless mode: no standalone SSE stream and no session to delete.
      json(res, 405, { error: "method not allowed" });
      return;
    }

    // A request may ask for fewer tools than this instance offers. 96 tool definitions cost
    // ~35k tokens in every conversation, and a client that only reads analytics has no use for
    // the WordPress and GitHub write tools. Narrowing only: it can never add a toolset the
    // instance was not started with, nor turn a read-only tenant into a writing one.
    let options: ServerOptions;
    try {
      let base = tenant ? tenant.options : configuredOptions();
      // Managing who may connect belongs to the operator alone: a client that arrived through the
      // OAuth flow (or a hosted user) must not be able to list or revoke anyone's access.
      if (grant || tenant) base = { ...base, exclude: [...(base.exclude ?? []), ...OPERATOR_ONLY_TOOLS] };
      if (grant?.readOnly) base = { ...base, readOnly: true };
      options = narrowOptions(base, url);
    } catch (err) {
      json(res, 400, { error: (err as Error).message });
      return;
    }

    // Stateless: a fresh server + transport per request, so a crash in one
    // request never affects others and there is nothing to leak over days of uptime.
    const server = createServer(options);
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableDnsRebindingProtection: true, allowedHosts: [...hosts], allowedOrigins: [...origins] });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      if (tenant) await runWithAuth(tenant.auth, () => transport.handleRequest(req, res));
      else await transport.handleRequest(req, res);
    } catch (err) {
      console.error("request failed:", err);
      if (!res.headersSent) json(res, 500, { error: "internal error" });
    }
  };
  const httpServer = http.createServer((req, res) => {
    void handle(req, res).catch((err) => {
      console.error("request failed:", err instanceof Error ? err.message : "unknown error");
      if (!res.headersSent) json(res, 400, { error: "bad request" }); else res.destroy();
    });
  });

  httpServer.keepAliveTimeout = 65_000;
  httpServer.listen(PORT, HOST, () => {
    console.error(`google-seo-mcp listening on http://${HOST}:${PORT}${PATH} (auth: ${TOKEN ? "bearer token" : "NONE"}, credentials: ${describeCredentialSource()}${oauth ? `, ${oauth.describe()}` : ""}${hosted ? `, ${hosted.describe()}` : ""}${digest ? `, ${digest}` : ""})`);
  });

  const shutdown = () => {
    console.error("shutting down");
    httpServer.close(() => process.exit(0));
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}
