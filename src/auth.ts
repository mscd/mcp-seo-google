/**
 * One-time OAuth authorization helper.
 *
 *   npm run auth -- --client-secret ./client_secret.json            # Search Console + Analytics (read)
 *   npm run auth -- --gmail --client-secret ./client_secret.json    # Gmail read-only, for the attachment tools
 *   # or
 *   GOOGLE_OAUTH_CLIENT_ID=... GOOGLE_OAUTH_CLIENT_SECRET=... npm run auth
 *
 * Opens a browser, asks you to grant the scopes, and writes an authorized_user JSON:
 * ~/.config/google-seo-mcp/credentials.json (Google APIs) or ~/.config/google-seo-mcp/gmail.json (--gmail),
 * which the MCP server picks up automatically (GOOGLE_APPLICATION_CREDENTIALS / GMAIL_CREDENTIALS override the paths).
 */
import { envValue, loadDotEnv } from "./env.js";
loadDotEnv();
import fs from "node:fs";
import http from "node:http";
import path from "node:path";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { callbackHandler } from "./authCallback.js";
import { OAuth2Client, CodeChallengeMethod } from "google-auth-library";
import { DEFAULT_CREDENTIALS_PATH, SCOPES } from "./google.js";
import { DEFAULT_GMAIL_CREDENTIALS_PATH, GMAIL_SCOPES } from "./gmail.js";

const GMAIL = process.argv.includes("--gmail");

const PORT = Number(envValue("GOOGLE_OAUTH_PORT") ?? 53682);
const REDIRECT = `http://127.0.0.1:${PORT}/oauth2callback`;

function loadClient(): { clientId: string; clientSecret: string } {
  const idx = process.argv.indexOf("--client-secret");
  const file = idx >= 0 ? process.argv[idx + 1] : envValue("GOOGLE_OAUTH_CLIENT_SECRET_FILE");
  if (file) {
    const json = JSON.parse(fs.readFileSync(file, "utf8"));
    const c = json.installed ?? json.web ?? json;
    if (!c.client_id || !c.client_secret) throw new Error(`No client_id/client_secret found in ${file}`);
    return { clientId: c.client_id, clientSecret: c.client_secret };
  }
  const clientId = envValue("GOOGLE_OAUTH_CLIENT_ID");
  const clientSecret = envValue("GOOGLE_OAUTH_CLIENT_SECRET");
  if (!clientId || !clientSecret) {
    throw new Error(
      "Provide OAuth client credentials via --client-secret <file.json> or GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET env vars.",
    );
  }
  return { clientId, clientSecret };
}

function openBrowser(url: string) {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  try {
    // The URL is printed above; missing desktop utilities must not abort auth.
    if (process.platform === "win32") return;
    spawn(cmd, [url], { stdio: "ignore", detached: true }).on("error", () => {}).unref();
  } catch {
    /* user can open the URL manually */
  }
}

async function main() {
  const { clientId, clientSecret } = loadClient();
  const oauth2 = new OAuth2Client(clientId, clientSecret, REDIRECT);
  const state = randomBytes(32).toString("base64url");
  const { codeVerifier, codeChallenge } = await oauth2.generateCodeVerifierAsync();
  const url = oauth2.generateAuthUrl({ access_type: "offline", prompt: "consent", scope: GMAIL ? GMAIL_SCOPES : SCOPES, state, code_challenge: codeChallenge, code_challenge_method: CodeChallengeMethod.S256 });

  const code = await new Promise<string>((resolve, reject) => {
    const server = http.createServer(callbackHandler(REDIRECT, state, (err, code) => {
      clearTimeout(timer);
      server.close();
      if (err) reject(err); else resolve(code!);
    }));
    const timer = setTimeout(() => { server.closeAllConnections(); server.close(); reject(new Error("OAuth callback timed out after ten minutes")); }, 600_000);
    server.once("error", (err) => { clearTimeout(timer); reject(err); });
    server.listen(PORT, "127.0.0.1", () => {
      console.log("\n请在浏览器中打开以下链接完成授权：\n\n" + url + "\n");
      openBrowser(url);
    });
  });

  const { tokens } = await oauth2.getToken({ code, codeVerifier });
  if (!tokens.refresh_token) {
    throw new Error("No refresh_token returned. Remove the app from https://myaccount.google.com/permissions and run again.");
  }
  const out = GMAIL ? (envValue("GMAIL_CREDENTIALS") ?? DEFAULT_GMAIL_CREDENTIALS_PATH) : (envValue("GOOGLE_APPLICATION_CREDENTIALS") ?? DEFAULT_CREDENTIALS_PATH);
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(
    out,
    JSON.stringify({ type: "authorized_user", client_id: clientId, client_secret: clientSecret, refresh_token: tokens.refresh_token }, null, 2),
    { mode: 0o600 },
  );
  console.log(`已保存凭据到 ${out}`);
}

main().catch((e) => {
  console.error(e.message ?? e);
  process.exit(1);
});
