import http from "node:http";
import { timingSafeEqual } from "node:crypto";

/** Accept only the callback for the browser flow we initiated. Invalid requests
 * must not consume the flow, and errors are plain text rather than HTML. */
export function callbackHandler(redirect: string, state: string, finish: (err: Error | null, code?: string) => void) {
  let completed = false;
  return (req: http.IncomingMessage, res: http.ServerResponse) => {
    if (completed) { res.writeHead(410).end(); return; }
    let url: URL;
    try { url = new URL(req.url ?? "/", redirect); } catch { res.writeHead(400).end(); return; }
    if (req.method !== "GET") { res.writeHead(405).end(); return; }
    if (url.pathname !== "/oauth2callback") { res.writeHead(404).end(); return; }
    const given = Buffer.from(url.searchParams.get("state") ?? "");
    const expected = Buffer.from(state);
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) { res.writeHead(400).end("Invalid OAuth state"); return; }
    const err = url.searchParams.get("error");
    const code = url.searchParams.get("code");
    completed = true;
    res.writeHead(err || !code ? 400 : 200, { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" });
    res.end(err || !code ? "Authorization failed. Return to the terminal." : "Authorization complete. You may close this window.");
    finish(err || !code ? new Error("OAuth authorization failed") : null, code ?? undefined);
  };
}
