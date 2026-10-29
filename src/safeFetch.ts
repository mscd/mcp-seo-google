import { lookup } from "node:dns/promises";
import { isIP, type LookupFunction } from "node:net";
import ipaddr from "ipaddr.js";
import { Agent, EnvHttpProxyAgent, fetch as undiciFetch, type Dispatcher, type BodyInit } from "undici";

const MAX_BYTES = 20 * 1024 * 1024;

export function publicAddress(address: string): boolean {
  try { return ipaddr.process(address).range() === "unicast"; } catch { return false; }
}

type Resolve = (hostname: string, options: { all: true }) => Promise<{ address: string; family: number }[]>;
export async function publicTarget(raw: string, resolve: Resolve = lookup): Promise<URL> {
  const url = new URL(raw);
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error("Only HTTP(S) URLs without credentials are allowed");
  const host = url.hostname.replace(/^\[|\]$/g, "");
  const addresses = isIP(host) ? [{ address: host }] : await resolve(host, { all: true }).catch(() => {
    throw new Error(`Cannot validate public DNS for ${host}; public DNS resolution is required even when using an outbound proxy`);
  });
  if (!addresses.length || addresses.some(({ address }) => !publicAddress(address))) throw new Error("Private, local and reserved network destinations are not allowed");
  return url;
}

// Revalidate the actual socket lookup too, preventing a second DNS answer from
// rebinding a direct connection. An outbound proxy resolves CONNECT targets itself;
// its network policy must also prohibit private destinations and DNS rebinding.
const publicLookup: LookupFunction = (hostname, options, callback) => {
  lookup(hostname, { all: true }).then((addresses) => {
    if (!addresses.length || addresses.some(({ address }) => !publicAddress(address))) return callback(new Error("Blocked non-public DNS address"), "");
    const all = options.all;
    const family = options.family;
    const selected = addresses.filter((a) => !family || a.family === family);
    if (!selected.length) return callback(new Error("No public address for requested family"), "");
    if (all) callback(null, selected); else callback(null, selected[0].address, selected[0].family);
  }, (err: NodeJS.ErrnoException) => callback(err, ""));
};
const connect = { lookup: publicLookup };
const direct = new Agent({ connect });
// Preserve platform proxies and injected HTTPS authentication. Never bypass a
// configured proxy; proxy destination restrictions remain an additional boundary.
const proxy = new EnvHttpProxyAgent({ connect });

/** Transport and DNS injection allow deterministic tests without contacting public services. */
export function createSafeFetcher(dispatcher: Dispatcher, resolveAddress: Resolve = lookup) {
  return async function (raw: string, init: RequestInit = {}, timeoutMs = 20_000): Promise<Response> {
    const signal = init.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs);
    let current = raw;
    let method = init.method ?? "GET";
    let body = init.body;
    const headers = new Headers(init.headers);
    for (let hop = 0; hop <= 6; hop++) {
      // Bound DNS validation by the same request deadline.
      const url = await new Promise<URL>((resolve, reject) => {
        const abort = () => reject(signal.reason);
        signal.addEventListener("abort", abort, { once: true });
        if (signal.aborted) abort();
        publicTarget(current, resolveAddress).then(resolve, reject).finally(() => signal.removeEventListener("abort", abort));
      });
      const res = await undiciFetch(url, { ...init, method, body: body as BodyInit, headers: Object.fromEntries(headers), signal, redirect: "manual", dispatcher });
      if ([301, 302, 303, 307, 308].includes(res.status) && res.headers.has("location") && init.redirect !== "manual") {
        await res.body?.cancel();
        if (init.redirect === "error") throw new Error("Redirects are not allowed");
        const next = new URL(res.headers.get("location")!, url);
        if (next.origin !== url.origin) {
          // API keys also occur in custom headers; forward only harmless headers.
          for (const name of [...headers.keys()]) if (!["accept", "accept-language", "user-agent", "content-type"].includes(name)) headers.delete(name);
        }
        if (res.status === 303 && method !== "HEAD" || [301, 302].includes(res.status) && method === "POST") { method = "GET"; body = undefined; headers.delete("content-type"); headers.delete("content-length"); }
        current = next.href;
        continue;
      }
      const chunks: Uint8Array[] = [];
      let bytes = 0;
      try {
        for await (const chunk of res.body ?? []) {
          bytes += chunk.byteLength;
          if (bytes > MAX_BYTES) throw new Error("Response exceeds 20 MiB limit");
          chunks.push(chunk);
        }
      } catch (err) { await res.body?.cancel().catch(() => {}); throw err; }
      const responseHeaders = new Headers(Object.fromEntries(res.headers));
      responseHeaders.delete("content-encoding");
      responseHeaders.delete("content-length");
      const result = new Response([101, 204, 205, 304].includes(res.status) || method === "HEAD" ? null : Buffer.concat(chunks), { status: res.status, statusText: res.statusText, headers: responseHeaders });
      Object.defineProperties(result, { url: { value: url.href }, redirected: { value: hop > 0 } });
      return result;
    }
    throw new Error("Too many redirects");
  };
}

export const safeFetch = createSafeFetcher(Boolean(process.env.HTTPS_PROXY || process.env.https_proxy || process.env.HTTP_PROXY || process.env.http_proxy) ? proxy : direct);
