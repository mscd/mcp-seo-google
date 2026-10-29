import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { Agent, MockAgent } from 'undici';
import { publicAddress, publicTarget, createSafeFetcher, safeFetch } from '../../dist/safeFetch.js';
import { callbackHandler } from '../../dist/authCallback.js';
import { runWithAuth } from '../../dist/google.js';
import { wpPostIndexForHost } from '../../dist/tools/wp.js';

test('SSRF: only globally routable addresses are accepted, including mapped IPv6', async () => {
  for (const ip of ['127.0.0.1', '10.0.0.1', '172.16.0.1', '192.168.0.1', '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1', '::', '::1', 'fc00::1', 'fe80::1', '::ffff:127.0.0.1', '2001:db8::1']) assert.equal(publicAddress(ip), false, ip);
  for (const ip of ['8.8.8.8', '2606:4700:4700::1111']) assert.equal(publicAddress(ip), true, ip);
  for (const url of ['file:///etc/passwd', 'http://user:pass@example.com', 'http://2130706433', 'http://[::ffff:127.0.0.1]']) await assert.rejects(publicTarget(url));
  await assert.rejects(publicTarget('https://public.example', async () => [{ address: '8.8.8.8', family: 4 }, { address: '127.0.0.1', family: 4 }]), /not allowed/);
  await assert.rejects(safeFetch('http://127.0.0.1/private'), /not allowed/);
});

const publicDns = async () => [{ address: '8.8.8.8', family: 4 }];

test('SSRF: redirects are revalidated and cross-origin secrets are removed', async () => {
  const agent = new MockAgent(); agent.disableNetConnect();
  const fetch = createSafeFetcher(agent, publicDns);
  try {
    agent.get('https://public.example').intercept({ path: '/private' }).reply(302, '', { headers: { location: 'http://127.0.0.1/internal' } });
    await assert.rejects(fetch('https://public.example/private'), /not allowed/);
    agent.get('https://public.example').intercept({ path: '/redirect' }).reply(302, '', { headers: { location: 'https://other.example/final' } });
    agent.get('https://other.example').intercept({ path: '/final', headers: (headers) => !headers.authorization && !headers['x-api-key'] && !headers.cookie }).reply(200, 'ok');
    const res = await fetch('https://public.example/redirect', { headers: { authorization: 'test-secret', 'x-api-key': 'test-key', cookie: 'test-cookie' } });
    assert.equal(await res.text(), 'ok');
    assert.equal(res.url, 'https://other.example/final');
    assert.equal(res.redirected, true);
    agent.assertNoPendingInterceptors();
  } finally { await agent.close(); }
});

test('response bodies are size-limited before parsing', async () => {
  const agent = new MockAgent(); agent.disableNetConnect();
  try {
    agent.get('https://public.example').intercept({ path: '/' }).reply(200, Buffer.alloc(20 * 1024 * 1024 + 1));
    await assert.rejects(createSafeFetcher(agent, publicDns)('https://public.example/'), /20 MiB/);
  } finally { await agent.close(); }
});

test('the deadline covers slow bodies and caller cancellation', async () => {
  const server = http.createServer((req, res) => { res.writeHead(200); res.flushHeaders(); res.write('start'); });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  // Test transport routes a fictitious public host to our controlled local server.
  const agent = new Agent({ connect: { lookup: (host, opts, cb) => opts.all ? cb(null, [{ address: '127.0.0.1', family: 4 }]) : cb(null, '127.0.0.1', 4) } });
  const fetch = createSafeFetcher(agent, publicDns);
  try {
    const url = `http://public.example:${server.address().port}/`;
    const started = Date.now();
    await assert.rejects(fetch(url, {}, 100), /abort|timeout/i);
    assert.ok(Date.now() - started < 2000);
    await assert.rejects(fetch(url, { signal: AbortSignal.abort() }), /abort/i);
  } finally { await agent.destroy(); server.closeAllConnections(); await new Promise((r) => server.close(r)); }
});

test('OAuth callback rejects mismatched state without consuming the flow and never reflects HTML', async () => {
  const outcomes = [];
  const server = http.createServer(callbackHandler('http://localhost/oauth2callback', 'expected-state', (...args) => outcomes.push(args)));
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const request = (path, method = 'GET') => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port: server.address().port, path, method }, (res) => {
      let body = ''; res.on('data', (d) => body += d); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body }));
    }); req.on('error', reject); req.end();
  });
  try {
    assert.equal((await request('/oauth2callback?state=wrong&code=x')).status, 400);
    assert.equal((await request('/oauth2callback?state=expected-state&code=x', 'POST')).status, 405);
    assert.equal(outcomes.length, 0);
    const res = await request('/oauth2callback?state=expected-state&error=%3Cscript%3Ealert(1)%3C%2Fscript%3E');
    assert.equal(res.status, 400); assert.match(res.headers['content-type'], /^text\/plain/); assert.ok(!res.body.includes('<script>'));
    assert.equal(outcomes.length, 1); assert.ok(outcomes[0][0] instanceof Error);
  } finally { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
});

test('hosted WordPress enrichment never reads operator site configuration', async () => {
  const previous = process.env.WP_SITES;
  process.env.WP_SITES = 'invalid JSON must never be read for a tenant';
  try { assert.equal(await runWithAuth({ auth: {}, label: 'tenant' }, () => wpPostIndexForHost('example.com')), null); }
  finally { if (previous === undefined) delete process.env.WP_SITES; else process.env.WP_SITES = previous; }
});

test('OAuth callback accepts the matching code once', async () => {
  const outcomes = [];
  const server = http.createServer(callbackHandler('http://localhost/oauth2callback', 'expected-state', (...args) => outcomes.push(args)));
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const request = () => new Promise((resolve, reject) => {
    const req = http.get({ host: '127.0.0.1', port: server.address().port, path: '/oauth2callback?state=expected-state&code=valid-code' }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject);
  });
  try {
    assert.equal(await request(), 200); assert.deepEqual(outcomes, [[null, 'valid-code']]);
    assert.equal(await request(), 410); assert.equal(outcomes.length, 1);
  } finally { server.closeAllConnections(); await new Promise((r) => server.close(r)); }
});

test('HTTP rejects missing tokens, untrusted Host/Origin, and malformed headers without crashing', async () => {
  const env = { ...process.env, MCP_AUTH_TOKEN: '', MCP_HOST: '127.0.0.1', MCP_PORT: '0', MCP_TRANSPORT: 'http', MCP_PATH: '/mcp', SEO_MCP_OAUTH: '', SEO_MCP_HOSTED_CLIENT_ID: '', SEO_MCP_HOSTED_CLIENT_SECRET: '', SEO_MCP_HOSTED_SECRET: '', SEO_MCP_PUBLIC_URL: '', SEO_MCP_DIGEST_SITES: '', WP_SITES: '', MCP_ALLOWED_HOSTS: '', MCP_ALLOWED_ORIGINS: '' };
  const entry = new URL('../../dist/index.js', import.meta.url);
  for (const hosted of [{}, { SEO_MCP_HOSTED_CLIENT_ID: 'test', SEO_MCP_HOSTED_CLIENT_SECRET: 'test', SEO_MCP_HOSTED_SECRET: 'test', SEO_MCP_PUBLIC_URL: 'https://mcp.example.com' }]) {
    const missing = spawn(process.execPath, [entry.pathname, '--http'], { env: { ...env, ...hosted }, stdio: ['ignore', 'pipe', 'pipe'] });
    let log = ''; missing.stderr.on('data', (d) => log += d);
    const [status] = await once(missing, 'exit'); assert.notEqual(status, 0); assert.match(log, /requires MCP_AUTH_TOKEN/);
  }
  // Reserve a port for the process; retry-free local smoke setup mirrors existing OAuth E2E.
  const reserve = net.createServer(); reserve.listen(0, '127.0.0.1'); await once(reserve, 'listening');
  const port = reserve.address().port; await new Promise((r) => reserve.close(r));
  const proc = spawn(process.execPath, [entry.pathname, '--http'], { env: { ...env, MCP_PORT: String(port), MCP_AUTH_TOKEN: 'security-test-token', SEO_MCP_PUBLIC_URL: 'https://mcp.example.com', MCP_ALLOWED_HOSTS: '127.0.0.1:8787' }, stdio: ['ignore', 'pipe', 'pipe'] });
  let stderr = ''; proc.stderr.on('data', (d) => stderr += d);
  const request = (headers = {}, method = 'GET', path = '/healthz') => new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, path, method, headers }, (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); });
    req.on('error', reject); req.end();
  });
  try {
    for (let i = 0; i < 100 && !stderr.includes('listening on'); i++) { if (proc.exitCode !== null) throw new Error(stderr); await new Promise((r) => setTimeout(r, 20)); }
    assert.match(stderr, /listening on/);
    assert.equal(await request({}, 'POST', '/mcp'), 401);
    assert.equal(await request({ authorization: 'Bearer wrong' }, 'POST', '/mcp'), 401);
    assert.equal(await request({ host: '[', authorization: 'Bearer security-test-token' }), 403);
    assert.equal(await request({ host: 'evil.example' }), 403);
    assert.equal(await request({ origin: 'https://evil.example', authorization: 'Bearer security-test-token' }), 403);
    assert.equal(await request({ origin: `http://127.0.0.1:${port}` }), 200);
    assert.equal(await request({ host: 'mcp.example.com', origin: 'https://mcp.example.com' }), 200);
    assert.equal(await request({ host: '127.0.0.1:8787' }), 200);
    assert.equal(await request(), 200); assert.equal(proc.exitCode, null);
  } finally { const done = once(proc, 'exit'); proc.kill('SIGTERM'); await done; }
});
