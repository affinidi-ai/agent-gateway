// Drives the discovery demo the way an MCP client does, without a browser:
// call the Access Point without a token, follow the 401 challenge to the
// protected resource metadata and the authorization server's metadata, sign
// in at Hydra through the login form with PKCE and the RFC 8707 resource, and
// retry with the token. Then checks what the gateway did with the caller.
import crypto from 'node:crypto';
import fs from 'node:fs';
import { parseArgs } from 'node:util';

import { signIn as browse } from './browser.mjs';

const { values: args } = parseArgs({
  options: {
    resource: { type: 'string' },
    'client-id': { type: 'string' },
    'redirect-uri': { type: 'string' },
    'gateway-log': { type: 'string' },
  },
});
for (const name of ['resource', 'client-id', 'redirect-uri', 'gateway-log']) {
  if (!args[name]) {
    console.error(`check.mjs: --${name} is required`);
    process.exit(2);
  }
}
const RESOURCE = args.resource;
const LEGACY = '2024-11-05';
const CLIENT_INFO = { name: 'mcp-discovery-check', version: '1.0.0' };
const TIMEOUT = 20000;

let failures = 0;
function report(ok, name, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `: ${detail}` : ''}`);
  if (!ok) failures += 1;
  return ok;
}

const base64url = (bytes) => Buffer.from(bytes).toString('base64url');

function claims(token) {
  return JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8'));
}

function mcp(token, body, sessionId) {
  return fetch(RESOURCE, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(TIMEOUT),
  });
}

// A JSON-RPC answer, sent as JSON or as the last message of an SSE stream.
async function readMessage(response) {
  const text = await response.text();
  if (!(response.headers.get('content-type') ?? '').includes('text/event-stream')) {
    return text ? JSON.parse(text) : undefined;
  }
  const data = text
    .split('\n')
    .filter((line) => line.startsWith('data:'))
    .map((line) => line.slice('data:'.length).trim())
    .filter(Boolean);
  return data.length ? JSON.parse(data[data.length - 1]) : undefined;
}

const initialize = (token) =>
  mcp(token, { jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: LEGACY, capabilities: {}, clientInfo: CLIENT_INFO } });

// Authorization code with PKCE, signing in as `subject` at the login form.
async function signIn(server, subject) {
  const verifier = base64url(crypto.randomBytes(32));
  const state = base64url(crypto.randomBytes(16));
  const authorize = new URL(server.authorization_endpoint);
  authorize.search = new URLSearchParams({
    response_type: 'code',
    client_id: args['client-id'],
    redirect_uri: args['redirect-uri'],
    scope: 'tools',
    state,
    code_challenge: base64url(crypto.createHash('sha256').update(verifier).digest()),
    code_challenge_method: 'S256',
    resource: RESOURCE,
  }).toString();
  const callback = await browse(authorize, args['redirect-uri'], subject, TIMEOUT);
  if (callback.get('state') !== state) throw new Error('the authorization response lost the state');
  const code = callback.get('code');
  if (!code) throw new Error(`the authorization server refused: ${callback.get('error')}`);
  return redeem(server, code, verifier);
}

async function redeem(server, code, verifier) {
  const response = await fetch(server.token_endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code,
      redirect_uri: args['redirect-uri'],
      client_id: args['client-id'],
      code_verifier: verifier,
      resource: RESOURCE,
    }).toString(),
    signal: AbortSignal.timeout(TIMEOUT),
  });
  const body = await response.json();
  if (!response.ok || !body.access_token) throw new Error(`token request failed: HTTP ${response.status} ${body.error ?? ''}`);
  return body.access_token;
}

async function main() {
  // 1. No token: the challenge names the metadata.
  const challenged = await initialize();
  await challenged.body?.cancel();
  const challenge = challenged.headers.get('www-authenticate') ?? '';
  const metadataUrl = /resource_metadata="([^"]+)"/.exec(challenge)?.[1];
  report(
    challenged.status === 401 && Boolean(metadataUrl),
    'a call without a token gets 401 with a discovery challenge',
    `HTTP ${challenged.status}, WWW-Authenticate: ${challenge || '(none)'}`,
  );
  if (!metadataUrl) return;

  // 2. The protected resource metadata names the resource and Hydra, and a
  // browser client on another origin may read it.
  const browserOrigin = 'http://localhost:6274';
  const metadataResponse = await fetch(metadataUrl, { headers: { origin: browserOrigin }, signal: AbortSignal.timeout(TIMEOUT) });
  report(
    metadataResponse.headers.get('access-control-allow-origin') === browserOrigin,
    'a browser client on another origin may read the metadata',
    metadataResponse.headers.get('access-control-allow-origin') ?? '(no CORS header)',
  );
  const metadata = await metadataResponse.json();
  const issuer = metadata.authorization_servers?.[0];
  report(metadata.resource === RESOURCE, 'the metadata names the URL that was called as its resource', metadata.resource);
  report(Boolean(issuer), 'the metadata names the authorization server', issuer);
  report(metadata.scopes_supported?.includes('tools'), 'the metadata lists the scope', JSON.stringify(metadata.scopes_supported));
  if (!issuer) return;

  // 3. The authorization server's own metadata (RFC 8414).
  const server = await (
    await fetch(`${issuer.replace(/\/$/, '')}/.well-known/oauth-authorization-server`, { signal: AbortSignal.timeout(TIMEOUT) })
  ).json();
  report(server.issuer === issuer, 'the authorization server metadata names the same issuer', server.issuer);
  report(server.code_challenge_methods_supported?.includes('S256'), 'the authorization server supports PKCE S256');

  // 4. Sign in and retry.
  const token = await signIn(server, 'demo-user');
  const tokenClaims = claims(token);
  report(
    [tokenClaims.aud].flat().includes(RESOURCE),
    'the token is issued for the resource',
    `sub=${tokenClaims.sub} aud=${JSON.stringify(tokenClaims.aud)} scp=${JSON.stringify(tokenClaims.scp)}`,
  );
  const accepted = await initialize(token);
  const sessionId = accepted.headers.get('mcp-session-id') ?? undefined;
  const initialized = await readMessage(accepted);
  report(accepted.status === 200 && Boolean(initialized?.result), 'the retry with the token succeeds', `HTTP ${accepted.status}`);
  const notified = await mcp(token, { jsonrpc: '2.0', method: 'notifications/initialized' }, sessionId);
  await notified.body?.cancel();
  const tools = await readMessage(await mcp(token, { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} }, sessionId));
  report(tools.result?.tools?.some((tool) => tool.name === 'whoami'), 'the MCP server lists its tools through the gateway');
  const call = await readMessage(
    await mcp(token, { jsonrpc: '2.0', id: 3, method: 'tools/call', params: { name: 'whoami', arguments: {} } }, sessionId),
  );
  const seen = JSON.parse(call.result?.content?.[0]?.text ?? '{}');
  report(seen.authorization_header_received === false, "the caller's token never reaches the MCP server");

  // 5. The caller's identity reaches surface policy: another subject, with a
  // valid token, is refused by the policy that admits only demo-user.
  const otherToken = await signIn(server, 'someone-else');
  const refused = await initialize(otherToken);
  await refused.body?.cancel();
  report(refused.status === 403, 'surface policy sees the caller: another signed-in subject is refused', `HTTP ${refused.status}`);

  // 6. The gateway log records who called.
  // The log carries terminal colour codes around field names.
  const log = fs.readFileSync(args['gateway-log'], 'utf8').replace(/\x1b\[[0-9;]*m/g, '');
  report(
    /JWT Bearer source authentication succeeded.*subject=demo-user/.test(log),
    'the gateway log records the authenticated subject',
  );
}

try {
  await main();
} catch (error) {
  report(false, 'the discovery flow ran to the end', error.message);
}
console.log(failures === 0 ? 'RESULT: PASS' : `RESULT: FAIL (${failures})`);
process.exit(failures === 0 ? 0 : 1);
