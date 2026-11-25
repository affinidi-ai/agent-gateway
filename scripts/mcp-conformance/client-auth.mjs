// Outbound OAuth for the suite's client-credentials scenarios.
//
// Each scenario's server answers 401 with a `resource_metadata` challenge and
// expects the client to find the token endpoint from it. The gateway does not
// discover: its token endpoint is a credential provider setting. So this module
// does the discovery, writes a credential provider with the token endpoint it
// found and binds it to the surface's Target. The gateway then fetches the
// token and attaches it; what the suite judges is the gateway's token request.
//
// The provider sends the scenario's client secret or signed assertion to the
// token endpoint, so discovery trusts nothing the tested server names: every
// URL it follows or stores must be on the origin of the server under test or on
// loopback, where the suite's servers run.
import fs from 'node:fs';
import path from 'node:path';

export const SURFACE_ID = 'conformance-forwarding';
const PROVIDER_ID = 'conformance-target-auth';

const PROVIDERS = {
  'auth/client-credentials-basic': (context) => ({
    record: {
      provider_type: 'oauth2_client_credentials',
      client_id_secret_ref: 'conformance-client-id',
      client_secret_secret_ref: 'conformance-client-secret',
    },
    secrets: { 'conformance-client-id': context.client_id, 'conformance-client-secret': context.client_secret },
  }),
  // The assertion audience is the issuer identifier (RFC 7523bis); the gateway
  // would otherwise default it to the token endpoint.
  'auth/client-credentials-jwt': (context, issuer) => ({
    record: {
      provider_type: 'oauth2_client_credentials_jwt_auth',
      client_id_secret_ref: 'conformance-client-id',
      jwt_signing_key_secret_ref: 'conformance-signing-key',
      jwt_signing_algorithm: context.signing_algorithm,
      jwt_audience: issuer,
    },
    secrets: { 'conformance-client-id': context.client_id, 'conformance-signing-key': context.private_key_pem },
  }),
};

export function isAuthScenario(scenario) {
  return Object.hasOwn(PROVIDERS, scenario);
}

export function resourceMetadataUrl(challenge) {
  const match = /resource_metadata="([^"]+)"/.exec(challenge ?? '');
  if (!match) throw new Error('the 401 challenge names no resource_metadata');
  return match[1];
}

// RFC 8414 puts the well-known segment between the origin and the issuer path.
export function authorizationServerMetadataUrl(issuer) {
  const url = new URL(issuer);
  const issuerPath = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
  return `${url.origin}/.well-known/oauth-authorization-server${issuerPath}`;
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

export function trustedUrl(value, suiteUrl, what) {
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${what} is not a URL`);
  }
  const trusted =
    (url.protocol === 'http:' || url.protocol === 'https:') &&
    (url.origin === new URL(suiteUrl).origin || LOOPBACK_HOSTS.has(url.hostname));
  if (!trusted) throw new Error(`${what} ${url.origin} is neither the origin of the server under test nor loopback`);
  return url.href;
}

async function json(url) {
  const response = await fetch(url, { headers: { accept: 'application/json' }, redirect: 'error' });
  if (!response.ok) throw new Error(`${url} answered ${response.status}`);
  return response.json();
}

export async function discoverTokenEndpoint(suiteUrl) {
  const challenged = await fetch(suiteUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 'discover', method: 'ping' }),
    redirect: 'error',
  });
  if (challenged.status !== 401) throw new Error(`expected a 401 challenge from ${suiteUrl}, got ${challenged.status}`);
  const trust = (value, what) => trustedUrl(value, suiteUrl, what);
  const metadataUrl = trust(resourceMetadataUrl(challenged.headers.get('www-authenticate')), 'the resource_metadata URL');
  const resource = await json(metadataUrl);
  const issuer = resource.authorization_servers?.[0];
  if (!issuer) throw new Error('the protected resource metadata names no authorization server');
  trust(issuer, 'the authorization server');
  const server = await json(authorizationServerMetadataUrl(issuer));
  if (!server.token_endpoint) throw new Error('the authorization server metadata names no token endpoint');
  return { tokenEndpoint: trust(server.token_endpoint, 'the token endpoint'), issuer };
}

export function providerFiles(scenario, context, { tokenEndpoint, issuer }, now = new Date().toISOString()) {
  const { record, secrets } = PROVIDERS[scenario](context, issuer);
  const stamp = { created_at: now, updated_at: now };
  return {
    provider: { id: PROVIDER_ID, name: PROVIDER_ID, provider_id: PROVIDER_ID, token_endpoint: tokenEndpoint, ...record, ...stamp },
    secrets: Object.entries(secrets).map(([id, value]) => {
      if (typeof value !== 'string' || !value) throw new Error(`the scenario context lacks the value for ${id}`);
      return { id, name: id, secret_id: id, value, secret_type: 'ApiKey', tags: [], ...stamp };
    }),
    targetAuth: { method: { credential_provider: { provider_id: PROVIDER_ID, scopes: [] } }, fallback: 'reject' },
  };
}

// Secrets are readable by this user only; the gateway runs as the same user.
function writeJson(dir, id, value, { secret = false } = {}) {
  fs.mkdirSync(dir, { recursive: true, ...(secret ? { mode: 0o700 } : {}) });
  const file = path.join(dir, `${id}.json`);
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, secret ? { mode: 0o600 } : undefined);
  if (secret) {
    fs.chmodSync(dir, 0o700);
    fs.chmodSync(file, 0o600);
  }
}

// Adds the provider, its secrets and the Target binding to an env that env.mjs
// wrote. The storage paths are relative to the gateway's working directory,
// which is the env's config directory.
export function seedTargetAuth(envDir, scenario, context, discovered) {
  const storage = path.join(envDir, 'config', '_storage');
  const files = providerFiles(scenario, context, discovered);
  writeJson(path.join(storage, 'credential_providers'), files.provider.id, files.provider);
  for (const secret of files.secrets) writeJson(path.join(storage, 'secrets'), secret.id, secret, { secret: true });
  const surfaceFile = path.join(storage, 'agent_surfaces', `${SURFACE_ID}.json`);
  const surface = JSON.parse(fs.readFileSync(surfaceFile, 'utf8'));
  surface.target.auth = files.targetAuth;
  fs.writeFileSync(surfaceFile, `${JSON.stringify(surface, null, 2)}\n`);
}

// One modern request through the Access Point, with no credential of its own.
export async function callThroughGateway(url, version) {
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': version,
      'mcp-method': 'tools/list',
    },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'tools/list',
      params: {
        _meta: {
          'io.modelcontextprotocol/protocolVersion': version,
          'io.modelcontextprotocol/clientInfo': { name: 'conformance-client-driver', version: '1.0.0' },
          'io.modelcontextprotocol/clientCapabilities': {},
        },
      },
    }),
  });
  return { status: response.status, body: (await response.text()).slice(0, 400) };
}
