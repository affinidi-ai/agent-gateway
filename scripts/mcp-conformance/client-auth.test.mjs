import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import {
  SURFACE_ID,
  authorizationServerMetadataUrl,
  discoverTokenEndpoint,
  isAuthScenario,
  providerFiles,
  resourceMetadataUrl,
  seedTargetAuth,
  trustedUrl,
} from './client-auth.mjs';

const DISCOVERED = { tokenEndpoint: 'http://localhost:9/token', issuer: 'http://localhost:9' };
const NOW = '2026-01-01T00:00:00.000Z';

test('only the client-credentials scenarios are authorization scenarios', () => {
  assert.equal(isAuthScenario('auth/client-credentials-jwt'), true);
  assert.equal(isAuthScenario('auth/client-credentials-basic'), true);
  assert.equal(isAuthScenario('auth/scope-step-up'), false);
  assert.equal(isAuthScenario('tools_call'), false);
});

test('the challenge yields the resource metadata URL', () => {
  const challenge = 'Bearer error="invalid_token", resource_metadata="http://localhost:1/.well-known/oauth-protected-resource/mcp"';
  assert.equal(resourceMetadataUrl(challenge), 'http://localhost:1/.well-known/oauth-protected-resource/mcp');
  assert.throws(() => resourceMetadataUrl('Bearer error="invalid_token"'), /resource_metadata/);
  assert.throws(() => resourceMetadataUrl(null), /resource_metadata/);
});

test('authorization server metadata sits before the issuer path', () => {
  assert.equal(authorizationServerMetadataUrl('http://localhost:1'), 'http://localhost:1/.well-known/oauth-authorization-server');
  assert.equal(authorizationServerMetadataUrl('http://localhost:1/'), 'http://localhost:1/.well-known/oauth-authorization-server');
  assert.equal(
    authorizationServerMetadataUrl('http://localhost:1/tenant/a'),
    'http://localhost:1/.well-known/oauth-authorization-server/tenant/a',
  );
});

test('the JWT scenario becomes a client-assertion provider whose audience is the issuer', () => {
  const context = { client_id: 'cid', private_key_pem: 'PEM', signing_algorithm: 'ES256' };
  const files = providerFiles('auth/client-credentials-jwt', context, DISCOVERED, NOW);
  assert.deepEqual(files.provider, {
    id: 'conformance-target-auth',
    name: 'conformance-target-auth',
    provider_id: 'conformance-target-auth',
    token_endpoint: 'http://localhost:9/token',
    provider_type: 'oauth2_client_credentials_jwt_auth',
    client_id_secret_ref: 'conformance-client-id',
    jwt_signing_key_secret_ref: 'conformance-signing-key',
    jwt_signing_algorithm: 'ES256',
    jwt_audience: 'http://localhost:9',
    created_at: NOW,
    updated_at: NOW,
  });
  assert.deepEqual(
    files.secrets.map((secret) => [secret.secret_id, secret.value]),
    [
      ['conformance-client-id', 'cid'],
      ['conformance-signing-key', 'PEM'],
    ],
  );
  assert.deepEqual(files.targetAuth, {
    method: { credential_provider: { provider_id: 'conformance-target-auth', scopes: [] } },
    fallback: 'reject',
  });
});

test('the secret scenario becomes a client-secret provider', () => {
  const files = providerFiles('auth/client-credentials-basic', { client_id: 'cid', client_secret: 's' }, DISCOVERED, NOW);
  assert.equal(files.provider.provider_type, 'oauth2_client_credentials');
  assert.equal(files.provider.client_secret_secret_ref, 'conformance-client-secret');
  assert.equal(files.provider.jwt_audience, undefined);
});

test('a context without the value a secret needs is refused', () => {
  assert.throws(() => providerFiles('auth/client-credentials-basic', { client_id: 'cid' }, DISCOVERED, NOW), /conformance-client-secret/);
});

test('seeding writes the provider and secrets and binds the Target', () => {
  const envDir = fs.mkdtempSync(path.join(os.tmpdir(), 'client-auth-'));
  const storage = path.join(envDir, 'config', '_storage');
  fs.mkdirSync(path.join(storage, 'agent_surfaces'), { recursive: true });
  const surfaceFile = path.join(storage, 'agent_surfaces', `${SURFACE_ID}.json`);
  fs.writeFileSync(surfaceFile, JSON.stringify({ surface_id: SURFACE_ID, target: { endpoint: 'http://localhost:9/mcp' } }));
  seedTargetAuth(envDir, 'auth/client-credentials-basic', { client_id: 'cid', client_secret: 's' }, DISCOVERED);
  if (process.platform !== 'win32') {
    const mode = (...parts) => fs.statSync(path.join(storage, ...parts)).mode & 0o777;
    assert.equal(mode('secrets'), 0o700);
    assert.equal(mode('secrets', 'conformance-client-secret.json'), 0o600);
    assert.equal(mode('secrets', 'conformance-client-id.json'), 0o600);
  }
  const read = (...parts) => JSON.parse(fs.readFileSync(path.join(storage, ...parts), 'utf8'));
  assert.equal(read('credential_providers', 'conformance-target-auth.json').token_endpoint, 'http://localhost:9/token');
  assert.equal(read('secrets', 'conformance-client-secret.json').value, 's');
  const surface = read('agent_surfaces', `${SURFACE_ID}.json`);
  assert.equal(surface.target.endpoint, 'http://localhost:9/mcp');
  assert.equal(surface.target.auth.method.credential_provider.provider_id, 'conformance-target-auth');
});

test('discovery follows the challenge to the token endpoint and fails without one', async () => {
  let challenge = true;
  const server = http.createServer((req, res) => {
    const origin = `http://localhost:${server.address().port}`;
    if (req.method === 'POST') {
      if (!challenge) return res.writeHead(200).end('{}');
      res.writeHead(401, { 'www-authenticate': `Bearer resource_metadata="${origin}/.well-known/oauth-protected-resource/mcp"` });
      return res.end();
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    if (req.url === '/.well-known/oauth-protected-resource/mcp') return res.end(JSON.stringify({ authorization_servers: [`${origin}/as`] }));
    if (req.url === '/.well-known/oauth-authorization-server/as') return res.end(JSON.stringify({ token_endpoint: `${origin}/as/token` }));
    res.end('{}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://localhost:${server.address().port}`;
  try {
    assert.deepEqual(await discoverTokenEndpoint(`${origin}/mcp`), { tokenEndpoint: `${origin}/as/token`, issuer: `${origin}/as` });
    challenge = false;
    await assert.rejects(discoverTokenEndpoint(`${origin}/mcp`), /expected a 401 challenge/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('a URL is trusted on the origin of the server under test or on loopback only', () => {
  const suite = 'https://suite.example:8443/mcp';
  assert.equal(trustedUrl('https://suite.example:8443/token', suite, 'x'), 'https://suite.example:8443/token');
  for (const url of ['http://localhost:1/t', 'http://127.0.0.1:2/t', 'http://[::1]:3/t']) {
    assert.equal(trustedUrl(url, suite, 'x'), url);
  }
  for (const url of [
    'https://other.example/token',
    'https://suite.example/token',
    'http://suite.example:8443/token',
    'https://suite.example.evil.example:8443/token',
    'https://suite.example@evil.example/token',
    'ftp://localhost/token',
    'file:///etc/passwd',
  ]) {
    assert.throws(() => trustedUrl(url, suite, 'the token endpoint'), /the token endpoint .* neither the origin/, url);
  }
  assert.throws(() => trustedUrl('not a url', suite, 'the token endpoint'), /the token endpoint is not a URL/);
});

async function discoveryServer(metadata) {
  const requests = [];
  const server = http.createServer((req, res) => {
    requests.push(`${req.method} ${req.url}`);
    const origin = `http://localhost:${server.address().port}`;
    const { challenge = `${origin}/.well-known/oauth-protected-resource/mcp`, resource, authorizationServer } = metadata(origin);
    if (req.method === 'POST') {
      res.writeHead(401, { 'www-authenticate': `Bearer resource_metadata="${challenge}"` });
      return res.end();
    }
    res.writeHead(200, { 'content-type': 'application/json' });
    if (req.url === '/.well-known/oauth-protected-resource/mcp') return res.end(JSON.stringify(resource));
    if (req.url.startsWith('/.well-known/oauth-authorization-server')) return res.end(JSON.stringify(authorizationServer));
    res.end('{}');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { server, requests, origin: `http://localhost:${server.address().port}` };
}

test('discovery refuses a challenge, issuer or token endpoint that points off the server under test', async () => {
  const cases = [
    ['resource_metadata', () => ({ challenge: 'https://attacker.example/metadata', resource: {}, authorizationServer: {} }), /resource_metadata URL/],
    [
      'issuer',
      () => ({ resource: { authorization_servers: ['https://attacker.example'] }, authorizationServer: { token_endpoint: 'https://attacker.example/token' } }),
      /the authorization server https:\/\/attacker\.example/,
    ],
    [
      'token endpoint',
      (origin) => ({ resource: { authorization_servers: [`${origin}/as`] }, authorizationServer: { token_endpoint: 'https://attacker.example/token' } }),
      /the token endpoint https:\/\/attacker\.example/,
    ],
  ];
  for (const [name, metadata, message] of cases) {
    const { server, requests, origin } = await discoveryServer(metadata);
    try {
      await assert.rejects(discoverTokenEndpoint(`${origin}/mcp`), message, name);
      assert.ok(requests.every((request) => !request.includes('attacker')), name);
    } finally {
      await new Promise((resolve) => server.close(resolve));
    }
  }
});

test('discovery does not follow a redirect', async () => {
  const target = http.createServer((req, res) => res.writeHead(200).end('{}'));
  await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') {
      res.writeHead(401, { 'www-authenticate': `Bearer resource_metadata="http://localhost:${server.address().port}/meta"` });
      return res.end();
    }
    res.writeHead(302, { location: `http://localhost:${target.address().port}/elsewhere` }).end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(discoverTokenEndpoint(`http://localhost:${server.address().port}/mcp`), /fetch failed/);
  } finally {
    await Promise.all([server, target].map((s) => new Promise((resolve) => s.close(resolve))));
  }
});
