// Writes a disposable gateway environment for the discovery demo: one HTTPS
// inbound listener, a JWT verification strategy that trusts the demo Hydra, a
// request policy that admits only `demo-user`, and an MCP surface that
// publishes protected resource metadata naming Hydra. Nothing is copied from a
// developer env; the bootstrap comes from the binary's own --generate-bootstrap.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';

const REPO = path.resolve(import.meta.dirname, '..', '..');

const { values: args } = parseArgs({
  options: {
    dir: { type: 'string' },
    binary: { type: 'string' },
    'gateway-port': { type: 'string' },
    'mcp-url': { type: 'string' },
    issuer: { type: 'string' },
    'jwks-uri': { type: 'string' },
    cert: { type: 'string' },
    key: { type: 'string' },
    'inspector-origin': { type: 'string' },
  },
});
for (const name of ['dir', 'binary', 'gateway-port', 'mcp-url', 'issuer', 'jwks-uri', 'cert', 'key', 'inspector-origin']) {
  if (!args[name]) {
    console.error(`env.mjs: --${name} is required`);
    process.exit(2);
  }
}

const envDir = path.resolve(args.dir);
const configDir = path.join(envDir, 'config');
const storageDir = path.join(configDir, '_storage');
const port = Number(args['gateway-port']);
const origin = `https://localhost:${port}`;
const route = '/demo/mcp';
const now = new Date().toISOString();

fs.rmSync(envDir, { recursive: true, force: true });
fs.mkdirSync(path.join(configDir, 'certs'), { recursive: true });

const bootstrap = execFileSync(path.resolve(args.binary), ['--generate-bootstrap'], {
  cwd: envDir,
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'inherit'],
});
const backupKeyVar = /^backup_encryption_key = "env:\/\/([A-Za-z_][A-Za-z0-9_]*)"$/m.exec(bootstrap);
if (!backupKeyVar) {
  console.error('env.mjs: generated bootstrap does not read the backup key from the environment');
  process.exit(1);
}
fs.writeFileSync(path.join(envDir, 'backup-key-var'), backupKeyVar[1]);
fs.writeFileSync(path.join(configDir, 'config.toml'), bootstrap);
fs.copyFileSync(args.cert, path.join(configDir, 'certs', 'cert.pem'));
fs.copyFileSync(args.key, path.join(configDir, 'certs', 'key.pem'));

const gateway = JSON.parse(fs.readFileSync(path.join(REPO, 'config', 'examples', 'gateway.example.json'), 'utf8'));
gateway.did = { domain: 'localhost' };
gateway.webauthn = { rp_id: 'localhost', external_origin: origin };
gateway.cors = [origin, args['inspector-origin']];
gateway.listeners = [
  {
    id: 'mcp-discovery-inbound',
    name: 'MCP discovery demo',
    bind_address: '127.0.0.1',
    port,
    protocol: 'https',
    external_urls: [origin],
    listener_type: 'inbound',
  },
];
gateway.channels = [{ id: 'mcp-discovery', name: 'mcp-discovery', prefix: '/demo' }];
// The example's MCP Proxy prefixes would claim the demo route.
gateway.mcp_proxies = [];
gateway.routes = {
  connection_points_did: gateway.routes.connection_points_did,
  api: gateway.routes.api,
};
fs.writeFileSync(path.join(configDir, 'gateway.json'), `${JSON.stringify(gateway, null, 2)}\n`);

const write = (dir, id, record) => {
  fs.mkdirSync(path.join(storageDir, dir), { recursive: true });
  fs.writeFileSync(path.join(storageDir, dir, `${id}.json`), `${JSON.stringify(record, null, 2)}\n`);
};

write('jwt_verification_strategies', 'demo-hydra', {
  id: 'demo-hydra',
  name: 'Demo Ory Hydra',
  expected_issuer: args.issuer,
  jwks_source: { type: 'remote', jwks_uri: args['jwks-uri'] },
  created_at: now,
  updated_at: now,
});

// The caller's identity reaches surface policy: only `demo-user` is admitted.
write('policy_definitions', 'mcp-discovery-demo', {
  id: 'mcp-discovery-demo',
  name: 'mcp-discovery-demo',
  description: 'Admits only the demo user',
  policy_type: 'agent_surface',
  policy: `package surface.policy

default allow = false

allow if {
    input.source_auth.method == "jwt_bearer"
    input.source_auth.claims.sub == "demo-user"
}
`,
  enabled: true,
  created_at: now,
  updated_at: now,
});

const resource = `${origin}${route}`;
write('agent_surfaces', 'mcp-discovery-demo', {
  surface_id: 'mcp-discovery-demo',
  name: 'MCP discovery demo',
  description: 'MCP Access Point whose callers sign in at the demo Ory Hydra',
  status: 'active',
  access_point: {
    listen_address: origin,
    route,
    protocol: 'mcp',
    publish_to_did_document: false,
    terminate_trace_id: false,
    caller_authentication: {
      methods: [{ type: 'jwt_bearer', jwt_verification_strategy_id: 'demo-hydra', audiences: [] }],
      protected_resource: { resource, authorization_servers: [args.issuer], scopes: ['tools'] },
    },
  },
  target: {
    endpoint: args['mcp-url'],
    mcp_tool_policies_enabled: false,
    identity_injection: { inject_vp: false },
    policy: { policy_definition_id: 'mcp-discovery-demo' },
  },
  mcp_http: { allowed_origins: [origin, args['inspector-origin']] },
});

fs.writeFileSync(path.join(envDir, 'resource'), resource);
console.log(`env written to ${envDir}`);
