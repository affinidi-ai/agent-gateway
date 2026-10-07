// Writes a fresh, disposable gateway environment for one harness phase and a
// targets.json naming every URL the suite and compat.mjs exercise. Nothing is
// copied from a developer env: the bootstrap config comes from the binary's
// own --generate-bootstrap, the certificate is generated, and the backup key
// is supplied by run.sh at start-up through the environment only.
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { OPENAPI_SPEC } from './fixture.mjs';

const REPO = path.resolve(import.meta.dirname, '..', '..');

const { values: args } = parseArgs({
  options: {
    dir: { type: 'string' },
    binary: { type: 'string' },
    'inbound-port': { type: 'string' },
    'outbound-port': { type: 'string' },
    'reference-url': { type: 'string' },
    'upstream-url': { type: 'string' },
    'fixture-url': { type: 'string' },
  },
});
for (const name of ['dir', 'binary', 'inbound-port', 'outbound-port', 'reference-url', 'fixture-url']) {
  if (!args[name]) {
    console.error(`env.mjs: --${name} is required`);
    process.exit(2);
  }
}

const envDir = path.resolve(args.dir);
const configDir = path.join(envDir, 'config');
const storageDir = path.join(configDir, '_storage');
const inbound = `http://127.0.0.1:${Number(args['inbound-port'])}`;
const outbound = `http://127.0.0.1:${Number(args['outbound-port'])}`;
const reference = args['reference-url'];
// What the gateway forwards to; the suite's `direct` target stays on the
// reference server itself.
const upstream = args['upstream-url'] ?? reference;

fs.rmSync(envDir, { recursive: true, force: true });
fs.mkdirSync(configDir, { recursive: true });

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
// The variable is named by the binary and differs between lineages, so hand the
// name to the caller rather than assuming it.
fs.writeFileSync(path.join(envDir, 'backup-key-var'), backupKeyVar[1]);
fs.writeFileSync(path.join(configDir, 'config.toml'), bootstrap);

execFileSync(path.join(REPO, 'scripts', 'certs', 'generate-cert.sh'), [], { cwd: envDir, stdio: 'ignore' });

const gateway = JSON.parse(fs.readFileSync(path.join(REPO, 'config', 'examples', 'gateway.example.json'), 'utf8'));
gateway.did = { domain: 'localhost' };
gateway.webauthn = { rp_id: 'localhost', external_origin: `http://localhost:${Number(args['inbound-port'])}` };
gateway.cors = [inbound];
gateway.listeners = [
  {
    id: 'conformance-inbound',
    name: 'Conformance inbound',
    bind_address: '127.0.0.1',
    port: Number(args['inbound-port']),
    protocol: 'http',
    external_urls: [inbound],
    listener_type: 'inbound',
  },
  {
    id: 'conformance-outbound',
    name: 'Conformance outbound',
    bind_address: '127.0.0.1',
    port: Number(args['outbound-port']),
    protocol: 'http',
    external_urls: [outbound],
    listener_type: 'outbound',
  },
];
gateway.channels = [{ id: 'conformance', name: 'conformance', prefix: '/conformance' }];
gateway.mcp_proxies = [{ id: 'owned', name: 'owned', prefix: '/owned' }];
gateway.routes = {
  connection_points_did: gateway.routes.connection_points_did,
  api: gateway.routes.api,
};
fs.writeFileSync(path.join(configDir, 'gateway.json'), `${JSON.stringify(gateway, null, 2)}\n`);

const accessPoint = (route) => ({
  listen_address: inbound,
  route,
  protocol: 'mcp',
  publish_to_did_document: false,
  terminate_trace_id: false,
});
const target = (endpoint) => ({ endpoint, mcp_tool_policies_enabled: false, identity_injection: { inject_vp: false } });
const mcpHttp = (origin) => ({ mcp_http: { allowed_origins: [origin] } });

const surfaces = [
  {
    surface_id: 'conformance-forwarding',
    name: 'Conformance forwarding',
    description: 'MCP Access Point and Transit Point fronting the reference server',
    status: 'active',
    access_point: accessPoint('/conformance/mcp'),
    target: target(upstream),
    ...mcpHttp(inbound),
    transit: {
      points: [
        {
          id: 'conformance-transit',
          name: 'Conformance Transit',
          alias: 'conformance-mcp',
          target_endpoint: upstream,
          protocol: 'mcp',
          identity_injection: { inject_vp: false },
          listen_path: '/transit/conformance-mcp',
          require_transit_token: false,
          ...mcpHttp(outbound),
        },
      ],
      outbound_listen_address: outbound,
      transit_token_mode: 'embedded',
      sign_requests: false,
    },
  },
  {
    surface_id: 'conformance-proxy-surface',
    name: 'Conformance proxy surface',
    description: 'MCP Access Point dispatching to the gateway-owned Proxy',
    status: 'active',
    access_point: accessPoint('/conformance/owned-mcp'),
    target: target('proxy://conformance-owned'),
    ...mcpHttp(inbound),
  },
  {
    surface_id: 'conformance-legacy',
    name: 'Conformance legacy',
    description: 'MCP Access Point whose record still carries the retired protocol mode, fronting the reference server',
    status: 'active',
    access_point: accessPoint('/conformance/legacy-mcp'),
    target: target(upstream),
    mcp_protocol_mode: 'legacy',
  },
];
fs.mkdirSync(path.join(storageDir, 'agent_surfaces'), { recursive: true });
for (const surface of surfaces) {
  fs.writeFileSync(
    path.join(storageDir, 'agent_surfaces', `${surface.surface_id}.json`),
    `${JSON.stringify(surface, null, 2)}\n`,
  );
}

const now = new Date().toISOString();
const ownedProxy = {
  id: 'conformance-owned',
  name: 'Conformance owned proxy',
  description: 'Gateway-owned MCP Proxy over the REST fixture',
  base_url: args['fixture-url'],
  openapi_spec: OPENAPI_SPEC,
  status: 'active',
  channel_prefix: '/owned',
  endpoint_path: '/api',
  flatten_post_params: false,
  ...mcpHttp(inbound),
  created_at: now,
  updated_at: now,
};
fs.mkdirSync(path.join(storageDir, 'mcp_proxies'), { recursive: true });
fs.writeFileSync(path.join(storageDir, 'mcp_proxies', `${ownedProxy.id}.json`), `${JSON.stringify(ownedProxy, null, 2)}\n`);

const targets = {
  direct: reference,
  'access-point': `${inbound}/conformance/mcp`,
  transit: `${outbound}/transit/conformance-mcp`,
  'owned-proxy': `${inbound}/owned/api`,
  'proxy-surface': `${inbound}/conformance/owned-mcp`,
  'legacy-surface': `${inbound}/conformance/legacy-mcp`,
};
fs.writeFileSync(path.join(envDir, 'targets.json'), `${JSON.stringify(targets, null, 2)}\n`);
console.log(`env written to ${envDir}`);
