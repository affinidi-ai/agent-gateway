// The command `conformance client` spawns for each scenario. The suite starts its
// own server and appends that server's URL as the last argument. This driver
// runs the suite's reference client either straight at that URL (`direct`) or at
// an Access Point of a gateway whose Target is that URL (`gateway`), so a
// difference between the two results is the gateway's.
import { spawn, execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { callThroughGateway, discoverTokenEndpoint, isAuthScenario, seedTargetAuth } from './client-auth.mjs';
import { startClientShim } from './client-shim.mjs';

const HERE = import.meta.dirname;
const START_TIMEOUT_MS = 30_000;

export function settings(env, argv) {
  const suiteUrl = argv.at(-1);
  if (!suiteUrl || !/^https?:\/\//.test(suiteUrl)) {
    throw new Error('the suite did not pass its server URL as the last argument');
  }
  const required = (name) => {
    if (!env[name]) throw new Error(`${name} is required`);
    return env[name];
  };
  const mode = required('MCP_CONFORMANCE_DRIVER_MODE');
  if (mode !== 'direct' && mode !== 'gateway') {
    throw new Error(`MCP_CONFORMANCE_DRIVER_MODE must be direct or gateway, not ${mode}`);
  }
  const base = { mode, suiteUrl, referenceDir: required('MCP_CONFORMANCE_DRIVER_REFERENCE') };
  if (mode === 'direct') return base;
  return {
    ...base,
    binary: required('MCP_CONFORMANCE_DRIVER_BINARY'),
    workDir: required('MCP_CONFORMANCE_DRIVER_WORK'),
    inboundPort: Number(required('MCP_CONFORMANCE_DRIVER_INBOUND_PORT')),
    outboundPort: Number(required('MCP_CONFORMANCE_DRIVER_OUTBOUND_PORT')),
    fixtureUrl: required('MCP_CONFORMANCE_DRIVER_FIXTURE_URL'),
  };
}

export function accessPointUrl(inboundPort) {
  return `http://127.0.0.1:${inboundPort}/conformance/mcp`;
}

// The suite ends a client that outlives its timeout with a signal. Without
// this the gateway would outlive the driver and answer the next scenario.
const children = new Set();
function track(child) {
  children.add(child);
  child.once('exit', () => children.delete(child));
  return child;
}

export function killChildrenOnSignal(running, target = process) {
  for (const signal of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
    target.once(signal, () => {
      for (const child of running) child.kill('SIGKILL');
      target.exit(1);
    });
  }
}

function portOpen(port) {
  return new Promise((resolve) => {
    const socket = net.connect({ host: '127.0.0.1', port });
    socket.once('connect', () => {
      socket.destroy();
      resolve(true);
    });
    socket.once('error', () => resolve(false));
  });
}

async function waitForPort(port, child) {
  const deadline = Date.now() + START_TIMEOUT_MS;
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`gateway exited with ${child.exitCode} before listening`);
    if (await portOpen(port)) return;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error(`gateway did not listen on ${port} within ${START_TIMEOUT_MS} ms`);
}

async function startGateway(config, { seed, tokenEndpoint } = {}) {
  const scenario = (process.env.MCP_CONFORMANCE_SCENARIO ?? 'scenario').replace(/[^A-Za-z0-9_-]/g, '_');
  const envDir = path.join(config.workDir, scenario);
  execFileSync(
    process.execPath,
    [
      path.join(HERE, 'env.mjs'),
      '--dir', envDir,
      '--binary', config.binary,
      '--inbound-port', String(config.inboundPort),
      '--outbound-port', String(config.outboundPort),
      '--reference-url', config.suiteUrl,
      '--fixture-url', config.fixtureUrl,
    ],
    { stdio: ['ignore', 'ignore', 'inherit'] },
  );
  seed?.(envDir);
  const backupKeyVar = fs.readFileSync(path.join(envDir, 'backup-key-var'), 'utf8').trim();
  const log = fs.openSync(path.join(envDir, 'gateway.log'), 'w');
  const child = track(spawn(config.binary, ['--config', 'config.toml'], {
    cwd: path.join(envDir, 'config'),
    env: {
      ...process.env,
      [backupKeyVar]: crypto.randomBytes(32).toString('hex'),
      RUST_LOG: process.env.RUST_LOG ?? 'info',
      AG_TEST_MODE: 'true',
      AG_BDD_EGRESS_ALLOWLIST: config.fixtureUrl,
      // The suite's token endpoint is plain http on loopback, which the gateway
      // reaches only when test mode lists that exact URL.
      ...(tokenEndpoint ? { AG_BDD_OAUTH_ENDPOINT_ALLOWLIST: tokenEndpoint } : {}),
    },
    stdio: ['ignore', log, log],
  }));
  try {
    await waitForPort(config.inboundPort, child);
  } catch (error) {
    child.kill('SIGKILL');
    throw error;
  }
  return child;
}

function stop(child) {
  return new Promise((resolve) => {
    if (child.exitCode !== null) return resolve();
    child.once('exit', resolve);
    child.kill('SIGTERM');
    setTimeout(() => child.kill('SIGKILL'), 5_000).unref();
  });
}

function runReferenceClient(referenceDir, url) {
  return new Promise((resolve, reject) => {
    const client = track(
      spawn(process.execPath, ['--import', 'tsx', path.join('examples', 'clients', 'typescript', 'everything-client.ts'), url], {
        cwd: referenceDir,
        env: process.env,
        stdio: 'inherit',
      }),
    );
    client.once('error', reject);
    client.once('exit', (code, signal) => resolve(code ?? (signal ? 1 : 0)));
  });
}

// The gateway, not this driver, asks for the token: the driver only finds the
// token endpoint, stores the scenario's client as a credential provider and
// sends one request that carries no credential.
async function runAuthScenario(config, scenario) {
  const context = JSON.parse(process.env.MCP_CONFORMANCE_CONTEXT ?? '{}');
  const discovered = await discoverTokenEndpoint(config.suiteUrl);
  const gateway = await startGateway(config, {
    tokenEndpoint: discovered.tokenEndpoint,
    seed: (envDir) => seedTargetAuth(envDir, scenario, context, discovered),
  });
  try {
    const version = process.env.MCP_CONFORMANCE_PROTOCOL_VERSION ?? '2026-07-28';
    const reply = await callThroughGateway(accessPointUrl(config.inboundPort), version);
    console.log(`tools/list through the gateway: HTTP ${reply.status} ${reply.body}`);
    return reply.status === 200 ? 0 : 1;
  } finally {
    await stop(gateway);
  }
}

async function main() {
  const config = settings(process.env, process.argv);
  if (config.mode === 'direct') {
    return runReferenceClient(config.referenceDir, config.suiteUrl);
  }
  const scenario = process.env.MCP_CONFORMANCE_SCENARIO ?? '';
  if (isAuthScenario(scenario)) return runAuthScenario(config, scenario);
  const gateway = await startGateway(config);
  let shim;
  try {
    shim = await startClientShim(accessPointUrl(config.inboundPort));
    return await runReferenceClient(config.referenceDir, shim.url);
  } finally {
    await shim?.close();
    await stop(gateway);
  }
}

if (import.meta.filename === process.argv[1]) {
  killChildrenOnSignal(children);
  main().then(
    (code) => process.exit(code),
    (error) => {
      console.error(`client-driver: ${error.message}`);
      process.exit(1);
    },
  );
}
