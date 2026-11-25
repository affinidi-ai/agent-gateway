import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import test from 'node:test';
import { hasExited, settings } from './client-driver.mjs';

const GATEWAY_ENV = {
  MCP_CONFORMANCE_DRIVER_MODE: 'gateway',
  MCP_CONFORMANCE_DRIVER_REFERENCE: '/ref',
  MCP_CONFORMANCE_DRIVER_BINARY: '/bin/gateway',
  MCP_CONFORMANCE_DRIVER_WORK: '/work',
  MCP_CONFORMANCE_DRIVER_LOGS: '/logs',
  MCP_CONFORMANCE_DRIVER_INBOUND_PORT: '1',
  MCP_CONFORMANCE_DRIVER_OUTBOUND_PORT: '2',
  MCP_CONFORMANCE_DRIVER_FIXTURE_URL: 'http://127.0.0.1:3',
};
const ARGV = ['node', 'client-driver.mjs', 'http://127.0.0.1:9/mcp'];

test('gateway mode reads its work and log directories from the environment', () => {
  const config = settings(GATEWAY_ENV, ARGV);
  assert.equal(config.workDir, '/work');
  assert.equal(config.logDir, '/logs');
  assert.equal(config.inboundPort, 1);
});

test('gateway mode refuses an environment without the log directory', () => {
  const env = { ...GATEWAY_ENV };
  delete env.MCP_CONFORMANCE_DRIVER_LOGS;
  assert.throws(() => settings(env, ARGV), /MCP_CONFORMANCE_DRIVER_LOGS is required/);
});

test('direct mode needs no gateway settings', () => {
  const config = settings({ MCP_CONFORMANCE_DRIVER_MODE: 'direct', MCP_CONFORMANCE_DRIVER_REFERENCE: '/ref' }, ARGV);
  assert.deepEqual(config, { mode: 'direct', suiteUrl: 'http://127.0.0.1:9/mcp', referenceDir: '/ref' });
});

test('a child ended by a signal has exited', async () => {
  const child = spawn(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { stdio: 'ignore' });
  assert.equal(hasExited(child), false);
  const ended = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGKILL');
  await ended;
  assert.equal(child.exitCode, null);
  assert.equal(hasExited(child), true);
});

test('a child that exited with a code has exited', async () => {
  const child = spawn(process.execPath, ['-e', 'process.exit(3)'], { stdio: 'ignore' });
  await new Promise((resolve) => child.once('exit', resolve));
  assert.equal(hasExited(child), true);
});
