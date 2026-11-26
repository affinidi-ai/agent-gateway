import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { HARNESS_EXIT_CODE, HARNESS_FAILURE_FILE, hasExited, recordHarnessFailure, settings } from './client-driver.mjs';

const DRIVER = path.join(import.meta.dirname, 'client-driver.mjs');

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
  const env = { MCP_CONFORMANCE_DRIVER_MODE: 'direct', MCP_CONFORMANCE_DRIVER_REFERENCE: '/ref', MCP_CONFORMANCE_DRIVER_LOGS: '/logs' };
  assert.deepEqual(settings(env, ARGV), { mode: 'direct', suiteUrl: 'http://127.0.0.1:9/mcp', referenceDir: '/ref', logDir: '/logs' });
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

test('a failure to run a scenario is recorded for the harness on one line', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'client-driver-'));
  try {
    const logDir = path.join(dir, 'nested', 'logs');
    recordHarnessFailure(logDir, 'gateway', 'tools_call', new Error('gateway exited with 1\nbefore   listening'));
    assert.equal(fs.readFileSync(path.join(logDir, HARNESS_FAILURE_FILE), 'utf8'), 'gateway tools_call: gateway exited with 1 before listening\n');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a gateway that cannot be started ends the driver with its own exit code and a marker', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'client-driver-'));
  try {
    const logDir = path.join(dir, 'logs');
    const run = spawnSync(process.execPath, [DRIVER, 'http://127.0.0.1:9/mcp'], {
      encoding: 'utf8',
      env: {
        ...process.env,
        ...GATEWAY_ENV,
        MCP_CONFORMANCE_DRIVER_BINARY: path.join(dir, 'absent-gateway'),
        MCP_CONFORMANCE_DRIVER_REFERENCE: dir,
        MCP_CONFORMANCE_DRIVER_WORK: path.join(dir, 'work'),
        MCP_CONFORMANCE_DRIVER_LOGS: logDir,
        MCP_CONFORMANCE_SCENARIO: 'tools_call',
      },
    });
    assert.equal(run.status, HARNESS_EXIT_CODE);
    assert.match(fs.readFileSync(path.join(logDir, HARNESS_FAILURE_FILE), 'utf8'), /^gateway tools_call: .+\n$/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a driver that cannot read its settings still exits with the harness code', () => {
  const run = spawnSync(process.execPath, [DRIVER, 'http://127.0.0.1:9/mcp'], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  assert.equal(run.status, HARNESS_EXIT_CODE);
  assert.match(run.stderr, /MCP_CONFORMANCE_DRIVER_MODE is required/);
});
