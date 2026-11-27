import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const HERE = import.meta.dirname;

// A suite CLI whose `list` prints one scenario and then fails when LIST_FAILS is
// set, and whose `server` records each scenario it is asked to run.
function stubCli(dir) {
  const cli = path.join(dir, 'conformance');
  fs.writeFileSync(
    cli,
    `#!/usr/bin/env bash
if [ "$1" = list ]; then
  echo "  - first-scenario [2026-07-28]"
  if [ -n "\${LIST_FAILS:-}" ]; then echo "list failed" >&2; exit 1; fi
  echo "  - second-scenario [2026-07-28]"
  exit 0
fi
echo "$@" >> "${dir}/ran"
`,
    { mode: 0o755 },
  );
  return cli;
}

function withDir(body) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'report-scripts-'));
  try {
    return body(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const bash = (script, args, env) => spawnSync('bash', [path.join(HERE, script), ...args], { encoding: 'utf8', env: { PATH: process.env.PATH, ...env } });

test('the scenario list carries the flags that run each scenario on the requirement-set wire', () => {
  withDir((dir) => {
    const run = bash('report-scenarios.sh', [stubCli(dir), 'server', '2026-07-28'], {});
    assert.equal(run.status, 0);
    assert.equal(run.stdout, 'first-scenario --spec-version 2026-07-28 --force\nsecond-scenario --spec-version 2026-07-28 --force\n');
  });
});

test('a list that fails after printing a scenario fails the listing', () => {
  withDir((dir) => {
    const run = bash('report-scenarios.sh', [stubCli(dir), 'server', '2026-07-28'], { LIST_FAILS: '1' });
    assert.notEqual(run.status, 0);
  });
});

function reportCli(dir, env) {
  return bash('report-cli.sh', ['server', '--url', 'http://127.0.0.1:1/mcp', '-o', path.join(dir, 'out')], {
    MCP_CONFORMANCE_REAL_CLI: stubCli(dir),
    MCP_CONFORMANCE_REPORT_SPEC: '2026-07-28',
    MCP_CONFORMANCE_REPORT_FAILED: path.join(dir, 'failed'),
    ...env,
  });
}

test('the Fabric report runs every listed scenario', () => {
  withDir((dir) => {
    const run = reportCli(dir, {});
    assert.equal(run.status, 0);
    assert.match(run.stdout, /^=== first-scenario ===\n=== second-scenario ===\n$/);
    assert.equal(fs.readFileSync(path.join(dir, 'ran'), 'utf8').split('\n').filter(Boolean).length, 2);
  });
});

test('the Fabric report runs nothing and fails when the scenario list fails partway', () => {
  withDir((dir) => {
    const run = reportCli(dir, { LIST_FAILS: '1' });
    assert.equal(run.status, 1);
    assert.match(run.stderr, /could not list its server scenarios/);
    assert.equal(fs.existsSync(path.join(dir, 'ran')), false);
    assert.doesNotMatch(run.stdout, /===/);
  });
});
