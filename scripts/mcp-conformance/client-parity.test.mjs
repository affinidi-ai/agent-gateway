import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { compare, difference, resultDir } from './client-parity.mjs';

function results(checksByScenario) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'client-parity-'));
  for (const [scenario, runs] of Object.entries(checksByScenario)) {
    runs.forEach((checks, index) => {
      const dir = path.join(root, `${scenario}-2026-01-0${index + 1}T00-00-00-000Z`);
      fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, 'checks.json'), JSON.stringify(checks));
    });
  }
  return root;
}
const check = (id, status) => ({ id, status });

test('the newest result of a scenario is used, including one in a group folder', () => {
  const root = results({ tools_call: [[check('a', 'FAILURE')], [check('a', 'SUCCESS')]], 'auth/basic': [[check('b', 'SUCCESS')]] });
  assert.match(resultDir(root, 'tools_call'), /tools_call-2026-01-02T/);
  assert.match(resultDir(root, 'auth/basic'), /auth[\\/]basic-2026-01-01T/);
  assert.equal(resultDir(root, 'tools'), undefined);
});

test('equal results are in parity and a must-pass scenario passes', () => {
  const checks = { tools_call: [[check('a', 'SUCCESS'), check('b', 'SUCCESS')]] };
  const outcome = compare({ direct: results(checks), gateway: results(checks), scenarios: ['tools_call'], mustPass: ['tools_call'] });
  assert.equal(outcome.failures, 0);
  assert.deepEqual(outcome.lines, ['PASS  parity tools_call: 2 check(s) match', 'PASS  passes tools_call: 2 check(s)']);
});

test('a check that differs through the gateway breaks parity and names both sides', () => {
  assert.deepEqual(difference(['a:SUCCESS', 'b:SUCCESS'], ['a:FAILURE', 'b:SUCCESS']), ['direct a:SUCCESS', 'gateway a:FAILURE']);
  const outcome = compare({
    direct: results({ s: [[check('a', 'SUCCESS')]] }),
    gateway: results({ s: [[check('a', 'FAILURE')]] }),
    scenarios: ['s'],
    mustPass: ['s'],
  });
  assert.equal(outcome.failures, 2);
  assert.equal(outcome.lines[0], 'FAIL  parity s: direct a:SUCCESS; gateway a:FAILURE');
  assert.equal(outcome.lines[1], 'FAIL  passes s: a:FAILURE');
});

test('the same failure on both sides is parity but not a pass', () => {
  const checks = { s: [[check('a', 'FAILURE')]] };
  const lenient = compare({ direct: results(checks), gateway: results(checks), scenarios: ['s'], mustPass: ['t'] });
  assert.deepEqual(lenient.lines, ['PASS  parity s: 1 check(s) match', 'FAIL  passes t: not among the scenarios run']);
  const strict = compare({ direct: results(checks), gateway: results(checks), scenarios: ['s'], mustPass: ['s'] });
  assert.equal(strict.failures, 1);
});

test('a missing or empty result fails', () => {
  const missing = compare({ direct: results({ s: [[check('a', 'SUCCESS')]] }), gateway: results({}), scenarios: ['s'], mustPass: [] });
  assert.deepEqual(missing.lines, ['FAIL  parity s: no result for gateway']);
  const empty = compare({ direct: results({ s: [[]] }), gateway: results({ s: [[]] }), scenarios: ['s'], mustPass: ['s'] });
  assert.equal(empty.lines[1], 'FAIL  passes s: no checks ran');
});
