import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { compare, difference, parseVerdicts, resultDir } from './client-parity.mjs';

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
const verdicts = (text) => parseVerdicts(text);
const PASS = verdicts('tools_call pass\ns pass\n');
const outcomeOf = (direct, gateway, scenarios, mustPass, directVerdicts = PASS, gatewayVerdicts = PASS) =>
  compare({ direct: results(direct), gateway: results(gateway), scenarios, mustPass, directVerdicts, gatewayVerdicts });

test('the newest result of a scenario is used, including one in a group folder', () => {
  const root = results({ tools_call: [[check('a', 'FAILURE')], [check('a', 'SUCCESS')]], 'auth/basic': [[check('b', 'SUCCESS')]] });
  assert.match(resultDir(root, 'tools_call'), /tools_call-2026-01-02T/);
  assert.match(resultDir(root, 'auth/basic'), /auth[\\/]basic-2026-01-01T/);
  assert.equal(resultDir(root, 'tools'), undefined);
});

test('verdict lines are parsed and a malformed one is refused', () => {
  assert.deepEqual([...verdicts('a pass\nauth/b fail\n')], [['a', 'pass'], ['auth/b', 'fail']]);
  assert.deepEqual([...verdicts('')], []);
  assert.throws(() => verdicts('a maybe'), /not a verdict line/);
  assert.throws(() => verdicts('a pass extra'), /not a verdict line/);
});

test('equal results are in parity and a must-pass scenario passes', () => {
  const checks = { tools_call: [[check('a', 'SUCCESS'), check('b', 'SUCCESS')]] };
  const outcome = outcomeOf(checks, checks, ['tools_call'], ['tools_call']);
  assert.equal(outcome.failures, 0);
  assert.deepEqual(outcome.lines, ['PASS  parity tools_call: verdict pass, 2 check(s) match', 'PASS  passes tools_call: 2 check(s)']);
});

test('a check that differs through the gateway breaks parity and names both sides', () => {
  assert.deepEqual(difference(['a:SUCCESS', 'b:SUCCESS'], ['a:FAILURE', 'b:SUCCESS']), ['direct a:SUCCESS', 'gateway a:FAILURE']);
  const outcome = outcomeOf({ s: [[check('a', 'SUCCESS')]] }, { s: [[check('a', 'FAILURE')]] }, ['s'], ['s']);
  assert.equal(outcome.failures, 2);
  assert.equal(outcome.lines[0], 'FAIL  parity s: direct a:SUCCESS; gateway a:FAILURE');
  assert.equal(outcome.lines[1], 'FAIL  passes s: a:FAILURE');
});

test('the same failure on both sides is parity but not a pass', () => {
  const checks = { s: [[check('a', 'FAILURE')]] };
  const lenient = outcomeOf(checks, checks, ['s'], ['t']);
  assert.deepEqual(lenient.lines, ['PASS  parity s: verdict pass, 1 check(s) match', 'FAIL  passes t: not among the scenarios run']);
  const strict = outcomeOf(checks, checks, ['s'], ['s']);
  assert.equal(strict.failures, 1);
});

test('a warning is not a pass for a must-pass scenario', () => {
  const checks = { s: [[check('a', 'SUCCESS'), check('b', 'WARNING')]] };
  const outcome = outcomeOf(checks, checks, ['s'], ['s']);
  assert.deepEqual(outcome.lines, ['PASS  parity s: verdict pass, 2 check(s) match', 'FAIL  passes s: b:WARNING']);
});

test('a scenario the suite failed without a failed check is not a pass and may break parity', () => {
  const checks = { s: [[check('a', 'SUCCESS')]] };
  const failedThrough = outcomeOf(checks, checks, ['s'], ['s'], verdicts('s pass'), verdicts('s fail'));
  assert.deepEqual(failedThrough.lines, [
    'FAIL  parity s: verdict direct pass, gateway fail',
    'FAIL  passes s: suite verdict fail',
  ]);
  const failedBoth = outcomeOf(checks, checks, ['s'], [], verdicts('s fail'), verdicts('s fail'));
  assert.deepEqual(failedBoth.lines, ['PASS  parity s: verdict fail, 1 check(s) match']);
});

test('a scenario with no verdict fails parity', () => {
  const checks = { s: [[check('a', 'SUCCESS')]] };
  const outcome = outcomeOf(checks, checks, ['s'], [], verdicts('s pass'), verdicts(''));
  assert.equal(outcome.lines[0], 'FAIL  parity s: verdict direct pass, gateway missing');
});

test('a missing or empty result fails', () => {
  const missing = outcomeOf({ s: [[check('a', 'SUCCESS')]] }, {}, ['s'], []);
  assert.deepEqual(missing.lines, ['FAIL  parity s: no result for gateway']);
  const empty = outcomeOf({ s: [[]] }, { s: [[]] }, ['s'], ['s']);
  assert.equal(empty.lines[1], 'FAIL  passes s: no checks ran');
});
