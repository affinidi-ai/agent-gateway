import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import { countsLine, gapRows, listSection, loadResults, only, redact, renderGaps, tally, targetSource } from './suite-report.mjs';

const roots = [];
after(() => roots.forEach((root) => fs.rmSync(root, { recursive: true, force: true })));

function resultsDir(entries) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'suite-report-'));
  roots.push(root);
  for (const [name, checks] of Object.entries(entries)) {
    const dir = path.join(root, name);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'checks.json'), JSON.stringify(checks));
  }
  return root;
}
const check = (id, status, errorMessage) => ({ id, status, description: `${id} description`, ...(errorMessage ? { errorMessage } : {}) });
const results = (entries) => new Map(Object.entries(entries));

const REQUIREMENTS = `# frozen
server:
  - tools-list
  - caching

client:
  - tools_call
  - auth/metadata-default

not_scored:
  - scenario: tasks-lifecycle
    leg: server
    reason: extension
`;

test('a section lists its own entries only', () => {
  assert.deepEqual(listSection(REQUIREMENTS, 'server'), ['tools-list', 'caching']);
  assert.deepEqual(listSection(REQUIREMENTS, 'client'), ['tools_call', 'auth/metadata-default']);
  assert.deepEqual(listSection(REQUIREMENTS, 'authorization'), []);
});

test('a baseline section keeps the check id and skips reason comments', () => {
  const baseline = 'server:\n  # why\n  - caching:sep-2549-prompts-list-caching-hints\n  - tools-list\n';
  assert.deepEqual(listSection(baseline, 'server'), ['caching:sep-2549-prompts-list-caching-hints', 'tools-list']);
  assert.deepEqual(listSection(baseline, 'client'), []);
});

test('server results drop the leg prefix and the newest run of a scenario wins', () => {
  const dir = resultsDir({
    'server-tools-list-2026-01-01T00-00-00-000Z': [check('a', 'FAILURE')],
    'server-tools-list-2026-01-02T00-00-00-000Z': [check('a', 'SUCCESS')],
    'server-server-stateless-2026-01-01T00-00-00-000Z': [check('b', 'SUCCESS')],
  });
  const loaded = loadResults(dir, 'server');
  assert.deepEqual([...loaded.keys()].sort(), ['server-stateless', 'tools-list']);
  assert.equal(loaded.get('tools-list')[0].status, 'SUCCESS');
});

test('client results keep their group folder and a missing directory is empty', () => {
  const dir = resultsDir({
    'tools_call-2026-01-01T00-00-00-000Z': [check('a', 'SUCCESS')],
    'auth/client-credentials-basic-2026-01-01T00-00-00-000Z': [check('b', 'FAILURE')],
  });
  assert.deepEqual([...loadResults(dir, 'client').keys()].sort(), ['auth/client-credentials-basic', 'tools_call']);
  assert.equal(loadResults(path.join(dir, 'absent'), 'client').size, 0);
});

test('authorization results drop the authorization-server prefix', () => {
  const dir = resultsDir({
    'authorization-server-authorization-code-grant-2026-01-01T00-00-00-000Z': [check('a', 'SKIPPED')],
    'authorization-server-authorization-server-metadata-endpoint-2026-01-01T00-00-00-000Z': [check('b', 'FAILURE')],
  });
  assert.deepEqual([...loadResults(dir, 'authorization').keys()].sort(), ['authorization-code-grant', 'authorization-server-metadata-endpoint']);
});

test('only the named scenarios are kept', () => {
  const kept = only(results({ a: [check('x', 'SUCCESS')], b: [check('y', 'FAILURE')], 'auth/c': [] }), ['b', 'auth/c', 'absent']);
  assert.deepEqual([...kept.keys()], ['b', 'auth/c']);
  assert.equal(only(results({ a: [] }), []).size, 0);
});

test('failures are split into expected, unscored and unexpected', () => {
  const counts = tally({
    results: results({
      'tools-list': [check('ok', 'SUCCESS'), check('listed', 'WARNING'), check('new', 'FAILURE'), check('note', 'INFO')],
      caching: [check('x', 'FAILURE'), check('y', 'WARNING')],
      'tasks-lifecycle': [check('t1', 'FAILURE'), check('t2', 'WARNING'), check('t3', 'SUCCESS'), check('t4', 'SKIPPED')],
    }),
    scored: ['tools-list', 'caching'],
    baseline: ['tools-list:listed', 'caching'],
  });
  assert.deepEqual(counts, { passed: 2, expected: 3, unscored: 2, unexpected: 1 });
});

test('a baseline entry does not cover an unscored scenario or another check', () => {
  const counts = tally({
    results: results({ 'tasks-lifecycle': [check('t1', 'FAILURE')], 'tools-list': [check('other', 'FAILURE')] }),
    scored: ['tools-list'],
    baseline: ['tasks-lifecycle:t1', 'tools-list:listed'],
  });
  assert.deepEqual(counts, { passed: 0, expected: 0, unscored: 1, unexpected: 1 });
});

test('the counts line names unexpected failures only when there are some', () => {
  assert.equal(
    countsLine({ passed: 147, expected: 1, unscored: 36, unexpected: 0 }),
    '147 passed; 1 expected failure(s); 36 unscored failure(s)',
  );
  assert.equal(
    countsLine({ passed: 1, expected: 0, unscored: 0, unexpected: 2 }),
    '1 passed; 0 expected failure(s); 0 unscored failure(s); 2 unexpected failure(s)',
  );
});

test('credentials are removed from a message', () => {
  const part = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const jwt = [part({ alg: 'ES256' }), part({ sub: 'client' }), part('signature')].join('.');
  const cases = [
    `sent Authorization: Bearer ${jwt} to the server`,
    'header was Basic Y2xpZW50OnMzY3IzdC12YWx1ZQ==',
    'body client_secret=s3cr3t-value&grant_type=client_credentials',
    `body client_assertion=${jwt}&x=1`,
    '{"access_token":"tok-12345","refresh_token": "ref-67890"}',
    'client_secret: "s3cr3t-value"',
    `assertion ${jwt} was rejected`,
  ];
  for (const text of cases) {
    const cleaned = redact(text);
    for (const secret of [jwt, 'Y2xpZW50OnMzY3IzdC12YWx1ZQ==', 's3cr3t-value', 'tok-12345', 'ref-67890']) {
      assert.ok(!cleaned.includes(secret), `${secret} left in: ${cleaned}`);
    }
    assert.match(cleaned, /\[redacted\]/);
  }
  assert.equal(redact('body grant_type=client_credentials&x=1 kept'), 'body grant_type=client_credentials&x=1 kept');
});

test('a short Bearer or DPoP value is removed whatever its length or characters', () => {
  const cases = [
    ['Authorization: Bearer abc', 'Authorization: [redacted]'],
    ['got Bearer secret and DPoP proof here', 'got Bearer [redacted] and DPoP [redacted] here'],
    ['bearer tok', 'bearer [redacted]'],
    ['DPoP x', 'DPoP [redacted]'],
  ];
  for (const [input, expected] of cases) assert.equal(redact(input), expected);
});

test('a Basic value is removed when it looks generated and the word is kept otherwise', () => {
  assert.equal(redact('sent Basic dXNlcjpwdw=='), 'sent Basic [redacted]');
  assert.equal(redact('sent Basic abcdefghijklmnopqrstuvwxyz'), 'sent Basic [redacted]');
  assert.equal(redact('Basic authentication is required'), 'Basic authentication is required');
});

test('any field that names a credential has its value removed', () => {
  const cases = [
    ['api_key=abc123', 'api_key=[redacted]'],
    ['{"clientSecret":"plain"}', '{"clientSecret":"[redacted]"}'],
    ['x-api-key: plain', 'x-api-key: [redacted]'],
    ['password: hunter2 and more', 'password: [redacted] and more'],
    ['Cookie: session=plain', 'Cookie: [redacted]'],
    ['Authorization: Basic plain extra', 'Authorization: [redacted] extra'],
    ['signing_key_pem: plain', 'signing_key_pem: [redacted]'],
    ['id_token=plain&state=1', 'id_token=[redacted]&state=1'],
  ];
  for (const [input, expected] of cases) assert.equal(redact(input), expected);
});

test('a field about a credential rather than holding one is kept', () => {
  for (const text of [
    'token_endpoint: http://localhost:1/token',
    'token_type=Bearer',
    'token_endpoint_auth_method: client_secret_basic',
    'public_key_url=http://localhost/jwks',
  ]) {
    assert.equal(redact(text), text);
  }
});

test('a message without credentials is unchanged', () => {
  const text = 'CreateTaskResult MUST carry ttlMs (renamed from v1 `ttl`)';
  assert.equal(redact(text), text);
  assert.equal(redact('Client used client_secret_post, expected client_secret_basic'), 'Client used client_secret_post, expected client_secret_basic');
});

test('gap rows carry the failed and warned checks, never their details', () => {
  const rows = gapRows(
    results({
      'b-scenario': [check('ok', 'SUCCESS'), { ...check('warned', 'WARNING'), details: { token: 'tok-12345' } }],
      'a-scenario': [check('failed', 'FAILURE', 'sent Bearer tok-12345')],
    }),
    [],
  );
  assert.deepEqual(rows, [
    { scenario: 'a-scenario', check: 'failed', status: 'FAILURE', message: 'sent Bearer [redacted]' },
    { scenario: 'b-scenario', check: 'warned', status: 'WARNING', message: 'warned description' },
  ]);
});

test('a scenario the suite failed without a failed check is still a gap', () => {
  const rows = gapRows(results({ quiet: [check('skipped', 'SKIPPED')], loud: [check('failed', 'FAILURE', 'boom')] }), ['quiet', 'loud', 'absent']);
  assert.deepEqual(
    rows.map((row) => `${row.scenario}|${row.check}|${row.status}`),
    ['absent|-|FAILURE', 'loud|failed|FAILURE', 'quiet|-|FAILURE'],
  );
  assert.match(rows[0].message, /without a failed check/);
});

test('passing results leave no gap rows', () => {
  assert.deepEqual(gapRows(results({ fine: [check('ok', 'SUCCESS'), check('note', 'INFO')] }), []), []);
});

test('the gaps file has one section per target and keeps a table row on one line', () => {
  const text = renderGaps([
    { name: 'direct', passed: 3, rows: [{ scenario: 's', check: 'c', status: 'FAILURE', message: 'first | second\nthird' }] },
    { name: 'client', passed: 5, rows: [] },
  ]);
  assert.match(text, /^# MCP conformance: open gaps\n/);
  assert.match(text, /## direct\n\n3 passed; 1 open gap\(s\)\n/);
  assert.ok(text.includes('| s | c | FAILURE | first \\| second third |'));
  assert.match(text, /## client\n\n5 passed; 0 open gap\(s\)\n/);
  assert.equal(text.split('\n').filter((line) => line.startsWith('| Scenario |')).length, 1);
});

test('a long message is cut', () => {
  const text = renderGaps([{ name: 't', passed: 0, rows: [{ scenario: 's', check: 'c', status: 'FAILURE', message: 'x'.repeat(900) }] }]);
  const row = text.split('\n').find((line) => line.startsWith('| s |'));
  assert.ok(row.length < 560, `row is ${row.length} long`);
  assert.ok(row.includes('…'));
});

test('the client target reads the run through the gateway', () => {
  assert.deepEqual(targetSource('client'), { dir: 'client-gateway', leg: 'client' });
  assert.deepEqual(targetSource('transit'), { dir: 'transit', leg: 'server' });
  assert.deepEqual(targetSource('authorization'), { dir: 'authorization', leg: 'authorization' });
});
