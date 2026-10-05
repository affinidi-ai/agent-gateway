// Checks over the suite's own results that the suite does not make:
//
//   results present  every selected target has a result for each scenario it
//                    was run with (the scored requirement set, or the owned subset)
//   caching parity   the Access Point and Transit Point pass the reference
//                    server's ttlMs/cacheScope through unchanged; a SKIP line,
//                    which run.sh copies into the summary, says when there is
//                    nothing to compare
//   real owned calls owned tools/call results carry the REST fixture's text and
//                    are not tool errors, so a pass is not an empty success
//
// Frame counts are deliberately not compared: how the reference server frames
// and times streamed messages is fixture behaviour, not gateway behaviour.
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { SIMPLE_TEXT } from './fixture.mjs';

const { values } = parseArgs({
  options: {
    results: { type: 'string' },
    targets: { type: 'string' },
    'owned-scenarios': { type: 'string' },
    requirements: { type: 'string' },
  },
});
for (const name of ['results', 'targets', 'owned-scenarios', 'requirements']) {
  if (!values[name]) {
    console.error(`check-results.mjs: --${name} is required`);
    process.exit(2);
  }
}

const OWNED = new Set(['owned-proxy', 'proxy-surface']);
const FORWARDING = ['access-point', 'transit', 'fabric'];
const targets = values.targets.split(',');
const ownedScenarios = values['owned-scenarios'].split(',');

let failures = 0;
function report(ok, name, detail) {
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `: ${detail}` : ''}`);
  if (!ok) failures += 1;
}

// The frozen requirement file is a flat mapping of section name to a list of
// scenario names; only the `server` list is needed.
function scoredServerScenarios(file) {
  const scenarios = [];
  let inServer = false;
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    if (/^\S/.test(line) && !line.startsWith('#')) inServer = line.trim() === 'server:';
    const entry = inServer && line.match(/^\s+-\s+([\w/-]+)\s*$/);
    if (entry) scenarios.push(entry[1]);
  }
  if (scenarios.length === 0) throw new Error(`no server scenarios found in ${file}`);
  return scenarios;
}

function loadResults(target) {
  const dir = path.join(values.results, target);
  const byScenario = new Map();
  if (!fs.existsSync(dir)) return byScenario;
  for (const entry of fs.readdirSync(dir).sort()) {
    const match = entry.match(/^server-(.+)-\d{4}-\d{2}-\d{2}T[\d-]+Z$/);
    const file = path.join(dir, entry, 'checks.json');
    if (match && fs.existsSync(file)) byScenario.set(match[1], JSON.parse(fs.readFileSync(file, 'utf8')));
  }
  return byScenario;
}

const scored = scoredServerScenarios(values.requirements);
const results = new Map(targets.map((target) => [target, loadResults(target)]));

for (const target of targets) {
  const expected = OWNED.has(target) ? ownedScenarios : scored;
  const missing = expected.filter((scenario) => !results.get(target).has(scenario));
  report(missing.length === 0, `${target} has results for ${expected.length} scenarios`, missing.join(', '));
}

function cacheHints(checks) {
  const hints = new Map();
  for (const check of checks ?? []) {
    if (check.id.endsWith('-caching-hints') && check.status === 'SUCCESS') {
      hints.set(check.id, { ttlMs: check.details?.ttlMs, cacheScope: check.details?.cacheScope });
    }
  }
  return hints;
}

const forwarding = FORWARDING.filter((name) => results.has(name));
if (results.has('direct')) {
  const reference = cacheHints(results.get('direct').get('caching'));
  report(reference.size > 0, 'direct reports cache hints', reference.size ? '' : 'no caching-hints checks passed');
  if (forwarding.length === 0) console.log('SKIP  caching parity (no forwarding target was run)');
  for (const target of forwarding) {
    const observed = cacheHints(results.get(target).get('caching'));
    const mismatches = [...reference].filter(([id, hint]) => JSON.stringify(observed.get(id)) !== JSON.stringify(hint));
    report(
      mismatches.length === 0,
      `${target} caching parity with direct (${reference.size} hints)`,
      mismatches.map(([id, hint]) => `${id} expected ${JSON.stringify(hint)} got ${JSON.stringify(observed.get(id))}`).join('; '),
    );
  }
} else {
  console.log('SKIP  caching parity (direct was not run)');
}

function simpleTextResult(target) {
  const check = results
    .get(target)
    .get('tools-call-simple-text')
    ?.find((item) => item.id === 'tools-call-simple-text');
  return check?.details?.result;
}

for (const target of targets.filter((name) => OWNED.has(name))) {
  const result = simpleTextResult(target);
  const text = result?.content?.find((item) => item.type === 'text')?.text ?? '';
  report(
    result !== undefined && result.isError !== true && text.includes(SIMPLE_TEXT),
    `${target} tools-call-simple-text returns the REST fixture text`,
    JSON.stringify(result)?.slice(0, 300),
  );
}

process.exit(failures === 0 ? 0 : 1);
