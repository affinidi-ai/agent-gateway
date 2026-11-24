// Reads the suite's saved checks.json files for run.sh.
//
//   counts  one summary fragment for a target: checks passed, failures its
//           baseline expects, and failures in scenarios the requirement set
//           runs but does not score, which the suite never fails a run on
//   gaps    the report-only file: every failed or warned check per target,
//           with the suite's message and never the check's details
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';

const FAILING = new Set(['FAILURE', 'WARNING']);
const MESSAGE_LIMIT = 500;
const REDACTED = '[redacted]';
const NO_CHECK_MESSAGE = 'The suite failed this scenario without a failed check; see the suite log';

// The entries of one top-level list in the suite's flat YAML files: scenario
// names in a requirement set, `<scenario>` or `<scenario>:<check-id>` in a baseline.
export function listSection(text, section) {
  const entries = [];
  let inSection = false;
  for (const line of text.split('\n')) {
    if (/^\S/.test(line) && !line.startsWith('#')) inSection = line.trim() === `${section}:`;
    const entry = inSection && line.match(/^\s+-\s+([\w/:.-]+)\s*$/);
    if (entry) entries.push(entry[1]);
  }
  return entries;
}

function checkFiles(dir, prefix = '') {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir, { withFileTypes: true })
    .sort((a, b) => a.name.localeCompare(b.name))
    .flatMap((entry) => {
      const relative = path.posix.join(prefix, entry.name);
      if (entry.isDirectory()) return checkFiles(path.join(dir, entry.name), relative);
      return entry.name === 'checks.json' ? [prefix] : [];
    });
}

// Scenario name to its checks. A result directory is `<scenario>-<timestamp>`,
// with `server-` in front on the server leg; the newest run of a scenario wins.
export function loadResults(dir, leg) {
  const byScenario = new Map();
  for (const relative of checkFiles(dir)) {
    const match = relative.match(/^(.+)-\d{4}-\d{2}-\d{2}T[\d-]+Z$/);
    if (!match) continue;
    const scenario = leg === 'server' ? match[1].replace(/^server-/, '') : match[1];
    byScenario.set(scenario, JSON.parse(fs.readFileSync(path.join(dir, relative, 'checks.json'), 'utf8')));
  }
  return byScenario;
}

// The suite applies a baseline to scored scenarios only, so a baseline entry
// never turns an unscored failure into an expected one.
export function tally({ results, scored, baseline }) {
  const scoredSet = new Set(scored);
  const listed = new Set(baseline);
  const counts = { passed: 0, expected: 0, unscored: 0, unexpected: 0 };
  for (const [scenario, checks] of results) {
    for (const check of checks) {
      if (check.status === 'SUCCESS') counts.passed += 1;
      if (!FAILING.has(check.status)) continue;
      if (!scoredSet.has(scenario)) counts.unscored += 1;
      else if (listed.has(scenario) || listed.has(`${scenario}:${check.id}`)) counts.expected += 1;
      else counts.unexpected += 1;
    }
  }
  return counts;
}

export function countsLine({ passed, expected, unscored, unexpected }) {
  const line = `${passed} passed; ${expected} expected failure(s); ${unscored} unscored failure(s)`;
  return unexpected > 0 ? `${line}; ${unexpected} unexpected failure(s)` : line;
}

const SECRET_FIELDS =
  'client_secret|client_assertion|access_token|refresh_token|id_token|subject_token|actor_token|assertion|password|private_key';
const SCHEME_VALUE = /\b(Bearer|Basic|DPoP)\s+([A-Za-z0-9._~+/=-]{8,})/gi;

// A scheme name is also an ordinary word ("Basic authentication"), so only a
// value that looks generated is removed: it has a digit or is long.
export function redact(text) {
  return text
    .replace(/-----BEGIN [^-]+-----[\s\S]*?(?:-----END [^-]+-----|$)/g, REDACTED)
    .replace(/\beyJ[\w-]+\.[\w-]+\.[\w-]*/g, REDACTED)
    .replace(SCHEME_VALUE, (whole, scheme, value) => (/\d/.test(value) || value.length >= 20 ? `${scheme} ${REDACTED}` : whole))
    .replace(new RegExp(`\\b(${SECRET_FIELDS})("?\\s*[:=]\\s*"?)[^\\s"&,}]+`, 'gi'), `$1$2${REDACTED}`);
}

export function gapRows(results, failedScenarios) {
  const rows = [];
  for (const [scenario, checks] of results) {
    for (const check of checks.filter((item) => FAILING.has(item.status))) {
      rows.push({ scenario, check: check.id, status: check.status, message: redact(check.errorMessage ?? check.description ?? '') });
    }
  }
  const withRows = new Set(rows.map((row) => row.scenario));
  for (const scenario of failedScenarios.filter((name) => !withRows.has(name))) {
    rows.push({ scenario, check: '-', status: 'FAILURE', message: NO_CHECK_MESSAGE });
  }
  return rows.sort((a, b) => a.scenario.localeCompare(b.scenario));
}

function cell(text) {
  const line = String(text).replace(/\s+/g, ' ').trim();
  const cut = line.length > MESSAGE_LIMIT ? `${line.slice(0, MESSAGE_LIMIT)}…` : line;
  return cut.replaceAll('|', '\\|');
}

export function gapsLine({ passed, rows }) {
  return `${passed} passed; ${rows.length} open gap(s)`;
}

export function renderGaps(targets) {
  const lines = ['# MCP conformance: open gaps', '', 'Every failed or warned check of a report-only run, per target.'];
  for (const target of targets) {
    lines.push('', `## ${target.name}`, '', gapsLine(target));
    if (target.rows.length === 0) continue;
    lines.push('', '| Scenario | Check | Status | Message |', '| --- | --- | --- | --- |');
    for (const row of target.rows) {
      lines.push(`| ${cell(row.scenario)} | ${cell(row.check)} | ${row.status} | ${cell(row.message)} |`);
    }
  }
  return `${lines.join('\n')}\n`;
}

// The client target's results are the run through the gateway.
export function targetSource(name) {
  return name === 'client' ? { dir: 'client-gateway', leg: 'client' } : { dir: name, leg: 'server' };
}

function passedCount(results) {
  return tally({ results, scored: [], baseline: [] }).passed;
}

function failedScenarios(failedDir, name) {
  const file = failedDir && path.join(failedDir, `${name}.failed`);
  if (!file || !fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n').filter(Boolean);
}

function requireOptions(command, values, names) {
  for (const name of names) {
    if (!values[name]) {
      console.error(`suite-report.mjs ${command}: --${name} is required`);
      process.exit(2);
    }
  }
}

function counts(values) {
  requireOptions('counts', values, ['results', 'leg', 'requirements']);
  const results = loadResults(values.results, values.leg);
  if (results.size === 0) {
    console.error(`suite-report.mjs counts: no results in ${values.results}`);
    process.exit(1);
  }
  const baseline = values.baseline ? listSection(fs.readFileSync(values.baseline, 'utf8'), values.leg) : [];
  const expectedScenarios = values['expected-scenarios']?.split(',').filter(Boolean) ?? [];
  console.log(
    countsLine(
      tally({
        results,
        scored: listSection(fs.readFileSync(values.requirements, 'utf8'), values.leg),
        baseline: [...baseline, ...expectedScenarios],
      }),
    ),
  );
}

function gaps(values) {
  requireOptions('gaps', values, ['results', 'targets', 'out']);
  const empty = [];
  const targets = values.targets.split(',').map((name) => {
    const source = targetSource(name);
    const results = loadResults(path.join(values.results, source.dir), source.leg);
    if (results.size === 0) empty.push(name);
    return { name, passed: passedCount(results), rows: gapRows(results, failedScenarios(values['failed-dir'], name)) };
  });
  fs.writeFileSync(values.out, renderGaps(targets));
  for (const target of targets) console.log(`${target.name}: ${gapsLine(target)}`);
  if (empty.length > 0) {
    console.error(`suite-report.mjs gaps: no results for ${empty.join(', ')}`);
    process.exit(1);
  }
}

if (import.meta.filename === process.argv[1]) {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      results: { type: 'string' },
      leg: { type: 'string' },
      requirements: { type: 'string' },
      baseline: { type: 'string' },
      'expected-scenarios': { type: 'string' },
      targets: { type: 'string' },
      out: { type: 'string' },
      'failed-dir': { type: 'string' },
    },
  });
  if (positionals[0] === 'counts') counts(values);
  else if (positionals[0] === 'gaps') gaps(values);
  else {
    console.error('suite-report.mjs: the first argument is counts or gaps');
    process.exit(2);
  }
}
