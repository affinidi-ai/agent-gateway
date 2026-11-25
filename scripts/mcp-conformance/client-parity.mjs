// Compares the suite's client-scenario results for the reference client run
// straight at the suite's server (`direct`) and through the gateway (`gateway`).
//
//   parity     every scenario has the same suite verdict (the exit status of its
//              run) and the same check ids with the same statuses in both runs,
//              so a difference is the gateway's
//   must pass  each named scenario has the passing suite verdict through the
//              gateway and checks, none of them failed or warned, so parity is
//              not two empty or two failed runs
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';

const NOT_PASSING = new Set(['FAILURE', 'WARNING']);

// `<scenario> pass|fail` per line, the suite's exit status of one scenario run.
export function parseVerdicts(text) {
  const verdicts = new Map();
  for (const line of text.split('\n').filter(Boolean)) {
    const [scenario, verdict, ...rest] = line.trim().split(/\s+/);
    if (!scenario || !['pass', 'fail'].includes(verdict) || rest.length) throw new Error(`not a verdict line: ${line}`);
    verdicts.set(scenario, verdict);
  }
  return verdicts;
}

// The newest result directory of a scenario: `<scenario>-<timestamp>`.
export function resultDir(root, scenario) {
  const parent = path.join(root, path.dirname(scenario));
  const prefix = `${path.basename(scenario)}-`;
  if (!fs.existsSync(parent)) return undefined;
  const matches = fs
    .readdirSync(parent)
    .filter((name) => name.startsWith(prefix) && /^\d{4}-\d{2}-\d{2}T/.test(name.slice(prefix.length)))
    .sort();
  return matches.length ? path.join(parent, matches.at(-1)) : undefined;
}

export function checkStatuses(root, scenario) {
  const dir = resultDir(root, scenario);
  if (!dir) return undefined;
  const file = path.join(dir, 'checks.json');
  if (!fs.existsSync(file)) return undefined;
  return JSON.parse(fs.readFileSync(file, 'utf8'))
    .map((check) => `${check.id}:${check.status}`)
    .sort();
}

// The check lines present on one side only, prefixed with the side.
export function difference(direct, gateway) {
  const remaining = [...gateway];
  const only = [];
  for (const line of direct) {
    const at = remaining.indexOf(line);
    if (at === -1) only.push(`direct ${line}`);
    else remaining.splice(at, 1);
  }
  return [...only, ...remaining.map((line) => `gateway ${line}`)];
}

export function compare({ direct, gateway, scenarios, mustPass, directVerdicts, gatewayVerdicts }) {
  const lines = [];
  let failures = 0;
  const report = (ok, name, detail) => {
    lines.push(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail ? `: ${detail}` : ''}`);
    if (!ok) failures += 1;
  };
  for (const scenario of scenarios) {
    const [a, b] = [checkStatuses(direct, scenario), checkStatuses(gateway, scenario)];
    if (!a || !b) {
      report(false, `parity ${scenario}`, `no result for ${[!a && 'direct', !b && 'gateway'].filter(Boolean).join(' and ')}`);
      continue;
    }
    const [verdictA, verdictB] = [directVerdicts.get(scenario), gatewayVerdicts.get(scenario)];
    const diff = [
      ...(verdictA === verdictB ? [] : [`verdict direct ${verdictA ?? 'missing'}, gateway ${verdictB ?? 'missing'}`]),
      ...difference(a, b),
    ];
    report(diff.length === 0, `parity ${scenario}`, diff.length ? diff.join('; ') : `verdict ${verdictB}, ${b.length} check(s) match`);
    if (mustPass.includes(scenario)) {
      const notPassing = b.filter((line) => NOT_PASSING.has(line.slice(line.lastIndexOf(':') + 1)));
      const problems = [...(verdictB === 'pass' ? [] : [`suite verdict ${verdictB ?? 'missing'}`]), ...notPassing];
      const ok = b.length > 0 && problems.length === 0;
      report(ok, `passes ${scenario}`, ok ? `${b.length} check(s)` : problems.join('; ') || 'no checks ran');
    }
  }
  for (const scenario of mustPass) {
    if (!scenarios.includes(scenario)) report(false, `passes ${scenario}`, 'not among the scenarios run');
  }
  return { lines, failures };
}

if (import.meta.filename === process.argv[1]) {
  const { values } = parseArgs({
    options: {
      direct: { type: 'string' },
      gateway: { type: 'string' },
      scenarios: { type: 'string' },
      'must-pass': { type: 'string' },
      'direct-verdicts': { type: 'string' },
      'gateway-verdicts': { type: 'string' },
    },
  });
  for (const name of ['direct', 'gateway', 'scenarios', 'must-pass', 'direct-verdicts', 'gateway-verdicts']) {
    if (!values[name]) {
      console.error(`client-parity.mjs: --${name} is required`);
      process.exit(2);
    }
  }
  const { lines, failures } = compare({
    direct: values.direct,
    gateway: values.gateway,
    scenarios: values.scenarios.split(','),
    mustPass: values['must-pass'].split(','),
    directVerdicts: parseVerdicts(fs.readFileSync(values['direct-verdicts'], 'utf8')),
    gatewayVerdicts: parseVerdicts(fs.readFileSync(values['gateway-verdicts'], 'utf8')),
  });
  console.log(lines.join('\n'));
  process.exit(failures ? 1 : 0);
}
