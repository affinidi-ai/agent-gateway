import fs from 'fs';
import path from 'path';
import { BUILTIN_POLICY_TEMPLATES } from '../builtinPolicyTemplates';
import { defaultParameterValues, renderTemplate } from '../regoTemplate';
import type { ParameterValues, PolicyTemplate } from '../types';

const FIXTURE = path.join(__dirname, '..', '__fixtures__', 'renderedTemplates.json');
const REGENERATE =
  'UPDATE_RENDERED_TEMPLATES=1 CI=true npm test --prefix www/default -- --watchAll=false renderedTemplates';

const BUSINESS_HOURS = 'business-hours-access-window';
const BERLIN_FIRST_HOUR = { start_time: '00:00', end_time: '01:00', time_zone: 'Europe/Berlin' };

/** Business-hours settings the gateway's template tests evaluate at fixed instants. */
const BUSINESS_HOURS_VARIANTS: Record<string, ParameterValues> = {
  deny: { mode: 'deny' },
  overnight: { start_time: '22:00', end_time: '06:00' },
  'overnight-deny': { mode: 'deny', start_time: '22:00', end_time: '06:00' },
  'every-day': { days: [] },
  'every-day-overnight': { days: [], start_time: '22:00', end_time: '06:00' },
  'weekend-berlin': { days: ['Saturday', 'Sunday'], time_zone: 'Europe/Berlin' },
  'friday-first-hour-berlin': { days: ['Friday'], ...BERLIN_FIRST_HOUR },
  'saturday-first-hour-berlin': { days: ['Saturday'], ...BERLIN_FIRST_HOUR },
  'typed-settings': {
    mode: 'deny',
    days: [' saturday', 'Sunday', 'SUNDAY'],
    start_time: '22:00',
    end_time: '6:30',
    time_zone: ' Europe/Berlin ',
  },
};

function renderModule(template: PolicyTemplate, values: ParameterValues): string {
  const { rego, errors } = renderTemplate(template, {
    ...defaultParameterValues(template),
    ...values,
  });
  if (rego === null) throw new Error(`${template.id} does not render: ${JSON.stringify(errors)}`);
  return rego;
}

/** Every built-in template with its defaults, keyed `<id>:<type>`, and the business-hours
 * variants, keyed `<id>:<variant>:<type>`, in key order. */
function templateModules(): Record<string, string> {
  const rendered: Record<string, string> = {};
  for (const template of BUILTIN_POLICY_TEMPLATES) {
    rendered[template.id] = renderModule(template, {});
    const [id, policyType] = template.id.split(':');
    if (id !== BUSINESS_HOURS) continue;
    for (const [variant, values] of Object.entries(BUSINESS_HOURS_VARIANTS)) {
      rendered[`${id}:${variant}:${policyType}`] = renderModule(template, values);
    }
  }
  return Object.fromEntries(
    Object.entries(rendered).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  );
}

describe('rendered built-in templates', () => {
  const rendered = templateModules();
  const text = `${JSON.stringify(rendered, null, 2)}\n`;

  it('match the fixture the gateway compiles and evaluates', () => {
    if (process.env.UPDATE_RENDERED_TEMPLATES) {
      fs.mkdirSync(path.dirname(FIXTURE), { recursive: true });
      fs.writeFileSync(FIXTURE, text);
      return;
    }
    const stored = fs.readFileSync(FIXTURE, 'utf8');
    const fixture = JSON.parse(stored) as Record<string, string>;
    const missing = Object.keys(rendered).filter(k => !(k in fixture));
    const extra = Object.keys(fixture).filter(k => !(k in rendered));
    const changed = Object.keys(rendered).filter(k => k in fixture && fixture[k] !== rendered[k]);
    const problems = [
      missing.length ? `missing ${missing.join(', ')}` : '',
      extra.length ? `extra ${extra.join(', ')}` : '',
      changed.length ? `changed ${changed.join(', ')}` : '',
    ].filter(Boolean);
    if (problems.length === 0 && stored !== text) problems.push('formatted differently');
    if (problems.length > 0) {
      throw new Error(
        `renderedTemplates.json is out of date (${problems.join('; ')}). Regenerate it with: ${REGENERATE}`
      );
    }
  });

  it('writes a typed day list in the listed spelling, once each', () => {
    expect(rendered[`${BUSINESS_HOURS}:typed-settings:gateway`]).toContain(
      'in {"Saturday", "Sunday"}'
    );
  });
});
