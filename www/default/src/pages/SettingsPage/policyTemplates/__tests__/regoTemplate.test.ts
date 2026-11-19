import {
  defaultDecision,
  defaultParameterValues,
  insertTemplateRules,
  parseListInput,
  renderTemplate as fillTemplate,
} from '../regoTemplate';
import type { PolicyTemplate } from '../types';

const threshold: PolicyTemplate = {
  id: 'threshold',
  name: 'At least N trust checks pass',
  summary: '',
  description: '',
  category: 'trust_checks',
  policy_type: 'agent_surface',
  rego: `package surface.policy

default allow := false

allow if {
  passing := [r | some r in input.trust_check_results.target; r.ok]
  count(passing) >= {{min_passing}}
}`,
  parameters: [
    {
      key: 'min_passing',
      label: 'Minimum passing checks',
      kind: 'integer',
      default: 2,
      min: 1,
      max: 50,
    },
  ],
  reads: [],
  examples: [],
};

const roles: PolicyTemplate = {
  ...threshold,
  id: 'roles',
  name: 'Allow listed roles',
  rego: `package surface.policy

default allow := false

allow if input.jwt.role in {{roles}}`,
  parameters: [{ key: 'roles', label: 'Roles', kind: 'string_list', default: ['admin'] }],
};

const businessHours: PolicyTemplate = {
  ...threshold,
  id: 'hours',
  name: 'Business-hours access window',
  rego: `package surface.policy

allow if {{mode}}in_window

in_window if {
  time.weekday([time.now_ns(), {{time_zone}}]) in {{days}}
  minute >= {{start_time}}
  minute < {{end_time}}
}`,
  parameters: [
    {
      key: 'mode',
      label: 'Inside the window',
      kind: 'choice',
      default: 'allow',
      options: [
        { value: 'allow', label: 'Allow requests', rego: '' },
        { value: 'deny', label: 'Deny requests', rego: 'not ' },
      ],
    },
    {
      key: 'days',
      label: 'Days',
      kind: 'string_list',
      default: ['Monday'],
      allowed: ['Monday', 'Tuesday'],
      optional: true,
    },
    { key: 'start_time', label: 'From', kind: 'time_of_day', default: '09:00' },
    {
      key: 'end_time',
      label: 'Until',
      kind: 'time_of_day',
      default: '17:00',
      differs_from: 'start_time',
    },
    { key: 'time_zone', label: 'Time zone', kind: 'string', default: 'UTC', format: 'time_zone' },
  ],
};

describe('renderTemplate setting checks', () => {
  const fill = (values: Record<string, unknown>) =>
    fillTemplate(businessHours, { ...defaultParameterValues(businessHours), ...values } as never);

  it('writes allowed values in their own spelling, whatever case was typed', () => {
    expect(fill({ days: ['monday', 'TUESDAY'] }).rego).toContain('in {"Monday", "Tuesday"}');
  });

  it('refuses a value that is not allowed', () => {
    const result = fill({ days: ['Mon'] });
    expect(result.rego).toBeNull();
    expect(result.errors.days).toBe('"Mon" isn\'t accepted. Use Monday, Tuesday.');
  });

  it('writes the picked option of a choice, and refuses one that is not offered', () => {
    expect(fill({}).rego).toContain('allow if in_window');
    expect(fill({ mode: 'deny' }).rego).toContain('allow if not in_window');
    const result = fill({ mode: 'sometimes' });
    expect(result.rego).toBeNull();
    expect(result.errors.mode).toBe('Pick one of Allow requests, Deny requests.');
  });

  it('writes a time of day as minutes since midnight', () => {
    const rego = fill({ start_time: '08:30', end_time: '23:59' }).rego;
    expect(rego).toContain('minute >= 510');
    expect(rego).toContain('minute < 1439');
    expect(fill({ start_time: '0:00' }).rego).toContain('minute >= 0');
  });

  it('refuses a time of day that is not HH:MM within the day', () => {
    for (const value of ['24:00', '9', '09:60', 'noon', '']) {
      expect(fill({ start_time: value }).errors.start_time).toBe(
        'Enter a time from 00:00 to 23:59.'
      );
    }
  });

  it('accepts an end before the start, for a window that crosses midnight, but not the same time', () => {
    expect(fill({ start_time: '22:00', end_time: '06:00' }).errors).toEqual({});
    expect(fill({ start_time: '09:00', end_time: '9:00' }).errors.end_time).toBe(
      'Must differ from From.'
    );
  });

  it('writes an empty optional list as the empty set, and refuses an empty required one', () => {
    expect(fill({ days: [] }).rego).toContain('in set()');
    const required = {
      ...businessHours,
      parameters: businessHours.parameters.map(p =>
        p.key === 'days' ? { ...p, optional: false } : p
      ),
    } as PolicyTemplate;
    expect(
      fillTemplate(required, { ...defaultParameterValues(required), days: [] }).errors.days
    ).toBe('Enter at least one value.');
  });

  it('writes a time zone in its canonical spelling and refuses an unknown one', () => {
    expect(fill({ time_zone: 'asia/singapore' }).rego).toContain('"Asia/Singapore"');
    expect(fill({ time_zone: '+01:00' }).errors.time_zone).toBeDefined();
    expect(fill({ time_zone: '-08:00' }).errors.time_zone).toBeDefined();
    expect(fill({ time_zone: 'Mars/Olympus' }).errors.time_zone).toBe(
      'Enter an IANA time zone, for example Europe/Berlin.'
    );
  });
});

describe('renderTemplate (fillTemplate)', () => {
  it('fills an integer setting with its default', () => {
    const result = fillTemplate(threshold, defaultParameterValues(threshold));
    expect(result.errors).toEqual({});
    expect(result.rego).toContain('count(passing) >= 2');
    expect(result.rego).not.toContain('{{');
  });

  it('fills an integer setting with a value inside its range', () => {
    const result = fillTemplate(threshold, { min_passing: 5 });
    expect(result.rego).toContain('count(passing) >= 5');
  });

  it('refuses an integer below its minimum and returns no Rego', () => {
    const result = fillTemplate(threshold, { min_passing: 0 });
    expect(result.rego).toBeNull();
    expect(result.errors.min_passing).toBe('Enter a whole number from 1 to 50.');
  });

  it('refuses a fractional integer setting', () => {
    expect(fillTemplate(threshold, { min_passing: 2.5 }).rego).toBeNull();
  });

  it('renders a list setting as a Rego set of string literals', () => {
    const result = fillTemplate(roles, { roles: ['admin', 'operator'] });
    expect(result.rego).toContain('allow if input.jwt.role in {"admin", "operator"}');
  });

  it('escapes quotes and backslashes so a value cannot end the string literal', () => {
    const result = fillTemplate(roles, { roles: ['a" } allow := true #'] });
    expect(result.rego).toContain('{"a\\" } allow := true #"}');
    expect(result.rego).not.toMatch(/^allow := true/m);
  });

  it('refuses an empty list setting', () => {
    const result = fillTemplate(roles, { roles: [] });
    expect(result.rego).toBeNull();
    expect(result.errors.roles).toBe('Enter at least one value.');
  });

  it('drops blank and duplicate list entries', () => {
    const result = fillTemplate(roles, { roles: [' admin ', '', 'admin', 'ops'] });
    expect(result.rego).toContain('in {"admin", "ops"}');
  });

  it('falls back to the default for a setting that has no value', () => {
    const result = fillTemplate(roles, {});
    expect(result.rego).toContain('in {"admin"}');
  });
});

describe('renderTemplate with a single-value setting', () => {
  const zone: PolicyTemplate = {
    ...threshold,
    id: 'zone',
    rego: 'package surface.policy\n\nzone := {{time_zone}}',
    parameters: [{ key: 'time_zone', label: 'Time zone', kind: 'string', default: 'UTC' }],
  };

  it('renders the trimmed value as one string literal', () => {
    expect(fillTemplate(zone, { time_zone: ' Europe/Berlin ' }).rego).toContain(
      'zone := "Europe/Berlin"'
    );
  });

  it('escapes a quote so the value stays one string', () => {
    expect(fillTemplate(zone, { time_zone: 'a" || true' }).rego).toContain(
      'zone := "a\\" || true"'
    );
  });

  it('refuses a blank value', () => {
    const out = fillTemplate(zone, { time_zone: '  ' });
    expect(out.rego).toBeNull();
    expect(out.errors.time_zone).toBe('Enter a value.');
  });
});

describe('renderTemplate with several settings', () => {
  const claimValues: PolicyTemplate = {
    ...threshold,
    id: 'claim_values',
    rego: 'package surface.policy\n\nallow if input.jwt[{{claim}}] in {{values}}',
    parameters: [
      { key: 'claim', label: 'Claim', kind: 'string', default: 'role' },
      { key: 'values', label: 'Values', kind: 'string_list', default: ['admin'] },
    ],
  };

  it('keeps a placeholder typed inside a value as text', () => {
    const result = fillTemplate(claimValues, { claim: 'x{{values}}', values: ['admin'] });
    expect(result.rego).toBe(
      'package surface.policy\n\nallow if input.jwt["x{{values}}"] in {"admin"}'
    );
    expect(result.rego?.match(/\{"admin"\}/g)).toHaveLength(1);
  });
});

describe('parseListInput', () => {
  it('splits on commas and new lines and trims each value', () => {
    expect(parseListInput('admin, operator\n auditor ')).toEqual(['admin', 'operator', 'auditor']);
  });

  it('returns an empty list for blank input', () => {
    expect(parseListInput('  ,\n ')).toEqual([]);
  });
});

describe('defaultDecision', () => {
  it('reads deny from default allow := false', () => {
    expect(defaultDecision('package p\n\ndefault allow := false')).toBe('deny');
  });

  it('reads allow from the legacy default allow = true form', () => {
    expect(defaultDecision('package p\n# comment\ndefault allow = true')).toBe('allow');
  });

  it('treats a module without a default as deny', () => {
    expect(defaultDecision('package p\nallow if input.jwt.sub')).toBe('deny');
  });
});

describe('insertTemplateRules', () => {
  const existing = `package surface.policy

default allow := false

allow if input.jwt.iss == "https://login.example"`;

  it('appends the rules without the package line or the default', () => {
    const result = insertTemplateRules(
      existing,
      'Allow listed roles',
      `package surface.policy

default allow := false

allow if input.jwt.role in {"admin"}`
    );
    expect(result.policy).toBe(`package surface.policy

default allow := false

allow if input.jwt.iss == "https://login.example"

# Inserted from template: Allow listed roles
allow if input.jwt.role in {"admin"}
# End of template: Allow listed roles
`);
    expect(result.added).toBe('allow if input.jwt.role in {"admin"}');
  });

  it('places a new import after the package line and skips one already present', () => {
    const result = insertTemplateRules(
      'package surface.policy\nimport rego.v1\n\ndefault allow := false',
      'T',
      'package surface.policy\nimport rego.v1\nimport future.keywords.every\n\nallow if input.jwt.sub'
    );
    const lines = result.policy.split('\n');
    expect(lines[0]).toBe('package surface.policy');
    expect(lines[1]).toBe('import future.keywords.every');
    expect(lines[2]).toBe('import rego.v1');
    expect(result.policy.match(/import rego\.v1/g)).toHaveLength(1);
  });

  it('keeps a template name with a line break inside the comment', () => {
    const result = insertTemplateRules(existing, 'Evil\nallow := true', 'allow if input.jwt.sub');
    expect(result.policy).toContain('# Inserted from template: Evil allow := true\n');
    expect(result.policy).not.toMatch(/^allow := true/m);
  });

  it('keeps the template package line when the policy has none', () => {
    const result = insertTemplateRules(
      '',
      'Methods',
      'package gateway.policy\n\nallow if input.http.method == "GET"'
    );
    expect(result.policy).toBe(
      'package gateway.policy\n\n# Inserted from template: Methods\nallow if input.http.method == "GET"\n# End of template: Methods\n'
    );
  });
});
