import {
  parsePolicyRules,
  removeRule,
  removeRuleGroup,
  ruleInUse,
  setDefaultDeny,
} from '../regoRules';
import { insertTemplateRules } from '../regoTemplate';

const groupsOf = (rego: string) => {
  const parsed = parsePolicyRules(rego);
  if (!parsed.ok) throw new Error('expected the policy to parse');
  return parsed;
};

describe('parsePolicyRules', () => {
  it('lists written rules first, then one group per inserted template', () => {
    const rego = [
      'package surface.policy',
      '',
      'default allow := false',
      '',
      'allow if input.http.method == "GET"',
      '',
      '# Inserted from template: Allow by JWT claim or role',
      'jwt_claim_values(v) := [v] if is_string(v)',
      '',
      'allow if {',
      '  some v in jwt_claim_values(input.source_auth.claims["role"])',
      '  v in {"admin"}',
      '}',
      '# End of template: Allow by JWT claim or role',
      '',
      'deny_reason := "no match" if not allow',
    ].join('\n');

    const parsed = groupsOf(rego);

    expect(parsed.defaultDecision).toBe('deny');
    expect(parsed.groups.map(g => g.source)).toEqual([
      { kind: 'editor' },
      { kind: 'template', name: 'Allow by JWT claim or role' },
    ]);
    expect(parsed.groups[0].rules.map(r => [r.head, r.kind, r.startLine])).toEqual([
      ['allow', 'allow', 5],
      ['deny_reason', 'deny', 16],
    ]);
    expect(parsed.groups[1]).toMatchObject({ startLine: 7, endLine: 14 });
    expect(parsed.groups[1].rules.map(r => [r.head, r.kind, r.startLine, r.endLine])).toEqual([
      ['jwt_claim_values(v)', 'helper', 8, 8],
      ['allow', 'allow', 10, 13],
    ]);
  });

  it('ignores brackets inside strings, raw strings and comments', () => {
    const rego = [
      'package gateway.policy',
      'allow if {',
      '  input.http.path == "/a{"  # closes } later',
      '  x := `raw }`',
      '}',
      'helper := 1',
    ].join('\n');

    const rules = groupsOf(rego).groups[0].rules;

    expect(rules.map(r => [r.head, r.startLine, r.endLine])).toEqual([
      ['allow', 2, 5],
      ['helper', 6, 6],
    ]);
    expect(rules[0].summary).toBe('allow if { input.http.path == "/a{" x := `raw }` }');
  });

  it('reads old-style rules, a brace on the next line, and indented statements', () => {
    const rego = [
      'package gateway.policy',
      '  default allow = true',
      'allow {',
      '  input.x',
      '}',
      'allow if',
      '{',
      '  input.y',
      '}',
    ].join('\n');

    const parsed = groupsOf(rego);

    expect(parsed.defaultDecision).toBe('allow');
    expect(parsed.groups[0].rules.map(r => [r.startLine, r.endLine])).toEqual([
      [3, 5],
      [6, 9],
    ]);
  });

  it('has no groups for an empty policy or one with only a package and default', () => {
    expect(groupsOf('').groups).toEqual([]);
    expect(groupsOf('package surface.policy\n\ndefault allow = false\n')).toMatchObject({
      defaultDecision: 'deny',
      groups: [],
    });
    expect(groupsOf('package surface.policy\n').defaultDecision).toBeNull();
  });

  it('refuses a policy whose brackets do not balance', () => {
    expect(parsePolicyRules('package p\nallow if {\n  x').ok).toBe(false);
    expect(parsePolicyRules('package p\n}\n').ok).toBe(false);
  });

  it('runs a template block without an end line to the next block', () => {
    const rego = [
      'package p',
      '# Inserted from template: A',
      'allow if input.a',
      '# Inserted from template: B',
      'allow if input.b',
    ].join('\n');

    const parsed = groupsOf(rego);

    expect(parsed.groups.map(g => [g.startLine, g.endLine, g.rules.length])).toEqual([
      [2, 3, 1],
      [4, 5, 1],
    ]);
  });
});

describe('removeRuleGroup', () => {
  it('removes a template block and keeps a rule written after it', () => {
    const inserted = insertTemplateRules(
      'package p\n\ndefault allow := false\n',
      'Allow listed HTTP methods',
      'package p\n\nallow if input.http.method in {"GET"}\n'
    ).policy;
    const rego = `${inserted}\nallow if input.x\n`;
    const group = groupsOf(rego).groups.find(g => g.source.kind === 'template');

    const result = removeRuleGroup(rego, group!);

    expect(result).toBe('package p\n\ndefault allow := false\n\nallow if input.x\n');
  });
});

describe('setDefaultDeny', () => {
  it('turns default allow true into false with either operator', () => {
    expect(setDefaultDeny('package p\ndefault allow = true\n')).toBe(
      'package p\ndefault allow = false\n'
    );
    expect(setDefaultDeny('package p\ndefault allow := true\n')).toBe(
      'package p\ndefault allow := false\n'
    );
  });

  it('leaves a policy that already denies unchanged', () => {
    expect(setDefaultDeny('package p\ndefault allow := false\n')).toBe(
      'package p\ndefault allow := false\n'
    );
  });
});

describe('removeRule and ruleInUse', () => {
  const rego = [
    'package p',
    '',
    'default allow := false',
    '',
    '# Paths the Target must never see',
    'unsafe if contains(input.http.path, "..")',
    '',
    'allow if {',
    '  not unsafe',
    '  input.http.method == "GET"',
    '}',
    '',
    'allow if input.http.method == "HEAD"',
  ].join('\n');
  const rules = () => {
    const parsed = parsePolicyRules(rego);
    if (!parsed.ok) throw new Error('expected the policy to parse');
    return { parsed, all: parsed.groups.flatMap(g => g.rules) };
  };

  it('removes one rule with the comment above it and keeps the rest', () => {
    const { all } = rules();
    const head = all.find(r => r.summary.startsWith('allow if input.http.method == "HEAD"'))!;
    expect(removeRule(rego, head)).toBe(
      'package p\n\ndefault allow := false\n\n# Paths the Target must never see\nunsafe if contains(input.http.path, "..")\n\nallow if {\n  not unsafe\n  input.http.method == "GET"\n}\n'
    );
    const helper = all.find(r => r.head === 'unsafe')!;
    expect(removeRule(rego, helper)).not.toContain('Paths the Target must never see');
  });

  it('refuses a helper another rule refers to, but never an allow rule', () => {
    const { parsed, all } = rules();
    expect(ruleInUse(rego, parsed, all.find(r => r.head === 'unsafe')!)).toBe(true);
    expect(all.filter(r => r.kind === 'allow').some(r => ruleInUse(rego, parsed, r))).toBe(false);
  });

  it('keeps refusing one of several different definitions of a used helper', () => {
    const more = `${rego}\n\nunsafe if contains(input.http.path, "%2e")\n`;
    const parsed = parsePolicyRules(more);
    if (!parsed.ok) throw new Error('expected the policy to parse');
    const helpers = parsed.groups.flatMap(g => g.rules).filter(r => r.head === 'unsafe');
    expect(helpers.every(r => ruleInUse(more, parsed, r))).toBe(true);
  });

  it('lets a helper go when an identical copy of it remains', () => {
    const twice = `${rego}\n\nunsafe if contains(input.http.path, "..")\n`;
    const parsed = parsePolicyRules(twice);
    if (!parsed.ok) throw new Error('expected the policy to parse');
    const helpers = parsed.groups.flatMap(g => g.rules).filter(r => r.head === 'unsafe');
    expect(helpers).toHaveLength(2);
    expect(ruleInUse(twice, parsed, helpers[0])).toBe(false);
  });
});
