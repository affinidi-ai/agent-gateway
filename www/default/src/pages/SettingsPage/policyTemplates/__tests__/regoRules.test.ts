import {
  groupUse,
  parsePolicyRules,
  removeRule,
  removeRuleGroup,
  ruleUse,
  setDefaultDeny,
  type ParsedPolicy,
  type PolicyRule,
  type RuleGroup,
} from '../regoRules';
import { insertTemplateRules } from '../regoTemplate';

const ruleInUse = (parsed: ParsedPolicy, rule: PolicyRule) => ruleUse(parsed, rule) !== null;
const groupInUse = (parsed: ParsedPolicy, group: RuleGroup) => groupUse(parsed, group) !== null;

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

  it('drops the allow-all comment above the default line', () => {
    expect(
      setDefaultDeny('package p\n\n# Allow all traffic by default\ndefault allow = true\n')
    ).toBe('package p\n\ndefault allow = false\n');
  });

  it('keeps any other comment above the default line', () => {
    expect(setDefaultDeny('package p\n\n# Baseline\ndefault allow = true\n')).toBe(
      'package p\n\n# Baseline\ndefault allow = false\n'
    );
  });

  it('leaves a policy that already denies unchanged', () => {
    expect(setDefaultDeny('package p\ndefault allow := false\n')).toBe(
      'package p\ndefault allow := false\n'
    );
  });
});

describe('removeRule and ruleUse', () => {
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
    expect(ruleInUse(parsed, all.find(r => r.head === 'unsafe')!)).toBe(true);
    expect(all.filter(r => r.kind === 'allow').some(r => ruleInUse(parsed, r))).toBe(false);
  });

  it('keeps refusing one of several different definitions of a used helper', () => {
    const more = `${rego}\n\nunsafe if contains(input.http.path, "%2e")\n`;
    const parsed = parsePolicyRules(more);
    if (!parsed.ok) throw new Error('expected the policy to parse');
    const helpers = parsed.groups.flatMap(g => g.rules).filter(r => r.head === 'unsafe');
    expect(helpers.every(r => ruleInUse(parsed, r))).toBe(true);
  });

  it('lets a helper go when an identical copy of it remains', () => {
    const twice = `${rego}\n\nunsafe if contains(input.http.path, "..")\n`;
    const parsed = parsePolicyRules(twice);
    if (!parsed.ok) throw new Error('expected the policy to parse');
    const helpers = parsed.groups.flatMap(g => g.rules).filter(r => r.head === 'unsafe');
    expect(helpers).toHaveLength(2);
    expect(ruleInUse(parsed, helpers[0])).toBe(false);
  });
});

describe('rule kinds', () => {
  it('labels only deny_reason as a deny reason and every other name but allow a helper', () => {
    const rego = [
      'package p',
      'deny contains "x" if input.x',
      'deny_x if input.y',
      'deny_reason := "no" if not allow',
      'allow if count(deny) == 0',
    ].join('\n');
    expect(groupsOf(rego).groups[0].rules.map(r => [r.head, r.kind])).toEqual([
      ['deny', 'helper'],
      ['deny_x', 'helper'],
      ['deny_reason', 'deny'],
      ['allow', 'allow'],
    ]);
  });

  it('keeps each rule its comment-stripped code lines, with a # inside a string kept', () => {
    const rego = ['package p', 'allow if {', '  input.x == "a#b" # note', '}'].join('\n');
    expect(groupsOf(rego).groups[0].rules[0].code).toEqual(['allow if {', 'input.x == "a#b"', '}']);
  });
});

describe('ruleUse by reachability from allow', () => {
  const inUse = (rego: string) => {
    const parsed = groupsOf(rego);
    const all = parsed.groups.flatMap(g => g.rules);
    return all.map(r => [r.head, ruleInUse(parsed, r)]);
  };

  it('refuses each deny rule that allow counts', () => {
    const rego = [
      'package p',
      'default allow := false',
      'deny contains "no path" if not input.http.path',
      'deny contains "bad method" if input.http.method == "DELETE"',
      'allow if count(deny) == 0',
    ].join('\n');
    expect(inUse(rego)).toEqual([
      ['deny', true],
      ['deny', true],
      ['allow', false],
    ]);
  });

  it('refuses a deny_ rule that allow reads under not', () => {
    const rego = [
      'package p',
      'deny_x if input.x',
      'allow if {',
      '  not deny_x',
      '  input.y',
      '}',
    ].join('\n');
    expect(inUse(rego)).toEqual([
      ['deny_x', true],
      ['allow', false],
    ]);
  });

  it('lets a deny rule go when only deny_reason reads it', () => {
    const rego = [
      'package p',
      'deny contains "no path" if not input.http.path',
      'deny_reason := concat(", ", deny)',
      'allow if input.y',
    ].join('\n');
    expect(inUse(rego)).toEqual([
      ['deny', false],
      ['deny_reason', false],
      ['allow', false],
    ]);
  });

  it('refuses a function helper that allow calls', () => {
    const rego = ['package p', 'h(x) if x == "a"', 'allow if h(input.y)'].join('\n');
    expect(inUse(rego)).toEqual([
      ['h(x)', true],
      ['allow', false],
    ]);
  });

  it('refuses an else chain rule that allow reads', () => {
    const rego = [
      'package p',
      'level := 2 if {',
      '  input.a',
      '} else := 1 if {',
      '  input.b',
      '} else := 0',
      'allow if level > 0',
    ].join('\n');
    expect(inUse(rego)).toEqual([
      ['level', true],
      ['allow', false],
    ]);
  });

  it('refuses a rule allow reaches only through another rule', () => {
    const rego = ['package p', 'base if input.a', 'mid if not base', 'allow if mid'].join('\n');
    expect(inUse(rego)).toEqual([
      ['base', true],
      ['mid', true],
      ['allow', false],
    ]);
  });

  it('lets a rule go when its name appears only inside strings', () => {
    const rego = [
      'package p',
      'h if input.a',
      'allow if input.note == `h is',
      'not here`',
      'allow if input.x == "h"',
    ].join('\n');
    expect(inUse(rego)[0]).toEqual(['h', false]);
  });

  it('refuses a rule allow reads through data.surface.policy', () => {
    const rego = ['package surface.policy', 'h if input.a', 'allow if data.surface.policy.h'].join(
      '\n'
    );
    expect(inUse(rego)[0]).toEqual(['h', true]);
  });

  it('does not read a field of the same name as a reference', () => {
    const rego = ['package p', 'method if input.a', 'allow if input.http.method == "GET"'].join(
      '\n'
    );
    expect(inUse(rego)[0]).toEqual(['method', false]);
  });

  it('refuses a rule read after a # inside a string on the same line', () => {
    const rego = ['package p', 'h if input.a', 'allow if { input.x == "#"; not h }'].join('\n');
    expect(inUse(rego)[0]).toEqual(['h', true]);
  });

  it('refuses both definitions that differ only after a # inside a string', () => {
    const rego = [
      'package p',
      'h if input.x == "a#1"',
      'h if input.x == "a#2"',
      'allow if not h',
    ].join('\n');
    expect(inUse(rego)).toEqual([
      ['h', true],
      ['h', true],
      ['allow', false],
    ]);
  });

  it('lets one copy go when the same template was added twice', () => {
    const template =
      'package p\n\nunsafe if contains(input.http.path, "..")\n\nallow if not unsafe\n';
    const once = insertTemplateRules(
      'package p\n\ndefault allow := false\n',
      'Safe paths',
      template
    ).policy;
    const twice = insertTemplateRules(once, 'Safe paths', template).policy;
    const parsed = groupsOf(twice);
    const helpers = parsed.groups.flatMap(g => g.rules).filter(r => r.head === 'unsafe');
    expect(helpers).toHaveLength(2);
    expect(helpers.map(r => ruleInUse(parsed, r))).toEqual([false, false]);
  });

  it('refuses a deny_reason that allow reads under not', () => {
    const rego = [
      'package p',
      'deny_reason := "blocked" if { input.bad }',
      'allow if { not deny_reason }',
    ].join('\n');
    expect(inUse(rego)[0]).toEqual(['deny_reason', true]);
  });

  it('refuses each deny_reason definition that allow compares', () => {
    const rego = [
      'package p',
      'default deny_reason := ""',
      'deny_reason := "blocked" if input.bad',
      'allow if deny_reason == ""',
    ].join('\n');
    expect(inUse(rego)).toEqual([
      ['default deny_reason', true],
      ['deny_reason', true],
      ['allow', false],
    ]);
  });

  it('refuses a deny_reason that allow reaches through another rule', () => {
    const rego = [
      'package p',
      'deny_reason := "blocked" if input.bad',
      'blocked if { deny_reason }',
      'allow if not blocked',
    ].join('\n');
    expect(inUse(rego)[0]).toEqual(['deny_reason', true]);
  });

  it('refuses every rule while the package is imported under an alias', () => {
    const rego = [
      'package surface.policy',
      'import data.surface.policy as p',
      'h if input.a',
      'g if input.b',
      'allow if not p.h',
    ].join('\n');
    expect(inUse(rego)).toEqual([
      ['h', true],
      ['g', true],
      ['allow', false],
    ]);
  });

  it('refuses a rule read through the last segment of an imported package', () => {
    const rego = [
      'package surface.policy',
      'import data.surface.policy',
      'h if input.a',
      'allow if not policy.h',
    ].join('\n');
    expect(inUse(rego)[0]).toEqual(['h', true]);
  });

  it('refuses a rule read through a bracket on the package document', () => {
    const rego = [
      'package surface.policy',
      'h if input.a',
      'allow if not data.surface.policy["h"]',
    ].join('\n');
    expect(inUse(rego)[0]).toEqual(['h', true]);
  });

  it('refuses a rule read through a copy of the whole package document', () => {
    const rego = [
      'package surface.policy',
      'h if input.a',
      'doc := data.surface.policy',
      'allow if not doc.h',
    ].join('\n');
    expect(inUse(rego)[0]).toEqual(['h', true]);
  });

  it('keeps an unread rule free beside a named read of the package or a rego import', () => {
    const rego = [
      'package surface.policy',
      'import rego.v1',
      'h if input.a',
      'g if input.b',
      'allow if data.surface.policy.h',
    ].join('\n');
    expect(inUse(rego).slice(0, 2)).toEqual([
      ['h', true],
      ['g', false],
    ]);
  });

  it('refuses a dotted rule allow reads by its first segment', () => {
    const rego = ['package p', 'blocked.ip if input.ip == "10.0.0.1"', 'allow if not blocked'].join(
      '\n'
    );
    expect(inUse(rego)[0]).toEqual(['blocked.ip', true]);
  });

  it('refuses a rule read after a string with an escaped quote or backslash', () => {
    const quote = ['package p', 'h if input.a', 'allow if { input.x == "a\\"b"; not h }'].join(
      '\n'
    );
    const slash = ['package p', 'h if input.a', 'allow if { input.x == "a\\\\"; not h }'].join(
      '\n'
    );
    expect(inUse(quote)[0]).toEqual(['h', true]);
    expect(inUse(slash)[0]).toEqual(['h', true]);
  });

  it('refuses a rule allow reads through with or some … in', () => {
    const withAs = [
      'package p',
      'fixture := {"x": true}',
      'allow if { input.x with input as fixture }',
    ].join('\n');
    const someIn = [
      'package p',
      'allowed := {"a"}',
      'allow if { some x in allowed; x == input.y }',
    ].join('\n');
    expect(inUse(withAs)[0]).toEqual(['fixture', true]);
    expect(inUse(someIn)[0]).toEqual(['allowed', true]);
  });
});

describe('groupUse', () => {
  const policy = (outside: string) =>
    [
      'package p',
      '',
      'default allow := false',
      '',
      outside,
      '',
      '# Inserted from template: Safe paths',
      'unsafe if contains(input.http.path, "..")',
      '',
      'allow if {',
      '  not unsafe',
      '  input.http.method == "GET"',
      '}',
      '# End of template: Safe paths',
    ].join('\n');
  const templateGroup = (rego: string) => {
    const parsed = groupsOf(rego);
    return { parsed, group: parsed.groups.find(g => g.source.kind === 'template')! };
  };

  it('refuses a template group whose helper a rule outside it reads under not', () => {
    const rego = policy('allow if {\n  not unsafe\n  input.http.method == "HEAD"\n}');
    const { parsed, group } = templateGroup(rego);
    expect(groupInUse(parsed, group)).toBe(true);
  });

  it('lets a template group go when nothing outside it reads its rules', () => {
    const rego = policy('allow if input.http.method == "HEAD"');
    const { parsed, group } = templateGroup(rego);
    expect(groupInUse(parsed, group)).toBe(false);
  });

  it('lets a template group go when an identical copy of it remains', () => {
    const rego = `${policy('allow if not unsafe')}\n\n# Inserted from template: Safe paths\nunsafe if contains(input.http.path, "..")\n# End of template: Safe paths\n`;
    const parsed = groupsOf(rego);
    const first = parsed.groups.find(g => g.source.kind === 'template')!;
    expect(groupInUse(parsed, first)).toBe(false);
  });

  it('ignores a rule outside the group that only deny_reason reads', () => {
    const rego = policy('deny_reason := "unsafe path" if unsafe');
    const { parsed, group } = templateGroup(rego);
    expect(groupInUse(parsed, group)).toBe(false);
  });

  it('refuses a group whose helper allow reaches only through a helper outside it', () => {
    const rego = policy('risky if unsafe\n\nallow if not risky');
    const { parsed, group } = templateGroup(rego);
    expect(groupInUse(parsed, group)).toBe(true);
  });

  it('refuses a group whose read helper has only a different definition outside it', () => {
    const rego = policy('unsafe if contains(input.http.path, "%2e")\n\nallow if not unsafe');
    const { parsed, group } = templateGroup(rego);
    expect(groupInUse(parsed, group)).toBe(true);
  });

  it('refuses a group whose deny_reason allow reads from outside it', () => {
    const rego = [
      'package p',
      'allow if not deny_reason',
      '# Inserted from template: Reasons',
      'deny_reason := "bad" if input.bad',
      '# End of template: Reasons',
    ].join('\n');
    const { parsed, group } = templateGroup(rego);
    expect(groupInUse(parsed, group)).toBe(true);
  });

  it('refuses every group while the package is imported under an alias', () => {
    const rego = policy('allow if doc.unsafe').replace(
      'package p',
      'package p\n\nimport data.p as doc'
    );
    const { parsed, group } = templateGroup(rego);
    expect(groupInUse(parsed, group)).toBe(true);
  });
});

describe('ruleUse and groupUse', () => {
  it('names the first rule that reads a helper, not another definition of it', () => {
    const parsed = groupsOf(
      [
        'package p',
        '',
        'default allow := false',
        '',
        'values(v) := [v] if is_string(v)',
        '',
        'values(v) := v if is_array(v)',
        '',
        'allow if "a" in values(input.x)',
      ].join('\n')
    );
    const [first] = parsed.groups[0].rules.filter(r => r.head.startsWith('values'));
    expect(ruleUse(parsed, first)).toEqual({ kind: 'reader', name: 'allow', line: 9 });
  });

  it('gives the whole-document read as the reason', () => {
    const parsed = groupsOf('package p\n\nblocked if input.x\n\nallow if not data.p["blocked"]\n');
    expect(ruleUse(parsed, parsed.groups[0].rules[0])).toEqual({ kind: 'document' });
  });

  it('names the rule outside a group that reads it, and null when nothing does', () => {
    const parsed = groupsOf(
      'package p\n\n# Inserted from template: T\nblocked if input.x\n# End of template: T\n\nallow if not blocked\n'
    );
    const group = parsed.groups.find(g => g.source.kind === 'template')!;
    expect(groupUse(parsed, group)).toEqual({ kind: 'reader', name: 'allow', line: 7 });
    expect(
      ruleUse(parsed, parsed.groups.find(g => g.source.kind === 'editor')!.rules[0])
    ).toBeNull();
  });
});

describe('ruleUse through other rules', () => {
  it('names the helper that reads a deny rule allow reaches through it', () => {
    const parsed = groupsOf(
      [
        'package p',
        '',
        'default allow := false',
        '',
        'deny_x if input.blocked',
        '',
        'h if not deny_x',
        '',
        'allow if h',
      ].join('\n')
    );
    const denyX = parsed.groups[0].rules.find(r => r.head === 'deny_x')!;
    expect(ruleUse(parsed, denyX)).toEqual({ kind: 'reader', name: 'h', line: 7 });
  });
});
