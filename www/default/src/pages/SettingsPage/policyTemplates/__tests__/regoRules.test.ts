import renderedTemplates from '../__fixtures__/renderedTemplates.json';
import {
  groupUse,
  isPlainAllow,
  isUnconditionalAllow,
  parsePolicyRules,
  removeRule,
  removeRuleGroup,
  ruleName,
  ruleRoles,
  ruleUse,
  setDefaultDeny,
  splitConditions,
  summarizeDecision,
  type DecisionSummary,
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

describe('split rule heads', () => {
  const splitHead = [
    'package p',
    'default allow := false',
    'allow',
    'if { count(deny) == 0 }',
    'deny contains msg',
    'if {',
    '  input.bad',
    '  msg := "bad"',
    '}',
  ].join('\n');

  it('refuses Remove on a deny rule an allow with its if on the next line reads', () => {
    const parsed = groupsOf(splitHead);
    const deny = parsed.groups[0].rules.find(r => ruleName(r) === 'deny')!;
    expect(ruleUse(parsed, deny)).toEqual({ kind: 'reader', name: 'allow', line: 3 });
  });

  it('joins a head and its if body on the next line into one rule', () => {
    expect(groupsOf(splitHead).groups[0].rules.map(r => [r.head, r.startLine, r.endLine])).toEqual([
      ['allow', 3, 4],
      ['deny', 5, 9],
    ]);
  });

  it('joins a head that ends in contains, :=, = or a line that starts with else', () => {
    const rego = [
      'package p',
      'deny contains',
      '  msg if input.bad',
      'level',
      '  := 1 if input.a',
      'tier',
      '  = 2',
      'x := 1 if {',
      '  input.a',
      '}',
      'else := 0',
    ].join('\n');
    expect(groupsOf(rego).groups[0].rules.map(r => [r.head, r.startLine, r.endLine])).toEqual([
      ['deny', 2, 3],
      ['level', 4, 5],
      ['tier', 6, 7],
      ['x', 8, 11],
    ]);
  });

  it('starts a new rule on a line whose name only begins with a keyword', () => {
    const rego = ['package p', 'x := 1', 'if_set := 2', 'contains_x := 3', 'elsewhere := 4'].join(
      '\n'
    );
    expect(groupsOf(rego).groups[0].rules.map(r => r.head)).toEqual([
      'x',
      'if_set',
      'contains_x',
      'elsewhere',
    ]);
  });

  it.each([
    ['an if body after a template marker', 'allow\n# Inserted from template: T\nif { input.x }'],
    ['a statement named after a keyword', 'some x in input.list'],
    ['an assignment with no head', '# Inserted from template: T\n:= 1'],
  ])('reads %s as unparsed', (_label, body) => {
    expect(parsePolicyRules(`package p\n${body}\n`).ok).toBe(false);
  });
});

const onlyRule = (body: string) => {
  const rules = groupsOf(`package p\n${body}\n`).groups.flatMap(g => g.rules);
  expect(rules).toHaveLength(1);
  return rules[0];
};

describe('isPlainAllow and isUnconditionalAllow', () => {
  it.each([
    ['a bare allow', 'allow'],
    ['allow := true', 'allow := true'],
    ['allow = true', 'allow = true'],
    ['allow if true', 'allow if true'],
    ['allow if { true }', 'allow if { true }'],
    ['allow { true }', 'allow { true }'],
    ['allow if { true } over lines', 'allow if {\n  true\n}'],
    ['allow if { true; }', 'allow if { true; }'],
  ])('reads %s as a plain, unconditional allow', (_label, body) => {
    const rule = onlyRule(body);
    expect([isPlainAllow(rule), isUnconditionalAllow(rule)]).toEqual([true, true]);
  });

  it.each([
    ['allow if a condition', 'allow if input.x'],
    ['allow if { conditions }', 'allow if {\n  input.x\n  input.y\n}'],
    ['allow := true if a condition', 'allow := true if { input.x }'],
    ['an old-style body', 'allow {\n  input.x\n}'],
    ['a split head', 'allow\nif { input.x }'],
    ['true and a condition', 'allow if { true; input.x }'],
  ])('reads %s as a plain, conditional allow', (_label, body) => {
    const rule = onlyRule(body);
    expect([isPlainAllow(rule), isUnconditionalAllow(rule)]).toEqual([true, false]);
  });

  it.each([
    [':= false', 'allow := false if { input.x }'],
    [':= <expr>', 'allow := input.x'],
    ['allow(x)', 'allow(x) if x'],
    ['allow contains', 'allow contains "a" if input.x'],
    ['allow[x]', 'allow[x] if { some x in input.list }'],
    ['else', 'allow if { input.x } else := false'],
    ['allow.x', 'allow.x := true'],
    ['default allow := 1', 'default allow := 1'],
    [':= a name starting with true', 'allow := true_value'],
  ])('reads %s as not plain', (_label, body) => {
    const rule = onlyRule(body);
    expect([isPlainAllow(rule), isUnconditionalAllow(rule)]).toEqual([false, false]);
  });

  it('reads else inside a string or a raw string as plain', () => {
    expect(isPlainAllow(onlyRule('allow if input.x == "else"'))).toBe(true);
    expect(isPlainAllow(onlyRule('allow if input.x == `or else`'))).toBe(true);
  });

  it('reads a rule with another name as not plain', () => {
    expect(isPlainAllow(onlyRule('allowed if input.x'))).toBe(false);
  });
});

describe('splitConditions', () => {
  it.each<[string, string, string[] | null]>([
    [
      'every, one line',
      'allow if {\n  every r in xs { r.ok }\n  count(xs) > 0\n}',
      ['every r in xs { r.ok }', 'count(xs) > 0'],
    ],
    [
      'every, multi-line',
      'allow if {\n  every r in xs {\n    r.ok\n    r.x\n  }\n  y\n}',
      ['every r in xs { r.ok; r.x }', 'y'],
    ],
    [
      'set comprehension',
      'allow if {\n  s := {x | some x in xs; x > 1}\n  count(s) > 0\n}',
      ['s := {x | some x in xs; x > 1}', 'count(s) > 0'],
    ],
    [
      'array comprehension',
      'allow if {\n  a := [x | some x in xs; x > 1]\n  count(a) > 0\n}',
      ['a := [x | some x in xs; x > 1]', 'count(a) > 0'],
    ],
    [
      'object comprehension',
      'allow if {\n  o := {k: v | some k, v in m; v > 1}\n  count(o) > 0\n}',
      ['o := {k: v | some k, v in m; v > 1}', 'count(o) > 0'],
    ],
    [
      'multi-line comprehension',
      'allow if {\n  s := {x |\n    some x in xs\n    x > 1\n  }\n  count(s) > 0\n}',
      ['s := {x | some x in xs; x > 1 }', 'count(s) > 0'],
    ],
    ['; in a block', 'allow if { a; b; c }', ['a', 'b', 'c']],
    ['; mixed with newlines', 'allow if {\n  a; b\n  c\n}', ['a', 'b', 'c']],
    ['trailing ;', 'allow if { a; }', ['a']],
    ['old-style { a; b }', 'allow { a; b }', ['a', 'b']],
    ['multi-line call', 'allow if {\n  count(\n    xs\n  ) > 0\n  y\n}', ['count(xs) > 0', 'y']],
    [
      'multi-line call args',
      'allow if {\n  startswith(\n    input.path,\n    "/a"\n  )\n}',
      ['startswith(input.path, "/a")'],
    ],
    ['binary op dangling at end of line', 'allow if {\n  x ==\n  y\n}', null],
    ['binary op starting next line', 'allow if {\n  x\n  == y\n}', null],
    [
      'with on the same line',
      'allow if {\n  f(x) with input.a as 1\n  y\n}',
      ['f(x) with input.a as 1', 'y'],
    ],
    ['with on the next line', 'allow if {\n  f(x)\n  with input.a as 1\n}', null],
    ['an index on the next line', 'allow if {\n  x := input.y\n  [0]\n  z\n}', null],
    ['call arguments on the next line', 'allow if {\n  count\n  (xs) > 0\n  z\n}', null],
    ['raw string with braces', 'allow if {\n  x == `{a}; }`\n  y\n}', ['x == `{a}; }`', 'y']],
    ['raw string with an opening brace only', 'allow if {\n  x == `{`\n  y\n}', ['x == `{`', 'y']],
    ['multi-line raw string', 'allow if {\n  x == `a\n  }`\n  y\n}', null],
    ['one-line allow if x', 'allow if x', ['x']],
    [
      'one-line allow if with call',
      'allow if startswith(input.path, "/a")',
      ['startswith(input.path, "/a")'],
    ],
    ['one-line allow if on next line', 'allow if\n  input.x', ['input.x']],
    ['string with ;', 'allow if {\n  x == "a;b"\n  y\n}', ['x == "a;b"', 'y']],
    ['string with }', 'allow if {\n  x == "}"\n  y == "{"\n}', ['x == "}"', 'y == "{"']],
    [
      'string with escaped quote, ; and }',
      'allow if {\n  x == "a\\"; }"\n  y\n}',
      ['x == "a\\"; }"', 'y'],
    ],
    ['one-line string with ; and }', 'allow if x == "a;b}"', ['x == "a;b}"']],
    ['else inside a string', 'allow if { x == "else" }', ['x == "else"']],
    ['comment in the body', 'allow if {\n  a # c; d }\n  b\n}', ['a', 'b']],
    ['split head', 'allow\nif {\n  a\n  b\n}', ['a', 'b']],
    ['set literal expression, not a block', 'allow if {"a"} == x', null],
    ['set == set expression', 'allow if {1} == {1}', null],
    ['bare allow', 'allow', null],
    ['allow := true', 'allow := true', null],
    ['allow if true', 'allow if true', null],
    ['allow { true }', 'allow { true }', null],
    ['empty block', 'allow if {\n}', null],
    [
      'not / some lines',
      'allow if {\n  some x in xs\n  not x.bad\n}',
      ['some x in xs', 'not x.bad'],
    ],
    [
      'object literal over lines',
      'allow if {\n  o := {\n    "a": 1,\n    "b": 2,\n  }\n  o.a == 1\n}',
      ['o := { "a": 1, "b": 2, }', 'o.a == 1'],
    ],
    ['an unknown character', 'allow if {\n  x ~ y\n  z\n}', null],
    [
      'whitespace collapsed outside strings only',
      'allow if {\n  x  ==   "a  b"\n  y\n}',
      ['x == "a  b"', 'y'],
    ],
  ])('%s', (_label, body, expected) => {
    expect(splitConditions(onlyRule(body))).toEqual(expected);
  });

  it.each([
    ['else', 'allow := true if { a } else := false'],
    ['else on its own line', 'allow if {\n  a\n}\nelse := false if {\n  b\n}'],
    ['else between plain bodies', 'allow if { a } else if { b }'],
    [':= false', 'allow := false if { a; b }'],
    [':= <expr>', 'allow := input.x if { a; b }'],
    ['allow(x)', 'allow(x) if { x; y }'],
    ['allow contains', 'allow contains x if { x := 1; y }'],
    ['allow[x]', 'allow[x] if { x := 1; y }'],
    ['allow.x', 'allow.x if { a; b }'],
  ])('returns null for %s', (_label, body) => {
    expect(splitConditions(onlyRule(body))).toBeNull();
  });

  it('returns null for a rule with another name', () => {
    expect(splitConditions(onlyRule('allowed if { a; b }'))).toBeNull();
  });

  const builtinAllowRules = Object.entries(renderedTemplates as Record<string, string>).flatMap(
    ([key, rego]) =>
      groupsOf(rego)
        .groups.flatMap(g => g.rules)
        .filter(r => ruleName(r) === 'allow')
        .map((rule, i) => [`${key} #${i}`, rule] as const)
  );

  const sourceConditionLines = (rule: PolicyRule) =>
    rule.code.length > 1 && rule.code[0] === 'allow if {' && rule.code[rule.code.length - 1] === '}'
      ? rule.code.slice(1, -1)
      : [rule.code.join(' ').replace(/^allow if /, '')];

  it('finds the built-in allow rules', () => {
    expect(builtinAllowRules.length).toBeGreaterThan(20);
  });

  it.each(builtinAllowRules)('splits the built-in %s into its source lines', (_key, rule) => {
    expect(splitConditions(rule)).toEqual(sourceConditionLines(rule));
  });
});

describe('summarizeDecision', () => {
  const summary = (rego: string) => summarizeDecision(parsePolicyRules(rego));

  it.each<[string, string, DecisionSummary | null]>([
    ['S1 Rego that does not parse', 'package p\nallow if {\n', null],
    ['S3 empty Rego', '', null],
    ['S10 no rules and no default', 'package p\n', null],
    ['no rules and default false', 'package p\ndefault allow := false\n', null],
    [
      'S4 a non-plain allow',
      'package p\ndefault allow := false\nallow := false if { input.x }\n',
      { kind: 'unsummarised' },
    ],
    [
      'S4 over default true',
      'package p\ndefault allow := true\nallow := false if input.x\n',
      { kind: 'unsummarised' },
    ],
    [
      'S4 over an unconditional allow',
      'package p\nallow\nallow.x := 1\n',
      { kind: 'unsummarised' },
    ],
    [
      'S5 default true',
      'package p\ndefault allow := true\nallow if input.x\n',
      { kind: 'allows-all', reason: 'default' },
    ],
    [
      'S5 default true with no allow rule',
      'package p\ndefault allow = true\nh if input.x\n',
      { kind: 'allows-all', reason: 'default' },
    ],
    [
      'S5b allow := true beside default false',
      'package p\ndefault allow := false\nallow if input.x\nallow := true\n',
      { kind: 'allows-all', reason: 'unconditional' },
    ],
    [
      'S5b allow if { true }',
      'package p\ndefault allow := false\nallow if { true }\n',
      { kind: 'allows-all', reason: 'unconditional' },
    ],
    [
      'S6 one allow rule',
      'package p\ndefault allow := false\nallow if input.x\n',
      { kind: 'any-allow', allowRules: 1, hasDefault: true },
    ],
    [
      'S6 three allow rules',
      'package p\ndefault allow := false\nallow if input.x\nallow if input.y\nallow if {\n  input.z\n}\n',
      { kind: 'any-allow', allowRules: 3, hasDefault: true },
    ],
    [
      'S7 allow rules without a default',
      'package p\nallow if input.x\nallow if input.y\n',
      { kind: 'any-allow', allowRules: 2, hasDefault: false },
    ],
    [
      'S8 default false and no allow rule',
      'package p\ndefault allow := false\ndeny_reason := "no"\n',
      { kind: 'denies-all', hasDefault: true },
    ],
    [
      'S9 no default and no allow rule',
      'package p\nh if input.x\n',
      { kind: 'denies-all', hasDefault: false },
    ],
  ])('%s', (_label, rego, expected) => {
    expect(summary(rego)).toEqual(expected);
  });

  it('summarises an allow with its if on the next line as one conditional rule', () => {
    expect(
      summary(
        'package p\ndefault allow := false\nallow\nif { count(deny) == 0 }\ndeny contains msg\nif {\n  input.bad\n  msg := "bad"\n}\n'
      )
    ).toEqual({ kind: 'any-allow', allowRules: 1, hasDefault: true });
  });

  it.each(Object.entries(renderedTemplates as Record<string, string>))(
    'summarises the built-in %s with something other than unsummarised',
    (_key, rego) => {
      const parsed = parsePolicyRules(rego);
      expect(parsed.ok).toBe(true);
      expect(summarizeDecision(parsed)?.kind).not.toBe('unsummarised');
    }
  );
});

describe('ruleRoles', () => {
  const roles = (rego: string) => {
    const parsed = groupsOf(rego);
    const role = ruleRoles(parsed);
    return parsed.groups.flatMap(g => g.rules).map(r => [r.head, role(r)]);
  };

  it('reads a deny set allow counts as used by allow', () => {
    expect(
      roles('package p\nallow if { count(deny) == 0 }\ndeny contains msg if {\n  msg := "x"\n}')
    ).toEqual([
      ['allow', 'allow'],
      ['deny', 'used-by-allow'],
    ]);
  });

  it('reads a deny set only deny_reason reads as not used by allow', () => {
    expect(
      roles(
        'package p\ndeny contains "x" if input.x\ndeny_reason := concat(", ", deny)\nallow if input.y'
      )
    ).toEqual([
      ['deny', 'not-used-by-allow'],
      ['deny_reason', 'deny-reason'],
      ['allow', 'allow'],
    ]);
  });

  it('reads a helper reached through another helper as used by allow', () => {
    expect(roles('package p\nbase if input.a\nmid if not base\nallow if mid')).toEqual([
      ['base', 'used-by-allow'],
      ['mid', 'used-by-allow'],
      ['allow', 'allow'],
    ]);
  });

  it('reads every rule as used while the Rego reads its package as a whole document', () => {
    expect(
      roles('package p\nh if input.a\ng if input.b\nallow if not data.p["h"]\ndeny_reason := "no"')
    ).toEqual([
      ['h', 'used-by-allow'],
      ['g', 'used-by-allow'],
      ['allow', 'allow'],
      ['deny_reason', 'deny-reason'],
    ]);
  });

  it('reads a dotted allow.x as used by allow, and a rule it reads too', () => {
    expect(roles('package p\nh if input.a\nallow.x := h')).toEqual([
      ['h', 'used-by-allow'],
      ['allow.x', 'used-by-allow'],
    ]);
  });

  it('reads both copies of a helper from a template added twice as used, and both removable', () => {
    const template =
      'package p\n\nunsafe if contains(input.http.path, "..")\n\nallow if not unsafe\n';
    const once = insertTemplateRules(
      'package p\n\ndefault allow := false\n',
      'Safe paths',
      template
    ).policy;
    const parsed = groupsOf(insertTemplateRules(once, 'Safe paths', template).policy);
    const role = ruleRoles(parsed);
    const helpers = parsed.groups.flatMap(g => g.rules).filter(r => r.head === 'unsafe');
    expect(helpers.map(role)).toEqual(['used-by-allow', 'used-by-allow']);
    expect(helpers.map(r => ruleUse(parsed, r))).toEqual([null, null]);
  });

  it('reads a deny set an allow with its if on the next line counts as used by allow', () => {
    expect(
      roles('package p\nallow\nif { count(deny) == 0 }\ndeny contains msg\nif {\n  msg := "x"\n}')
    ).toEqual([
      ['allow', 'allow'],
      ['deny', 'used-by-allow'],
    ]);
  });

  it('reads every rule but allow and deny_reason as used by allow when the policy does not parse', () => {
    const role = ruleRoles(parsePolicyRules('package p\nallow if {\n'));
    expect(
      [onlyRule('h if input.a'), onlyRule('allow if h'), onlyRule('deny_reason := "no"')].map(role)
    ).toEqual(['used-by-allow', 'allow', 'deny-reason']);
  });
});

describe('import lines', () => {
  const ifImport = 'package surface.policy\nimport future.keywords.if\n';
  const containsImport = 'package surface.policy\nimport future.keywords.contains\n';

  it.each<[string, string, DecisionSummary | null]>([
    [
      'both keyword imports before default true',
      `${ifImport}import future.keywords.contains\ndefault allow := true\nallow if input.x\n`,
      { kind: 'allows-all', reason: 'default' },
    ],
    [
      'the contains import before an unconditional allow',
      `${containsImport}allow if { true }\n`,
      { kind: 'allows-all', reason: 'unconditional' },
    ],
    [
      'the if import before default true',
      `${ifImport}default allow := true\nallow if input.x\n`,
      { kind: 'allows-all', reason: 'default' },
    ],
    [
      'the if import before an unconditional allow',
      `${ifImport}allow if { true }\n`,
      { kind: 'allows-all', reason: 'unconditional' },
    ],
    [
      'a rule that ends in a field named contains',
      'package p\nallow if input.flags.contains\nallow if { true }\n',
      { kind: 'allows-all', reason: 'unconditional' },
    ],
  ])('summarises %s', (_label, rego, expected) => {
    expect(summarizeDecision(parsePolicyRules(rego))).toEqual(expected);
  });

  it('reads the default after the contains import', () => {
    expect(groupsOf(`${containsImport}default allow := true\n`).defaultDecision).toBe('allow');
  });

  it('reads a deny set after the contains import as used by allow, and refuses its Remove', () => {
    const parsed = groupsOf(
      `${containsImport}deny contains msg if {\n  input.bad\n  msg := "bad"\n}\ndefault allow := false\nallow if count(deny) == 0\n`
    );
    const rules = parsed.groups.flatMap(g => g.rules);
    const deny = rules.find(r => r.head === 'deny')!;
    expect(rules.map(r => r.head)).toEqual(['deny', 'allow']);
    expect(ruleRoles(parsed)(deny)).toBe('used-by-allow');
    expect(ruleUse(parsed, deny)).toEqual({ kind: 'reader', name: 'allow', line: 8 });
  });
});

describe('a dotted allow starts the walk', () => {
  it('refuses Remove on a rule allow.x reads', () => {
    const parsed = groupsOf('package p\nh if input.a\nallow.x := h');
    expect(ruleUse(parsed, parsed.groups[0].rules[0])).toEqual({
      kind: 'reader',
      name: 'allow.x',
      line: 3,
    });
  });

  it('refuses a template group whose rule allow.x outside it reads', () => {
    const parsed = groupsOf(
      'package p\nallow.x := h\n# Inserted from template: T\nh if input.a\n# End of template: T\n'
    );
    const group = parsed.groups.find(g => g.source.kind === 'template')!;
    expect(groupUse(parsed, group)).toEqual({ kind: 'reader', name: 'allow.x', line: 2 });
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
