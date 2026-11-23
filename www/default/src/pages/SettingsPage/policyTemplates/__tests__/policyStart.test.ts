import { BUILTIN_POLICY_TEMPLATES } from '../builtinPolicyTemplates';
import { groupsForOtherType } from '../policyStart';
import { parsePolicyRules } from '../regoRules';

const group = (name: string, body = 'allow if input.x') =>
  `# Inserted from template: ${name}\n${body}\n# End of template: ${name}\n`;

describe('groupsForOtherType', () => {
  it('names the Type a group was written for when its template has no variant for this one', () => {
    const parsed = parsePolicyRules(
      `package gateway.policy\n\ndefault allow := false\n\nallow if input.y\n\n${group(
        'Require authenticated caller'
      )}\n${group('Allow listed HTTP methods')}`
    );
    expect(groupsForOtherType(parsed, 'gateway', BUILTIN_POLICY_TEMPLATES)).toEqual([
      null,
      'agent_surface',
      null,
    ]);
  });

  it('marks no group of a template that serves this Type', () => {
    const parsed = parsePolicyRules(
      `package surface.policy\n\n${group('Require authenticated caller')}`
    );
    expect(groupsForOtherType(parsed, 'agent_surface', BUILTIN_POLICY_TEMPLATES)).toEqual([null]);
  });

  it('marks no group whose name no template has', () => {
    const parsed = parsePolicyRules(`package gateway.policy\n\n${group('Partner GETs')}`);
    expect(groupsForOtherType(parsed, 'gateway', BUILTIN_POLICY_TEMPLATES)).toEqual([null]);
  });

  it('marks nothing while the Rego cannot be parsed', () => {
    expect(
      groupsForOtherType(parsePolicyRules('allow if {'), 'gateway', BUILTIN_POLICY_TEMPLATES)
    ).toEqual([]);
  });
});
