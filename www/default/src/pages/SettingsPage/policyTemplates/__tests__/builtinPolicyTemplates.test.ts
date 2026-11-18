import { BUILTIN_POLICY_TEMPLATES } from '../builtinPolicyTemplates';
import { EXPECTED_PACKAGE } from '../policyDefaults';
import { defaultParameterValues, renderTemplate } from '../regoTemplate';
import { CATEGORY_LABELS } from '../types';

describe('built-in policy templates', () => {
  it('offers templates for both policy types', () => {
    const types = new Set(BUILTIN_POLICY_TEMPLATES.map(t => t.policy_type));
    expect(types).toEqual(new Set(['gateway', 'agent_surface']));
  });

  it('gives every template a unique id', () => {
    const ids = BUILTIN_POLICY_TEMPLATES.map(t => t.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it.each(BUILTIN_POLICY_TEMPLATES.map(t => [t.id, t] as const))(
    '%s renders with its defaults under the package of its type',
    (_id, template) => {
      const { rego, errors } = renderTemplate(template, defaultParameterValues(template));
      expect(errors).toEqual({});
      expect(rego).not.toBeNull();
      expect(rego).not.toContain('{{');
      expect(rego!.split('\n')[0]).toBe(`package ${EXPECTED_PACKAGE[template.policy_type]}`);
      expect(rego).toMatch(/^default allow := (true|false)$/m);
    }
  );

  it.each(BUILTIN_POLICY_TEMPLATES.map(t => [t.id, t] as const))(
    '%s has a known category, a summary and well-formed examples',
    (_id, template) => {
      expect(Object.keys(CATEGORY_LABELS)).toContain(template.category);
      expect(template.summary.trim()).not.toBe('');
      // A clock-dependent template cannot state a fixed decision for an input.
      const clockDependent = template.rego.includes('time.now_ns()');
      expect(clockDependent || template.examples.length > 0).toBe(true);
      for (const ex of template.examples) {
        expect(['allow', 'deny']).toContain(ex.expected);
        expect(typeof ex.input).toBe('object');
      }
    }
  );

  it('marks templates that allow outside what they restrict as standalone', () => {
    const standalone = new Set(
      BUILTIN_POLICY_TEMPLATES.filter(t => t.standalone).map(t => t.id.split(':')[0])
    );
    expect(standalone).toEqual(
      new Set([
        'deny-by-default',
        'restrict-mcp-tools-by-role',
        'allowlist-outbound-destinations',
        'allow-all-monitor',
      ])
    );
  });

  it('reads caller identity from source_auth, never from an input.jwt path', () => {
    for (const t of BUILTIN_POLICY_TEMPLATES) {
      expect(t.rego).not.toMatch(/input\.jwt\b/);
    }
  });
});
