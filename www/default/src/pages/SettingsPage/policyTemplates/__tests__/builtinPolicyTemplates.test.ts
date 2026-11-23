import { BUILTIN_POLICY_TEMPLATES } from '../builtinPolicyTemplates';
import { EXPECTED_PACKAGE } from '../policyDefaults';
import {
  defaultParameterValues,
  renderTemplate,
  sampleParameterValues,
  templateRole,
} from '../regoTemplate';
import { missingSettings, renderWithText } from '../templateSettings';
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

  it('starts every deployment-specific setting empty, with a sample, and only those', () => {
    const withSample = BUILTIN_POLICY_TEMPLATES.filter(t => t.policy_type === 'agent_surface')
      .flatMap(t => t.parameters.map(p => [t.id.split(':')[0], p] as const))
      .filter(([, p]) => 'sample' in p && p.sample !== undefined);
    expect(withSample.map(([id, p]) => `${id}.${p.key}`)).toEqual([
      'allow-by-jwt-claim.values',
      'allow-by-jwt-issuer-audience.issuers',
      'allow-by-jwt-issuer-audience.audiences',
      'restrict-mcp-tools-by-role.admin_roles',
      'restrict-mcp-tools-by-role.safe_tools',
      'require-verified-credential-subject.dids',
      'allowlist-outbound-destinations.destinations',
      'allow-path-prefixes.prefixes',
      'allow-listed-surfaces.surfaces',
      'allow-listed-subjects.subjects',
      'tool-allow-by-jwt-claim.values',
      'tool-role-with-deny-reason.admin_role',
    ]);
    for (const [, p] of withSample) {
      expect(p.default).toEqual(p.kind === 'string_list' ? [] : '');
    }
  });

  it.each(BUILTIN_POLICY_TEMPLATES.map(t => [t.id, t] as const))(
    '%s refuses to render with an empty deployment setting, so its Use is blocked',
    (_id, template) => {
      const required = template.parameters.filter(p => 'sample' in p && p.sample !== undefined);
      const { rego, errors } = renderTemplate(template, defaultParameterValues(template));
      expect(Object.keys(errors).sort()).toEqual(required.map(p => p.key).sort());
      expect(rego === null).toBe(required.length > 0);
    }
  );

  it('marks a single-value setting missing only while it is blank, as Use renders it', () => {
    const template = BUILTIN_POLICY_TEMPLATES.find(t =>
      t.id.startsWith('tool-role-with-deny-reason')
    )!;
    expect(missingSettings(template, { admin_role: '  ' })).toEqual(new Set(['admin_role']));
    expect(missingSettings(template, { admin_role: ',' })).toEqual(new Set());
    expect(renderWithText(template, { admin_role: ',' }).rego).not.toBeNull();
  });

  it.each(BUILTIN_POLICY_TEMPLATES.map(t => [t.id, t] as const))(
    '%s renders with its sample settings under the package of its type',
    (_id, template) => {
      const { rego, errors } = renderTemplate(template, sampleParameterValues(template));
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

  it('gives every template that adds rules examples for the Template examples card', () => {
    const addsRules = BUILTIN_POLICY_TEMPLATES.filter(t => templateRole(t) === 'rules');
    expect(addsRules.length).toBeGreaterThan(0);
    expect(addsRules.filter(t => t.examples.length === 0).map(t => t.id)).toEqual([]);
  });

  it('says a business-hours window past midnight counts on each listed day', () => {
    const template = BUILTIN_POLICY_TEMPLATES.find(
      t => t.id === 'business-hours-access-window:gateway'
    )!;
    expect(template.rego).toContain('access_day\n  access_minute < {{end_time}}');
    const until = template.parameters.find(p => p.key === 'end_time')!;
    expect(until.help).toContain('Monday 01:00 is inside and Saturday 01:00 is outside');
  });

  it('marks templates that allow outside what they restrict as standalone', () => {
    const standalone = new Set(
      BUILTIN_POLICY_TEMPLATES.filter(t => t.standalone).map(t => t.id.split(':')[0])
    );
    expect(standalone).toEqual(
      new Set([
        'deny-by-default',
        'restrict-mcp-tools-by-role',
        'allowlist-outbound-destinations',
        'business-hours-access-window',
        'allow-all-monitor',
      ])
    );
  });

  it('gives the standalone, MCP tool and default-only templates the whole-policy role', () => {
    const roles = Object.fromEntries(
      BUILTIN_POLICY_TEMPLATES.map(t => [t.id.split(':')[0], templateRole(t)])
    );
    expect(Object.keys(roles).filter(id => roles[id] === 'policy')).toEqual([
      'deny-by-default',
      'restrict-mcp-tools-by-role',
      'allowlist-outbound-destinations',
      'business-hours-access-window',
      'allow-all-monitor',
      'tool-allow-authenticated',
      'tool-allow-by-jwt-claim',
      'tool-role-with-deny-reason',
      'tool-allow-every-caller',
    ]);
    expect(roles['allow-http-methods']).toBe('rules');
    expect(roles['require-authentication']).toBe('rules');
  });

  it('gives a template with nothing past its default line the whole-policy role', () => {
    const base = BUILTIN_POLICY_TEMPLATES.find(t => t.id === 'allow-http-methods:gateway')!;
    expect(
      templateRole({ ...base, rego: 'package gateway.policy\n\ndefault allow := true\n' })
    ).toBe('policy');
    expect(templateRole({ ...base, standalone: false, policy_input: undefined })).toBe('rules');
  });

  it('reads input.jwt only in templates for MCP tool bindings, which are Agent Surface only', () => {
    const toolTemplates = BUILTIN_POLICY_TEMPLATES.filter(t => t.policy_input === 'mcp_tool');
    const others = BUILTIN_POLICY_TEMPLATES.filter(t => t.policy_input !== 'mcp_tool');
    expect(toolTemplates.length).toBeGreaterThan(0);
    expect(toolTemplates.every(t => t.policy_type === 'agent_surface')).toBe(true);
    expect(toolTemplates.every(t => t.category === 'mcp_tool_policies')).toBe(true);
    expect(others.filter(t => /input\.jwt\b/.test(t.rego)).map(t => t.id)).toEqual([]);
  });

  it.each(BUILTIN_POLICY_TEMPLATES.map(t => [t.id, t] as const))(
    '%s links to a section of a policy docs page',
    (_id, template) => {
      expect(template.docs_href).toMatch(
        /^https:\/\/docs\.affinidi\.com\/products\/affinidi-trust-fabric\/agent-gateway\/.+\/#[a-z0-9_-]+$/
      );
      expect(template.docs_label?.trim()).toBeTruthy();
    }
  );
});
