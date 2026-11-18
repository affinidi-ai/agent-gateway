import { BUILTIN_POLICY_TEMPLATES } from '../builtinPolicyTemplates';
import { groupTemplateEntries, templateEntryKey } from '../usePolicyTemplates';
import type { PolicyTemplate } from '../types';

describe('groupTemplateEntries', () => {
  it('groups the variants of a built-in template under its catalogue id', () => {
    const entries = groupTemplateEntries([...BUILTIN_POLICY_TEMPLATES]);
    const deny = entries.find(e => e.key === 'deny-by-default')!;
    expect(Object.keys(deny.variants).sort()).toEqual(['agent_surface', 'gateway']);
    const trust = entries.find(e => e.key === 'require-trust-registry-recognition')!;
    expect(Object.keys(trust.variants)).toEqual(['agent_surface']);
    expect(new Set(entries.map(e => e.key)).size).toBe(entries.length);
  });

  it('keeps an organisation template as its own entry', () => {
    const org: PolicyTemplate = {
      ...BUILTIN_POLICY_TEMPLATES[0],
      id: 'org:abc-1',
      builtin: false,
    };
    expect(templateEntryKey(org)).toBe('org:abc-1');
    expect(groupTemplateEntries([org])).toEqual([
      { key: 'org:abc-1', variants: { [org.policy_type]: org } },
    ]);
  });
});
