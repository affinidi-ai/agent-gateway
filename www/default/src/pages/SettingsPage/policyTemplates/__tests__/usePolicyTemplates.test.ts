import { BUILTIN_POLICY_TEMPLATES } from '../builtinPolicyTemplates';
import {
  galleryTemplates,
  groupTemplateEntries,
  surfaceOnlyKeys,
  templateEntryKey,
} from '../usePolicyTemplates';
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

describe('galleryTemplates', () => {
  const entries = groupTemplateEntries([...BUILTIN_POLICY_TEMPLATES]);

  it('lists only the Gateway variants for a Gateway policy', () => {
    const gateway = galleryTemplates(entries, 'gateway');
    expect(gateway.length).toBeGreaterThan(0);
    expect(gateway.every(t => t.policy_type === 'gateway')).toBe(true);
    expect(gateway.map(templateEntryKey)).not.toContain('require-trust-registry-recognition');
    expect(gateway.map(templateEntryKey)).toContain('deny-by-default');
  });

  it('lists every Agent Surface variant for an Agent Surface policy', () => {
    const surface = galleryTemplates(entries, 'agent_surface');
    expect(surface.every(t => t.policy_type === 'agent_surface')).toBe(true);
    expect(surface.map(templateEntryKey)).toEqual(
      expect.arrayContaining(['require-trust-registry-recognition', 'deny-by-default'])
    );
  });
});

describe('surfaceOnlyKeys', () => {
  it('names the entries with no Gateway variant', () => {
    const keys = surfaceOnlyKeys(groupTemplateEntries([...BUILTIN_POLICY_TEMPLATES]));
    expect(keys.has('require-trust-registry-recognition')).toBe(true);
    expect(keys.has('deny-by-default')).toBe(false);
  });
});
