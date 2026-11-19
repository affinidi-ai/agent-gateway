import { BUILTIN_POLICY_TEMPLATES, POLICY_TEMPLATE_LIBRARY } from '../builtinPolicyTemplates';
import {
  galleryTemplates,
  groupTemplateEntries,
  surfaceOnlyKeys,
  templateEntryKey,
} from '../policyTemplateLibrary';

describe('groupTemplateEntries', () => {
  it('groups the variants of a built-in template under its catalogue id', () => {
    const entries = groupTemplateEntries([...BUILTIN_POLICY_TEMPLATES]);
    const deny = entries.find(e => e.key === 'deny-by-default')!;
    expect(Object.keys(deny.variants).sort()).toEqual(['agent_surface', 'gateway']);
    const trust = entries.find(e => e.key === 'require-trust-registry-recognition')!;
    expect(Object.keys(trust.variants)).toEqual(['agent_surface']);
    expect(new Set(entries.map(e => e.key)).size).toBe(entries.length);
  });
});

describe('POLICY_TEMPLATE_LIBRARY', () => {
  it('holds every built-in template, Agent Surface variants first', () => {
    const { templates, entries } = POLICY_TEMPLATE_LIBRARY;
    expect(templates).toHaveLength(BUILTIN_POLICY_TEMPLATES.length);
    const firstGateway = templates.findIndex(t => t.policy_type === 'gateway');
    expect(templates.slice(firstGateway).every(t => t.policy_type === 'gateway')).toBe(true);
    expect(entries.map(e => e.key)).toEqual(Array.from(new Set(templates.map(templateEntryKey))));
  });

  it('has no template outside the built-in catalogue', () => {
    const builtinIds = new Set(BUILTIN_POLICY_TEMPLATES.map(t => t.id));
    expect(POLICY_TEMPLATE_LIBRARY.templates.filter(t => !builtinIds.has(t.id))).toEqual([]);
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
