import { listPolicyTemplates, savePolicyTemplate } from '../policyTemplateStore';

const NEW_TEMPLATE = {
  name: 'Partner traffic',
  summary: 'Partners only',
  category: 'authentication' as const,
  policy_type: 'agent_surface' as const,
  rego: 'package surface.policy\n\ndefault allow := false',
  reads: [],
  examples: [],
};

const organization = async () =>
  (await listPolicyTemplates('agent_surface')).filter(t => !t.builtin);

beforeEach(() => window.sessionStorage.clear());

describe('policyTemplateStore', () => {
  it('keeps a saved template in the tab session', async () => {
    await savePolicyTemplate(NEW_TEMPLATE);

    expect(await organization()).toEqual([
      expect.objectContaining({ name: 'Partner traffic', builtin: false }),
    ]);
    expect(window.sessionStorage.getItem('policy-templates:organization')).toContain(
      'Partner traffic'
    );
    expect((await listPolicyTemplates('gateway')).some(t => !t.builtin)).toBe(false);
  });

  it('ignores stored entries that are not templates', async () => {
    window.sessionStorage.setItem(
      'policy-templates:organization',
      JSON.stringify([{ id: 'org:x', name: 'broken' }, 'text'])
    );
    expect(await organization()).toEqual([]);

    const stored = { ...JSON.parse(JSON.stringify(await savePolicyTemplate(NEW_TEMPLATE))) };
    window.sessionStorage.setItem(
      'policy-templates:organization',
      JSON.stringify([
        { ...stored, examples: [{ name: { text: 'x' }, input: {}, expected: 'allow' }] },
      ])
    );
    expect(await organization()).toEqual([]);
    window.sessionStorage.setItem(
      'policy-templates:organization',
      JSON.stringify([{ ...stored, examples: [{ name: 'ok', input: {}, expected: 'maybe' }] }])
    );
    expect(await organization()).toEqual([]);
    window.sessionStorage.setItem(
      'policy-templates:organization',
      JSON.stringify([{ ...stored, examples: [{ name: 'ok', input: {}, expected: 'deny' }] }])
    );
    expect(await organization()).toHaveLength(1);

    window.sessionStorage.setItem('policy-templates:organization', '{not json');
    expect(await organization()).toEqual([]);
  });

  it('rejects an inherited key as a category and drops fields it does not check', async () => {
    const stored = JSON.parse(JSON.stringify(await savePolicyTemplate(NEW_TEMPLATE)));
    window.sessionStorage.setItem(
      'policy-templates:organization',
      JSON.stringify([{ ...stored, category: 'toString' }])
    );
    expect(await organization()).toEqual([]);

    window.sessionStorage.setItem(
      'policy-templates:organization',
      JSON.stringify([{ ...stored, standalone: false, docs_href: 'https://example.invalid/' }])
    );
    const [template] = await organization();
    expect(template).not.toHaveProperty('docs_href');
    expect(template).not.toHaveProperty('standalone');
  });

  it('keeps a saved template for the page when storage refuses the write', async () => {
    const setItem = jest.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('QuotaExceededError');
    });
    try {
      await savePolicyTemplate({ ...NEW_TEMPLATE, name: 'Kept in memory' });
      expect((await organization()).map(t => t.name)).toContain('Kept in memory');
    } finally {
      setItem.mockRestore();
    }
  });

  it('refuses a name already used for the same type', async () => {
    await savePolicyTemplate(NEW_TEMPLATE);
    await expect(savePolicyTemplate({ ...NEW_TEMPLATE, name: 'partner TRAFFIC' })).rejects.toThrow(
      'A template named "partner TRAFFIC" already exists.'
    );
  });
});
