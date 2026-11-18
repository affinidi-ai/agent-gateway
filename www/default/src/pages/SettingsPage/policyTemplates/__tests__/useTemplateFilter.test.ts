import { act, renderHook } from '@testing-library/react';
import { BUILTIN_POLICY_TEMPLATES } from '../builtinPolicyTemplates';
import { matchesTemplateQuery, useTemplateFilter } from '../useTemplateFilter';

const surfaceTemplates = BUILTIN_POLICY_TEMPLATES.filter(t => t.policy_type === 'agent_surface');
const byId = (id: string) => surfaceTemplates.find(t => t.id === `${id}:agent_surface`)!;

describe('matchesTemplateQuery', () => {
  it('matches the name, summary, read inputs and category, ignoring case', () => {
    expect(matchesTemplateQuery(byId('allow-during-business-hours'), 'BUSINESS')).toBe(true);
    expect(matchesTemplateQuery(byId('all-trust-checks-pass'), 'trust checks')).toBe(true);
    expect(matchesTemplateQuery(byId('allow-http-methods'), 'routing')).toBe(true);
    expect(matchesTemplateQuery(byId('allow-http-methods'), 'zzz')).toBe(false);
    expect(matchesTemplateQuery(byId('allow-http-methods'), '  ')).toBe(true);
  });
});

describe('useTemplateFilter', () => {
  it('lists each category once and filters by category and search together', () => {
    const { result } = renderHook(() => useTemplateFilter(surfaceTemplates));
    expect(result.current.visible).toHaveLength(surfaceTemplates.length);
    expect(new Set(result.current.categories).size).toBe(result.current.categories.length);

    act(() => result.current.setCategory('trust_checks'));
    expect(result.current.visible.every(t => t.category === 'trust_checks')).toBe(true);

    act(() => result.current.setQuery('at least'));
    expect(result.current.visible.map(t => t.name)).toEqual(['At least N trust checks pass']);
  });
});
