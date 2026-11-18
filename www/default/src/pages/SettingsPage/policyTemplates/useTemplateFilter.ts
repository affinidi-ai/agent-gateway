import { useMemo, useState } from 'react';
import { CATEGORY_LABELS, type PolicyTemplate, type PolicyTemplateCategory } from './types';

export type CategoryFilter = PolicyTemplateCategory | 'all';

/** True when a template matches a search on its name, summary, inputs or category. */
export function matchesTemplateQuery(template: PolicyTemplate, query: string): boolean {
  const q = query.trim().toLowerCase();
  return (
    !q ||
    template.name.toLowerCase().includes(q) ||
    template.summary.toLowerCase().includes(q) ||
    template.reads.some(r => r.toLowerCase().includes(q)) ||
    CATEGORY_LABELS[template.category].toLowerCase().includes(q)
  );
}

/** Search and category filtering shared by the templates panel and the Start from gallery. */
export function useTemplateFilter(templates: PolicyTemplate[]) {
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState<CategoryFilter>('all');

  const categories = useMemo(
    () => Array.from(new Set(templates.map(t => t.category))),
    [templates]
  );
  const visible = useMemo(
    () =>
      templates.filter(
        t => (category === 'all' || t.category === category) && matchesTemplateQuery(t, query)
      ),
    [templates, category, query]
  );

  return { query, setQuery, category, setCategory, categories, visible };
}
