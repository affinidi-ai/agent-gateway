import React from 'react';
import SearchInput from '../../../components/shared/SearchInput';
import { FilterChipGroup } from '../../../components/shared/filters';
import { CATEGORY_LABELS, type PolicyTemplateCategory } from './types';
import type { CategoryFilter } from './useTemplateFilter';

interface TemplateFilterBarProps {
  query: string;
  onQueryChange: (query: string) => void;
  category: CategoryFilter;
  onCategoryChange: (category: CategoryFilter) => void;
  categories: PolicyTemplateCategory[];
  /** Prefix of the search's test id (`-search-input`) and the chips' wrapper (`-categories`). */
  testIdPrefix: string;
  /** Stretches the search over the whole width, as in the templates column. */
  fullWidth?: boolean;
  className?: string;
}

const FULL_WIDTH_WRAPPER: React.CSSProperties = { display: 'block' };

/** The template search and category chips, shared by the Start from gallery and the column. */
const TemplateFilterBar: React.FC<TemplateFilterBarProps> = ({
  query,
  onQueryChange,
  category,
  onCategoryChange,
  categories,
  testIdPrefix,
  fullWidth = false,
  className = '',
}) => (
  <div className={`policy-template-filters ${className}`.trim()}>
    <SearchInput
      value={query}
      onChange={onQueryChange}
      placeholder="Search templates, e.g. role, trust, path"
      width={fullWidth ? '100%' : '280px'}
      wrapperStyle={fullWidth ? FULL_WIDTH_WRAPPER : undefined}
      aria-label="Search templates"
      data-testid={`${testIdPrefix}-search-input`}
    />
    {categories.length > 1 && (
      <div data-testid={`${testIdPrefix}-categories`}>
        <FilterChipGroup
          chips={[
            { value: '', label: 'All' },
            ...categories.map(c => ({ value: c, label: CATEGORY_LABELS[c] })),
          ]}
          selected={new Set(category === 'all' ? [] : [category])}
          onSelect={value => onCategoryChange((value || 'all') as CategoryFilter)}
          multiple
        />
      </div>
    )}
  </div>
);

export default TemplateFilterBar;
