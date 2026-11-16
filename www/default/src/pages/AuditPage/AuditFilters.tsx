import React, { useMemo } from 'react';
import SearchInput from '../../components/shared/SearchInput';
import { FilterChipGroup, FilterOverflowMenu } from '../../components/shared/filters';
import type { FilterOption } from '../../components/shared/filters';
import { CATEGORY_OPTIONS, flowIcon, scopeIcon } from './auditHelpers';
import type { DecisionFilter, FlowFilter, ScopeFilter } from './types';

interface AuditFiltersProps {
  searchInput: string;
  onSearchChange: (v: string) => void;
  onSearchSubmit: () => void;
  onClearText: () => void;
  category: string;
  selectedCats: string[];
  categoryCounts: Record<string, number>;
  onToggleCategory: (val: string) => void;
  onSelectAllCategories: () => void;
  decisionFilter: DecisionFilter;
  onDecisionChange: (v: DecisionFilter) => void;
  decisionCounts?: Record<string, number>;
  flowFilter: FlowFilter;
  onFlowChange: (v: FlowFilter) => void;
  scopeFilter: ScopeFilter;
  onScopeChange: (v: ScopeFilter) => void;
  /**
   * Whether the read stopped before the end of the history, so every category
   * count is a lower bound and is shown with a trailing `+`.
   */
  countsAreLowerBounds?: boolean;
}

// Every option sits in the overflow menu, so the policy-decision filter row stays
// one line. They are marked rather than given a zero count: a count of 0 would
// say the gateway found none of them, which it never reported.
const FLOW_OPTIONS: FilterOption[] = [
  { value: '', label: 'All' },
  { value: 'access_point', label: 'Access Point', lowFrequency: true },
  { value: 'transit_point', label: 'Transit Point', lowFrequency: true },
  { value: 'fabric', label: 'Fabric', lowFrequency: true },
];

const SCOPE_OPTIONS: FilterOption[] = [
  { value: '', label: 'All' },
  { value: 'gateway', label: 'Gateway', lowFrequency: true },
  { value: 'surface', label: 'Surface', lowFrequency: true },
  { value: 'mcp_tool', label: 'MCP Tool', lowFrequency: true },
  { value: 'response', label: 'Response', lowFrequency: true },
];

/** Search box + category (OR-set) pills, then a consolidated policy-decision filter row. */
const AuditFilters: React.FC<AuditFiltersProps> = ({
  searchInput,
  onSearchChange,
  onSearchSubmit,
  onClearText,
  category,
  selectedCats,
  categoryCounts,
  onToggleCategory,
  onSelectAllCategories,
  decisionFilter,
  onDecisionChange,
  decisionCounts = {},
  flowFilter,
  onFlowChange,
  scopeFilter,
  onScopeChange,
  countsAreLowerBounds = false,
}) => {
  // Helper: Split options into inline (show always) and overflow (low-frequency/zero-count)
  const splitByFrequency = (
    options: FilterOption[],
    counts?: Record<string, number>,
    moveAllToOverflow?: boolean
  ): { inline: FilterOption[]; overflow: FilterOption[] } => {
    const inline: FilterOption[] = [];
    const overflow: FilterOption[] = [];

    options.forEach(opt => {
      const count = opt.value && counts ? (counts[opt.value] ?? 0) : undefined;
      const shouldOverflow =
        (count !== undefined && count === 0) ||
        opt.lowFrequency === true ||
        (moveAllToOverflow && opt.value === '');

      if (shouldOverflow && !(opt.value === '' && !moveAllToOverflow)) {
        // Move to overflow if marked, or if zero-count/low-frequency and not "All" (unless moveAllToOverflow is true)
        overflow.push(opt);
      } else {
        inline.push(opt);
      }
    });

    return { inline, overflow };
  };

  // Compute inline/overflow splits for Category, Flow and Type facets
  const { inline: categoryInline, overflow: categoryOverflow } = useMemo(
    () => splitByFrequency(CATEGORY_OPTIONS, categoryCounts),
    [categoryCounts]
  );
  // No counts: these facets describe one policy decision, not a tally across the
  // history. Passing `{}` here would read as "zero of everything", which both
  // shows a `(0)` marker on every option and forces them all into the overflow
  // menu, so `lowFrequency` would decide nothing.
  const { inline: flowInline, overflow: flowOverflow } = useMemo(
    () => splitByFrequency(FLOW_OPTIONS, undefined, true),
    []
  );
  const { inline: scopeInline, overflow: scopeOverflow } = useMemo(
    () => splitByFrequency(SCOPE_OPTIONS, undefined, true),
    []
  );

  // Helper: Handle "All" selection for multi-select facets
  // If user selects "All", clear all specific selections
  // If user selects a specific item, deselect "All"
  const handleCategoryToggle = (val: string) => {
    if (val === '') {
      onSelectAllCategories();
    } else {
      onToggleCategory(val);
    }
  };

  const handleCategoryClear = () => {
    onSelectAllCategories();
  };

  const handleFlowToggle = (val: string) => {
    if (val === '') {
      // Clicking "All" clears the filter
      onFlowChange('');
    } else {
      // Toggle: if already selected, clear it; otherwise, select it
      onFlowChange(flowFilter === val ? '' : (val as FlowFilter));
    }
  };

  const handleTypeToggle = (val: string) => {
    if (val === '') {
      // Clicking "All" clears the filter
      onScopeChange('');
    } else {
      // Toggle: if already selected, clear it; otherwise, select it
      onScopeChange(scopeFilter === val ? '' : (val as ScopeFilter));
    }
  };

  const handleFlowClear = () => {
    onFlowChange('');
  };

  const handleTypeClear = () => {
    onScopeChange('');
  };

  // Category options with dynamic counts
  const categoryInlineChips = categoryInline.map(opt => {
    const isAll = opt.value === '';
    const count = isAll
      ? Object.values(categoryCounts).reduce((a, b) => a + b, 0)
      : (categoryCounts[opt.value] ?? 0);
    return { value: opt.value, label: opt.label, count };
  });

  const categoryOverflowChips = categoryOverflow.map(opt => {
    const count = categoryCounts[opt.value] ?? 0;
    return { value: opt.value, label: opt.label, count };
  });

  // Decision options (single-select chips) with counts
  const decisionChips: FilterOption[] = [
    {
      value: '',
      label: 'All',
    },
    {
      value: 'allow',
      label: 'Allow',
    },
    {
      value: 'deny',
      label: 'Deny',
    },
  ];

  // Flow and Type options carry an icon and no count: the response tallies
  // categories, not policy-decision markers, so there is no number to show. A
  // count of 0 here would read as "none of these", which is not what the gateway
  // said.
  const flowInlineWithIcons = flowInline.map(opt => ({
    ...opt,
    icon: opt.value ? flowIcon(opt.value) : undefined,
  }));

  const flowOverflowWithIcons = flowOverflow.map(opt => ({
    ...opt,
    icon: opt.value ? flowIcon(opt.value) : undefined,
  }));

  const scopeInlineWithIcons = scopeInline.map(opt => ({
    ...opt,
    icon: opt.value ? scopeIcon(opt.value) : undefined,
  }));

  const scopeOverflowWithIcons = scopeOverflow.map(opt => ({
    ...opt,
    icon: opt.value ? scopeIcon(opt.value) : undefined,
  }));

  return (
    <div className="audit-filters mb-3" style={{ marginBottom: '2rem' }}>
      <form
        className="d-sm-flex align-items-center mb-3"
        onSubmit={e => {
          e.preventDefault();
          onSearchSubmit();
        }}
      >
        <SearchInput
          value={searchInput}
          onChange={v => {
            onSearchChange(v);
            if (v === '') onClearText();
          }}
          placeholder="Filter Audit Log..."
          data-testid="audit-search"
        />
      </form>

      {/* Filter facets — category, decision, flow, and type in one row */}
      <div
        className="d-flex align-items-center flex-wrap"
        style={{ gap: '2.25rem', rowGap: '0.5rem' }}
        data-testid="audit-policy-filters"
      >
        {/* Category facet — multi-select chips with counts and overflow menu */}
        <div className="d-flex align-items-center" style={{ gap: '0.4rem' }}>
          <span className="fw-semibold text-body">Category:</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <FilterChipGroup
              chips={categoryInlineChips}
              selected={new Set(selectedCats)}
              onSelect={handleCategoryToggle}
              multiple={true}
              countsAreLowerBounds={countsAreLowerBounds}
            />
            {categoryOverflowChips.length > 0 && (
              <FilterOverflowMenu
                options={categoryOverflowChips}
                selected={
                  new Set(
                    selectedCats.filter(cat => categoryOverflow.some(opt => opt.value === cat))
                  )
                }
                onToggle={handleCategoryToggle}
                onClear={handleCategoryClear}
                facetLabel="Category"
                countsAreLowerBounds={countsAreLowerBounds}
              />
            )}
          </div>
        </div>

        {/* Decision facet — single-select (All/Allow/Deny radio-like) */}
        <div className="d-flex align-items-center" style={{ gap: '0.4rem' }}>
          <span className="fw-semibold text-body">Decision:</span>
          <FilterChipGroup
            chips={decisionChips}
            selected={decisionFilter || ''}
            onSelect={val => onDecisionChange(val as DecisionFilter)}
            multiple={false}
            showBadge={false}
          />
        </div>

        {/* Flow facet — inline chips + overflow menu */}
        <div className="d-flex align-items-center" style={{ gap: '0.4rem' }}>
          <span className="fw-semibold text-body">Flow:</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <FilterChipGroup
              chips={flowInlineWithIcons}
              selected={flowFilter || ''}
              onSelect={handleFlowToggle}
              multiple={false}
              showBadge={false}
            />
            {flowOverflowWithIcons.length > 0 && (
              <FilterOverflowMenu
                options={flowOverflowWithIcons}
                selected={new Set(flowFilter ? [flowFilter] : [])}
                onToggle={handleFlowToggle}
                onClear={handleFlowClear}
                facetLabel="Flow"
                showBadge={false}
                currentValue={flowFilter || ''}
              />
            )}
          </div>
        </div>

        {/* Type (Scope) facet — inline chips + overflow menu */}
        <div className="d-flex align-items-center" style={{ gap: '0.4rem' }}>
          <span className="fw-semibold text-body">Type:</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.375rem' }}>
            <FilterChipGroup
              chips={scopeInlineWithIcons}
              selected={scopeFilter || ''}
              onSelect={handleTypeToggle}
              multiple={false}
              showBadge={false}
            />
            {scopeOverflowWithIcons.length > 0 && (
              <FilterOverflowMenu
                options={scopeOverflowWithIcons}
                selected={new Set(scopeFilter ? [scopeFilter] : [])}
                onToggle={handleTypeToggle}
                onClear={handleTypeClear}
                facetLabel="Type"
                showBadge={false}
                currentValue={scopeFilter || ''}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default AuditFilters;
