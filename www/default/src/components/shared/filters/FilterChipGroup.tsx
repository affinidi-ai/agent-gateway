import React from 'react';
import { FilterChip } from './FilterChip';
import type { FilterOption } from './types';

interface FilterChipGroupProps {
  chips: FilterOption[];
  selected: Set<string> | string;
  onSelect: (value: string) => void;
  multiple?: boolean;
  showBadge?: boolean;
}

/**
 * FilterChipGroup — renders a set of filter chips for one facet
 * Supports both multi-select (Set<string>) and single-select (string) modes
 */
export const FilterChipGroup: React.FC<FilterChipGroupProps> = ({
  chips,
  selected,
  onSelect,
  multiple = false,
  showBadge = true,
}) => (
  <div
    style={{
      display: 'flex',
      alignItems: 'center',
      flexWrap: 'wrap',
      gap: '0.375rem',
    }}
  >
    {chips.map(chip => {
      let isSelected: boolean;
      if (multiple) {
        const selectedSet = selected as Set<string>;
        // "All" option (value='') is selected when the set is empty (no specific categories selected)
        if (chip.value === '') {
          isSelected = selectedSet.size === 0;
        } else {
          isSelected = selectedSet.has(chip.value);
        }
      } else {
        isSelected = (selected as string) === chip.value;
      }

      return (
        <FilterChip
          key={chip.value || 'all'}
          value={chip.value}
          label={chip.label}
          selected={isSelected}
          count={chip.count}
          onClick={() => onSelect(chip.value)}
          ariaPressed={multiple ? isSelected : undefined}
          showBadge={showBadge}
        />
      );
    })}
  </div>
);
