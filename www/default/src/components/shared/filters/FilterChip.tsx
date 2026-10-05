import React from 'react';
import { Badge } from '../Badge';

interface FilterChipProps {
  value: string;
  label: string;
  selected: boolean;
  count?: number;
  onClick: () => void;
  ariaPressed?: boolean;
  showBadge?: boolean;
}

/**
 * FilterChip — single filter button with optional count badge
 * Uses --radius-sm (0.375rem) for visual distinction from tab-like components
 */
export const FilterChip: React.FC<FilterChipProps> = ({
  value,
  label,
  selected,
  count,
  onClick,
  ariaPressed,
  showBadge = true,
}) => (
  <button
    type="button"
    onClick={onClick}
    aria-pressed={ariaPressed}
    className={`filter-chip${selected ? ' filter-chip--selected' : ''}`}
    data-testid={`filter-chip-${value || 'all'}`}
    style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '0.4rem',
      padding: '0.45rem 1rem',
      borderRadius: 'var(--radius-sm, 0.375rem)',
      border: `1px solid ${selected ? '#4a90e2' : '#dee2e6'}`,
      backgroundColor: selected ? '#f0f4ff' : '#fff',
      color: selected ? '#4a90e2' : '#6c757d',
      fontWeight: 500,
      fontSize: '0.8125rem',
      cursor: 'pointer',
      transition: 'all 0.15s ease',
    }}
    onMouseEnter={e => {
      if (!selected) {
        (e.target as HTMLButtonElement).style.backgroundColor = '#f8f9fa';
        (e.target as HTMLButtonElement).style.borderColor = '#4a90e2';
        (e.target as HTMLButtonElement).style.color = '#4a90e2';
      }
    }}
    onMouseLeave={e => {
      if (!selected) {
        (e.target as HTMLButtonElement).style.backgroundColor = '#fff';
        (e.target as HTMLButtonElement).style.borderColor = '#dee2e6';
        (e.target as HTMLButtonElement).style.color = '#6c757d';
      }
    }}
  >
    {label}
    {count === 0 && (
      <span style={{ fontSize: '0.75rem', color: 'inherit', opacity: 0.7, marginLeft: '0.25rem' }}>
        (0)
      </span>
    )}
    {showBadge && count !== undefined && count > 0 && (
      <Badge value={count} tone={selected ? 'primary' : 'secondary'} size="sm" className="ms-1" />
    )}
  </button>
);
