import React, { useState, useRef, useEffect } from 'react';
import { Badge } from '../Badge';
import type { FilterOption } from './types';

interface FilterOverflowMenuProps {
  /** All available options (will be filtered to show overflow items) */
  options: FilterOption[];
  /** Currently selected values (Set<string> for multi-select) */
  selected: Set<string>;
  /** Called when a checkbox is toggled */
  onToggle: (value: string) => void;
  /** Called when "Clear" button is clicked — resets only this overflow menu's selections */
  onClear: () => void;
  /** For data-testid and debug purposes */
  facetLabel?: string;
  /** Whether to show count badges on menu items (default: true) */
  showBadge?: boolean;
  /** Current single-select value (optional); if set and in options, shows its label in trigger */
  currentValue?: string;
}

/**
 * FilterOverflowMenu — dropdown menu for low-frequency/zero-count filter items
 * Supports multi-select (checkboxes) with optional icons
 * Shows "Show more (N)" badge when items are selected inside
 */
export const FilterOverflowMenu: React.FC<FilterOverflowMenuProps> = ({
  options,
  selected,
  onToggle,
  onClear,
  facetLabel = 'More',
  showBadge = true,
  currentValue,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (
        menuRef.current &&
        triggerRef.current &&
        !menuRef.current.contains(e.target as Node) &&
        !triggerRef.current.contains(e.target as Node)
      ) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') setIsOpen(false);
  };

  // For single-select facets, if currentValue is in options, show it in trigger
  const selectedOption =
    currentValue !== undefined ? options.find(opt => opt.value === currentValue) : undefined;
  const triggerLabel = selectedOption ? selectedOption.label : 'Show more';

  // Count how many items from this menu are selected
  const selectedCount = selected.size;

  return (
    <div style={{ position: 'relative', display: 'inline-block' }}>
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className={`filter-overflow-trigger${isOpen ? ' filter-overflow-trigger--open' : ''}`}
        style={{
          padding: '0.45rem 1rem',
          borderRadius: 'var(--radius-sm, 0.375rem)',
          border: `1px solid ${isOpen ? '#4a90e2' : '#dee2e6'}`,
          backgroundColor: isOpen ? '#f0f4ff' : '#fff',
          color: isOpen ? '#4a90e2' : '#6c757d',
          fontWeight: 500,
          fontSize: '0.8125rem',
          cursor: 'pointer',
          transition: 'all 0.15s ease',
          display: 'inline-flex',
          alignItems: 'center',
          gap: '0.4rem',
        }}
        data-testid={`filter-overflow-trigger-${facetLabel?.toLowerCase()}`}
      >
        {triggerLabel}
        {selectedCount > 0 && <Badge value={selectedCount} tone="secondary" size="sm" />}
        <i
          className="fas fa-chevron-down"
          style={{
            fontSize: '0.65rem',
            transition: 'transform 0.15s ease',
            transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)',
          }}
          aria-hidden="true"
        />
      </button>

      {isOpen && (
        <div
          ref={menuRef}
          onKeyDown={handleKeyDown}
          className="filter-overflow-menu"
          style={{
            position: 'absolute',
            top: 'calc(100% + 0.5rem)',
            left: 0,
            backgroundColor: '#fff',
            border: '1px solid #dee2e6',
            borderRadius: 'var(--radius-sm, 0.375rem)',
            boxShadow: '0 2px 8px rgba(0, 0, 0, 0.1)',
            zIndex: 1000,
            minWidth: '200px',
          }}
          data-testid={`filter-overflow-menu-${facetLabel?.toLowerCase()}`}
        >
          {/* Menu items as checkboxes */}
          {options.map(option => (
            <label
              key={option.value || 'all'}
              className="filter-overflow-item"
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '0.5rem',
                padding: '0.625rem 1rem',
                cursor: 'pointer',
                borderBottom: '1px solid #f0f0f0',
                transition: 'background-color 0.15s ease',
              }}
              onMouseEnter={e => {
                (e.currentTarget as HTMLLabelElement).style.backgroundColor = '#f8f9fa';
              }}
              onMouseLeave={e => {
                (e.currentTarget as HTMLLabelElement).style.backgroundColor = 'transparent';
              }}
            >
              <input
                type="checkbox"
                checked={
                  currentValue !== undefined
                    ? option.value === currentValue
                    : selected.has(option.value)
                }
                onChange={() => onToggle(option.value)}
                style={{ cursor: 'pointer' }}
                data-testid={`filter-overflow-checkbox-${option.value || 'all'}`}
              />
              {option.icon && (
                <i
                  className={`fas ${option.icon}`}
                  style={{ fontSize: '0.8rem', opacity: 0.7 }}
                  aria-hidden="true"
                />
              )}
              <span style={{ fontSize: '0.8125rem', flex: 1 }}>{option.label}</span>
              {option.count === 0 && (
                <span style={{ fontSize: '0.75rem', color: '#999', opacity: 0.7 }}>(0)</span>
              )}
              {showBadge && option.count !== undefined && option.count > 0 && (
                <Badge value={option.count} tone="secondary" size="sm" />
              )}
            </label>
          ))}

          {/* Clear button */}
          <button
            type="button"
            onClick={() => {
              onClear();
              setIsOpen(false);
            }}
            className="filter-overflow-clear"
            style={{
              width: '100%',
              padding: '0.625rem 1rem',
              textAlign: 'left',
              border: 'none',
              backgroundColor: '#f8f9fa',
              color: '#6c757d',
              fontSize: '0.8125rem',
              fontWeight: 500,
              cursor: 'pointer',
              transition: 'background-color 0.15s ease',
              borderTop: '1px solid #dee2e6',
            }}
            onMouseEnter={e => {
              (e.target as HTMLButtonElement).style.backgroundColor = '#e9ecef';
            }}
            onMouseLeave={e => {
              (e.target as HTMLButtonElement).style.backgroundColor = '#f8f9fa';
            }}
            data-testid={`filter-overflow-clear-${facetLabel?.toLowerCase()}`}
          >
            Clear
          </button>
        </div>
      )}
    </div>
  );
};
