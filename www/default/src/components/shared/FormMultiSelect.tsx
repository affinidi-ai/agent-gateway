import React, { useCallback, useEffect, useId, useRef, useState } from 'react';
import type { FormSelectOption } from './FormSelect';

interface FormMultiSelectProps<T extends string> {
  /** Selected values, in the order they were picked. */
  values: readonly T[];
  options: readonly FormSelectOption<T>[];
  /** Called with the option the operator checked or unchecked; the menu stays open. */
  onToggle: (value: T) => void;
  /** Applied to the toggle button; each option gets `${testid}-option-${value}`. */
  testid?: string;
  size?: 'sm' | 'lg';
  disabled?: boolean;
  isInvalid?: boolean;
  /** Rendered on the toggle when nothing is selected. */
  placeholder?: string;
  className?: string;
  ariaLabel?: string;
}

function nextEnabledIndex<T extends string>(
  options: readonly FormSelectOption<T>[],
  from: number,
  direction: 1 | -1
): number {
  const n = options.length;
  let idx = from;
  for (let i = 0; i < n; i++) {
    idx = (idx + direction + n) % n;
    if (!options[idx].disabled) return idx;
  }
  return -1;
}

/**
 * `FormSelect`'s multi-select sibling: the same Bootstrap look and two-line options, with the same
 * right-hand check on each selected one. Clicking an option (or Enter/Space on the highlighted one) toggles it and keeps the
 * menu open; Escape, Tab or a click outside closes it. The toggle lists the selected labels in
 * `values` order. The menu opens in the page flow under the toggle, at most 320px tall, and
 * scrolls when the options are longer.
 */
function FormMultiSelect<T extends string>({
  values,
  options,
  onToggle,
  testid,
  size = 'sm',
  disabled = false,
  isInvalid = false,
  placeholder,
  className,
  ariaLabel,
}: FormMultiSelectProps<T>): React.ReactElement {
  const [open, setOpen] = useState(false);
  const [highlightIdx, setHighlightIdx] = useState(-1);
  const [keyboardActive, setKeyboardActive] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const menuId = useId();
  const optionId = useCallback((idx: number) => `${menuId}-opt-${idx}`, [menuId]);

  const selected = new Set<string>(values);
  const selectedOptions = values
    .map(v => options.find(o => o.value === v))
    .filter((o): o is FormSelectOption<T> => !!o);

  const openMenu = () => {
    if (disabled) return;
    setHighlightIdx(nextEnabledIndex(options, -1, 1));
    setKeyboardActive(false);
    setOpen(true);
  };

  const closeMenu = (focusToggle: boolean) => {
    setOpen(false);
    if (focusToggle) toggleRef.current?.focus();
  };

  const toggle = (idx: number) => {
    const opt = options[idx];
    if (!opt || opt.disabled) return;
    onToggle(opt.value);
  };

  useEffect(() => {
    if (!open) return;
    const handler = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const handleToggleKey = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return;
    if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(event.key)) {
      event.preventDefault();
      openMenu();
    } else if (event.key === 'Escape' && open) {
      event.preventDefault();
      closeMenu(false);
    }
  };

  const handleMenuKey = (event: React.KeyboardEvent<HTMLUListElement>) => {
    switch (event.key) {
      case 'ArrowDown':
      case 'ArrowUp':
        event.preventDefault();
        setKeyboardActive(true);
        setHighlightIdx(prev =>
          nextEnabledIndex(options, prev, event.key === 'ArrowDown' ? 1 : -1)
        );
        return;
      case 'Home':
        event.preventDefault();
        setKeyboardActive(true);
        setHighlightIdx(nextEnabledIndex(options, -1, 1));
        return;
      case 'End':
        event.preventDefault();
        setKeyboardActive(true);
        setHighlightIdx(nextEnabledIndex(options, 0, -1));
        return;
      case 'Enter':
      case ' ':
        event.preventDefault();
        toggle(highlightIdx);
        return;
      case 'Escape':
        event.preventDefault();
        closeMenu(true);
        return;
      case 'Tab':
        closeMenu(false);
        return;
    }
  };

  const sizeClass = size === 'lg' ? 'form-select-lg' : size === 'sm' ? 'form-select-sm' : '';
  const toggleLabel = selectedOptions.map(o => o.label).join(', ');
  const toggleDescription =
    selectedOptions.length === 1 ? selectedOptions[0].description : undefined;

  return (
    <div ref={rootRef} className={`position-relative ${className || ''}`}>
      <button
        ref={toggleRef}
        type="button"
        className={`form-select ${sizeClass} text-start text-truncate${isInvalid ? ' is-invalid' : ''}`}
        role="combobox"
        aria-haspopup="listbox"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        aria-activedescendant={open && highlightIdx >= 0 ? optionId(highlightIdx) : undefined}
        aria-invalid={isInvalid || undefined}
        aria-label={ariaLabel}
        disabled={disabled}
        data-testid={testid}
        onClick={() => (open ? closeMenu(false) : openMenu())}
        onKeyDown={handleToggleKey}
        title={
          toggleLabel
            ? toggleDescription
              ? `${toggleLabel} — ${toggleDescription}`
              : toggleLabel
            : undefined
        }
      >
        {toggleLabel ? (
          <>
            {toggleLabel}
            {toggleDescription && (
              <span className="text-muted ms-2" style={{ fontSize: '11px' }}>
                {toggleDescription}
              </span>
            )}
          </>
        ) : (
          <span className="text-muted">{placeholder ?? 'Select…'}</span>
        )}
      </button>
      {open && (
        <ul
          id={menuId}
          role="listbox"
          aria-multiselectable="true"
          className="dropdown-menu show w-100 mt-1"
          // In flow, not floating: a dashboard `.card` hides overflow, so a floating menu inside
          // one is cut off at the card's edge. In flow it pushes the form down and scrolls itself.
          style={{
            position: 'static',
            maxHeight: 320,
            overflowY: 'auto',
          }}
          tabIndex={-1}
          onKeyDown={handleMenuKey}
          onMouseMove={() => {
            if (keyboardActive) setKeyboardActive(false);
          }}
          ref={el => {
            if (el && open && !el.contains(document.activeElement)) el.focus();
          }}
        >
          {options.map((opt, idx) => {
            const isSelected = selected.has(opt.value);
            const isHighlighted = keyboardActive && idx === highlightIdx;
            return (
              <li key={opt.value}>
                <button
                  type="button"
                  id={optionId(idx)}
                  role="option"
                  aria-selected={isSelected}
                  disabled={opt.disabled}
                  className={`dropdown-item ${isHighlighted ? 'active' : ''}`}
                  data-testid={testid ? `${testid}-option-${opt.value}` : undefined}
                  onClick={() => toggle(idx)}
                >
                  <div className={`d-flex align-items-start gap-2 ${opt.indent ? 'ps-3' : ''}`}>
                    <div className="flex-grow-1" style={{ minWidth: 0 }}>
                      <div className="fw-semibold" style={{ fontSize: '12px' }}>
                        {opt.label}
                      </div>
                      {opt.description && (
                        <div
                          className={`${isHighlighted ? '' : 'text-muted'}`}
                          style={{ fontSize: '11px', whiteSpace: 'normal' }}
                        >
                          {opt.description}
                        </div>
                      )}
                    </div>
                    {isSelected && (
                      <i
                        className="fas fa-check mt-1"
                        style={{ fontSize: '10px' }}
                        aria-hidden="true"
                        data-testid={testid ? `${testid}-option-${opt.value}-check` : undefined}
                      />
                    )}
                  </div>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

export default FormMultiSelect;
