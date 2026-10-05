import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';

/**
 * Two-line option shape for `FormSelect`. `description` renders as a
 * small muted subheader under `label`; when omitted the option renders
 * as a single-line entry.
 */
export interface FormSelectOption<T extends string> {
  value: T;
  label: string;
  description?: string;
  disabled?: boolean;
  indent?: boolean;
}

interface FormSelectProps<T extends string> {
  value: T;
  options: readonly FormSelectOption<T>[];
  onChange: (value: T) => void;
  /** Applied to the toggle button so existing testids keep working. */
  testid?: string;
  size?: 'sm' | 'lg';
  disabled?: boolean;
  /**
   * When `true`, adds Bootstrap's `.is-invalid` class to the toggle so
   * a sibling `.invalid-feedback` styles as an error message and the
   * toggle picks up the red-border validation state — mirrors the
   * `Form.Select`/`Form.Control` `isInvalid` prop shape.
   */
  isInvalid?: boolean;
  /** Rendered on the toggle when no option matches `value`. */
  placeholder?: string;
  className?: string;
  ariaLabel?: string;
}

function nextEnabledIndex<T extends string>(
  options: readonly FormSelectOption<T>[],
  from: number,
  direction: 1 | -1
): number {
  if (options.length === 0) return -1;
  const n = options.length;
  let idx = from;
  for (let i = 0; i < n; i++) {
    idx = (idx + direction + n) % n;
    if (!options[idx].disabled) return idx;
  }
  return -1;
}

function firstEnabledIndex<T extends string>(options: readonly FormSelectOption<T>[]): number {
  return options.findIndex(o => !o.disabled);
}

function lastEnabledIndex<T extends string>(options: readonly FormSelectOption<T>[]): number {
  for (let i = options.length - 1; i >= 0; i--) if (!options[i].disabled) return i;
  return -1;
}

/**
 * Bootstrap-styled controlled listbox rendering two-line options
 * (header + optional subheader). Mimics `<Form.Select>`'s look at
 * `size="sm"` and supports arrow-key nav, Enter/Space to open/select,
 * Escape to close, Home/End, and click-outside dismiss.
 *
 * Shared form primitive; import as a bare default
 * (`import FormSelect from '.../shared/FormSelect'`). Distinct from
 * `react-bootstrap`'s namespaced `Form.Select` — the two can coexist
 * in the same module.
 */
function FormSelect<T extends string>({
  value,
  options,
  onChange,
  testid,
  size = 'sm',
  disabled = false,
  isInvalid = false,
  placeholder,
  className,
  ariaLabel,
}: FormSelectProps<T>): React.ReactElement {
  const [open, setOpen] = useState(false);
  const [highlightIdx, setHighlightIdx] = useState<number>(() => {
    const i = options.findIndex(o => o.value === value);
    return i >= 0 ? i : firstEnabledIndex(options);
  });

  const [keyboardActive, setKeyboardActive] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const menuId = useId();
  const optionId = useCallback((idx: number) => `${menuId}-opt-${idx}`, [menuId]);

  const selectedIdx = useMemo(() => options.findIndex(o => o.value === value), [options, value]);
  const selectedOption = selectedIdx >= 0 ? options[selectedIdx] : undefined;

  const openMenu = useCallback(() => {
    if (disabled) return;
    setHighlightIdx(prev =>
      prev >= 0 && !options[prev]?.disabled ? prev : firstEnabledIndex(options)
    );
    setKeyboardActive(false);
    setOpen(true);
  }, [disabled, options]);

  const closeMenu = useCallback((focusToggle: boolean) => {
    setOpen(false);
    if (focusToggle) toggleRef.current?.focus();
  }, []);

  const commit = useCallback(
    (idx: number) => {
      const opt = options[idx];
      if (!opt || opt.disabled) return;
      onChange(opt.value);
      closeMenu(true);
    },
    [options, onChange, closeMenu]
  );

  useEffect(() => {
    if (!open) return;
    const handler = (event: MouseEvent) => {
      if (!rootRef.current) return;
      if (!rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const handleToggleKey = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    if (disabled) return;
    switch (event.key) {
      case 'ArrowDown':
      case 'ArrowUp':
      case 'Enter':
      case ' ':
        event.preventDefault();
        openMenu();
        return;
      case 'Escape':
        if (open) {
          event.preventDefault();
          closeMenu(false);
        }
        return;
    }
  };

  const handleMenuKey = (event: React.KeyboardEvent<HTMLUListElement>) => {
    switch (event.key) {
      case 'ArrowDown':
        event.preventDefault();
        setKeyboardActive(true);
        setHighlightIdx(prev => nextEnabledIndex(options, prev, 1));
        return;
      case 'ArrowUp':
        event.preventDefault();
        setKeyboardActive(true);
        setHighlightIdx(prev => nextEnabledIndex(options, prev, -1));
        return;
      case 'Home':
        event.preventDefault();
        setKeyboardActive(true);
        setHighlightIdx(firstEnabledIndex(options));
        return;
      case 'End':
        event.preventDefault();
        setKeyboardActive(true);
        setHighlightIdx(lastEnabledIndex(options));
        return;
      case 'Enter':
      case ' ':
        event.preventDefault();
        commit(highlightIdx);
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
  const toggleLabel = selectedOption?.label ?? placeholder ?? '';
  const toggleDescription = selectedOption?.description;

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
        title={toggleDescription ? `${toggleLabel} — ${toggleDescription}` : undefined}
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
          <span className="text-muted">Select…</span>
        )}
      </button>
      {open && (
        <ul
          id={menuId}
          role="listbox"
          className="dropdown-menu show w-100"
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            zIndex: 1000,
            maxHeight: 320,
            overflowY: 'auto',
          }}
          tabIndex={-1}
          onKeyDown={handleMenuKey}
          onMouseMove={() => {
            if (keyboardActive) setKeyboardActive(false);
          }}
          ref={el => {
            if (el && open) el.focus();
          }}
        >
          {options.map((opt, idx) => {
            const isSelected = idx === selectedIdx;
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
                  onClick={() => commit(idx)}
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

export default FormSelect;
