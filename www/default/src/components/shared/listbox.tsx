import React, { useCallback, useEffect, useId, useRef, useState } from 'react';

/**
 * Two-line option shape for `FormSelect` and `FormMultiSelect`. `description` renders as a
 * small muted subheader under `label`; when omitted the option renders as a single-line entry.
 */
export interface FormSelectOption<T extends string> {
  value: T;
  label: string;
  description?: string;
  disabled?: boolean;
  indent?: boolean;
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

export function firstEnabledIndex<T extends string>(
  options: readonly FormSelectOption<T>[]
): number {
  return options.findIndex(o => !o.disabled);
}

function lastEnabledIndex<T extends string>(options: readonly FormSelectOption<T>[]): number {
  for (let i = options.length - 1; i >= 0; i--) if (!options[i].disabled) return i;
  return -1;
}

interface UseListboxArgs<T extends string> {
  options: readonly FormSelectOption<T>[];
  disabled: boolean;
  /** Option highlighted before the menu is first opened. */
  initialHighlight: number;
  /** Called with an enabled option's value on click, Enter or Space. */
  onActivate: (value: T) => void;
  /** Close the menu and refocus the toggle after an activation. */
  closeOnActivate: boolean;
}

/**
 * The keyboard, focus and outside-click behaviour `FormSelect` and `FormMultiSelect` share:
 * arrow keys, Home and End move the highlight over enabled options; Enter or Space activates it;
 * Escape closes and refocuses the toggle; Tab and a click outside close. The caller sets
 * `role="combobox"`, `aria-expanded` and `aria-controls` on the toggle and `role="listbox"` on
 * the menu, so the a11y lint rules can see them.
 */
export function useListbox<T extends string>({
  options,
  disabled,
  initialHighlight,
  onActivate,
  closeOnActivate,
}: UseListboxArgs<T>) {
  const [open, setOpen] = useState(false);
  const [highlightIdx, setHighlightIdx] = useState(initialHighlight);
  const [keyboardActive, setKeyboardActive] = useState(false);
  const rootRef = useRef<HTMLDivElement | null>(null);
  const toggleRef = useRef<HTMLButtonElement | null>(null);
  const menuId = useId();
  const optionId = useCallback((idx: number) => `${menuId}-opt-${idx}`, [menuId]);

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

  const activate = useCallback(
    (idx: number) => {
      const opt = options[idx];
      if (!opt || opt.disabled) return;
      onActivate(opt.value);
      if (closeOnActivate) closeMenu(true);
    },
    [options, onActivate, closeOnActivate, closeMenu]
  );

  useEffect(() => {
    if (!open) return;
    const handler = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  const moveHighlight = (event: React.KeyboardEvent, next: (prev: number) => number) => {
    event.preventDefault();
    setKeyboardActive(true);
    setHighlightIdx(next);
  };

  const toggleProps = {
    ref: toggleRef,
    type: 'button' as const,
    'aria-haspopup': 'listbox' as const,
    'aria-activedescendant': open && highlightIdx >= 0 ? optionId(highlightIdx) : undefined,
    disabled,
    onClick: () => (open ? closeMenu(false) : openMenu()),
    onKeyDown: (event: React.KeyboardEvent<HTMLButtonElement>) => {
      if (disabled) return;
      if (['ArrowDown', 'ArrowUp', 'Enter', ' '].includes(event.key)) {
        event.preventDefault();
        openMenu();
      } else if (event.key === 'Escape' && open) {
        event.preventDefault();
        closeMenu(false);
      }
    },
  };

  const menuProps = {
    id: menuId,
    tabIndex: -1,
    onKeyDown: (event: React.KeyboardEvent<HTMLUListElement>) => {
      switch (event.key) {
        case 'ArrowDown':
          moveHighlight(event, prev => nextEnabledIndex(options, prev, 1));
          return;
        case 'ArrowUp':
          moveHighlight(event, prev => nextEnabledIndex(options, prev, -1));
          return;
        case 'Home':
          moveHighlight(event, () => firstEnabledIndex(options));
          return;
        case 'End':
          moveHighlight(event, () => lastEnabledIndex(options));
          return;
        case 'Enter':
        case ' ':
          event.preventDefault();
          activate(highlightIdx);
          return;
        case 'Escape':
          event.preventDefault();
          closeMenu(true);
          return;
        case 'Tab':
          closeMenu(false);
          return;
      }
    },
    onMouseMove: () => {
      if (keyboardActive) setKeyboardActive(false);
    },
    ref: (el: HTMLUListElement | null) => {
      if (el && !el.contains(document.activeElement)) el.focus();
    },
  };

  return {
    open,
    menuId,
    rootRef,
    toggleProps,
    menuProps,
    optionId,
    highlightIdx,
    keyboardActive,
    activate,
  };
}

/** The toggle's text: the label, then the description muted beside it, or the placeholder. */
export function ListboxToggleContent({
  label,
  description,
  placeholder,
}: {
  label: string;
  description?: string;
  placeholder?: string;
}): React.ReactElement {
  if (!label) return <span className="text-muted">{placeholder ?? 'Select…'}</span>;
  return (
    <>
      {label}
      {description && (
        <span className="text-muted ms-2" style={{ fontSize: '11px' }}>
          {description}
        </span>
      )}
    </>
  );
}

/** The options of an open listbox, each with a right-hand check while selected. */
export function ListboxOptions<T extends string>({
  options,
  isSelected,
  listbox,
  testid,
}: {
  options: readonly FormSelectOption<T>[];
  isSelected: (opt: FormSelectOption<T>, idx: number) => boolean;
  listbox: {
    optionId: (idx: number) => string;
    highlightIdx: number;
    keyboardActive: boolean;
    activate: (idx: number) => void;
  };
  testid?: string;
}): React.ReactElement {
  return (
    <>
      {options.map((opt, idx) => {
        const selected = isSelected(opt, idx);
        const highlighted = listbox.keyboardActive && idx === listbox.highlightIdx;
        return (
          <li key={opt.value}>
            <button
              type="button"
              id={listbox.optionId(idx)}
              role="option"
              aria-selected={selected}
              disabled={opt.disabled}
              className={`dropdown-item ${highlighted ? 'active' : ''}`}
              data-testid={testid ? `${testid}-option-${opt.value}` : undefined}
              onClick={() => listbox.activate(idx)}
            >
              <div className={`d-flex align-items-start gap-2 ${opt.indent ? 'ps-3' : ''}`}>
                <div className="flex-grow-1" style={{ minWidth: 0 }}>
                  <div className="fw-semibold" style={{ fontSize: '12px' }}>
                    {opt.label}
                  </div>
                  {opt.description && (
                    <div
                      className={highlighted ? '' : 'text-muted'}
                      style={{ fontSize: '11px', whiteSpace: 'normal' }}
                    >
                      {opt.description}
                    </div>
                  )}
                </div>
                {selected && (
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
    </>
  );
}

export function selectSizeClass(size: 'sm' | 'lg'): string {
  return size === 'lg' ? 'form-select-lg' : 'form-select-sm';
}
