import React, { useMemo } from 'react';
import {
  firstEnabledIndex,
  ListboxOptions,
  ListboxToggleContent,
  selectSizeClass,
  useListbox,
} from './listbox';
import type { FormSelectOption } from './listbox';

export type { FormSelectOption } from './listbox';

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
  const selectedIdx = useMemo(() => options.findIndex(o => o.value === value), [options, value]);
  const selectedOption = selectedIdx >= 0 ? options[selectedIdx] : undefined;
  const listbox = useListbox({
    options,
    disabled,
    initialHighlight: selectedIdx >= 0 ? selectedIdx : firstEnabledIndex(options),
    onActivate: onChange,
    closeOnActivate: true,
  });

  const toggleLabel = selectedOption?.label ?? placeholder ?? '';
  const toggleDescription = selectedOption?.description;

  return (
    <div ref={listbox.rootRef} className={`position-relative ${className || ''}`}>
      <button
        {...listbox.toggleProps}
        role="combobox"
        aria-expanded={listbox.open}
        aria-controls={listbox.open ? listbox.menuId : undefined}
        className={`form-select ${selectSizeClass(size)} text-start text-truncate${isInvalid ? ' is-invalid' : ''}`}
        aria-invalid={isInvalid || undefined}
        aria-label={ariaLabel}
        data-testid={testid}
        title={toggleDescription ? `${toggleLabel} — ${toggleDescription}` : undefined}
      >
        <ListboxToggleContent label={toggleLabel} description={toggleDescription} />
      </button>
      {listbox.open && (
        <ul
          {...listbox.menuProps}
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
        >
          <ListboxOptions
            options={options}
            isSelected={(_opt, idx) => idx === selectedIdx}
            listbox={listbox}
            testid={testid}
          />
        </ul>
      )}
    </div>
  );
}

export default FormSelect;
