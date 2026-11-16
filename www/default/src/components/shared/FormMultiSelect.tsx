import React from 'react';
import { ListboxOptions, ListboxToggleContent, selectSizeClass, useListbox } from './listbox';
import type { FormSelectOption } from './listbox';

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

/**
 * `FormSelect`'s multi-select sibling on the same listbox core (`listbox.tsx`): the same
 * Bootstrap look, two-line options and right-hand check on each selected one. Clicking an option
 * (or Enter/Space on the highlighted one) toggles it and keeps the menu open; Escape, Tab or a
 * click outside closes it. The toggle lists the selected labels in `values` order. The menu opens
 * in the page flow under the toggle, at most 320px tall, and scrolls when the options are longer.
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
  const listbox = useListbox({
    options,
    disabled,
    initialHighlight: -1,
    onActivate: onToggle,
    closeOnActivate: false,
  });

  const selected = new Set<string>(values);
  const selectedOptions = values
    .map(v => options.find(o => o.value === v))
    .filter((o): o is FormSelectOption<T> => !!o);
  const toggleLabel = selectedOptions.map(o => o.label).join(', ');
  const toggleDescription =
    selectedOptions.length === 1 ? selectedOptions[0].description : undefined;

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
        title={
          toggleLabel
            ? toggleDescription
              ? `${toggleLabel} — ${toggleDescription}`
              : toggleLabel
            : undefined
        }
      >
        <ListboxToggleContent
          label={toggleLabel}
          description={toggleDescription}
          placeholder={placeholder}
        />
      </button>
      {listbox.open && (
        <ul
          {...listbox.menuProps}
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
        >
          <ListboxOptions
            options={options}
            isSelected={opt => selected.has(opt.value)}
            listbox={listbox}
            testid={testid}
          />
        </ul>
      )}
    </div>
  );
}

export default FormMultiSelect;
