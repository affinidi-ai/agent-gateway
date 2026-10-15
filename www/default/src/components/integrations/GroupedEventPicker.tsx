import React, { useEffect, useRef, useState } from 'react';

/** One selectable event, listed under its group. */
export interface PickerEntry {
  key: string;
  label: string;
  description: string;
  group: string;
  groupLabel: string;
}

interface GroupedEventPickerProps {
  /** Selectable events, in display order. */
  entries: PickerEntry[];
  /** Selected event keys. Keys the entries do not list are kept as they are. */
  selected: string[];
  onChange: (selected: string[]) => void;
  /** Prefix for the toggles' ids and data-testids, unique on the page. */
  testIdPrefix: string;
  disabled?: boolean;
  /** Adds a search box and a count of the selected events. */
  searchable?: boolean;
}

interface Group {
  group: string;
  label: string;
  entries: PickerEntry[];
}

/** Groups the entries in order of first appearance. */
const groupEntries = (entries: PickerEntry[]): Group[] => {
  const groups: Group[] = [];
  for (const entry of entries) {
    let group = groups.find(candidate => candidate.group === entry.group);
    if (!group) {
      group = { group: entry.group, label: entry.groupLabel, entries: [] };
      groups.push(group);
    }
    group.entries.push(entry);
  }
  return groups;
};

interface GroupToggleProps {
  id: string;
  checked: boolean;
  indeterminate: boolean;
  disabled: boolean;
  onToggle: () => void;
  label: string;
}

/** A checkbox whose partial state is shown with the native `indeterminate` property. */
const GroupToggle: React.FC<GroupToggleProps> = ({
  id,
  checked,
  indeterminate,
  disabled,
  onToggle,
  label,
}) => {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (ref.current) {
      ref.current.indeterminate = indeterminate;
    }
  }, [indeterminate]);
  return (
    <div className="custom-control custom-checkbox mb-1">
      <input
        ref={ref}
        type="checkbox"
        className="custom-control-input"
        id={id}
        data-testid={id}
        checked={checked}
        disabled={disabled}
        onChange={onToggle}
      />
      <label className="custom-control-label font-weight-bold" htmlFor={id}>
        {label}
      </label>
    </div>
  );
};

const matchesSearch = (entry: PickerEntry, term: string) =>
  [entry.label, entry.key, entry.description, entry.groupLabel].some(text =>
    text.toLowerCase().includes(term)
  );

/**
 * Chooses events: each is listed under its group, each group has a toggle that turns the
 * events it shows on or off, and each event has its own toggle.
 */
const GroupedEventPicker: React.FC<GroupedEventPickerProps> = ({
  entries,
  selected,
  onChange,
  testIdPrefix,
  disabled = false,
  searchable = false,
}) => {
  const [search, setSearch] = useState('');
  const term = search.trim().toLowerCase();
  const shown = term ? entries.filter(entry => matchesSearch(entry, term)) : entries;
  const isSelected = (key: string) => selected.includes(key);

  const setEvents = (keys: string[], on: boolean) => {
    const remaining = selected.filter(key => !keys.includes(key));
    onChange(on ? [...remaining, ...keys] : remaining);
  };

  const toggleEvent = (key: string) =>
    onChange(isSelected(key) ? selected.filter(name => name !== key) : [...selected, key]);

  const selectedCount = entries.filter(entry => isSelected(entry.key)).length;

  return (
    <div data-testid={`${testIdPrefix}-picker`}>
      {searchable && (
        <div className="d-flex align-items-center gap-3 mb-3">
          <input
            type="search"
            className="form-control"
            style={{ maxWidth: '320px' }}
            placeholder="Search events"
            aria-label="Search events"
            value={search}
            onChange={event => setSearch(event.target.value)}
          />
          <span className="text-muted small">
            {selectedCount} of {entries.length} events selected
          </span>
        </div>
      )}
      {shown.length === 0 && <p className="text-muted">No events match your search.</p>}
      {groupEntries(shown).map(group => {
        const keys = group.entries.map(entry => entry.key);
        const groupSelected = keys.filter(isSelected).length;
        const allOn = groupSelected === keys.length;
        return (
          <fieldset key={group.group} className="mb-3">
            <GroupToggle
              id={`${testIdPrefix}-group-${group.group}`}
              checked={allOn}
              indeterminate={groupSelected > 0 && !allOn}
              disabled={disabled}
              onToggle={() => setEvents(keys, !allOn)}
              label={group.label}
            />
            <div className="pl-4">
              {group.entries.map(entry => {
                const id = `${testIdPrefix}-event-${entry.key}`;
                return (
                  <div key={entry.key} className="custom-control custom-checkbox mb-1">
                    <input
                      type="checkbox"
                      className="custom-control-input"
                      id={id}
                      data-testid={id}
                      checked={isSelected(entry.key)}
                      disabled={disabled}
                      onChange={() => toggleEvent(entry.key)}
                    />
                    <label className="custom-control-label" htmlFor={id}>
                      {entry.label}
                      <small className="d-block text-muted">{entry.description}</small>
                    </label>
                  </div>
                );
              })}
            </div>
          </fieldset>
        );
      })}
    </div>
  );
};

export default GroupedEventPicker;
