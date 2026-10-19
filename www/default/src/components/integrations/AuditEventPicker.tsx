import React, { useEffect, useRef } from 'react';
import type { AuditEventCatalogEntry } from '../../types';

interface AuditEventPickerProps {
  /** Selectable events, in display order, from `GET /v1/settings/audit-events`. */
  catalog: AuditEventCatalogEntry[];
  /** Selected event names. Names the catalog does not list are kept as they are. */
  selected: string[];
  onChange: (selected: string[]) => void;
  /** Prefix for the toggles' ids and data-testids, unique on the page. */
  testIdPrefix: string;
  disabled?: boolean;
}

interface Group {
  group: string;
  label: string;
  events: AuditEventCatalogEntry[];
}

/** Groups the catalog in order of first appearance. */
const groupCatalog = (catalog: AuditEventCatalogEntry[]): Group[] => {
  const groups: Group[] = [];
  for (const entry of catalog) {
    let group = groups.find(candidate => candidate.group === entry.group);
    if (!group) {
      group = { group: entry.group, label: entry.group_label, events: [] };
      groups.push(group);
    }
    group.events.push(entry);
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

/**
 * Chooses which audit events a sink receives: events are listed under their
 * group, each group has a toggle that turns the whole group on or off, and
 * each event has its own toggle.
 */
const AuditEventPicker: React.FC<AuditEventPickerProps> = ({
  catalog,
  selected,
  onChange,
  testIdPrefix,
  disabled = false,
}) => {
  const isSelected = (event: string) => selected.includes(event);

  const setEvents = (events: string[], on: boolean) => {
    const remaining = selected.filter(name => !events.includes(name));
    onChange(on ? [...remaining, ...events] : remaining);
  };

  const toggleEvent = (event: string) => {
    if (isSelected(event)) {
      onChange(selected.filter(name => name !== event));
    } else {
      onChange([...selected, event]);
    }
  };

  return (
    <div data-testid={`${testIdPrefix}-picker`}>
      {groupCatalog(catalog).map(group => {
        const names = group.events.map(entry => entry.event);
        const selectedCount = names.filter(isSelected).length;
        const allOn = selectedCount === names.length;
        return (
          <fieldset key={group.group} className="mb-3">
            <GroupToggle
              id={`${testIdPrefix}-group-${group.group}`}
              checked={allOn}
              indeterminate={selectedCount > 0 && !allOn}
              disabled={disabled}
              onToggle={() => setEvents(names, !allOn)}
              label={group.label}
            />
            <div className="pl-4">
              {group.events.map(entry => {
                const id = `${testIdPrefix}-event-${entry.event}`;
                return (
                  <div key={entry.event} className="custom-control custom-checkbox mb-1">
                    <input
                      type="checkbox"
                      className="custom-control-input"
                      id={id}
                      data-testid={id}
                      checked={isSelected(entry.event)}
                      disabled={disabled}
                      onChange={() => toggleEvent(entry.event)}
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

export default AuditEventPicker;
