import React from 'react';
import type { AuditEventCatalogEntry } from '../../types';
import GroupedEventPicker from './GroupedEventPicker';

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

/** Chooses which audit events a sink receives, grouped as the audit catalog groups them. */
const AuditEventPicker: React.FC<AuditEventPickerProps> = ({ catalog, ...props }) => (
  <GroupedEventPicker
    {...props}
    entries={catalog.map(entry => ({
      key: entry.event,
      label: entry.label,
      description: entry.description,
      group: entry.group,
      groupLabel: entry.group_label,
    }))}
  />
);

export default AuditEventPicker;
