import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import type { AuditEventCatalogEntry } from '../../types';
import AuditEventPicker from './AuditEventPicker';

interface AuditEventsSectionProps {
  /** The events this Governance Audit integration receives. */
  selected: string[];
  onChange: (selected: string[]) => void;
  disabled?: boolean;
  /** Loads the selectable audit events; the API by default. */
  loadCatalog?: () => Promise<AuditEventCatalogEntry[]>;
}

/** "Events to send" for a Governance Audit integration. */
const AuditEventsSection: React.FC<AuditEventsSectionProps> = ({
  selected,
  onChange,
  disabled = false,
  loadCatalog = () => apiClient.getAuditEventCatalog(),
}) => {
  const [catalog, setCatalog] = useState<AuditEventCatalogEntry[]>([]);
  const [loadFailed, setLoadFailed] = useState(false);

  useEffect(() => {
    let active = true;
    loadCatalog()
      .then(entries => {
        if (active) setCatalog(entries);
      })
      .catch(() => {
        if (active) setLoadFailed(true);
      });
    return () => {
      active = false;
    };
    // Load once; the catalog does not change while the page is open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="mb-3" data-testid="integration-audit-events">
      <label className="form-label fw-bold mb-1">Events to send</label>
      <p className="text-muted small mb-2">
        Only the events selected here are sent to this integration, whether or not the VP Audit Log
        keeps them.
      </p>
      {loadFailed ? (
        <p className="text-danger small mb-0" data-testid="integration-audit-events-error">
          The list of audit events could not be loaded, so it cannot be changed now. The
          integration&rsquo;s current selection is kept when you save.
        </p>
      ) : (
        <>
          <AuditEventPicker
            testIdPrefix="integration-audit"
            catalog={catalog}
            selected={selected}
            onChange={onChange}
            disabled={disabled}
          />
          {selected.length === 0 && (
            <p className="text-warning small mb-0" data-testid="integration-audit-events-empty">
              <i className="fas fa-exclamation-triangle me-1" aria-hidden="true"></i>
              No events are selected, so this integration will receive nothing.
            </p>
          )}
        </>
      )}
    </div>
  );
};

export default AuditEventsSection;
