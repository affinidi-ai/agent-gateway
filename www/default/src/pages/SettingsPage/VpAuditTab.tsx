import React, { useEffect, useRef, useState } from 'react';
import { AuditEventCatalogEntry, Settings } from '../../types';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import FieldHelp from '../../components/shared/FieldHelp';
import AuditEventPicker from '../../components/integrations/AuditEventPicker';

interface VpAuditTabProps {
  settings: Settings | null;
  updateSettings: (settings: Partial<Settings>) => Promise<void>;
  /** Loads the selectable audit events; the API by default. */
  loadCatalog?: () => Promise<AuditEventCatalogEntry[]>;
}

const VpAuditTab: React.FC<VpAuditTabProps> = ({
  settings,
  updateSettings,
  loadCatalog = () => apiClient.getAuditEventCatalog(),
}) => {
  const [auditEnabled, setAuditEnabled] = useState(settings?.audit_enabled ?? false);
  const [events, setEvents] = useState<string[]>(settings?.audit_events ?? []);
  const [catalog, setCatalog] = useState<AuditEventCatalogEntry[]>([]);
  const [catalogError, setCatalogError] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const initialized = useRef(false);

  useEffect(() => {
    // Only sync from settings once on mount to avoid overwriting the user's
    // in-progress edits when the parent re-renders with a stale settings value.
    if (initialized.current || settings === null) return;
    initialized.current = true;
    setAuditEnabled(settings.audit_enabled ?? false);
    setEvents(settings.audit_events ?? []);
  }, [settings]);

  useEffect(() => {
    let active = true;
    loadCatalog()
      .then(entries => {
        if (active) setCatalog(entries);
      })
      .catch(() => {
        if (active) setCatalogError(true);
      });
    return () => {
      active = false;
    };
    // Load once; the catalog does not change while the page is open.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    showToast('loading', 'Saving VP Audit settings...');
    try {
      await updateSettings({
        audit_enabled: auditEnabled,
        audit_events: events,
      });
      showToast('success', 'VP Audit settings saved!');
    } catch (error) {
      const msg = error instanceof Error ? error.message : 'Failed to save';
      showToast('error', msg);
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="card shadow mb-3">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-file-contract"></i> VP Audit
        </h6>
      </div>
      <div className="card-body">
        <p className="text-muted mb-3">
          Record VP evidence of gateway authorisation decisions for compliance auditing.{' '}
          <FieldHelp testId="field-help-vp-audit-intro" ariaLabel="About VP Auditing">
            A VP (Verifiable Presentation) is a cryptographically signed record. Enabling this keeps
            one for every event selected below, so you can prove after the fact what the gateway
            allowed or denied and why.
          </FieldHelp>
        </p>
        <p className="text-muted mb-3" data-testid="vp-audit-scope-note">
          These settings control the VP Audit Log only. Governance Audit integrations choose their
          own events, whether or not the log keeps them.
        </p>
        <form onSubmit={handleSave}>
          <div className="mb-3">
            <div className="custom-control custom-switch">
              <input
                type="checkbox"
                className="custom-control-input"
                id="audit_enabled"
                data-testid="vp-audit-enabled-toggle"
                checked={auditEnabled}
                onChange={e => setAuditEnabled(e.target.checked)}
              />
              <label className="custom-control-label" htmlFor="audit_enabled">
                Enable VP Auditing
              </label>
            </div>
          </div>

          {auditEnabled && (
            <div className="mb-3 pl-3">
              <h6 className="mb-2 font-weight-bold">Events to keep</h6>
              {catalogError ? (
                <p className="text-danger" data-testid="vp-audit-catalog-error">
                  The list of audit events could not be loaded. Reload the page to try again.
                </p>
              ) : (
                <AuditEventPicker
                  testIdPrefix="vp-audit"
                  catalog={catalog}
                  selected={events}
                  onChange={setEvents}
                  disabled={isSaving}
                />
              )}
            </div>
          )}

          <button
            type="submit"
            className="btn btn-primary btn-sm"
            data-testid="vp-audit-save-button"
            disabled={isSaving}
          >
            {isSaving ? (
              <>
                <i className="fas fa-spinner fa-spin"></i> Saving...
              </>
            ) : (
              <>
                <i className="fas fa-save"></i> Save
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
};

export default VpAuditTab;
