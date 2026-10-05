import React, { useEffect, useRef, useState } from 'react';
import { Settings } from '../../types';
import { showToast } from '../../utils/toaster';
import FieldHelp from '../../components/shared/FieldHelp';

interface VpAuditTabProps {
  settings: Settings | null;
  updateSettings: (settings: Partial<Settings>) => Promise<void>;
}

const VpAuditTab: React.FC<VpAuditTabProps> = ({ settings, updateSettings }) => {
  const [auditEnabled, setAuditEnabled] = useState(settings?.audit_enabled ?? false);
  const [categories, setCategories] = useState({
    policies: settings?.audit_categories?.policies ?? false,
    trust_checks: settings?.audit_categories?.trust_checks ?? false,
    identity: settings?.audit_categories?.identity ?? false,
  });
  const [isSaving, setIsSaving] = useState(false);
  const initialized = useRef(false);

  useEffect(() => {
    // Only sync from settings once on mount to avoid overwriting the user's
    // in-progress edits when the parent re-renders with a stale settings value.
    if (initialized.current || settings === null) return;
    initialized.current = true;
    setAuditEnabled(settings.audit_enabled ?? false);
    setCategories({
      policies: settings.audit_categories?.policies ?? false,
      trust_checks: settings.audit_categories?.trust_checks ?? false,
      identity: settings.audit_categories?.identity ?? false,
    });
  }, [settings]);

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    showToast('loading', 'Saving VP Audit settings...');
    try {
      await updateSettings({
        audit_enabled: auditEnabled,
        audit_categories: categories,
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
            one for every decision below, so you can prove after the fact what the gateway allowed
            or denied and why.
          </FieldHelp>
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
              <h6 className="mb-2 font-weight-bold">Audit Categories</h6>

              <div className="custom-control custom-checkbox mb-2">
                <input
                  type="checkbox"
                  className="custom-control-input"
                  id="cat_policies"
                  data-testid="vp-audit-category-policies"
                  checked={categories.policies}
                  onChange={e => setCategories(prev => ({ ...prev, policies: e.target.checked }))}
                />
                <label className="custom-control-label" htmlFor="cat_policies">
                  Policy Decisions
                  <small className="d-block text-muted">
                    OPA allow/deny events{' '}
                    <FieldHelp testId="field-help-vp-audit-policies" ariaLabel="About OPA">
                      OPA (Open Policy Agent) is the engine that evaluates this gateway's Gateway
                      and Agent Surface policies.
                    </FieldHelp>
                  </small>
                </label>
              </div>

              <div className="custom-control custom-checkbox mb-2">
                <input
                  type="checkbox"
                  className="custom-control-input"
                  id="cat_trust_checks"
                  data-testid="vp-audit-category-trust_checks"
                  checked={categories.trust_checks}
                  onChange={e =>
                    setCategories(prev => ({ ...prev, trust_checks: e.target.checked }))
                  }
                />
                <label className="custom-control-label" htmlFor="cat_trust_checks">
                  Trust Checks
                  <small className="d-block text-muted">
                    TRQP query outcomes{' '}
                    <FieldHelp testId="field-help-vp-audit-trust-checks" ariaLabel="About TRQP">
                      TRQP (Trust Registry Query Protocol) is how this gateway asks a connected
                      Trust Registry whether a caller or target agent is recognised.
                    </FieldHelp>
                  </small>
                </label>
              </div>

              <div className="custom-control custom-checkbox mb-2">
                <input
                  type="checkbox"
                  className="custom-control-input"
                  id="cat_identity"
                  data-testid="vp-audit-category-identity"
                  checked={categories.identity}
                  onChange={e => setCategories(prev => ({ ...prev, identity: e.target.checked }))}
                />
                <label className="custom-control-label" htmlFor="cat_identity">
                  Identity Bindings
                  <small className="d-block text-muted">
                    Managed identity VP injections{' '}
                    <FieldHelp
                      testId="field-help-vp-audit-identity"
                      ariaLabel="About managed identity VP injections"
                    >
                      A managed identity is a DID this gateway maintains on an agent's behalf. This
                      records each time its credential (VP) is attached to an outbound request.
                    </FieldHelp>
                  </small>
                </label>
              </div>
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
