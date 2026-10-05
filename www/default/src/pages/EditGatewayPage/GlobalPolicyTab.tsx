import React, { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';

interface GatewayOpaPolicyConfig {
  enabled: boolean;
  policy: string;
  policy_definition_id?: string;
  policy_definition_ids?: string[];
}

interface PolicyDefinition {
  id: string;
  name: string;
  description: string;
  policy_type: 'gateway' | 'agent_surface';
  policy: string;
  enabled: boolean;
}

interface GlobalPolicyTabProps {
  gatewayId: string;
  isSelfGateway: boolean;
}

const GlobalPolicyTab: React.FC<GlobalPolicyTabProps> = ({ gatewayId, isSelfGateway }) => {
  const navigate = useNavigate();
  const [policyConfig, setPolicyConfig] = useState<GatewayOpaPolicyConfig | null>(null);
  const [availablePolicies, setAvailablePolicies] = useState<PolicyDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isModified, setIsModified] = useState(false);

  const opaEnabled = policyConfig?.enabled ?? false;
  const selectedPolicyId = policyConfig?.policy_definition_id || '';

  // Load both the current gateway policy and available policy definitions
  useEffect(() => {
    const fetchData = async () => {
      try {
        setLoading(true);

        const [policyResp, defsResp] = await Promise.all([
          apiClient.get(`/gateways/${gatewayId}/policy`),
          apiClient.fetch('/api/v1/policy-definitions').then(r => {
            if (!r.ok) throw new Error('Failed to load policy definitions');
            return r.json();
          }),
        ]);

        setPolicyConfig(policyResp.data.opa_policy_config || null);

        // Only show enabled gateway-type policies
        const gatewayPolicies = (defsResp as PolicyDefinition[]).filter(
          p => p.policy_type === 'gateway' && p.enabled
        );
        setAvailablePolicies(gatewayPolicies);
      } catch (err: any) {
        console.error('Failed to load gateway policy data:', err);
        setError(err.message || 'Failed to load gateway policy');
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, [gatewayId]);

  const handleSave = useCallback(async () => {
    try {
      setSaving(true);
      setError(null);

      await apiClient.put(`/gateways/${gatewayId}/policy`, {
        opa_policy_config: policyConfig,
      });
      setSuccess('Gateway policy updated successfully!');
      setIsModified(false);
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: any) {
      setError(err.message || 'Failed to update gateway policy');
    } finally {
      setSaving(false);
    }
  }, [gatewayId, policyConfig]);

  // Keyboard shortcut for save (Ctrl+S / Cmd+S)
  useEffect(() => {
    const handleKeyboardSave = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key === 's') {
        event.preventDefault();
        if (!saving && isModified) {
          handleSave();
        }
      }
    };
    document.addEventListener('keydown', handleKeyboardSave);
    return () => document.removeEventListener('keydown', handleKeyboardSave);
  }, [saving, isModified, handleSave]);

  if (loading) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border" role="status">
          <span className="visually-hidden"></span>
        </div>
      </div>
    );
  }

  const directionLabel = isSelfGateway
    ? 'all inbound traffic to this gateway'
    : 'all outbound traffic to this remote gateway';

  const selectedPolicy = availablePolicies.find(p => p.id === selectedPolicyId);

  return (
    <div className="p-3">
      {error && (
        <div className="alert alert-danger alert-dismissible fade show" role="alert">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
          <button
            type="button"
            className="btn-close"
            onClick={() => setError(null)}
            aria-label="Close"
          />
        </div>
      )}

      {success && (
        <div className="alert alert-success alert-dismissible fade show" role="alert">
          <i className="fas fa-check-circle me-2"></i>
          {success}
          <button
            type="button"
            className="btn-close"
            onClick={() => setSuccess(null)}
            aria-label="Close"
          />
        </div>
      )}

      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-shield-alt"></i> Gateway-Level OPA Policy
            </h6>
            <div className="d-flex align-items-center">
              {isModified && (
                <button
                  className={`btn btn-sm btn-primary me-3 ${saving ? 'disabled' : ''}`}
                  onClick={handleSave}
                  disabled={saving}
                >
                  <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
                  {saving ? ' Saving...' : ' Save Policy'}
                </button>
              )}
              <div className="form-check">
                <input
                  className="form-check-input"
                  type="checkbox"
                  id="gateway-opa-enabled"
                  checked={opaEnabled}
                  onChange={e => {
                    if (e.target.checked) {
                      setPolicyConfig({
                        enabled: true,
                        policy: policyConfig?.policy || '',
                        policy_definition_id: policyConfig?.policy_definition_id,
                        policy_definition_ids: policyConfig?.policy_definition_ids,
                      });
                    } else {
                      setPolicyConfig(null);
                    }
                    setIsModified(true);
                  }}
                />
                <label
                  className={`form-check-label ${opaEnabled ? '' : 'text-muted'}`}
                  htmlFor="gateway-opa-enabled"
                >
                  Enabled
                </label>
              </div>
            </div>
          </div>
        </div>

        {!opaEnabled && (
          <div className="card-body">
            <p className="text-muted mb-0">
              <i className="fas fa-info-circle me-2"></i>
              Enable this to enforce a gateway-wide OPA policy on <strong>{directionLabel}</strong>.
              This policy is evaluated <strong>before</strong> any channel-level policies. A gateway
              deny cannot be overridden by a channel allow.
            </p>
          </div>
        )}

        {opaEnabled && (
          <div className="card-body">
            <div
              className="alert alert-info mb-3"
              style={{ borderLeft: '4px solid var(--accent-blue)' }}
            >
              <small>
                <i className="fas fa-layer-group me-2 text-primary"></i>
                <strong>Layered Enforcement:</strong> This gateway-level policy applies to{' '}
                <strong>{directionLabel}</strong>. It is evaluated <strong>before</strong>{' '}
                channel-level policies. Both layers must allow the request for it to proceed.
                Gateway deny cannot be overridden by channel allow (no privilege escalation).
              </small>
            </div>

            {/* Policy Selection Dropdown */}
            <div className="mb-3 mb-3">
              <label className="font-weight-bold">Select Gateway Policy</label>
              {availablePolicies.length === 0 ? (
                <div className="alert alert-warning mb-0">
                  <i className="fas fa-info-circle me-2"></i>
                  No gateway policies have been defined yet.{' '}
                  <a
                    href="#"
                    onClick={e => {
                      e.preventDefault();
                      navigate('/policy-definitions/new?type=gateway');
                    }}
                    className="font-weight-bold"
                  >
                    Create one in Settings &rarr; Policies
                  </a>
                </div>
              ) : (
                <>
                  <select
                    className="form-control form-control-sm dropdown-styling"
                    value={selectedPolicyId}
                    onChange={e => {
                      const newId = e.target.value;
                      const selected = availablePolicies.find(p => p.id === newId);
                      setPolicyConfig({
                        ...policyConfig!,
                        policy_definition_id: newId || undefined,
                        policy: selected?.policy || policyConfig?.policy || '',
                        policy_definition_ids: (policyConfig?.policy_definition_ids || []).filter(
                          x => x !== newId
                        ),
                      });
                      setIsModified(true);
                    }}
                  >
                    <option value="">-- No policy selected --</option>
                    {availablePolicies.map(p => (
                      <option key={p.id} value={p.id}>
                        {p.name}
                        {p.description ? ` — ${p.description}` : ''}
                      </option>
                    ))}
                  </select>
                  <small className="form-text text-muted">
                    Select a gateway policy from your policy definitions.{' '}
                    <a
                      href="#"
                      onClick={e => {
                        e.preventDefault();
                        navigate('/settings?tab=policies');
                      }}
                    >
                      Manage policies in Settings
                    </a>
                  </small>
                  <div className="mt-3">
                    <label className="font-weight-bold d-block">
                      Additional policies{' '}
                      <span className="text-muted fw-normal">(deny-overrides)</span>
                    </label>
                    <small className="form-text text-muted d-block mb-2">
                      Every selected policy must allow the request; any deny blocks it.
                    </small>
                    {availablePolicies.filter(p => p.id !== selectedPolicyId).length === 0 ? (
                      <p className="text-muted small mb-0">No other gateway policies available.</p>
                    ) : (
                      availablePolicies
                        .filter(p => p.id !== selectedPolicyId)
                        .map(p => {
                          const ids = policyConfig?.policy_definition_ids || [];
                          return (
                            <div className="form-check" key={p.id}>
                              <input
                                className="form-check-input"
                                type="checkbox"
                                id={`gw-extra-${p.id}`}
                                checked={ids.includes(p.id)}
                                onChange={e => {
                                  const current = policyConfig?.policy_definition_ids || [];
                                  const next = e.target.checked
                                    ? [...current, p.id]
                                    : current.filter(x => x !== p.id);
                                  setPolicyConfig({
                                    ...policyConfig!,
                                    policy_definition_ids: next,
                                  });
                                  setIsModified(true);
                                }}
                              />
                              <label className="form-check-label" htmlFor={`gw-extra-${p.id}`}>
                                {p.name}
                                {p.description ? ` — ${p.description}` : ''}
                              </label>
                            </div>
                          );
                        })
                    )}
                  </div>
                </>
              )}
            </div>

            {/* Preview of selected policy */}
            {selectedPolicy && (
              <div className="card bg-light border-0 mb-3">
                <div className="card-body">
                  <div className="d-flex justify-content-between align-items-center mb-2">
                    <h6 className="font-weight-bold mb-0">
                      <i className="fas fa-eye me-2"></i>
                      Policy Preview: {selectedPolicy.name}
                    </h6>
                    <button
                      className="btn btn-sm btn-outline-primary"
                      onClick={() => navigate(`/policy-definitions/${selectedPolicy.id}`)}
                    >
                      <i className="fas fa-edit me-1"></i> Edit Policy
                    </button>
                  </div>
                  {selectedPolicy.description && (
                    <p className="text-muted small mb-2">{selectedPolicy.description}</p>
                  )}
                  <pre
                    className="policy-preview-block p-3 rounded mb-0"
                    style={{
                      fontSize: '0.85rem',
                      maxHeight: '300px',
                      overflow: 'auto',
                    }}
                  >
                    <code>{selectedPolicy.policy}</code>
                  </pre>
                </div>
              </div>
            )}

            {!selectedPolicyId && availablePolicies.length > 0 && (
              <div className="text-center text-muted py-3">
                <i className="fas fa-hand-pointer fa-2x mb-2" style={{ opacity: 0.3 }}></i>
                <p className="mb-0">
                  Select a policy from the dropdown above, or{' '}
                  <a
                    href="#"
                    onClick={e => {
                      e.preventDefault();
                      navigate('/policy-definitions/new?type=gateway');
                    }}
                  >
                    create a new gateway policy
                  </a>
                  .
                </p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default GlobalPolicyTab;
