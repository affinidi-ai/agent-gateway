import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../../hooks/useLimitGuard';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import SearchInput from '../../components/shared/SearchInput';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import { apiClient } from '../../api';
import PolicyConfirmPopover from './PolicyConfirmPopover';
import { useGlobalPolicyAssignments } from './useGlobalPolicyAssignments';

export interface PolicyDefinition {
  id: string;
  name: string;
  description: string;
  policy_type: 'gateway' | 'agent_surface';
  policy: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
  content_hash?: string;
}

/** Shortens a `sha256:<hex>` content hash for a dense table cell; the full value is a tooltip. */
const truncateHash = (hash?: string): string =>
  hash ? (hash.length > 19 ? `${hash.slice(0, 19)}…` : hash) : '—';

interface PolicyListTabProps {
  policyType: 'gateway' | 'agent_surface';
  label: string;
  icon: string;
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const PolicyListTab: React.FC<PolicyListTabProps> = ({
  policyType,
  label,
  icon,
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const [policies, setPolicies] = useState<PolicyDefinition[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const globalAssignments = useGlobalPolicyAssignments(true);

  const fetchPolicies = useCallback(async () => {
    try {
      const resp = await apiClient.fetch('/api/v1/policy-definitions');
      if (!resp.ok) throw new Error(`Failed to load policies: ${resp.statusText}`);
      const data: PolicyDefinition[] = await resp.json();
      setPolicies(data.filter(p => p.policy_type === policyType));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  }, [policyType]);

  useEffect(() => {
    fetchPolicies();
  }, [fetchPolicies]);

  const performDelete = useCallback(async (id: string) => {
    setDeletingId(id);
    try {
      const resp = await apiClient.fetch(`/api/v1/policy-definitions/${encodeURIComponent(id)}`, {
        method: 'DELETE',
      });
      if (!resp.ok) throw new Error(`Failed to delete: ${resp.statusText}`);
      setPolicies(prev => prev.filter(p => p.id !== id));
    } catch (e: any) {
      setError(e.message);
    } finally {
      setDeletingId(null);
    }
  }, []);

  const [confirmTarget, setConfirmTarget] = useState<{
    policy: PolicyDefinition;
    anchor: HTMLElement;
    action: 'delete' | 'enable-global';
  } | null>(null);
  const [impact, setImpact] = useState<{
    loading: boolean;
    surfaces: number;
    gateways: number;
    totalSurfaces: number;
    totalGateways: number;
    error: boolean;
  }>({
    loading: false,
    surfaces: 0,
    gateways: 0,
    totalSurfaces: 0,
    totalGateways: 0,
    error: false,
  });
  const [committing, setCommitting] = useState(false);

  const openConfirm = useCallback(
    async (policy: PolicyDefinition, anchor: HTMLElement, action: 'delete' | 'enable-global') => {
      setConfirmTarget({ policy, anchor, action });
      setImpact({
        loading: true,
        surfaces: 0,
        gateways: 0,
        totalSurfaces: 0,
        totalGateways: 0,
        error: false,
      });
      try {
        const resp = await apiClient.fetch(
          `/api/v1/policy-definitions/${encodeURIComponent(policy.id)}/impact`
        );
        if (!resp.ok) throw new Error('impact');
        const data = await resp.json();
        setImpact({
          loading: false,
          surfaces: data.surfaces ?? 0,
          gateways: data.gateways ?? 0,
          totalSurfaces: data.total_surfaces ?? 0,
          totalGateways: data.total_gateways ?? 0,
          error: false,
        });
      } catch {
        setImpact({
          loading: false,
          surfaces: 0,
          gateways: 0,
          totalSurfaces: 0,
          totalGateways: 0,
          error: true,
        });
      }
    },
    []
  );

  const commitConfirm = useCallback(async () => {
    if (!confirmTarget) return;
    setCommitting(true);
    try {
      if (confirmTarget.action === 'delete') {
        await performDelete(confirmTarget.policy.id);
      } else {
        await globalAssignments
          .setEnforcement(policyType, confirmTarget.policy.id, true, false)
          .catch(() => {});
      }
    } finally {
      setCommitting(false);
      setConfirmTarget(null);
    }
  }, [confirmTarget, performDelete, globalAssignments, policyType]);

  const filtered = useMemo(() => {
    const q = searchTerm.trim().toLowerCase();
    if (!q) return policies;
    return policies.filter(
      p =>
        p.name.toLowerCase().includes(q) ||
        p.description.toLowerCase().includes(q) ||
        p.id.toLowerCase().includes(q) ||
        (p.content_hash ?? '').toLowerCase().includes(q)
    );
  }, [policies, searchTerm]);

  useEffect(() => {
    onFilteredCountChange?.(filtered.length);
  }, [filtered.length, onFilteredCountChange]);

  // A policy is referenced and enforced only within its own plane, so the
  // confirmation counts and wording use just that scope.
  const scopeNoun = policyType === 'gateway' ? 'gateway' : 'surface';
  const referencingCount = policyType === 'gateway' ? impact.gateways : impact.surfaces;
  const totalInPlane = policyType === 'gateway' ? impact.totalGateways : impact.totalSurfaces;

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className={`fas ${icon}`}></i> {label} Policies
          <Badge
            value={filtered.length}
            tone="primary"
            className="ms-2"
            ariaLabel={`${filtered.length} ${label.toLowerCase()} policies`}
          />
        </h6>
        <div className="d-flex align-items-center gap-2">
          {!externalProvided && (
            <SearchInput
              value={internalSearchTerm}
              onChange={setInternalSearchTerm}
              placeholder={`Filter ${label.toLowerCase()} policies...`}
            />
          )}
          <AppButton
            variant="primary"
            size="md"
            className="shadow-sm"
            onClick={e =>
              guard(
                policyType === 'gateway' ? 'policies.fabric' : 'policies.agent-surface',
                () => navigate(`/policy-definitions/new?type=${policyType}`),
                e
              )
            }
            iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
          >
            Define {label} Policy
          </AppButton>
          {balloonNode}
        </div>
      </div>
      <div className="card-body">
        {error && (
          <div className="alert alert-danger alert-dismissible fade show mb-3">
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
        {globalAssignments.error && (
          <div className="alert alert-danger alert-dismissible fade show mb-3">
            <i className="fas fa-exclamation-triangle me-2"></i>
            {globalAssignments.error}
            <button
              type="button"
              className="btn-close"
              onClick={globalAssignments.clearError}
              aria-label="Close"
            />
          </div>
        )}
        {loading ? (
          <div className="text-center py-4">
            <div className="spinner-border spinner-border-sm text-primary" role="status" />
          </div>
        ) : policies.length === 0 ? (
          <EmptyState
            icon={icon}
            title={`No ${label.toLowerCase()} policies yet`}
            body={`${label} policies decide whether requests are allowed. Add one to enforce access rules at this scope.`}
            docsHref={DOCS_URL.policies}
          />
        ) : filtered.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No {label.toLowerCase()} policies match your search.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-sm table-hover mb-0">
              <thead className="thead-light">
                <tr>
                  <th>Name</th>
                  <th>ID</th>
                  <th>SHA</th>
                  <th>Description</th>
                  <th style={{ width: '80px' }}>Status</th>
                  <th style={{ width: '120px' }} className="text-center">
                    Global
                  </th>
                  <th style={{ width: '80px' }} className="text-center">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(p => (
                  <tr
                    key={p.id}
                    onClick={() => navigate(`/policy-definitions/${p.id}`)}
                    style={{ cursor: 'pointer' }}
                  >
                    <td className="font-weight-bold">{p.name}</td>
                    <td>
                      <code className="small text-muted">{p.id}</code>
                    </td>
                    <td>
                      <code className="small text-muted" title={p.content_hash}>
                        {truncateHash(p.content_hash)}
                      </code>
                    </td>
                    <td className="text-muted small">{p.description || '—'}</td>
                    <td className="text-center">
                      {p.enabled ? (
                        <span className="badge text-bg-success">Enabled</span>
                      ) : (
                        <span className="badge text-bg-secondary">Disabled</span>
                      )}
                    </td>
                    <td className="text-center" onClick={e => e.stopPropagation()}>
                      <div className="form-check form-switch d-inline-flex align-items-center m-0">
                        <input
                          className="form-check-input"
                          type="checkbox"
                          role="switch"
                          checked={
                            globalAssignments.isEnforced(policyType, p.id) ||
                            (confirmTarget?.action === 'enable-global' &&
                              confirmTarget.policy.id === p.id)
                          }
                          disabled={
                            globalAssignments.saving ||
                            globalAssignments.loading ||
                            (confirmTarget?.action === 'enable-global' &&
                              confirmTarget.policy.id === p.id)
                          }
                          onChange={e => {
                            if (globalAssignments.isEnforced(policyType, p.id)) {
                              // Turning off is not destructive — apply immediately.
                              globalAssignments
                                .setEnforcement(
                                  policyType,
                                  p.id,
                                  false,
                                  globalAssignments.isMonitorOnly(policyType, p.id)
                                )
                                .catch(() => {});
                            } else {
                              // Enabling shows a blast-radius confirmation first.
                              openConfirm(p, e.currentTarget, 'enable-global');
                            }
                          }}
                          aria-label={`Enforce policy ${p.name} globally`}
                        />
                      </div>
                      <div className="text-muted" style={{ fontSize: '10px', lineHeight: 1.2 }}>
                        Every {label.toLowerCase()}, appliance-wide
                      </div>
                      {globalAssignments.isEnforced(policyType, p.id) && (
                        <>
                          <div className="d-flex align-items-center justify-content-center small mt-1">
                            <input
                              className="form-check-input mt-0 me-1"
                              type="checkbox"
                              id={`monitor-${p.id}`}
                              checked={globalAssignments.isMonitorOnly(policyType, p.id)}
                              disabled={globalAssignments.saving}
                              onChange={e =>
                                globalAssignments
                                  .setEnforcement(policyType, p.id, true, e.target.checked)
                                  .catch(() => {})
                              }
                            />
                            <label className="mb-0 text-muted" htmlFor={`monitor-${p.id}`}>
                              Monitor
                            </label>
                          </div>
                          <div className="text-muted" style={{ fontSize: '10px', lineHeight: 1.2 }}>
                            Audit only, never blocks
                          </div>
                        </>
                      )}
                    </td>
                    <td
                      className="text-center"
                      style={{ whiteSpace: 'nowrap' }}
                      onClick={e => e.stopPropagation()}
                    >
                      <AppButton
                        variant="outline-danger"
                        size="sm"
                        title="Delete"
                        aria-label={`Delete policy ${p.name}`}
                        disabled={deletingId === p.id}
                        onClick={e => {
                          e.stopPropagation();
                          openConfirm(p, e.currentTarget, 'delete');
                        }}
                      >
                        <i
                          className={`fas ${deletingId === p.id ? 'fa-spinner fa-spin' : 'fa-trash'}`}
                          aria-hidden="true"
                        />
                      </AppButton>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {confirmTarget && (
        <PolicyConfirmPopover
          anchor={confirmTarget.anchor}
          title={confirmTarget.action === 'delete' ? 'Delete policy' : 'Enforce globally'}
          confirmLabel={confirmTarget.action === 'delete' ? 'Delete' : 'Continue'}
          confirmVariant={confirmTarget.action === 'delete' ? 'danger' : 'primary'}
          confirmDisabled={impact.loading}
          busy={committing}
          onConfirm={commitConfirm}
          onCancel={() => setConfirmTarget(null)}
        >
          {impact.loading ? (
            <div className="text-center py-1">
              <span className="spinner-border spinner-border-sm text-primary" role="status" />
            </div>
          ) : confirmTarget.action === 'delete' ? (
            <>
              Delete <strong>{confirmTarget.policy.name}</strong>?{' '}
              {impact.error
                ? 'This cannot be undone.'
                : referencingCount === 0
                  ? `No ${scopeNoun} references it, this cannot be undone.`
                  : `${referencingCount} ${scopeNoun}${referencingCount === 1 ? '' : 's'} reference it, they fail closed once it is gone (the gateway starts denying those requests instead of guessing).`}
            </>
          ) : (
            <>
              Enforce <strong>{confirmTarget.policy.name}</strong> on every {scopeNoun}?{' '}
              {impact.error
                ? `Every ${scopeNoun} will enforce it appliance-wide.`
                : `All ${totalInPlane} ${scopeNoun}${totalInPlane === 1 ? '' : 's'} will enforce it, on top of each ${scopeNoun}'s own policy.`}
            </>
          )}
        </PolicyConfirmPopover>
      )}
    </div>
  );
};

export default PolicyListTab;
