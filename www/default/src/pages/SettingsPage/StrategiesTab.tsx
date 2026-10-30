import React, { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { Badge } from '../../components/shared/Badge';
import { formatDateTime, topAndTail } from '../../utils/stringUtils';
import { AppButton } from '../../components/shared/AppButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import {
  providersUsingStrategy,
  surfacesUsingStrategy,
  type ProviderRef,
  type SurfaceRef,
} from '../../utils/strategyUsage';
import { useInPageConfirm } from '../../hooks/useInPageConfirm';

export interface JwksSource {
  type: 'remote' | 'static';
  jwks_uri?: string;
  jwks?: any[];
}

export interface JwtVerificationStrategy {
  id: string;
  name: string;
  expected_issuer: string;
  jwks_source: JwksSource;
  authorization_server?: { issuer: string } | null;
  created_at: string;
  updated_at: string;
}

interface StrategyUsage {
  surfaces: SurfaceRef[] | 'unknown';
  providers: ProviderRef[] | 'unknown';
}

async function readList(url: string): Promise<unknown> {
  const response = await apiClient.fetch(url);
  if (!response.ok) throw new Error(response.statusText);
  return response.json();
}

interface StrategiesTabProps {
  externalSearchTerm?: string;
  onFilteredCountChange?: (n: number) => void;
}

const StrategiesTab: React.FC<StrategiesTabProps> = ({
  externalSearchTerm,
  onFilteredCountChange,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const [strategies, setStrategies] = useState<JwtVerificationStrategy[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [internalSearchTerm, setInternalSearchTerm] = useState('');
  const externalProvided = externalSearchTerm !== undefined;
  const searchTerm = externalProvided ? externalSearchTerm! : internalSearchTerm;
  const setSearchTerm = setInternalSearchTerm;
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [confirming, setConfirming] = useState<JwtVerificationStrategy | null>(null);
  const [usedBy, setUsedBy] = useState<StrategyUsage | 'loading'>('loading');
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const checkingId = useRef<string | null>(null);
  const headingRef = useRef<HTMLHeadingElement>(null);
  const { dialogRef, rememberTrigger, returnFocus, cancelOnEscape } = useInPageConfirm(
    confirming?.id ?? null
  );

  const canEdit = hasPermission('jwt_verification_strategies.edit');
  const canDelete = hasPermission('jwt_verification_strategies.delete');

  useEffect(() => {
    loadStrategies();
  }, []);

  const loadStrategies = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.fetch('/api/v1/jwt-verification-strategies');
      if (!response.ok) {
        throw new Error(`Failed to load strategies: ${response.statusText}`);
      }
      const data: JwtVerificationStrategy[] = await response.json();
      setStrategies(data);
    } catch (e: any) {
      setError(e.message ?? 'Unknown error');
    } finally {
      setLoading(false);
    }
  };

  const askDelete = async (strategy: JwtVerificationStrategy) => {
    rememberTrigger();
    checkingId.current = strategy.id;
    setConfirming(strategy);
    setDeleteError(null);
    setUsedBy('loading');
    const [surfaceList, providerList] = await Promise.allSettled([
      readList('/api/v1/surfaces'),
      readList('/api/v1/credential-providers'),
    ]);
    const providers =
      providerList.status === 'fulfilled'
        ? providersUsingStrategy(providerList.value, strategy.id)
        : 'unknown';
    const surfaces =
      surfaceList.status === 'fulfilled'
        ? surfacesUsingStrategy(
            surfaceList.value,
            strategy.id,
            providers === 'unknown' ? [] : providers.map(p => p.id)
          )
        : 'unknown';
    if (checkingId.current === strategy.id) setUsedBy({ surfaces, providers });
  };

  const cancelDelete = () => {
    checkingId.current = null;
    returnFocus();
    setConfirming(null);
  };

  const handleDelete = async (strategy: JwtVerificationStrategy) => {
    setDeletingId(strategy.id);
    setDeleteError(null);
    try {
      const response = await apiClient.fetch(
        `/api/v1/jwt-verification-strategies/${encodeURIComponent(strategy.id)}`,
        { method: 'DELETE' }
      );
      if (!response.ok) {
        throw new Error(`Delete failed: ${response.statusText}`);
      }
      setStrategies(prev => prev.filter(s => s.id !== strategy.id));
      checkingId.current = null;
      headingRef.current?.focus();
      setConfirming(null);
    } catch (e: any) {
      setDeleteError(e.message ?? 'Delete failed');
    } finally {
      setDeletingId(null);
    }
  };

  const filtered = strategies.filter(
    s =>
      s.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.expected_issuer.toLowerCase().includes(searchTerm.toLowerCase())
  );

  useEffect(() => {
    onFilteredCountChange?.(filtered.length);
  }, [filtered.length, onFilteredCountChange]);

  return (
    <>
      {/* Search + Add */}
      <div className="card shadow mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary" ref={headingRef} tabIndex={-1}>
            <i className="fas fa-id-badge"></i> JWT Verification Strategies
            <Badge
              value={filtered.length}
              suffix={searchTerm ? ` of ${strategies.length}` : undefined}
              className="ms-2"
              ariaLabel={`${filtered.length}${searchTerm ? ` of ${strategies.length}` : ''} JWT verification strategies`}
            />
          </h6>
          {canEdit && (
            <AppButton
              variant="primary"
              size="md"
              className="shadow-sm"
              data-testid="jwt-strategies-add-button"
              onClick={() => navigate('/jwt-verification-strategies/new')}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add Strategy
            </AppButton>
          )}
        </div>

        <div className="card-body">
          {!externalProvided && (
            <div className="input-group mb-3">
              <input
                type="text"
                className="form-control bg-light border-0 small"
                placeholder="Search by name or expected issuer…"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
              />
              <div className="input-group-append">
                <AppButton
                  variant="primary"
                  type="button"
                  aria-label="Search strategies"
                  iconStart={<i className="fas fa-search fa-sm" aria-hidden="true" />}
                />
              </div>
            </div>
          )}

          {confirming && (
            <div
              ref={dialogRef}
              tabIndex={-1}
              className="alert alert-warning"
              role="alertdialog"
              aria-labelledby="strategy-delete-title"
              data-testid="strategy-delete-confirm"
              onKeyDown={cancelOnEscape(cancelDelete, deletingId === confirming.id)}
            >
              <strong id="strategy-delete-title">
                Delete JWT verification strategy &quot;{confirming.name}&quot;?
              </strong>
              <p className="mb-1 mt-2">
                A surface that still references it cannot verify tokens. Without authorization
                server discovery, a caller that presents a token is refused with 500 and a caller
                without one is left to the surface&apos;s policy. A surface that advertises an
                authorization server can no longer be served and refuses every caller until the
                strategy is restored. A credential provider that uses it for consent identity can no
                longer obtain credentials that need the user&apos;s consent.
              </p>
              <div aria-live="polite">
                {usedBy === 'loading' && <p className="mb-1">Checking which surfaces use it…</p>}
                {usedBy !== 'loading' && usedBy.surfaces === 'unknown' && (
                  <p className="mb-1">Could not check which surfaces use it.</p>
                )}
                {usedBy !== 'loading' && usedBy.providers === 'unknown' && (
                  <p className="mb-1">Could not check which credential providers use it.</p>
                )}
                {usedBy !== 'loading' && Array.isArray(usedBy.surfaces) && (
                  <UsageList
                    items={usedBy.surfaces}
                    none="No surface uses it."
                    heading={n => `Used by ${n} ${n === 1 ? 'surface' : 'surfaces'}:`}
                  />
                )}
                {usedBy !== 'loading' &&
                  Array.isArray(usedBy.providers) &&
                  usedBy.providers.length > 0 && (
                    <UsageList
                      items={usedBy.providers}
                      heading={n =>
                        `Used by ${n} ${n === 1 ? 'credential provider' : 'credential providers'} for consent identity:`
                      }
                    />
                  )}
              </div>
              {deleteError && (
                <div className="text-danger mb-2" role="alert" data-testid="strategy-delete-error">
                  {deleteError}
                </div>
              )}
              <AppButton
                variant="danger"
                size="sm"
                className="me-2"
                data-testid="strategy-delete-confirm-button"
                onClick={() => handleDelete(confirming)}
                loading={deletingId === confirming.id}
                loadingLabel="Deleting"
              >
                Delete strategy
              </AppButton>
              <AppButton
                variant="secondary"
                size="sm"
                data-testid="strategy-delete-cancel-button"
                onClick={cancelDelete}
                disabled={deletingId === confirming.id}
              >
                Cancel
              </AppButton>
            </div>
          )}

          {loading && (
            <div className="text-center py-4">
              <div className="spinner-border text-primary" role="status" />
            </div>
          )}

          {error && (
            <div className="alert alert-danger">
              <i className="fas fa-exclamation-triangle me-2"></i>
              {error}
              <AppButton
                variant="outline-danger"
                size="sm"
                className="ms-3"
                onClick={loadStrategies}
              >
                Retry
              </AppButton>
            </div>
          )}

          {!loading && !error && strategies.length === 0 && (
            <EmptyState
              icon="fa-id-badge"
              title="No JWT verification strategies yet"
              body="JWT verification strategies define how bearer tokens are validated. Add one to accept tokens from an identity provider."
              docsHref={DOCS_URL.jwtStrategies}
            />
          )}

          {!loading && !error && strategies.length > 0 && filtered.length === 0 && (
            <div className="text-center text-muted py-5">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p className="mb-0">No strategies match your search.</p>
            </div>
          )}

          {!loading && !error && filtered.length > 0 && (
            <div className="table-responsive">
              <table className="table table-hover table-sm" width="100%" cellSpacing="0">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Details</th>
                    <th>Updated</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(strategy => (
                    <tr
                      key={strategy.id}
                      data-testid={`strategy-row-${strategy.id}`}
                      onClick={() => navigate(`/jwt-verification-strategies/${strategy.id}`)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td>
                        <strong>{strategy.name}</strong>
                        {strategy.authorization_server && (
                          <span
                            className="badge text-bg-success ms-2"
                            data-testid="strategy-discovered-badge"
                            title="An authorization server is pinned from discovery"
                          >
                            Discovered
                          </span>
                        )}
                        <div>
                          <small className="text-muted">
                            {topAndTail(strategy.expected_issuer, 30, 20)}
                          </small>
                        </div>
                      </td>
                      <td>
                        <div>
                          <small>
                            <span className="badge badge-secondary mr-1">Issuer</span>{' '}
                            <code>{topAndTail(strategy.expected_issuer, 25, 40)}</code>
                          </small>
                        </div>
                        <div>
                          <small>
                            <span className="badge badge-secondary mr-1">JWKS</span>
                            {strategy.jwks_source.type === 'remote' &&
                              strategy.jwks_source.jwks_uri && (
                                <>
                                  <code>{topAndTail(strategy.jwks_source.jwks_uri, 25, 40)}</code>
                                  <a
                                    href={strategy.jwks_source.jwks_uri}
                                    target="_blank"
                                    rel="noopener noreferrer"
                                    className="ml-1"
                                    onClick={e => e.stopPropagation()}
                                    title="Open JWKS URI"
                                  >
                                    <i className="fas fa-external-link-alt fa-xs"></i>
                                  </a>
                                </>
                              )}
                            {strategy.jwks_source.type === 'static' && (
                              <>{strategy.jwks_source.jwks?.length ?? 0} key(s)</>
                            )}
                          </small>
                        </div>
                      </td>
                      <td>
                        <small>{formatDateTime(strategy.updated_at, true)}</small>
                      </td>
                      <td style={{ whiteSpace: 'nowrap' }}>
                        {canEdit && (
                          <AppButton
                            variant="outline-primary"
                            size="sm"
                            className="me-1"
                            data-testid={`jwt-strategy-edit-button-${strategy.id}`}
                            onClick={() => navigate(`/jwt-verification-strategies/${strategy.id}`)}
                            title="Edit"
                            aria-label={`Edit strategy ${strategy.name}`}
                            iconStart={<i className="fas fa-edit" aria-hidden="true" />}
                          />
                        )}
                        {canDelete && (
                          <AppButton
                            variant="outline-danger"
                            size="sm"
                            onClick={e => {
                              e.stopPropagation();
                              askDelete(strategy);
                            }}
                            disabled={deletingId === strategy.id}
                            title="Delete"
                            aria-label={`Delete strategy ${strategy.name}`}
                            data-testid={`strategy-delete-button-${strategy.id}`}
                            loading={deletingId === strategy.id}
                            loadingLabel="Deleting"
                          >
                            <i className="fas fa-trash" aria-hidden="true" />
                          </AppButton>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </>
  );
};

const UsageList: React.FC<{
  items: SurfaceRef[];
  none?: string;
  heading: (count: number) => string;
}> = ({ items, none, heading }) => {
  if (items.length === 0) return none ? <p className="mb-1">{none}</p> : null;
  return (
    <>
      <p className="mb-1">{heading(items.length)}</p>
      <ul className="mb-2">
        {items.map(item => (
          <li key={item.id}>{item.name}</li>
        ))}
      </ul>
    </>
  );
};

export default StrategiesTab;
