import React, { useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import { useLimitGuard } from '../../hooks/useLimitGuard';
import { AppButton } from '../../components/shared/AppButton';
import { Badge } from '../../components/shared/Badge';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import { formatDateTime } from '../../utils/stringUtils';
import { getA2aProxyBackendLabel } from '../A2aProxyPage/backendMetadata';
import type { A2aProxy } from '../A2aProxyPage/types';

interface A2aProxiesSectionProps {
  proxies: A2aProxy[];
  searchTerm: string;
  canEdit: boolean;
  canDelete: boolean;
  onDelete: (id: string) => void;
}

const A2aProxiesSection: React.FC<A2aProxiesSectionProps> = ({
  proxies,
  searchTerm,
  canEdit,
  canDelete,
  onDelete,
}) => {
  const navigate = useNavigate();
  const { guard, balloonNode } = useLimitGuard();
  const filteredProxies = useMemo(() => {
    const term = searchTerm.trim().toLowerCase();
    if (!term) return proxies;
    return proxies.filter(proxy => {
      const backend = proxy.backend;
      return (
        proxy.name.toLowerCase().includes(term) ||
        proxy.description.toLowerCase().includes(term) ||
        proxy.id.toLowerCase().includes(term) ||
        backend.base_url.toLowerCase().includes(term)
      );
    });
  }, [proxies, searchTerm]);

  return (
    <div className="card shadow mb-4" data-testid="a2a-proxies-section">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-robot me-1" aria-hidden="true" /> A2A Proxies
          <Badge
            value={filteredProxies.length}
            suffix={searchTerm ? ` of ${proxies.length}` : undefined}
            className="ms-2"
            ariaLabel={`${filteredProxies.length}${searchTerm ? ` of ${proxies.length}` : ''} A2A proxies`}
          />
        </h6>
        {canEdit && (
          <>
            <AppButton
              data-testid="a2a-proxies-add-button"
              variant="primary"
              size="sm"
              className="shadow-sm"
              onClick={e => guard('proxies.a2a', () => navigate('/proxies/a2a-proxies/new'), e)}
              iconStart={<i className="fas fa-plus fa-sm me-1" aria-hidden="true" />}
            >
              Add A2A Proxy
            </AppButton>
            {balloonNode}
          </>
        )}
      </div>
      <div className="card-body">
        {filteredProxies.length === 0 ? (
          searchTerm ? (
            <div className="text-center text-muted py-4">
              <i className="fas fa-robot fa-3x mb-3 opacity-25" aria-hidden="true" />
              <p>No A2A Proxies match your filter</p>
            </div>
          ) : (
            <EmptyState
              icon="fa-robot"
              title="No A2A Proxies yet"
              body="A2A Proxies adapt a Microsoft Copilot Direct Line backend so it can be reached through A2A, the protocol AI agents use to call each other directly. Create one to make a Copilot-based bot callable as an A2A agent."
              docsHref={DOCS_URL.proxies}
            />
          )
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Description</th>
                  <th>Backend</th>
                  <th>Status</th>
                  <th>Updated</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredProxies.map(proxy => (
                  <tr
                    key={proxy.id}
                    data-testid={`a2a-proxy-row-${proxy.id}`}
                    onClick={
                      canEdit ? () => navigate(`/proxies/a2a-proxies/${proxy.id}`) : undefined
                    }
                    style={canEdit ? { cursor: 'pointer' } : undefined}
                  >
                    <td>
                      <strong>{proxy.name}</strong>
                      <div>
                        <small className="text-muted">{proxy.id}</small>
                      </div>
                    </td>
                    <td>
                      <small>{proxy.description || '—'}</small>
                    </td>
                    <td>
                      <span className="badge text-bg-info">
                        {getA2aProxyBackendLabel(proxy.backend.kind)}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`badge ${proxy.status === 'active' ? 'text-bg-success' : 'text-bg-secondary'}`}
                      >
                        {proxy.status.toUpperCase()}
                      </span>
                    </td>
                    <td>
                      <small>{formatDateTime(proxy.updated_at || proxy.created_at, true)}</small>
                    </td>
                    <td>
                      <div className="d-flex flex-column flex-lg-row gap-2 align-items-start align-items-lg-center">
                        {canEdit && (
                          <AppButton
                            data-testid={`a2a-proxy-edit-button-${proxy.id}`}
                            variant="primary"
                            size="sm"
                            className="shadow-sm"
                            onClick={e => {
                              e.stopPropagation();
                              navigate(`/proxies/a2a-proxies/${proxy.id}`);
                            }}
                            title="Edit"
                            aria-label={`Edit A2A Proxy ${proxy.name}`}
                            iconStart={<i className="fas fa-edit" aria-hidden="true" />}
                          />
                        )}
                        {canDelete && (
                          <DeleteButton
                            onDelete={() => onDelete(proxy.id)}
                            className="btn-sm"
                            title="Delete A2A Proxy"
                          />
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default A2aProxiesSection;
