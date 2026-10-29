import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { AgentRecord, apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import SearchInput from '../components/shared/SearchInput';
import { DOCS_URL } from '../config/docs';
import { useApp } from '../context/AppContext';
import {
  AgentDid,
  AgentProtocolBadge,
  AgentStatusBadge,
  AgentTrustRegistryBadges,
} from './AgentsPage/AgentBadges';
import {
  UNNAMED_AGENT,
  agentMatchesFilter,
  lastActivityLabel,
  listRowSurfaceId,
  otherSurfacesNote,
  runtimeLabel,
} from './AgentsPage/agentLabels';

/**
 * Agents list page. Read-only: one row per Agent Surface's managed agent,
 * built by the gateway from the surface, its managed identity and the
 * retained metrics.
 */
const AgentsPage: React.FC = () => {
  const navigate = useNavigate();
  const { state } = useApp();
  const retentionMinutes = state.settings?.metrics_retention;

  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const loadAgents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setAgents(await apiClient.listAgents());
    } catch (err) {
      setError(err instanceof Error && err.message ? err.message : 'Failed to load agents');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAgents();
  }, [loadAgents]);

  const visible = useMemo(
    () => agents.filter(agent => agentMatchesFilter(agent, searchTerm)),
    [agents, searchTerm]
  );

  const openAgent = (agent: AgentRecord) => navigate(`/agents/${encodeURIComponent(agent.id)}`);

  if (loading) {
    return (
      <div
        style={{
          display: 'flex',
          justifyContent: 'center',
          alignItems: 'center',
          minHeight: '60vh',
        }}
      >
        <div className="spinner-border text-primary" role="status">
          <span className="visually-hidden">Loading agents</span>
        </div>
      </div>
    );
  }

  const filtered = searchTerm.trim() !== '';

  return (
    <div className="container-fluid" data-testid="page-agents">
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <SearchInput
          value={searchTerm}
          onChange={setSearchTerm}
          placeholder="Filter agents..."
          data-testid="agents-filter-input"
        />
      </div>

      {error && (
        <div className="alert alert-danger" role="alert" data-testid="agents-load-error">
          <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
          {error}
          <AppButton
            variant="outline-danger"
            size="sm"
            className="ms-3"
            onClick={loadAgents}
            data-testid="agents-retry-button"
          >
            Retry
          </AppButton>
        </div>
      )}

      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-robot me-2" aria-hidden="true" />
            Agents
            <Badge
              value={visible.length}
              suffix={filtered ? ` of ${agents.length}` : undefined}
              className="ms-2"
              ariaLabel={`${visible.length}${filtered ? ` of ${agents.length}` : ''} agents`}
              data-testid="agents-count"
            />
          </h6>
        </div>
        <div className="card-body">
          {agents.length === 0 ? (
            !error && (
              <EmptyState
                icon="fa-robot"
                title="No agents yet"
                body="Each Agent Surface's managed agent is listed here. Create a surface to add one."
                docsHref={DOCS_URL.createFirstSurface}
              />
            )
          ) : visible.length === 0 ? (
            <div className="text-center text-muted py-5" data-testid="agents-no-match">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p>No agents match your filter.</p>
            </div>
          ) : (
            <div className="table-responsive">
              <table className="table table-hover table-sm">
                <thead>
                  <tr>
                    <th style={{ width: '28%' }}>Agent</th>
                    <th style={{ width: '16%' }}>Runtime &amp; protocol</th>
                    <th style={{ width: '9%' }}>Status</th>
                    <th style={{ width: '17%' }}>Used by surfaces</th>
                    <th style={{ width: '15%' }}>Trust registry</th>
                    <th style={{ width: '15%' }}>Last activity</th>
                  </tr>
                </thead>
                <tbody>
                  {visible.map(agent => (
                    <tr
                      key={agent.id}
                      style={{ cursor: 'pointer' }}
                      tabIndex={0}
                      onClick={() => openAgent(agent)}
                      onKeyDown={e => {
                        if (e.target === e.currentTarget && (e.key === 'Enter' || e.key === ' ')) {
                          e.preventDefault();
                          openAgent(agent);
                        }
                      }}
                      data-testid={`agents-row-${agent.id}`}
                    >
                      <td>
                        <div>
                          {agent.name ? (
                            <strong data-testid="agents-name">{agent.name}</strong>
                          ) : (
                            <span className="text-muted fst-italic" data-testid="agents-unnamed">
                              {UNNAMED_AGENT}
                            </span>
                          )}
                        </div>
                        <AgentDid
                          did={agent.agent_did}
                          note={otherSurfacesNote(agent.did_surface_count)}
                        />
                      </td>
                      <td>
                        <div className="small" data-testid="agents-runtime">
                          {runtimeLabel(agent.runtime)}
                        </div>
                        <AgentProtocolBadge protocol={agent.protocol} runtime={agent.runtime} />
                      </td>
                      <td>
                        <AgentStatusBadge status={agent.status} />
                      </td>
                      <td>
                        <Link
                          to={`/surfaces/${encodeURIComponent(listRowSurfaceId(agent))}`}
                          onClick={e => e.stopPropagation()}
                          data-testid="agents-surface-link"
                        >
                          {agent.surface_name}
                        </Link>
                      </td>
                      <td>
                        <AgentTrustRegistryBadges trust={agent.trust_registry} />
                      </td>
                      <td>
                        <span
                          className={agent.last_activity_at ? 'small' : 'small text-muted'}
                          title={agent.last_activity_at ?? undefined}
                          data-testid="agents-last-activity"
                        >
                          {lastActivityLabel(agent.last_activity_at, retentionMinutes)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AgentsPage;
