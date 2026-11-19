import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { AgentRecord, apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import { Badge } from '../components/shared/Badge';
import { EmptyState } from '../components/shared/EmptyState';
import SearchInput from '../components/shared/SearchInput';
import { DOCS_URL } from '../config/docs';
import { usePermissions } from '../context/PermissionsContext';
import AgentsTable from './AgentsPage/AgentsTable';
import { agentMatchesFilter } from './AgentsPage/agentLabels';
import './AgentsPage/AgentRegistry.css';

/**
 * Agents list page. Read-only: one row per managed agent, built by the gateway
 * from the surfaces that target it, their identities and the retained metrics.
 */
const AgentsPage: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canAddSurface = hasPermission('surfaces.edit');

  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [retentionMinutes, setRetentionMinutes] = useState<number | undefined>(undefined);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  const loadAgents = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await apiClient.listAgents();
      setAgents(response.agents);
      setRetentionMinutes(response.window_minutes);
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

  const openAgent = (agent: AgentRecord) =>
    navigate(`/agent-registry/${encodeURIComponent(agent.id)}`);

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
        <div>
          <SearchInput
            value={searchTerm}
            onChange={setSearchTerm}
            placeholder="Filter agents..."
            data-testid="agents-filter-input"
          />
        </div>
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
                title="No managed agents yet"
                body="Agents show up here once they’re connected through a surface. Create a surface in Agent GW to start routing, securing, and monitoring your agents in one place."
                {...(canAddSurface
                  ? {
                      ctaLabel: 'Create a surface',
                      ctaTo: '/surfaces/new',
                      ctaTestId: 'agents-add-surface-link',
                    }
                  : {})}
                docsHref={DOCS_URL.surfaces}
                docsLabel="What’s a surface?"
                docsPlacement="actions"
              />
            )
          ) : visible.length === 0 ? (
            <div className="text-center text-muted py-5" data-testid="agents-no-match">
              <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
              <p>No agents match your filter.</p>
            </div>
          ) : (
            <AgentsTable agents={visible} retentionMinutes={retentionMinutes} onOpen={openAgent} />
          )}
        </div>
      </div>
    </div>
  );
};

export default AgentsPage;
