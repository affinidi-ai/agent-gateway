import React, { useCallback, useEffect, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useParams } from 'react-router-dom';
import { AgentDetails, ApiError, apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import { AgentProtocolBadge, AgentStatusBadge } from './AgentsPage/AgentBadges';
import { UNNAMED_AGENT } from './AgentsPage/agentLabels';
import AgentCardTab from './AgentDetailPage/AgentCardTab';
import ConnectionTab from './AgentDetailPage/ConnectionTab';
import OverviewTab from './AgentDetailPage/OverviewTab';
import SurfacesTab from './AgentDetailPage/SurfacesTab';
import TrafficTab from './AgentDetailPage/TrafficTab';

/** Read-only details of one agent: Overview, Agent Card, Surfaces and Traffic. */
const AgentDetailPage: React.FC = () => {
  const { agentId = '' } = useParams<{ agentId: string }>();
  const navigate = useNavigate();

  const [agent, setAgent] = useState<AgentDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);

  const loadAgent = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      setNotFound(false);
      setAgent(await apiClient.getAgent(agentId));
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setNotFound(true);
      } else {
        setError(err instanceof Error && err.message ? err.message : 'Failed to load agent');
      }
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    loadAgent();
  }, [loadAgent]);

  const backButton = (
    <div className="mb-3">
      <button
        type="button"
        className="btn btn-sm btn-secondary"
        onClick={() => navigate('/agents')}
        data-testid="agent-back-button"
      >
        <i className="fas fa-arrow-left" aria-hidden="true" /> Agents
      </button>
    </div>
  );

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="d-flex justify-content-center py-5">
          <div className="spinner-border text-primary" role="status">
            <span className="visually-hidden">Loading agent</span>
          </div>
        </div>
      </div>
    );
  }

  if (!agent) {
    return (
      <div className="container-fluid" data-testid="page-agent-details">
        {backButton}
        {notFound ? (
          <div className="alert alert-warning" role="alert" data-testid="agent-not-found">
            This agent doesn&apos;t exist or you don&apos;t have access to it.
          </div>
        ) : (
          <div className="alert alert-danger" role="alert" data-testid="agent-load-error">
            <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
            {error}
            <AppButton
              variant="outline-danger"
              size="sm"
              className="ms-3"
              onClick={loadAgent}
              data-testid="agent-retry-button"
            >
              Retry
            </AppButton>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="container-fluid" data-testid="page-agent-details">
      {backButton}
      <div className="card shadow mb-4">
        <div
          className="card-header py-3 d-flex flex-wrap align-items-center"
          style={{ gap: '0.5rem' }}
        >
          <h6 className="m-0 font-weight-bold text-primary" data-testid="agent-details-name">
            <i className="fas fa-robot me-2" aria-hidden="true" />
            {agent.name ?? <span className="text-muted fst-italic">{UNNAMED_AGENT}</span>}
          </h6>
          <AgentStatusBadge status={agent.status} />
          <AgentProtocolBadge protocol={agent.protocol} runtime={agent.runtime} />
        </div>
        <div className="card-body">
          <Tabs
            defaultActiveKey="overview"
            className="mb-3 custom-channel-tabs"
            mountOnEnter
            data-testid="agent-details-tabs"
          >
            <Tab
              eventKey="overview"
              title={
                <>
                  <i className="fas fa-info-circle" /> Overview
                </>
              }
            >
              <OverviewTab agent={agent} />
            </Tab>
            <Tab
              eventKey="agent-card"
              title={
                <>
                  <i className="fas fa-id-card" /> Agent Card
                </>
              }
            >
              <AgentCardTab agentId={agent.id} />
            </Tab>
            <Tab
              eventKey="connection"
              title={
                <>
                  <i className="fas fa-plug" /> Connection
                </>
              }
            >
              <ConnectionTab agent={agent} />
            </Tab>
            <Tab
              eventKey="surfaces"
              title={
                <>
                  <i className="fas fa-layer-group" /> Surfaces ({agent.surfaces.length})
                </>
              }
            >
              <SurfacesTab surfaces={agent.surfaces} />
            </Tab>
            <Tab
              eventKey="traffic"
              title={
                <>
                  <i className="fas fa-chart-bar" /> Traffic
                </>
              }
            >
              <TrafficTab traffic={agent.traffic} surfaces={agent.surfaces} />
            </Tab>
          </Tabs>
        </div>
      </div>
    </div>
  );
};

export default AgentDetailPage;
