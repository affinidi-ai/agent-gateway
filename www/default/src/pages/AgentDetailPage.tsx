import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Tab, Tabs } from 'react-bootstrap';
import { useNavigate, useParams } from 'react-router-dom';
import { AgentDetails, ApiError, apiClient } from '../api';
import { AppButton } from '../components/shared/AppButton';
import AgentCardTab from './AgentDetailPage/AgentCardTab';
import AgentDetailHeader from './AgentDetailPage/AgentDetailHeader';
import ConnectionTab from './AgentDetailPage/ConnectionTab';
import TrafficTab from './AgentDetailPage/TrafficTab';
import './AgentsPage/AgentRegistry.css';

const tabAttrs = (key: string) => ({ 'data-testid': `agent-tab-${key}` });

/** Read-only details of one agent: Agent Card, Connection and Traffic. */
const AgentDetailPage: React.FC = () => {
  const { agentId = '' } = useParams<{ agentId: string }>();
  const navigate = useNavigate();

  const [agent, setAgent] = useState<AgentDetails | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [notFound, setNotFound] = useState(false);

  const latestRequest = useRef(0);

  const loadAgent = useCallback(async () => {
    const request = ++latestRequest.current;
    const isCurrent = () => request === latestRequest.current;
    setLoading(true);
    setError(null);
    setNotFound(false);
    setAgent(null);
    try {
      const loaded = await apiClient.getAgent(agentId);
      if (isCurrent()) setAgent(loaded);
    } catch (err) {
      if (!isCurrent()) return;
      if (err instanceof ApiError && err.status === 404) {
        setNotFound(true);
      } else {
        setError(err instanceof Error && err.message ? err.message : 'Failed to load agent');
      }
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    loadAgent();
    return () => {
      latestRequest.current += 1;
    };
  }, [loadAgent]);

  const backButton = (
    <div className="mb-3">
      <button
        type="button"
        className="btn btn-sm btn-secondary"
        onClick={() => navigate('/agent-registry')}
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
        <AgentDetailHeader agent={agent} />
        <div className="card-body">
          <Tabs
            defaultActiveKey="agent-card"
            className="mb-3 custom-channel-tabs"
            mountOnEnter
            data-testid="agent-details-tabs"
          >
            <Tab
              eventKey="agent-card"
              tabAttrs={tabAttrs('agent-card')}
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
              tabAttrs={tabAttrs('connection')}
              title={
                <>
                  <i className="fas fa-plug" /> Connection
                </>
              }
            >
              <ConnectionTab agent={agent} />
            </Tab>
            <Tab
              eventKey="traffic"
              tabAttrs={tabAttrs('traffic')}
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
