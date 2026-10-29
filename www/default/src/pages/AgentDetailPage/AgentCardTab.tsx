import React, { useCallback, useEffect, useState } from 'react';
import { AgentCardResponse, apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { CopyButton } from '../../components/shared/CopyButton';

const UNAVAILABLE_TEXT: Record<'no_agent_card' | 'unsupported_runtime', string> = {
  no_agent_card: "This agent doesn't publish an Agent Card",
  unsupported_runtime: "Agent Card isn't available for this runtime",
};

/**
 * The card the agent publishes at its own endpoint. It is untrusted,
 * agent-supplied content: shown only as plain text, never as HTML or links.
 */
const AgentCardTab: React.FC<{ agentId: string }> = ({ agentId }) => {
  const [response, setResponse] = useState<AgentCardResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [failed, setFailed] = useState(false);

  const loadCard = useCallback(async () => {
    try {
      setLoading(true);
      setFailed(false);
      setResponse(await apiClient.getAgentCard(agentId));
    } catch {
      setFailed(true);
    } finally {
      setLoading(false);
    }
  }, [agentId]);

  useEffect(() => {
    loadCard();
  }, [loadCard]);

  if (loading) {
    return (
      <div className="text-center py-4" data-testid="agent-card-loading">
        <div className="spinner-border spinner-border-sm text-primary" role="status">
          <span className="visually-hidden">Loading Agent Card</span>
        </div>
      </div>
    );
  }

  if (failed || !response) {
    return (
      <div className="alert alert-danger d-flex align-items-center" data-testid="agent-card-error">
        <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
        Agent Card couldn&apos;t be loaded
        <AppButton
          variant="outline-danger"
          size="sm"
          className="ms-3"
          onClick={loadCard}
          data-testid="agent-card-retry-button"
        >
          Retry
        </AppButton>
      </div>
    );
  }

  if (!response.available) {
    return (
      <div className="text-muted py-4 text-center" data-testid={`agent-card-${response.reason}`}>
        <i className="fas fa-id-card fa-2x mb-2 d-block" aria-hidden="true" />
        {UNAVAILABLE_TEXT[response.reason] ?? "Agent Card isn't available"}
      </div>
    );
  }

  const json = JSON.stringify(response.card, null, 2);
  return (
    <div className="card" data-testid="agent-card-tab">
      <div className="card-header py-2 d-flex align-items-center justify-content-between">
        <span className="badge text-bg-warning" data-testid="agent-card-unverified">
          <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
          Published by the agent, not verified
        </span>
        <CopyButton
          text={json}
          variant="outline-primary"
          label="Copy JSON"
          title="Copy JSON"
          data-testid="agent-card-copy-button"
        />
      </div>
      <pre
        className="card-body mb-0 small"
        style={{ maxHeight: '60vh', overflow: 'auto', whiteSpace: 'pre-wrap' }}
        data-testid="agent-card-json"
      >
        {json}
      </pre>
    </div>
  );
};

export default AgentCardTab;
