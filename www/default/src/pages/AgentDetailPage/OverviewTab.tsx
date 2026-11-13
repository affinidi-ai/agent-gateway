import React from 'react';
import type { AgentRecord } from '../../api';
import { formatDateTime } from '../../utils/stringUtils';
import { AgentDid, AgentProtocolBadge, AgentTrustRegistryBadge } from '../AgentsPage/AgentBadges';
import { NO_DID, identitySourceLabel, runtimeLabel } from '../AgentsPage/agentLabels';

const OverviewTab: React.FC<{ agent: AgentRecord }> = ({ agent }) => {
  const details: { label: string; value: React.ReactNode; testId: string }[] = [
    { label: 'Runtime', value: runtimeLabel(agent.runtime), testId: 'agent-overview-runtime' },
    {
      label: 'Protocol',
      value: <AgentProtocolBadge protocol={agent.protocol} runtime={agent.runtime} />,
      testId: 'agent-overview-protocol',
    },
    { label: 'Description', value: '—', testId: 'agent-overview-description' },
  ];

  return (
    <div className="row" data-testid="agent-overview-tab">
      <div className="col-lg-7 mb-3">
        <h6 className="font-weight-bold">Identities ({agent.identities.length})</h6>
        {agent.identities.length === 0 ? (
          <div className="border rounded p-2 mb-3">
            <span className="text-muted small" data-testid="agents-no-did">
              {NO_DID}
            </span>
          </div>
        ) : (
          <ul className="list-unstyled mb-3" data-testid="agent-overview-identities">
            {agent.identities.map(identity => (
              <li
                key={identity.did}
                className="border rounded p-2 mb-2"
                data-testid="agent-overview-identity"
              >
                <AgentDid did={identity.did} full />
                <div className="text-muted small" data-testid="agent-overview-identity-source">
                  {identitySourceLabel(identity.source)}
                  {identity.created_at && `. Created ${formatDateTime(identity.created_at, true)}`}
                </div>
              </li>
            ))}
          </ul>
        )}
        <div className="d-flex align-items-center flex-wrap gap-2">
          <strong className="small">Trust registry</strong>
          <AgentTrustRegistryBadge trust={agent.trust_registry} />
        </div>
      </div>
      <div className="col-lg-5 mb-3">
        <h6 className="font-weight-bold">Details</h6>
        <dl className="row mb-0">
          {details.map(({ label, value, testId }) => (
            <React.Fragment key={label}>
              <dt className="col-5 text-muted fw-normal small">{label}</dt>
              <dd className="col-7 small" data-testid={testId}>
                {value}
              </dd>
            </React.Fragment>
          ))}
        </dl>
      </div>
    </div>
  );
};

export default OverviewTab;
