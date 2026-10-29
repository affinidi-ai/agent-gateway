import React from 'react';
import type { AgentRecord } from '../../api';
import { formatDateTime } from '../../utils/stringUtils';
import { AgentDid, AgentProtocolBadge, AgentTrustRegistryBadges } from '../AgentsPage/AgentBadges';
import {
  TRUST_NOT_CHECKED,
  didSourceLabel,
  otherSurfacesNote,
  runtimeLabel,
} from '../AgentsPage/agentLabels';

const OverviewTab: React.FC<{ agent: AgentRecord }> = ({ agent }) => {
  const otherSurfaces = otherSurfacesNote(agent.did_surface_count);
  const details: { label: string; value: React.ReactNode; testId: string }[] = [
    { label: 'Runtime', value: runtimeLabel(agent.runtime), testId: 'agent-overview-runtime' },
    {
      label: 'Protocol',
      value: <AgentProtocolBadge protocol={agent.protocol} runtime={agent.runtime} />,
      testId: 'agent-overview-protocol',
    },
    { label: 'Description', value: '—', testId: 'agent-overview-description' },
    {
      label: 'Identity created',
      value: agent.identity_created_at ? formatDateTime(agent.identity_created_at, true) : '—',
      testId: 'agent-overview-identity-created',
    },
  ];

  return (
    <div className="row" data-testid="agent-overview-tab">
      <div className="col-lg-7 mb-3">
        <h6 className="font-weight-bold">Identity</h6>
        <div className="border rounded p-2 mb-2">
          <AgentDid did={agent.agent_did} full />
        </div>
        {agent.agent_did && (
          <p className="text-muted small mb-3" data-testid="agent-overview-did-source">
            {didSourceLabel(agent)}
            {otherSurfaces && `. ${otherSurfaces}.`}
          </p>
        )}
        <div className="d-flex align-items-center flex-wrap" style={{ gap: '0.5rem' }}>
          <strong className="small">Trust registry</strong>
          <AgentTrustRegistryBadges trust={agent.trust_registry} />
        </div>
        <p className="text-muted small mt-1 mb-0" data-testid="agent-overview-trust-note">
          {TRUST_NOT_CHECKED}.
        </p>
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
