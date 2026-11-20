import React from 'react';
import { Link } from 'react-router-dom';
import type { AgentDetails, AgentRegistryOutcome } from '../../api';
import { CopyButton } from '../../components/shared/CopyButton';
import { TrustRecorderStateBadge } from '../../components/trust-recorder/TrustRecorderStateBadge';
import { usePermissions } from '../../context/PermissionsContext';
import { trustRecorderReasonText } from '../../utils/trustRecorderStatus';
import { AgentDid } from '../AgentsPage/AgentBadges';
import type { AgentConnectionTarget } from '../AgentsPage/agentLabels';
import { connectionTarget, routeDescription } from '../AgentsPage/agentLabels';

/** The A2A proxy or remote gateway by name, as plain text, or by id when it has none. */
const TargetLabel: React.FC<{ name?: string | null; id: string }> = ({ name, id }) =>
  name ? <span title={id}>{name}</span> : <code>{id}</code>;

const ROUTE_DESCRIPTIONS: Record<AgentConnectionTarget['kind'], string> = {
  url: routeDescription('url'),
  'a2a-proxy': routeDescription('a2a-proxy'),
  gateway: routeDescription('gateway'),
  unknown: "The endpoint can't be shown, so the target is hidden.",
};

/**
 * Which Trust Registry each of the agent's identities was written to, with the last Trust
 * Recorder outcome. The registry links to its page only with `trust_registries.edit`.
 */
const TrustRegistrySection: React.FC<{ outcomes: AgentRegistryOutcome[] }> = ({ outcomes }) => {
  const { hasPermission } = usePermissions();
  return (
    <section className="mt-4" data-testid="agent-connection-trust-registry">
      <h6 className="agent-preview-section-title m-0">Trust registry</h6>
      <div className="small text-muted mb-3">
        Where the agent&apos;s identities were recorded. Recording is not a trust decision.
      </div>
      {outcomes.length === 0 ? (
        <p className="text-muted small mb-0" data-testid="agent-connection-trust-registry-empty">
          No identity of this agent was sent to a trust registry.
        </p>
      ) : (
        <table className="table table-sm align-middle mb-0 agent-preview-changes">
          <thead>
            <tr>
              <th scope="col">Trust registry</th>
              <th scope="col">Identity</th>
              <th scope="col">Status</th>
            </tr>
          </thead>
          <tbody>
            {outcomes.map(outcome => {
              const label = (
                <TargetLabel name={outcome.trust_registry_name} id={outcome.trust_registry_id} />
              );
              const reason = trustRecorderReasonText(outcome.reason);
              return (
                <tr
                  key={`${outcome.trust_registry_id}-${outcome.did}`}
                  data-testid={`agent-connection-registry-${outcome.trust_registry_id}`}
                >
                  <td className="agent-preview-change-field text-break">
                    {hasPermission('trust_registries.edit') ? (
                      <Link
                        to={`/trust-registries/${encodeURIComponent(outcome.trust_registry_id)}`}
                      >
                        {label}
                      </Link>
                    ) : (
                      label
                    )}
                  </td>
                  <td>
                    <AgentDid did={outcome.did} />
                  </td>
                  <td>
                    <TrustRecorderStateBadge state={outcome.state} />
                    {reason && <div className="text-muted small text-break">{reason}</div>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
};

/**
 * Where the surfaces' `target.endpoint` sends callers.
 * Read-only; the route is changed in the surface editor.
 */
const ConnectionTab: React.FC<{ agent: AgentDetails }> = ({ agent }) => {
  const { hasPermission } = usePermissions();
  const target = connectionTarget(agent.endpoint);

  let rows: { label: string; value: React.ReactNode; testId: string }[];
  switch (target.kind) {
    case 'url':
      rows = [
        {
          label: 'Endpoint',
          value: (
            <>
              <code className="text-break">{target.display}</code>
              <CopyButton
                text={target.display}
                title="Copy endpoint"
                data-testid="agent-connection-copy-endpoint"
              />
            </>
          ),
          testId: 'agent-connection-endpoint',
        },
      ];
      break;
    case 'a2a-proxy':
      rows = [
        {
          label: 'A2A proxy',
          value: hasPermission('a2a_proxies.edit') ? (
            <Link
              to={`/proxies/a2a-proxies/${encodeURIComponent(target.proxyId)}`}
              data-testid="agent-connection-proxy-link"
            >
              <TargetLabel name={agent.target_name} id={target.proxyId} />
            </Link>
          ) : (
            <TargetLabel name={agent.target_name} id={target.proxyId} />
          ),
          testId: 'agent-connection-proxy',
        },
      ];
      break;
    case 'gateway':
      rows = [
        {
          label: 'Remote gateway',
          value: hasPermission('gateways.edit') ? (
            <Link
              to={`/gateways/${encodeURIComponent(target.gatewayId)}`}
              data-testid="agent-connection-gateway-link"
            >
              <TargetLabel name={agent.target_name} id={target.gatewayId} />
            </Link>
          ) : (
            <TargetLabel name={agent.target_name} id={target.gatewayId} />
          ),
          testId: 'agent-connection-gateway',
        },
        {
          label: 'Remote surface',
          value: target.channelId ? <code>{target.channelId}</code> : '—',
          testId: 'agent-connection-remote-surface',
        },
      ];
      break;
    default:
      rows = [
        {
          label: 'Endpoint',
          value: <span className="text-muted">Can&apos;t be shown</span>,
          testId: 'agent-connection-endpoint',
        },
      ];
  }

  return (
    <div data-testid="agent-connection-tab">
      <div className="mb-3">
        <h6 className="agent-preview-section-title m-0">Route</h6>
        <div className="small text-muted" data-testid="agent-connection-description">
          {ROUTE_DESCRIPTIONS[target.kind]}
        </div>
      </div>

      <table className="table table-sm align-middle mb-0 agent-preview-changes">
        <thead>
          <tr>
            <th scope="col">Field</th>
            <th scope="col">Value</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ label, value, testId }) => (
            <tr key={label}>
              <td className="agent-preview-change-field">{label}</td>
              <td className="text-break" data-testid={testId}>
                {value}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <TrustRegistrySection outcomes={agent.trust_registry.registries ?? []} />
    </div>
  );
};

export default ConnectionTab;
