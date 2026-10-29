import React from 'react';
import { Link } from 'react-router-dom';
import type { AgentRecord } from '../../api';
import { usePermissions } from '../../context/PermissionsContext';
import { connectionTarget, runtimeLabel } from '../AgentsPage/agentLabels';

/**
 * How the gateway reaches the agent: the surface's `target.endpoint`.
 * Read-only; the endpoint is changed in the surface editor.
 */
const ConnectionTab: React.FC<{ agent: AgentRecord }> = ({ agent }) => {
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
              {target.redacted && (
                <div className="text-muted small" data-testid="agent-connection-redacted">
                  Credentials, query string and fragment are hidden.
                </div>
              )}
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
              <code>{target.proxyId}</code>
            </Link>
          ) : (
            <code>{target.proxyId}</code>
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
              <code>{target.gatewayId}</code>
            </Link>
          ) : (
            <code>{target.gatewayId}</code>
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
      <dl className="row mb-2">
        <dt className="col-sm-3 text-muted fw-normal small">Reached through</dt>
        <dd className="col-sm-9 small" data-testid="agent-connection-runtime">
          {runtimeLabel(agent.runtime)}
        </dd>
        {rows.map(({ label, value, testId }) => (
          <React.Fragment key={label}>
            <dt className="col-sm-3 text-muted fw-normal small">{label}</dt>
            <dd className="col-sm-9 small" data-testid={testId}>
              {value}
            </dd>
          </React.Fragment>
        ))}
      </dl>
      <p className="text-muted small mb-0">
        Set on the surface&apos;s Managed Agent. Edit it from the surface.
      </p>
    </div>
  );
};

export default ConnectionTab;
