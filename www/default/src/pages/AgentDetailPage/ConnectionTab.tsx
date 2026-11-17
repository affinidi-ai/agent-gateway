import React from 'react';
import { Link } from 'react-router-dom';
import type { AgentDetails } from '../../api';
import { CopyButton } from '../../components/shared/CopyButton';
import { usePermissions } from '../../context/PermissionsContext';
import type { AgentConnectionTarget } from '../AgentsPage/agentLabels';
import {
  connectionTarget,
  protocolLabel,
  runtimeIcon,
  runtimeLabel,
} from '../AgentsPage/agentLabels';

/** The A2A proxy or remote gateway by name, as plain text, or by id when it has none. */
const TargetLabel: React.FC<{ name?: string | null; id: string }> = ({ name, id }) =>
  name ? <span title={id}>{name}</span> : <code>{id}</code>;

const ROUTE_DESCRIPTIONS: Record<AgentConnectionTarget['kind'], string> = {
  url: 'The gateway calls the agent URL directly.',
  'a2a-proxy': 'The gateway forwards to an A2A proxy.',
  gateway: 'The gateway forwards over the trust fabric to a remote gateway.',
  unknown: "The endpoint can't be shown, so the target is hidden.",
};

interface HopProps {
  label: string;
  value: string;
  icon: string;
  tone?: 'target' | 'hidden';
  testId?: string;
}

/** The last hop of the path: what `target.endpoint` names, as plain text. */
function targetHop(target: AgentConnectionTarget, targetName?: string | null): HopProps {
  const hop = { icon: runtimeIcon(target.kind), tone: 'target' as const };
  switch (target.kind) {
    case 'url':
      return { ...hop, label: 'Agent URL', value: new URL(target.display).host };
    case 'a2a-proxy':
      return { ...hop, label: 'A2A proxy', value: targetName || target.proxyId };
    case 'gateway':
      return { ...hop, label: 'Remote gateway', value: targetName || target.gatewayId };
    default:
      return { label: 'Target', value: 'Hidden', icon: 'fa-eye-slash', tone: 'hidden' };
  }
}

const Hop: React.FC<HopProps> = ({ label, value, icon, tone, testId }) => (
  <div className={`agent-connection-hop${tone ? ` is-${tone}` : ''}`} data-testid={testId}>
    <span className="agent-connection-hop-icon" aria-hidden="true">
      <i className={`fas ${icon}`} />
    </span>
    <div className="agent-connection-hop-text">
      <div className="agent-connection-hop-label">{label}</div>
      <div className="agent-connection-hop-value">{value}</div>
    </div>
  </div>
);

/**
 * How the gateway reaches the agent: the surface's `target.endpoint`, as a
 * path and a detail list. Read-only; the endpoint is changed in the surface editor.
 */
const ConnectionTab: React.FC<{ agent: AgentDetails }> = ({ agent }) => {
  const { hasPermission } = usePermissions();
  const target = connectionTarget(agent.endpoint);
  const hops: HopProps[] = [
    { label: 'Caller', value: `${protocolLabel(agent.protocol)} client`, icon: 'fa-user' },
    { label: 'Surface', value: 'Access Point', icon: 'fa-sign-in-alt' },
    { label: 'Gateway', value: 'This gateway', icon: 'fa-server' },
    { ...targetHop(target, agent.target_name), testId: 'agent-connection-target' },
  ];

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
        <h6 className="m-0 fw-bold">Upstream</h6>
        <div className="small text-muted" data-testid="agent-connection-description">
          {ROUTE_DESCRIPTIONS[target.kind]}
        </div>
      </div>

      <div
        className="agent-connection-path mb-3"
        role="group"
        aria-label="Upstream path"
        data-testid="agent-connection-path"
      >
        {hops.map((hop, index) => (
          <React.Fragment key={hop.label}>
            {index > 0 && (
              <span className="agent-connection-arrow" aria-hidden="true">
                <i className="fas fa-chevron-right" />
              </span>
            )}
            <Hop {...hop} />
          </React.Fragment>
        ))}
      </div>

      <dl className="agent-connection-details">
        <div>
          <dt>Route</dt>
          <dd data-testid="agent-connection-runtime">
            <span className="badge bg-info">
              <i className={`fas ${runtimeIcon(agent.runtime)} me-1`} aria-hidden="true" />
              {runtimeLabel(agent.runtime)}
            </span>
          </dd>
        </div>
        {rows.map(({ label, value, testId }) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd data-testid={testId}>{value}</dd>
          </div>
        ))}
      </dl>
    </div>
  );
};

export default ConnectionTab;
