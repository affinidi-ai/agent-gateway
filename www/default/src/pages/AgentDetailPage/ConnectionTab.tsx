import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import type { AgentDetails, AgentSurfaceSummary } from '../../api';
import { CopyButton } from '../../components/shared/CopyButton';
import { usePermissions } from '../../context/PermissionsContext';
import { SurfaceLinkButton } from '../IdentitiesPage/IdentitySurfaceCell';
import { AgentRouteBadge } from '../AgentsPage/AgentBadges';
import type { AgentConnectionTarget } from '../AgentsPage/agentLabels';
import {
  connectionTarget,
  routeDescription,
  runtimeIcon,
  surfacesUsedLabel,
} from '../AgentsPage/agentLabels';

/** The A2A proxy or remote gateway by name, as plain text, or by id when it has none. */
const TargetLabel: React.FC<{ name?: string | null; id: string }> = ({ name, id }) =>
  name ? <span title={id}>{name}</span> : <code>{id}</code>;

const ROUTE_DESCRIPTIONS: Record<AgentConnectionTarget['kind'], string> = {
  url: routeDescription('url'),
  'a2a-proxy': routeDescription('a2a-proxy'),
  gateway: routeDescription('gateway'),
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

/** One surface: its name linking to the surface page, and the URL callers use. */
const SurfaceRow: React.FC<{ surface: AgentSurfaceSummary; onOpen: (id: string) => void }> = ({
  surface,
  onOpen,
}) => (
  <div data-testid={`agent-connection-surface-${surface.surface_id}`}>
    <dt>
      <SurfaceLinkButton
        surface={{ id: surface.surface_id, name: surface.name, deleted: false }}
        onOpen={onOpen}
        data-testid="agent-connection-surface-link"
      />
    </dt>
    <dd data-testid="agent-connection-surface-url">
      {surface.public_url ? (
        <>
          <code className="text-break">{surface.public_url}</code>
          <CopyButton
            text={surface.public_url}
            title="Copy URL"
            data-testid="agent-connection-copy-surface-url"
          />
        </>
      ) : (
        <>
          <code className="text-break">{surface.route}</code>
          <span className="small text-muted ms-2">No external URL configured</span>
        </>
      )}
    </dd>
  </div>
);

/**
 * How callers reach the agent and how the gateway reaches it: each surface with the URL
 * callers use, then the surfaces' `target.endpoint`. Read-only; both are changed in the
 * surface editor.
 */
const ConnectionTab: React.FC<{ agent: AgentDetails }> = ({ agent }) => {
  const { hasPermission } = usePermissions();
  const navigate = useNavigate();
  const openSurface = (id: string) => navigate(`/surfaces/${encodeURIComponent(id)}`);
  const target = connectionTarget(agent.endpoint);
  const hops: HopProps[] = [
    {
      label: agent.surfaces.length === 1 ? 'Surface' : 'Surfaces',
      value:
        agent.surfaces.length === 1
          ? agent.surfaces[0].name
          : surfacesUsedLabel(agent.surfaces.length),
      icon: 'fa-sign-in-alt',
      testId: 'agent-connection-surfaces-hop',
    },
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
      <div className="mb-2">
        <h6 className="m-0 fw-bold">Surfaces</h6>
        <div className="small text-muted">The URLs callers use to reach this agent.</div>
      </div>
      {agent.surfaces.length === 0 ? (
        <p className="small text-muted mb-4" data-testid="agent-connection-no-surfaces">
          No surface uses this agent.
        </p>
      ) : (
        <dl className="agent-connection-details mb-4" data-testid="agent-connection-surfaces">
          {agent.surfaces.map(surface => (
            <SurfaceRow key={surface.surface_id} surface={surface} onOpen={openSurface} />
          ))}
        </dl>
      )}

      <div className="mb-3">
        <h6 className="m-0 fw-bold d-flex align-items-center gap-2">
          Route
          <AgentRouteBadge runtime={agent.runtime} data-testid="agent-connection-runtime" />
        </h6>
        <div className="small text-muted" data-testid="agent-connection-description">
          {ROUTE_DESCRIPTIONS[target.kind]}
        </div>
      </div>

      <div
        className="agent-connection-path mb-3"
        role="group"
        aria-label="Route path"
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
