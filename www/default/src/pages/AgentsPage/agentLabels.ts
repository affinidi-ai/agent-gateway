import type { AgentRecord, AgentRuntime, AgentTrustRegistry } from '../../api';
import { timeAgo } from '../../utils/stringUtils';

/**
 * Display text for the agent record's raw values. The API returns enums; the
 * pages never show them as-is.
 */

const RUNTIME_LABELS: Record<AgentRuntime, string> = {
  url: 'Direct',
  'a2a-proxy': 'Proxied',
  gateway: 'Fabric',
};

const RUNTIME_ICONS: Record<AgentRuntime, string> = {
  url: 'fa-link',
  'a2a-proxy': 'fa-exchange-alt',
  gateway: 'fa-network-wired',
};

/** What each route means, for the route badge's tooltip and screen readers. */
const ROUTE_DESCRIPTIONS: Record<AgentRuntime, string> = {
  url: 'The gateway calls the agent URL directly.',
  'a2a-proxy': 'The gateway forwards to an A2A proxy, which generates the Agent Card.',
  gateway: 'The gateway forwards over the trust fabric to a remote gateway.',
};

const PROTOCOL_LABELS: Record<string, string> = {
  a2a: 'A2A',
  ap2: 'AP2',
  mcp: 'MCP',
  didcomm: 'DIDComm',
};

/** The protocol badge colours of the Surfaces page. */
const PROTOCOL_BADGE_CLASSES: Record<string, string> = {
  a2a: 'text-bg-primary',
  ap2: 'text-bg-warning',
  mcp: 'text-bg-info',
};

export const UNNAMED_AGENT = 'Unnamed agent';
export const NO_DID = 'No DID';

export function displayName(agent: Pick<AgentRecord, 'name'>): string {
  return agent.name ?? UNNAMED_AGENT;
}

export function runtimeLabel(runtime: string): string {
  return RUNTIME_LABELS[runtime as AgentRuntime] ?? 'Unknown runtime';
}

export function runtimeIcon(runtime: string): string {
  return RUNTIME_ICONS[runtime as AgentRuntime] ?? 'fa-robot';
}

export function routeDescription(runtime: string): string {
  return (
    ROUTE_DESCRIPTIONS[runtime as AgentRuntime] ?? 'How the gateway reaches this agent is unknown.'
  );
}

export function protocolLabel(protocol: string): string {
  return PROTOCOL_LABELS[protocol] ?? 'Other protocol';
}

export function protocolBadgeClass(protocol: string): string {
  return PROTOCOL_BADGE_CLASSES[protocol] ?? 'text-bg-secondary';
}

export function trustRegistryLabel(trust: AgentTrustRegistry): string {
  return trust.recorded ? 'Recorded' : 'Not recorded';
}

/** What `target.endpoint` points at, safe to display. */
export type AgentConnectionTarget =
  | { kind: 'url'; display: string }
  | { kind: 'a2a-proxy'; proxyId: string }
  | { kind: 'gateway'; gatewayId: string; channelId: string | null }
  | { kind: 'unknown' };

/** The host the API puts in an endpoint it can't show without its credentials. */
const REDACTED_HOST = 'redacted.invalid';

function isRedacted(endpoint: string): boolean {
  const authority = endpoint.split('://')[1]?.split(/[/?#]/)[0];
  return authority?.toLowerCase() === REDACTED_HOST;
}

/**
 * Splits the endpoint by scheme. The API returns a URL without credentials,
 * query string or fragment; any that arrive are dropped here too. A redacted
 * endpoint is `unknown`, so it is never shown as a real host.
 */
export function connectionTarget(endpoint: string): AgentConnectionTarget {
  if (isRedacted(endpoint)) return { kind: 'unknown' };
  if (endpoint.startsWith('a2a-proxy://')) {
    const proxyId = endpoint.slice('a2a-proxy://'.length).replace(/\/+$/, '');
    return proxyId ? { kind: 'a2a-proxy', proxyId } : { kind: 'unknown' };
  }
  if (endpoint.startsWith('fabric://')) {
    const [gatewayId, channelId] = endpoint.slice('fabric://'.length).split('/');
    return gatewayId
      ? { kind: 'gateway', gatewayId, channelId: channelId || null }
      : { kind: 'unknown' };
  }
  try {
    const url = new URL(endpoint);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return { kind: 'unknown' };
    return { kind: 'url', display: `${url.origin}${url.pathname === '/' ? '' : url.pathname}` };
  } catch {
    return { kind: 'unknown' };
  }
}

/**
 * The short target shown under the agent name, so rows with the same name can
 * be told apart: the URL origin (scheme and host), the A2A proxy, or the remote gateway (and
 * channel). A proxy or gateway shows its name, or its id when the API returns none. `null` for
 * an endpoint that can't be shown.
 */
export function endpointHost(agent: Pick<AgentRecord, 'endpoint' | 'target_name'>): string | null {
  const target = connectionTarget(agent.endpoint);
  const name = agent.target_name?.trim() || null;
  switch (target.kind) {
    case 'url':
      return new URL(target.display).origin;
    case 'a2a-proxy':
      return name ?? target.proxyId;
    case 'gateway': {
      const gateway = name ?? target.gatewayId;
      return target.channelId ? `${gateway}/${target.channelId}` : gateway;
    }
    default:
      return null;
  }
}

/** "1 identity" or "N identities". */
export function identitiesLabel(count: number): string {
  return `${count} ${count === 1 ? 'identity' : 'identities'}`;
}

/** `360` → `6h`, `90` → `90m`, `2880` → `2d`. */
export function formatWindow(minutes: number): string {
  if (minutes > 0 && minutes % 1440 === 0) return `${minutes / 1440}d`;
  if (minutes > 0 && minutes % 60 === 0) return `${minutes / 60}h`;
  return `${minutes}m`;
}

/**
 * Activity is only known inside the metrics retention window, so "never" isn't
 * claimed: an agent idle for longer shows `None in last 6h`.
 */
export function lastActivityLabel(at: string | null, windowMinutes?: number): string {
  if (at) return timeAgo(at);
  return windowMinutes ? `None in last ${formatWindow(windowMinutes)}` : 'None retained';
}

/** Shortened in the middle, so both the method and the unique tail stay visible. */
export function shortenDid(did: string, head = 20, tail = 8): string {
  if (did.length <= head + tail + 1) return did;
  return `${did.slice(0, head)}…${did.slice(-tail)}`;
}

/** "Not used", "1 surface" or "N surfaces". */
export function surfacesUsedLabel(count: number): string {
  return count === 0 ? 'Not used' : `${count} surface${count === 1 ? '' : 's'}`;
}

/** Matches the display name, every surface name and the runtime label. */
export function agentMatchesFilter(agent: AgentRecord, term: string): boolean {
  const needle = term.trim().toLowerCase();
  if (!needle) return true;
  return [
    displayName(agent),
    ...agent.surfaces.map(surface => surface.name),
    runtimeLabel(agent.runtime),
  ].some(value => value.toLowerCase().includes(needle));
}
