import { apiClient } from '../../../../api';
import { generateRandomPath } from '../../../../utils/stringUtils';

export interface RoutingConfig {
  available_listen_addresses: string[];
  /**
   * Listen addresses configured for the *outbound* (transit) listener.
   * Distinct from `available_listen_addresses` (all listeners, including outbound, with
   * duplicates). The TP panel compares counts between the two lists to detect shared-domain
   * addresses — a URL appearing more times in the full list than in the outbound-only list
   * also belongs to an inbound listener.
   */
  available_outbound_listen_addresses?: string[];
  /**
   * The outbound addresses whose listener shares a hostname with an inbound listener, as the
   * gateway classifies them with the same function its save gate uses
   * (`outbound_address_shares_an_inbound_hostname`). Absent from a gateway older than that
   * field, which is the only reason `computeSharedOutboundAddresses` still falls back.
   */
  shared_hostname_outbound_addresses?: string[];
  channel_path_prefix: ChannelPrefix[];
  /**
   * The same prefixes under `/outbound`, as the gateway builds them. A Transit Point's
   * `listen_path` under one of these is reachable at every outbound address, whichever
   * hostname its listener has. Absent from a gateway older than the field, which is why
   * `outboundChannelPrefixes` can still derive them.
   */
  outbound_channel_path_prefix?: ChannelPrefix[];
}

export interface ChannelPrefix {
  id: string;
  name: string;
  prefix: string;
}

export const OUTBOUND_PREFIX = '/outbound';

/**
 * Returns the set of outbound listener URLs that are also reachable on an inbound listener
 * (shared domain), as the gateway classifies them.
 *
 * The classification comes from the gateway, which decides it per listener with the same
 * function its save gate uses. Two address lists cannot express it: a listener answers on
 * every one of its `external_urls`, so an alias URL in no inbound list still belongs to a
 * shared listener, and `https://host:9443` beside an inbound `https://host` is the same
 * hostname.
 *
 * The result is used to:
 * - Label shared addresses in the TP "Listen Address" dropdown.
 * - Narrow the channel-prefix options to the `/outbound/` forms on a shared selection.
 */
export function computeSharedOutboundAddresses(config: RoutingConfig): Set<string> {
  const outbound = config.available_outbound_listen_addresses ?? [];
  const classified = config.shared_hostname_outbound_addresses;
  if (classified) {
    const shared = new Set(classified);
    return new Set(outbound.filter(a => shared.has(a)));
  }
  const inbound = new Set(config.available_listen_addresses ?? []);
  return new Set(outbound.filter(a => inbound.has(a)));
}

/**
 * The prefixes the Listen Path picker offers for one node.
 *
 * An inbound address offers `channel_path_prefix` as it stands. An outbound address whose
 * listener shares a hostname with an inbound listener offers the `/outbound` forms alone,
 * since the inbound pipeline owns every other path there and the save refuses one. An
 * outbound address with a hostname of its own offers both forms, which the save accepts
 * both of, so a path stored in either form resolves in the picker; a root channel has no
 * usable plain form, because that is the whole listener.
 *
 * One implementation, read by the picker, by the required-field errors beside it and by the
 * save gate, so none of the three can offer what the others refuse.
 */
export function offeredChannelPrefixes(
  routing: RoutingConfig,
  addressSource: 'inbound' | 'outbound',
  address: string
): ChannelPrefix[] {
  const plain = routing.channel_path_prefix ?? [];
  if (addressSource !== 'outbound') return plain;
  const outbound = outboundChannelPrefixes(routing);
  if (computeSharedOutboundAddresses(routing).has(address)) return outbound;
  return plain.flatMap((c, idx) =>
    isRootPrefix(c.prefix) ? [outbound[idx] ?? c] : [c, outbound[idx]].filter(Boolean)
  );
}

/** A surface prefix that is the whole listener, so nothing can be set directly under it. */
function isRootPrefix(prefix: string): boolean {
  return prefix.replace(/\/$/, '') === '';
}

/**
 * The channel prefixes under `/outbound`: the gateway's own list when it sends one, and
 * otherwise the same rule applied here, so the two cannot disagree about which paths are
 * on offer.
 */
function outboundChannelPrefixes(routing: RoutingConfig): ChannelPrefix[] {
  const plain = routing.channel_path_prefix ?? [];
  const advertised = routing.outbound_channel_path_prefix;
  return plain.map((c, idx) => ({
    id: `outbound-${c.id}`,
    name: `outbound → ${c.name}`,
    prefix:
      advertised?.find(o => o.id === c.id)?.prefix ??
      advertised?.[idx]?.prefix ??
      `${OUTBOUND_PREFIX}${c.prefix.replace(/\/$/, '')}`,
  }));
}

/**
 * Returns the "meaningful" subset of listener addresses — those that are not
 * localhost / 127.0.0.1. Falls back to the full list when all entries are
 * local (e.g. a dev-only setup).
 *
 * Used to decide whether to show the Listen Address picker: when only one
 * meaningful address exists the picker adds no value and is hidden.
 */
export function meaningfulListenerAddresses(addresses: string[]): string[] {
  const unique = [...new Set(addresses)];
  const nonLocal = unique.filter(
    a =>
      !a.replace(/^https?:\/\//, '').startsWith('localhost:') &&
      !a.replace(/^https?:\/\//, '').startsWith('127.0.0.1:')
  );
  return nonLocal.length > 0 ? nonLocal : unique;
}

/**
 * Returns true when the Listen Address picker can be hidden.
 *
 * Rules:
 * - Hide when there is only one meaningful (non-localhost) address AND
 * - The saved address is that address, or nothing is saved yet.
 *
 * Show when the saved address is no longer in the meaningful set — this
 * happens after a new public listener is added post-save; the operator
 * must be able to switch to the new address.
 */
export function shouldHideListenerPicker(meaningful: string[], savedAddress: string): boolean {
  if (meaningful.length > 1) return false;
  if (!savedAddress) return true;
  return meaningful.includes(savedAddress);
}

let cachedRoutingConfig: RoutingConfig | null = null;
let routingConfigPromise: Promise<RoutingConfig | null> | null = null;

export function fetchRoutingConfig(): Promise<RoutingConfig | null> {
  if (cachedRoutingConfig) return Promise.resolve(cachedRoutingConfig);
  if (routingConfigPromise) return routingConfigPromise;
  routingConfigPromise = apiClient
    .fetch('/api/v1/config/surface-routing')
    .then(r => (r.ok ? r.json() : null))
    .then((data: RoutingConfig | null) => {
      if (data) cachedRoutingConfig = data;
      return data;
    })
    .catch(() => null);
  return routingConfigPromise;
}

/**
 * Synchronous accessor for the outbound listen addresses from the cached
 * routing config. Returns `null` when the routing config has not been
 * fetched yet (so pure validators can skip the check instead of raising a
 * false positive), or the (possibly empty) list of outbound listener URLs
 * once it has loaded. Warmed by `SurfaceFormShell` on mount via
 * `fetchRoutingConfig`.
 */
export function getCachedOutboundListenAddresses(): string[] | null {
  if (!cachedRoutingConfig) return null;
  return cachedRoutingConfig.available_outbound_listen_addresses ?? [];
}

/**
 * The cached routing config, or `null` while it has not been fetched, so a pure validator
 * can skip its check instead of raising a false positive. Warmed by `SurfaceFormShell`.
 */
export function getCachedRoutingConfig(): RoutingConfig | null {
  return cachedRoutingConfig;
}

/**
 * What `listenPathProblem` reads: the two fields of a Transit Point, from a canvas node's
 * config or from a built payload's `transit.points[]`, that decide where it answers. Both
 * are `unknown` because either source may be missing them or carry something else.
 */
export interface TransitPointRoute {
  listen_path?: unknown;
  listen_address?: unknown;
}

/**
 * What blocks a save of one Transit Point's Listen Path, or `null`. The two refusals the
 * admin API answers such a save with, in the same order, so the dashboard refuses exactly
 * what the gateway would (`listen_path_problems` in `src/proxy/server.rs`):
 *
 * - `listen_path_not_a_channel_prefix`: the path must sit under one of the configured
 *   surface prefixes, with or without `/outbound` in front, and needs a segment of its own
 *   after it. Both forms are accepted wherever the path is reachable, which is why this is
 *   checked against every prefix rather than against the narrower list the picker offers.
 * - `listen_path_not_served`: on an address whose listener shares a hostname with an inbound
 *   listener, a path outside `/outbound` answers on the outbound listener alone, so the
 *   inbound address never reaches it. Those are the addresses the picker narrows for.
 *
 * An empty `listen_path` is not a problem: the point then answers at the route the gateway
 * derives from its alias, and clearing the field is how the dashboard goes back to it.
 *
 * `routing` defaults to the cached config; while that is unfetched there is nothing to
 * check against and the answer is `null`.
 */
export function listenPathProblem(
  point: TransitPointRoute,
  routing: RoutingConfig | null = getCachedRoutingConfig()
): string | null {
  if (!routing) return null;
  const composed = typeof point.listen_path === 'string' ? point.listen_path.trim() : '';
  if (!composed) return null;
  const channels = routing.channel_path_prefix ?? [];
  const outbound = outboundChannelPrefixes(routing);
  const every = channels.flatMap((c, idx) => {
    const plain = c.prefix.replace(/\/$/, '');
    return [plain, outbound[idx]?.prefix ?? `${OUTBOUND_PREFIX}${plain}`].filter(Boolean);
  });
  const offered = every.map(p => `${p}/`).join(', ') || 'this gateway configures none';
  // Matched against every prefix, and read as the listener registers the path,
  // which is what `claims_a_channel_prefix` does: a nested prefix listed first
  // claims no path its own segments do not cover, and a path whose only
  // remainder is slashes claims the bare prefix.
  const registered = composed.replace(/\/+$/, '');
  const match = every.find(
    p => registered.startsWith(`${p}/`) && registered.slice(p.length).replace(/\//g, '') !== ''
  );
  if (!match) {
    return `Listen Path "${composed}" claims no segment of its own under a surface prefix this gateway serves Transit Points on (${offered}). Pick a prefix and a path under it, or clear the path to answer at the derived ${OUTBOUND_PREFIX} route.`;
  }
  const address = typeof point.listen_address === 'string' ? point.listen_address : '';
  const sharedHostname = computeSharedOutboundAddresses(routing).has(address);
  const underOutbound =
    registered === OUTBOUND_PREFIX || registered.startsWith(`${OUTBOUND_PREFIX}/`);
  if (sharedHostname && !underOutbound) {
    return `Listen Path "${composed}" is outside ${OUTBOUND_PREFIX}, and an inbound listener shares this outbound listener's hostname, so it answers on the outbound address alone. Pick one of the ${OUTBOUND_PREFIX} prefixes, or clear the path to answer at the derived ${OUTBOUND_PREFIX} route.`;
  }
  return null;
}

/**
 * Build the default Access Point config from a routing config: first
 * available listen address, first channel prefix, random suffix, and the
 * resulting joined route. Used both by the panel's seed effect and by
 * the create page so the AP is "Configured" before the user clicks it.
 */
export function buildDefaultAccessPointConfig(routing: RoutingConfig): {
  listen_address: string;
  route_prefix: string;
  route_suffix: string;
  route: string;
} {
  const suffix = generateRandomPath();
  const path = suffix.startsWith('/') ? suffix : `/${suffix}`;
  const prefix = routing.channel_path_prefix[0]?.prefix ?? '';
  const listen = routing.available_listen_addresses[0] ?? '';
  return {
    listen_address: listen,
    route_prefix: prefix,
    route_suffix: suffix,
    route: prefix && path ? `${prefix}${path}` : '',
  };
}
