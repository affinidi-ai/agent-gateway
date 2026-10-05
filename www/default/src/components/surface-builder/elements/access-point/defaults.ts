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
  channel_path_prefix: Array<{ id: string; name: string; prefix: string }>;
}

/**
 * Returns the set of outbound listener URLs that are also reachable on an inbound listener
 * (shared domain). `available_listen_addresses` now contains only inbound listener URLs,
 * so any outbound URL that appears in it at least once is shared.
 *
 * The result is used to:
 * - Label shared addresses in the TP "Listen Address" dropdown.
 * - Show the `/outbound/` channel-prefix options only for shared selections.
 */
export function computeSharedOutboundAddresses(config: RoutingConfig): Set<string> {
  const inbound = new Set(config.available_listen_addresses ?? []);
  const outbound = config.available_outbound_listen_addresses ?? [];
  return new Set(outbound.filter(a => inbound.has(a)));
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
