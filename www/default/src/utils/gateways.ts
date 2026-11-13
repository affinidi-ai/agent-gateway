import type { ConnectionRuntimeStatus } from './connectionHealth';

/** What a remote gateway is for: a Fabric peer, or an agent-pay gateway that takes payments. */
export type GatewayRole = 'peer' | 'payment';

export type GatewayStatus =
  | 'active'
  | 'pending'
  | 'awaiting-approval'
  | 'awaiting-mediator-access'
  | 'disabled'
  | 'failed';

/** Shape of a gateway record as returned by `GET /gateways` and `GET /payment-gateways`. */
export interface GatewayRecord {
  id: string;
  name: string;
  gateway_type: string;
  status?: string;
  creation_type?: string;
  role?: GatewayRole;
}

/** A full gateway list item, with its runtime health. */
export interface GatewayListItem extends GatewayRecord {
  description: string;
  did: string;
  gateway_type: 'self' | 'remote';
  status: GatewayStatus;
  created_at: string;
  updated_at: string;
  runtime_status?: ConnectionRuntimeStatus;
  /** Remote gateways: when a listener last heard from the peer; absent until it has. */
  peer_last_seen_at?: string | null;
  exposure_mode?: ExposureMode | null;
  exposed_channels?: string[];
}

/** Whether a gateway is still waiting to be connected or approved. */
export function isGatewayPending(gw: { status?: string }): boolean {
  return (
    gw.status === 'pending' ||
    gw.status === 'awaiting-approval' ||
    gw.status === 'awaiting-mediator-access'
  );
}

/**
 * Whether the gateway's row in the Gateways list opens its details page. A
 * `pending` gateway does, as the Add Gateway wizard offers; one waiting for
 * approval or for mediator access does not, since its row has its own action.
 */
export function opensGatewayDetails(gw: { status?: string }): boolean {
  return gw.status !== 'awaiting-approval' && gw.status !== 'awaiting-mediator-access';
}

/**
 * A remote gateway that is currently usable as a fabric routing target from
 * the surface builder (Managed Agent / Transit Point gateway pickers).
 *
 * Filters to `gateway_type === 'remote'` (excludes the self gateway) and
 * `status === 'active'` (excludes pending / awaiting-approval / failed /
 * disabled peers) and never a payment gateway, which is not a Fabric routing
 * target. Deliberately independent of `creation_type`: the fabric
 * link is bidirectional, so a peer auto-created by accepting an inbound
 * connection (`creation_type: 'system'`) is just as routable as one created
 * locally via the OOB wizard (`creation_type: 'user'`).
 */
export function isSelectableRemoteGateway(gw: {
  gateway_type?: string;
  status?: string;
  role?: string;
}): boolean {
  return gw.gateway_type === 'remote' && gw.status === 'active' && gw.role !== 'payment';
}

/**
 * Filter a raw `GET /gateways` payload down to the gateways selectable as a
 * fabric routing target (see {@link isSelectableRemoteGateway}). Tolerates a
 * missing / non-array payload by returning an empty list.
 */
export function filterSelectableGateways<
  T extends { gateway_type?: string; status?: string; role?: string },
>(gateways: T[] | null | undefined): T[] {
  return Array.isArray(gateways) ? gateways.filter(isSelectableRemoteGateway) : [];
}

/** Which local surfaces a remote gateway may reach over Fabric. */
export type ExposureMode = 'all' | 'none' | 'list';

/**
 * The effective exposure mode of a remote gateway record. A record without a
 * stored mode keeps its earlier meaning: an empty list is `all`, a non-empty
 * list is `list`.
 */
export function exposureModeOf(gw: {
  exposure_mode?: string | null;
  exposed_channels?: string[] | null;
}): ExposureMode {
  if (gw.exposure_mode === 'all' || gw.exposure_mode === 'none' || gw.exposure_mode === 'list') {
    return gw.exposure_mode;
  }
  return (gw.exposed_channels?.length ?? 0) === 0 ? 'all' : 'list';
}
