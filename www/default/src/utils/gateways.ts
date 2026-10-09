/** Shape of a gateway record as returned by `GET /gateways`. */
export interface GatewayRecord {
  id: string;
  name: string;
  gateway_type: string;
  status?: string;
  creation_type?: string;
}

/**
 * A remote gateway that is currently usable as a fabric routing target from
 * the surface builder (Managed Agent / Transit Point gateway pickers).
 *
 * Filters to `gateway_type === 'remote'` (excludes the self gateway) and
 * `status === 'active'` (excludes pending / awaiting-approval / failed /
 * disabled peers). Deliberately independent of `creation_type`: the fabric
 * link is bidirectional, so a peer auto-created by accepting an inbound
 * connection (`creation_type: 'system'`) is just as routable as one created
 * locally via the OOB wizard (`creation_type: 'user'`).
 */
export function isSelectableRemoteGateway(gw: { gateway_type?: string; status?: string }): boolean {
  return gw.gateway_type === 'remote' && gw.status === 'active';
}

/**
 * Filter a raw `GET /gateways` payload down to the gateways selectable as a
 * fabric routing target (see {@link isSelectableRemoteGateway}). Tolerates a
 * missing / non-array payload by returning an empty list.
 */
export function filterSelectableGateways<T extends { gateway_type?: string; status?: string }>(
  gateways: T[] | null | undefined
): T[] {
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
