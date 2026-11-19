import { ApiError } from '../api';
import type {
  MediatorAccessDid,
  MediatorAccessRefusal,
} from '../components/shared/MediatorAccessStep';

/** What a pairing paused for mediator access waits for, as the gateway returns it. */
export interface MediatorAccess {
  mediator_did: string;
  mediator_name: string;
  dids: { role: string; did: string; mediator_did: string; mediator_name?: string }[];
  expires_at?: string;
}

/** The label of each DID role, per wizard. */
export type MediatorAccessLabels = Record<string, string>;

export const CONNECTION_POINT_DID_LABELS: MediatorAccessLabels = {
  connection_point: 'Connection Point DID',
  permanent: 'Permanent DID for the paired gateway',
};

export const ADD_GATEWAY_DID_LABELS: MediatorAccessLabels = {
  temporary: 'Temporary DID for the handshake',
  permanent: 'Permanent DID for this pairing',
};

/** The DIDs of `access` with their labels, in the order the gateway sent them. */
export function labelledDids(
  access: MediatorAccess,
  labels: MediatorAccessLabels
): MediatorAccessDid[] {
  return access.dids.map(item => ({
    role: item.role,
    did: item.did,
    label: labels[item.role] ?? item.role,
    mediatorDid: item.mediator_did || access.mediator_did,
    mediatorName:
      item.mediator_name ||
      (item.mediator_did === access.mediator_did ? access.mediator_name : item.mediator_did),
  }));
}

/** Whether a paused pairing's invitation has expired, so Continue can only fail. */
export function mediatorAccessExpired(access: MediatorAccess, now: Date = new Date()): boolean {
  return Boolean(access.expires_at) && new Date(access.expires_at as string) <= now;
}

/** The refused DID of a `409 mediator_access_refused`, or `null` for any other error. */
export function mediatorAccessRefusal(
  error: unknown,
  labels: MediatorAccessLabels
): MediatorAccessRefusal | null {
  if (!(error instanceof ApiError) || error.code !== 'mediator_access_refused') return null;
  try {
    const body = JSON.parse(error.body ?? '') as { role?: string; did?: string };
    if (!body.did) return null;
    return { did: body.did, label: labels[body.role ?? ''] ?? body.role ?? 'DID' };
  } catch {
    return null;
  }
}
