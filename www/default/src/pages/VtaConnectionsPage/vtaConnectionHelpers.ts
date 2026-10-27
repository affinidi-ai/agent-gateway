import type { PairingRecord, PairingState, VtaConnection, VtaTransport } from './types';

/** Visual treatment for a pairing state. */
export interface PairingPresentation {
  label: string;
  /** Bootstrap contextual suffix, e.g. `success` → `bg-success`. */
  tone: 'success' | 'warning' | 'danger' | 'secondary';
  icon: string;
  /** One line explaining what the operator should expect or do next. */
  hint: string;
}

const PRESENTATION: Record<PairingState, PairingPresentation> = {
  draft: {
    label: 'Not paired',
    tone: 'secondary',
    icon: 'fa-circle-dashed',
    hint: 'Recorded, but pairing has not been started yet.',
  },
  awaiting_grant: {
    label: 'Awaiting grant',
    tone: 'warning',
    icon: 'fa-hourglass-half',
    hint: 'Run the grant command on your VTA, then verify.',
  },
  connected: {
    label: 'Connected',
    tone: 'success',
    icon: 'fa-circle-check',
    hint: 'Paired, verified and signing.',
  },
  degraded: {
    label: 'Degraded',
    tone: 'danger',
    icon: 'fa-triangle-exclamation',
    hint: 'The last check failed. This connection is not signing.',
  },
  revoked: {
    label: 'Revoked',
    tone: 'danger',
    icon: 'fa-ban',
    hint: 'Deliberately revoked. Pair again to use it.',
  },
};

export function presentPairing(state: PairingState): PairingPresentation {
  return PRESENTATION[state] ?? PRESENTATION.draft;
}

/**
 * Whether this connection can sign right now. Mirrors the backend's
 * `pairing::assert_usable`: both halves matter, and anything else fails closed.
 */
export function isUsable(connection: VtaConnection): boolean {
  return connection.enabled && connection.pairing.state === 'connected';
}

/**
 * Whether the VTA granted more than the gateway asked for.
 *
 * Surfaced prominently rather than quietly recorded: a gateway holding VTA
 * admin removes the separation the integration exists to provide, so the
 * operator has to see it.
 */
export function isOverPrivileged(pairing: PairingRecord): boolean {
  const role = (pairing.granted_role ?? '').toLowerCase();
  const contexts = pairing.granted_contexts ?? [];
  if (!pairing.granted_role) return false;
  const privileged = ['admin', 'super-admin', 'superadmin', 'owner', 'root'];
  return privileged.includes(role) || contexts.length !== 1;
}

export const TRANSPORT_LABELS: Record<VtaTransport, string> = {
  https: 'HTTPS',
  unix: 'Unix socket',
  didcomm: 'DIDComm via mediator',
};

/**
 * Turn an API failure into something an operator can act on.
 *
 * Raw transport strings ("error sending request for url …") tell a non-engineer
 * nothing, and the backend deliberately redacts VTA internals, so the useful
 * signal is the *category* of failure plus the address involved.
 */
export function explainFailure(message: string, endpoint?: string): string {
  const raw = (message ?? '').trim();
  const where = endpoint ? ` at ${endpoint}` : '';
  const lower = raw.toLowerCase();

  if (lower.includes('too broad') || lower.includes('super-admin') || lower.includes('admin')) {
    return raw;
  }
  if (lower.includes('not ready') || lower.includes('mediator')) {
    return `The mediator is not reachable, so the VTA${where} cannot be contacted. Check the mediator is running and this connection points at it.`;
  }
  if (lower.includes('timed out') || lower.includes('did not reply') || lower.includes('timeout')) {
    return `The VTA${where} did not respond in time. Check it is running and reachable from the gateway.`;
  }
  if (lower.includes('pinned')) {
    return raw;
  }
  if (lower.includes('disabled')) {
    return 'This connection is disabled. Enable it before pairing.';
  }
  if (lower.includes('control_key_ref') || lower.includes('control key')) {
    return 'This connection has no control key yet. Save it once so the gateway can mint one, then pair.';
  }
  return raw || 'The request failed for an unknown reason.';
}

/** Whether an outstanding pairing payload has expired. */
export function isPayloadExpired(expiresAt?: string | null): boolean {
  if (!expiresAt) return false;
  const at = Date.parse(expiresAt);
  return Number.isFinite(at) && at <= Date.now();
}

/**
 * The `default_signing` block that makes a connection the appliance default.
 *
 * Shared by the Settings picker and the connect wizard so the two cannot
 * disagree about what a complete block is. Returns `null` when the connection
 * cannot sign for the appliance, because a JWT names its key explicitly and a
 * context-less or keyless block would fail at the first request rather than
 * here.
 */
export function applianceSigningPayload(connection: VtaConnection): Record<string, string> | null {
  const keyId = connection.keys?.active?.key_id;
  if (!keyId || !connection.default_context_id) return null;
  return {
    backend: 'vta',
    connection_id: connection.id,
    context_id: connection.default_context_id,
    key_id: keyId,
  };
}
