import React from 'react';
import {
  ConnectionRuntimeStatus,
  errorCodeLabel,
  PeerLastSeen,
  reconnectAtLabel,
} from '../../utils/connectionHealth';
import type { GatewayListItem } from '../../utils/gateways';

const STATUS_BADGE: Record<string, string> = {
  active: 'text-bg-success',
  failed: 'text-bg-danger',
  'awaiting-approval': 'text-bg-warning',
  pending: 'text-bg-warning',
};

/** Why a gateway is failing, from its runtime health; undefined while connected. */
export function gatewayFailureTooltip(runtime?: ConnectionRuntimeStatus): string | undefined {
  if (!runtime || runtime.status === 'connected') return undefined;
  const parts = [
    runtime.error_message || errorCodeLabel(runtime.error_code),
    reconnectAtLabel(runtime),
  ].filter(Boolean);
  return parts.length ? parts.join('; ') : undefined;
}

export const gatewayStatusLabel = (status: string): string =>
  status === 'awaiting-approval' ? 'AWAITING APPROVAL' : status.toUpperCase();

interface GatewayStatusCellProps {
  gateway: Pick<
    GatewayListItem,
    'id' | 'status' | 'gateway_type' | 'runtime_status' | 'peer_last_seen_at'
  >;
}

/**
 * A gateway's status badge, the failure reason under a failed one, and when a
 * remote peer was last heard from.
 */
const GatewayStatusCell: React.FC<GatewayStatusCellProps> = ({ gateway }) => (
  <>
    <span
      className={`badge ${STATUS_BADGE[gateway.status] ?? 'text-bg-secondary'}`}
      title={
        gateway.status === 'failed' ? gatewayFailureTooltip(gateway.runtime_status) : undefined
      }
      data-testid={`gateway-status-${gateway.id}`}
    >
      {gatewayStatusLabel(gateway.status)}
    </span>
    {gateway.status === 'failed' && gateway.runtime_status && (
      <div className="text-muted" style={{ fontSize: '0.7rem' }}>
        {gateway.runtime_status.error_message || errorCodeLabel(gateway.runtime_status.error_code)}
        {reconnectAtLabel(gateway.runtime_status)
          ? `; ${reconnectAtLabel(gateway.runtime_status)}`
          : ''}
      </div>
    )}
    {gateway.gateway_type === 'remote' &&
      ['active', 'pending', 'failed'].includes(gateway.status) && (
        <PeerLastSeen gatewayId={gateway.id} peerLastSeenAt={gateway.peer_last_seen_at} />
      )}
  </>
);

export default GatewayStatusCell;
