import React from 'react';

/** Listener-level runtime state (mirrors the backend `ConnectionStatus`). */
export type RuntimeConnectionStatus = 'connected' | 'reconnecting' | 'failed';

/** Stable, machine-readable connection failure codes (mirrors the backend). */
export type ConnectionErrorCode =
  | 'MEDIATOR_UNREACHABLE'
  | 'MEDIATOR_DID_RESOLUTION_FAILED'
  | 'PROFILE_REGISTRATION_FAILED'
  | 'AUTHENTICATION_FAILED'
  | 'CRYPTO_MISMATCH'
  | 'WS_STREAM_BROKEN'
  | 'PEER_GATEWAY_UNAVAILABLE'
  | 'UNKNOWN';

/** Runtime health + diagnostics embedded on a connection point record. */
export interface ConnectionRuntimeStatus {
  status: RuntimeConnectionStatus;
  error_code?: ConnectionErrorCode;
  error_message?: string;
  original_error?: string;
  first_failed_at?: string;
  last_failed_at?: string;
  last_active_at?: string;
  next_retry_at?: string;
  consecutive_failures?: number;
  current_backoff_seconds?: number;
}

const ERROR_CODE_LABELS: Record<ConnectionErrorCode, string> = {
  MEDIATOR_UNREACHABLE: 'Mediator is unreachable',
  MEDIATOR_DID_RESOLUTION_FAILED: 'Could not resolve the mediator DID',
  PROFILE_REGISTRATION_FAILED: 'Failed to register with the mediator',
  AUTHENTICATION_FAILED: 'Authentication with the mediator failed',
  CRYPTO_MISMATCH: 'Mediator cryptography is incompatible',
  WS_STREAM_BROKEN: 'The mediator connection dropped',
  PEER_GATEWAY_UNAVAILABLE: 'The partner gateway is unavailable',
  UNKNOWN: 'Connection failed',
};

/** Human-friendly label for a stable error code. */
export function errorCodeLabel(code?: ConnectionErrorCode): string | undefined {
  if (!code) return undefined;
  return ERROR_CODE_LABELS[code] ?? code;
}

/** True only when the connection is actually established. */
export function isConnected(runtime?: ConnectionRuntimeStatus): boolean {
  return runtime?.status === 'connected';
}

/** Best display-safe reason for a not-connected runtime status. */
export function runtimeReason(runtime?: ConnectionRuntimeStatus): string | undefined {
  if (!runtime) return undefined;
  return runtime.error_message || errorCodeLabel(runtime.error_code);
}

/** "Reconnect in ~N min" when an automatic retry is scheduled. */
export function reconnectAtLabel(runtime?: ConnectionRuntimeStatus): string | undefined {
  if (!runtime?.next_retry_at) return undefined;
  const diffMs = new Date(runtime.next_retry_at).getTime() - Date.now();
  if (diffMs <= 0) return 'Attempt reconnecting now';
  const minutes = Math.round(diffMs / 60000);
  if (minutes < 1) return 'Attempt to reconnect in <1 min';
  return `Attempt to reconnect in ~${minutes} min`;
}

interface ConnectionHealthBadgeProps {
  runtime?: ConnectionRuntimeStatus;
  /** Render the "reconnect at …" line under the badge (default true). */
  showReconnectLine?: boolean;
}

/**
 * Renders a connection health badge. The UI has no "reconnecting" badge — a
 * not-connected connection point always shows FAILED, with an optional
 * "reconnect at <date>" line when an automatic retry is scheduled. Returns
 * `null` when no runtime status is available yet.
 */
export const ConnectionHealthBadge: React.FC<ConnectionHealthBadgeProps> = ({
  runtime,
  showReconnectLine = true,
}) => {
  if (!runtime) {
    return null;
  }

  const connected = runtime.status === 'connected';
  const tooltip = connected ? 'Connected to mediator' : runtimeReason(runtime) || 'Not connected';
  const reconnectLine = !connected ? reconnectAtLabel(runtime) : undefined;

  return (
    <span>
      <span className={`badge ${connected ? 'text-bg-success' : 'text-bg-danger'}`} title={tooltip}>
        <i className={`fas ${connected ? 'fa-check-circle' : 'fa-exclamation-circle'}`}></i>{' '}
        {connected ? 'CONNECTED' : 'FAILED'}
      </span>
      {showReconnectLine && reconnectLine && (
        <div className="text-muted" style={{ fontSize: '0.7rem' }}>
          {reconnectLine}
        </div>
      )}
    </span>
  );
};
