import React, { useId } from 'react';
import { OverlayTrigger, Tooltip } from 'react-bootstrap';
import { TrustRecorderStateBadge } from '../../components/trust-recorder/TrustRecorderStateBadge';
import type { ManagedSurfaceRef, TrustRecorderStatus } from '../../types';
import {
  formatTrustRecorderAttemptTime,
  formatTrustRecorderCounts,
  trustRecorderAttemptTime,
  trustRecorderReasonText,
  trustRecorderStateLabel,
} from '../../utils/trustRecorderStatus';

interface IdentityRecorderChipProps {
  status?: TrustRecorderStatus;
  surface?: ManagedSurfaceRef;
}

const TrustRecorderStatusDetails: React.FC<{
  status: TrustRecorderStatus;
  surface?: ManagedSurfaceRef;
}> = ({ status, surface }) => {
  const attemptTime = trustRecorderAttemptTime(status);
  const reason = trustRecorderReasonText(status.reason);
  return (
    <div data-testid="identities-recorder-tooltip">
      {surface && (
        <p className="fw-bold" data-testid="identities-recorder-surface">
          Recorder on {surface.surface_name}
        </p>
      )}
      <p data-testid="identities-recorder-last-attempt">
        {attemptTime
          ? `Last attempt: ${formatTrustRecorderAttemptTime(attemptTime)}`
          : 'No attempt yet'}
      </p>
      {reason && <p data-testid="identities-recorder-reason">{reason}</p>}
      {status.entries.length > 0 && (
        <ul className="list-unstyled mb-0">
          {status.entries.map((entry, index) => {
            const entryReason = trustRecorderReasonText(entry.reason);
            return (
              <li
                key={`${entry.trust_registry_id}-${index}`}
                className="mb-1"
                data-testid={`identities-recorder-entry-${entry.trust_registry_id}`}
              >
                <strong>{entry.trust_registry_id}</strong>
                <br />
                {trustRecorderStateLabel(entry.state)}
                {entryReason ? `: ${entryReason}` : ''}
                <br />
                {formatTrustRecorderCounts(entry)}
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
};

export const IdentityRecorderChip: React.FC<IdentityRecorderChipProps> = ({ status, surface }) => {
  const tooltipId = useId();
  if (!status) return null;
  return (
    <OverlayTrigger
      placement="auto"
      overlay={
        <Tooltip id={tooltipId} className="field-help-tooltip">
          <TrustRecorderStatusDetails status={status} surface={surface} />
        </Tooltip>
      }
    >
      <button
        type="button"
        className="btn btn-link p-0 border-0 text-decoration-none align-baseline"
        aria-label={`Trust Recorder status${surface ? ` on ${surface.surface_name}` : ''}: ${trustRecorderStateLabel(status.state)}`}
        onClick={event => event.stopPropagation()}
        data-testid={`identities-recorder-chip-${status.state}`}
      >
        <TrustRecorderStateBadge state={status.state} />
      </button>
    </OverlayTrigger>
  );
};

export default IdentityRecorderChip;
