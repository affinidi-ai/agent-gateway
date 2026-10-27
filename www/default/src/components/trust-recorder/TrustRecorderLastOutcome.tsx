import React from 'react';
import { useOptionalSurfaceMeta } from '../surface-builder/SurfaceMetaContext';
import type { TrustRecorderStatus } from '../../types';
import {
  formatTrustRecorderCounts,
  sumTrustRecorderCounts,
  trustRecorderAttemptTime,
  trustRecorderReasonText,
} from '../../utils/trustRecorderStatus';
import { TrustRecorderStateBadge } from './TrustRecorderStateBadge';
import { useTrustRecorderStatus } from './useTrustRecorderStatus';

interface TrustRecorderLastOutcomeProps {
  className?: string;
}

const OutcomeBody: React.FC<{ status: TrustRecorderStatus }> = ({ status }) => {
  const reason = trustRecorderReasonText(status.reason);
  const attemptTime = trustRecorderAttemptTime(status);
  return (
    <>
      <div className="d-flex flex-wrap align-items-center gap-2">
        <TrustRecorderStateBadge state={status.state} testId="trust-recorder-last-outcome-state" />
        {reason && <span data-testid="trust-recorder-last-outcome-reason">{reason}</span>}
        {attemptTime && (
          <span
            className="text-muted"
            title={attemptTime.absolute}
            data-testid="trust-recorder-last-outcome-time"
          >
            {attemptTime.relative}
          </span>
        )}
      </div>
      {status.entries.length > 0 && (
        <div className="text-muted mt-1" data-testid="trust-recorder-last-outcome-counts">
          {formatTrustRecorderCounts(sumTrustRecorderCounts(status.entries))}
        </div>
      )}
    </>
  );
};

const LastOutcomeForSurface: React.FC<{ surfaceId: string; className?: string }> = ({
  surfaceId,
  className,
}) => {
  const view = useTrustRecorderStatus(surfaceId);

  let body: React.ReactNode;
  if (view.phase === 'loading') {
    body = (
      <span className="text-muted" data-testid="trust-recorder-last-outcome-loading">
        Loading…
      </span>
    );
  } else if (view.phase === 'error') {
    body = (
      <span className="text-muted" data-testid="trust-recorder-last-outcome-unavailable">
        Status unavailable
      </span>
    );
  } else if (view.status === null) {
    body = (
      <span className="text-muted" data-testid="trust-recorder-last-outcome-empty">
        No attempt yet
      </span>
    );
  } else {
    body = <OutcomeBody status={view.status} />;
  }

  return (
    <div
      className={className}
      role="group"
      aria-label="Trust Recorder last outcome"
      aria-busy={view.phase === 'loading'}
      data-testid="trust-recorder-last-outcome"
    >
      <div className="fw-semibold small mb-1">Last outcome</div>
      <div className="small">{body}</div>
    </div>
  );
};

export const TrustRecorderLastOutcome: React.FC<TrustRecorderLastOutcomeProps> = ({
  className,
}) => {
  const meta = useOptionalSurfaceMeta();
  if (!meta || meta.isCreate || !meta.surfaceId) return null;
  return <LastOutcomeForSurface surfaceId={meta.surfaceId} className={className} />;
};

export default TrustRecorderLastOutcome;
