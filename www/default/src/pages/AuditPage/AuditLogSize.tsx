import React from 'react';
import { formatBytes } from '../../utils/formatBytes';

interface AuditLogSizeProps {
  /** Bytes the audit history takes on disk: the live log and the rotated files. */
  historyBytes: number;
  /** The size it is shown against, or 0 when none is configured. */
  softCapBytes: number;
}

/**
 * How large the audit history has grown, against the advisory size in
 * `[audit] vp_audit_log_soft_cap_bytes`. Nothing is enforced at that size: the
 * log keeps growing past it and no record is deleted, so this reads as usage
 * with a mark on it, never as a quota. Over the mark it says what an operator
 * can do about it.
 */
const AuditLogSize: React.FC<AuditLogSizeProps> = ({ historyBytes, softCapBytes }) => {
  // Nothing on disk, or a gateway that does not report the size: say nothing
  // rather than claim the history is empty.
  if (historyBytes <= 0) return null;

  const capped = softCapBytes > 0;
  const over = capped && historyBytes > softCapBytes;
  const filled = capped ? Math.min(100, (historyBytes / softCapBytes) * 100) : 0;

  return (
    <div className="small text-muted mb-2" data-testid="audit-log-size">
      <span>
        Audit log: {formatBytes(historyBytes)}
        {capped ? ` of ${formatBytes(softCapBytes)}` : ''}
      </span>
      {capped && (
        <div
          className="progress mt-1"
          style={{ height: '3px' }}
          role="img"
          aria-label={`Audit log ${formatBytes(historyBytes)} of ${formatBytes(softCapBytes)}`}
          data-testid="audit-log-size-bar"
        >
          <div
            className={`progress-bar ${over ? 'bg-warning' : 'bg-secondary'}`}
            style={{ width: `${filled}%` }}
          />
        </div>
      )}
      {over && (
        <span className="d-block mt-1" data-testid="audit-log-size-over">
          Forward records to a Governance Audit integration, or set <code>vp_audit_log_keep</code>{' '}
          to keep fewer rotated files (each up to <code>vp_audit_log_max_bytes</code>).
        </span>
      )}
    </div>
  );
};

export default AuditLogSize;
