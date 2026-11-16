import React from 'react';
import AuditListItem from './AuditListItem';
import { AppButton } from '../../components/shared/AppButton';
import FieldHelp from '../../components/shared/FieldHelp';
import type { UserNameResolver } from './eventNarrative';
import type { AuditEntry } from './types';

interface AuditListProps {
  isLoading: boolean;
  filteredEntries: AuditEntry[];
  selectedIdx: number | null;
  onSelect: (idx: number) => void;
  page: number;
  totalPages: number;
  /**
   * Whether the read's counts are lower bounds: it stopped before the end of
   * the history, or met records it could not read. The page count then reads
   * `of 687+`, and finding nothing means nothing was found in the records
   * searched, not that the log is empty.
   */
  countsAreLowerBounds?: boolean;
  /**
   * Why the last read failed, when it did. The gateway answers a read it could
   * not make with an error rather than an empty page, so the list says the
   * records could not be read instead of claiming the log holds none.
   */
  error?: string | null;
  /** Reads the log again, for the retry offered with the error. */
  onRetry?: () => void;
  onPageChange: (updater: number | ((p: number) => number)) => void;
  /** Names the users policy changes were made by. */
  userName?: UserNameResolver;
}

/** Master list of governance events with loading skeleton, empty state, and pagination. */
const AuditList: React.FC<AuditListProps> = ({
  isLoading,
  filteredEntries,
  selectedIdx,
  onSelect,
  page,
  totalPages,
  countsAreLowerBounds = false,
  error = null,
  onRetry,
  onPageChange,
  userName,
}) => {
  if (isLoading) {
    return (
      <ul className="audit-list" data-testid="audit-loading" aria-busy="true">
        {Array.from({ length: 8 }).map((_, i) => (
          <li key={i} className="audit-item-wrap">
            <div className="audit-item audit-item--skeleton" aria-hidden="true">
              <span className="audit-item-body">
                <span className="audit-skeleton-line" style={{ width: '45%' }} />
                <span className="audit-skeleton-line" style={{ width: '80%' }} />
                <span className="audit-skeleton-line" style={{ width: '30%' }} />
              </span>
            </div>
          </li>
        ))}
      </ul>
    );
  }

  // Before the empty state: a read that failed returned no records, which says
  // nothing about what the log holds. Showing the empty state here would tell
  // an administrator the gateway recorded nothing.
  if (error) {
    return (
      <div className="alert alert-danger" role="alert" data-testid="audit-error">
        <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
        Failed to load audit log: {error}
        {onRetry && (
          <AppButton
            variant="outline-danger"
            size="sm"
            className="ms-3"
            data-testid="audit-error-retry"
            onClick={onRetry}
          >
            Retry
          </AppButton>
        )}
        <div className="small mt-2 mb-0">
          No audit records could be read. That is not the same as the log holding none.
        </div>
      </div>
    );
  }

  if (filteredEntries.length === 0) {
    return (
      <div
        className="d-flex flex-column align-items-center text-center text-muted py-5 px-3"
        data-testid="audit-empty"
      >
        <div
          className="d-flex align-items-center justify-content-center mb-3"
          style={{
            width: 64,
            height: 64,
            borderRadius: '50%',
            background: 'rgba(74, 144, 226, 0.12)',
          }}
        >
          <i className="fas fa-clipboard-list fa-2x text-primary" aria-hidden="true" />
        </div>
        {countsAreLowerBounds ? (
          // The read did not return everything the history holds, so the log
          // is not known to be empty and the advice below would be wrong.
          <p className="mb-1 fw-semibold" data-testid="audit-empty-truncated">
            No governance events found in the records searched.
          </p>
        ) : (
          <>
            <p className="mb-1 fw-semibold">No governance events yet</p>
            <p className="small mb-0" style={{ maxWidth: 360 }}>
              Trigger an agent action, or enable VP Auditing{' '}
              <FieldHelp testId="field-help-audit-empty-vp" ariaLabel="About VP Auditing">
                VP Auditing records a signed Verifiable Presentation for every policy decision,
                trust check, and credential injection so you can prove after the fact what the
                gateway allowed or denied and why.
              </FieldHelp>{' '}
              in Settings › Security, to generate audit evidence.
            </p>
          </>
        )}
      </div>
    );
  }

  return (
    <>
      <ul className="audit-list" data-testid="audit-list">
        {filteredEntries.map((entry, idx) => (
          <AuditListItem
            key={entry.id ?? idx}
            entry={entry}
            idx={idx}
            isSelected={selectedIdx === idx}
            onSelect={() => onSelect(idx)}
            userName={userName}
          />
        ))}
      </ul>

      {totalPages > 1 && (
        <div
          className="d-flex justify-content-between align-items-center mt-3"
          data-testid="audit-pagination"
        >
          <span className="small text-muted">
            Page {page} of {totalPages}
            {countsAreLowerBounds ? '+' : ''}
          </span>
          <div>
            <button
              className="btn btn-sm btn-outline-secondary me-2"
              disabled={page <= 1}
              data-testid="audit-page-prev"
              onClick={() => onPageChange(p => p - 1)}
            >
              <i className="fas fa-chevron-left"></i> Prev
            </button>
            <button
              className="btn btn-sm btn-outline-secondary"
              disabled={page >= totalPages}
              data-testid="audit-page-next"
              onClick={() => onPageChange(p => p + 1)}
            >
              Next <i className="fas fa-chevron-right"></i>
            </button>
          </div>
        </div>
      )}
    </>
  );
};

export default AuditList;
