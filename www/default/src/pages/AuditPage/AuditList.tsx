import React from 'react';
import AuditListItem from './AuditListItem';
import FieldHelp from '../../components/shared/FieldHelp';
import type { AuditEntry } from './types';

interface AuditListProps {
  isLoading: boolean;
  filteredEntries: AuditEntry[];
  selectedIdx: number | null;
  onSelect: (idx: number) => void;
  page: number;
  totalPages: number;
  onPageChange: (updater: number | ((p: number) => number)) => void;
}

/** Master list of governance events with loading skeleton, empty state, and pagination. */
const AuditList: React.FC<AuditListProps> = ({
  isLoading,
  filteredEntries,
  selectedIdx,
  onSelect,
  page,
  totalPages,
  onPageChange,
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
        <p className="mb-1 fw-semibold">No governance events yet</p>
        <p className="small mb-0" style={{ maxWidth: 360 }}>
          Trigger an agent action, or enable VP Auditing{' '}
          <FieldHelp testId="field-help-audit-empty-vp" ariaLabel="About VP Auditing">
            VP Auditing records a signed Verifiable Presentation for every policy decision, trust
            check, and credential injection so you can prove after the fact what the gateway allowed
            or denied and why.
          </FieldHelp>{' '}
          in Settings › Security, to generate audit evidence.
        </p>
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
