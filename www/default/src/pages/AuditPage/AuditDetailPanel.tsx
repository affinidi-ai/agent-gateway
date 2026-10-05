import React from 'react';
import { timeAgo } from '../../utils/stringUtils';
import AuditEvidencePane from './AuditEvidencePane';
import AuditQuickFilters from './AuditQuickFilters';
import { callerDidOf, eventTypeName, policyDecision, surfaceIdOf } from './auditHelpers';
import { describeEntry } from './eventNarrative';
import type { AuditEntry } from './types';

interface AuditDetailPanelProps {
  entry: AuditEntry | null;
  filteredEntries: AuditEntry[];
  onTitleClick: () => void;
  onQuickFilter: (term: string, cat?: string) => void;
}

/**
 * Evidence panel docked inside the Audit Log card. It always shows the selected
 * event and fills the card height with its own internal scroll. Clicking the
 * title scrolls the list until the selected event is back in view.
 */
const AuditDetailPanel: React.FC<AuditDetailPanelProps> = ({
  entry,
  filteredEntries,
  onTitleClick,
  onQuickFilter,
}) => {
  const open = entry != null;
  const narrative = entry ? describeEntry(entry) : null;
  const tone = narrative?.tone ?? 'neutral';
  const pd = entry ? policyDecision(entry) : null;
  const callerDid = entry ? callerDidOf(entry) : null;
  const surfaceId = entry ? surfaceIdOf(entry) : null;
  const typeName = entry ? eventTypeName(entry) : '';

  return (
    <aside
      className={`audit-drawer ${open ? 'audit-drawer--open' : ''} ${
        open ? `audit-detail-panel--${tone}` : ''
      }`}
      role="region"
      aria-label="Event details"
      aria-hidden={!open}
      data-testid="audit-detail-panel"
      data-open={open}
    >
      {entry && narrative && (
        <>
          <div
            className="audit-drawer-header"
            role="button"
            tabIndex={0}
            data-testid="audit-detail-title"
            title="Scroll to this event in the list"
            aria-label="Scroll to this event in the list"
            onClick={onTitleClick}
            onKeyDown={e => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                onTitleClick();
              }
            }}
          >
            <div className="audit-drawer-heading">
              <div className="audit-drawer-eyebrow">
                <i className="fas fa-fingerprint text-primary" aria-hidden="true" />
                <span>Event details</span>
                {entry.trace_id && (
                  <span className="audit-trace-chip" title={entry.trace_id}>
                    {entry.trace_id}
                  </span>
                )}
              </div>
              <h2 className={`audit-drawer-title audit-item-title--${tone}`}>{narrative.title}</h2>
              <div className="audit-drawer-sub text-muted">{timeAgo(entry.timestamp)}</div>
            </div>
          </div>
          <div className="audit-drawer-filters" data-testid="audit-detail-filters">
            <AuditQuickFilters
              entry={entry}
              pd={pd}
              callerDid={callerDid}
              surfaceId={surfaceId}
              typeName={typeName}
              onQuickFilter={onQuickFilter}
            />
          </div>
          <div className="audit-drawer-body">
            <AuditEvidencePane
              entry={entry}
              filteredEntries={filteredEntries}
              onQuickFilter={onQuickFilter}
            />
          </div>
        </>
      )}
    </aside>
  );
};

export default AuditDetailPanel;
