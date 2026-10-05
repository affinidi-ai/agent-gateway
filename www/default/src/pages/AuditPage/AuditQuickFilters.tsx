import React from 'react';
import type { AuditEntry, PolicyDecisionData } from './types';

interface AuditQuickFiltersProps {
  entry: AuditEntry;
  pd: PolicyDecisionData | null;
  callerDid: string | null;
  surfaceId: string | null;
  typeName: string;
  onQuickFilter: (term: string, cat?: string) => void;
}

const BTN_CLASS = 'btn btn-xs btn-outline-secondary';
const BTN_STYLE: React.CSSProperties = { fontSize: '0.75rem', padding: '0.15rem 0.4rem' };

/** Row of one-click "filter by …" affordances shown under an expanded entry. */
const AuditQuickFilters: React.FC<AuditQuickFiltersProps> = ({
  entry,
  pd,
  callerDid,
  surfaceId,
  typeName,
  onQuickFilter,
}) => (
  <div
    className="mt-2 d-flex flex-wrap"
    style={{ gap: '0.3rem' }}
    data-testid="audit-quick-filters"
  >
    {entry.trace_id && (
      <button
        type="button"
        className={BTN_CLASS}
        style={BTN_STYLE}
        title={`Show all entries for this request (trace: ${entry.trace_id})`}
        data-testid="audit-quickfilter-request"
        onClick={() => onQuickFilter(entry.trace_id!)}
      >
        <i className="fas fa-filter mr-1" />
        This request
      </button>
    )}
    {callerDid && (
      <button
        type="button"
        className={BTN_CLASS}
        style={BTN_STYLE}
        title={`Filter by caller: ${callerDid}`}
        data-testid="audit-quickfilter-caller"
        onClick={() => onQuickFilter(callerDid)}
      >
        <i className="fas fa-filter mr-1" />
        This caller
      </button>
    )}
    {pd?.http_path && (
      <button
        type="button"
        className={BTN_CLASS}
        style={BTN_STYLE}
        title={`Filter by path: ${pd.http_path}`}
        data-testid="audit-quickfilter-path"
        onClick={() => onQuickFilter(pd.http_path!)}
      >
        <i className="fas fa-filter mr-1" />
        This path
      </button>
    )}
    {surfaceId && (pd?.scope === 'surface' || pd?.scope === 'mcp_tool') && (
      <button
        type="button"
        className={BTN_CLASS}
        style={BTN_STYLE}
        title={`Filter by surface: ${surfaceId}`}
        data-testid="audit-quickfilter-surface"
        onClick={() => onQuickFilter(surfaceId)}
      >
        <i className="fas fa-filter mr-1" />
        This surface
      </button>
    )}
    {typeName && (
      <button
        type="button"
        className={BTN_CLASS}
        style={BTN_STYLE}
        title={`Filter by event type: ${typeName}`}
        data-testid="audit-quickfilter-type"
        onClick={() => onQuickFilter('', typeName)}
      >
        <i className="fas fa-filter mr-1" />
        This type
      </button>
    )}
  </div>
);

export default AuditQuickFilters;
