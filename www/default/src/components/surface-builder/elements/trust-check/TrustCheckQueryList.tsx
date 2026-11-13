import React from 'react';
import { Badge } from '../../../shared/Badge';
import { isTemplateValue } from '../_shared/authorityReference';
import {
  defaultAuthorityIdTemplate,
  isMultiAuthorityQuery,
  listedAuthorities,
  queryProblem,
  subjectForTemplate,
  subjectLabel,
  type TrustCheckQueryConfig,
} from './definition';

interface TrustCheckQueryListProps {
  queries: TrustCheckQueryConfig[];
  /** The Managed Agent's or a Transit Point's target leg, rather than the caller leg. */
  isTargetLeg: boolean;
  /** Test id prefix, so the sidebar and editor lists stay distinct. */
  area: 'trust-check-panel' | 'trust-check-editor';
  /** A registry's display name, falling back to a shortened id. */
  registryName: (id: string) => string;
  /** An Issuer's or Authority's display name, falling back to a shortened DID. */
  authorityName: (did: string) => string;
  /** Shows the first `limit` queries, then "+N more". */
  limit?: number;
  /** Highlights the query whose settings are open. */
  selected?: number;
  /** Makes each row a button that selects its query. */
  onSelect?: (index: number) => void;
}

/** Label and badge icon of each record type, shared with the editor's record type toggle. */
export const RECORD_TYPE = {
  recognition: { label: 'Recognition', icon: 'fa-id-badge' },
  authorization: { label: 'Authorization', icon: 'fa-user-shield' },
} as const;

/** The single Authority of a query: a picked DID's name, or what a template resolves to. */
function singleAuthorityLabel(
  q: TrustCheckQueryConfig,
  isTargetLeg: boolean,
  authorityName: (did: string) => string
): string {
  const stored = typeof q.query?.authority_id === 'string' ? q.query.authority_id.trim() : '';
  const value = stored || defaultAuthorityIdTemplate(isTargetLeg ? 'ma-tp' : 'ap-ma');
  if (!isTemplateValue(value)) return authorityName(value);
  const subject = subjectForTemplate(value);
  if (!subject) return value;
  const label = subjectLabel(subject, !isTargetLeg);
  return label.charAt(0).toUpperCase() + label.slice(1);
}

/**
 * A Trust Check's queries, one row each: whether the query is ready, its
 * record type, and the registry and Authorities it checks (or its problem).
 * With `onSelect` each row is a button that opens the query's settings.
 */
const TrustCheckQueryList: React.FC<TrustCheckQueryListProps> = ({
  queries,
  isTargetLeg,
  area,
  registryName,
  authorityName,
  limit,
  selected,
  onSelect,
}) => {
  const shown = limit === undefined ? queries : queries.slice(0, limit);
  const remaining = queries.length - shown.length;

  const rows = shown.map((q, idx) => {
    const problem = queryProblem(q, isTargetLeg);
    const type = RECORD_TYPE[q.query_type === 'recognition' ? 'recognition' : 'authorization'];
    const rowId = `${area}-query-${idx}`;
    const names = isMultiAuthorityQuery(q)
      ? listedAuthorities(q.query).map(authorityName)
      : [singleAuthorityLabel(q, isTargetLeg, authorityName)];
    const authorities = names.length === 1 ? names[0] : `${names.length} Authorities`;
    const registry = registryName(q.trust_registry_id ?? '');
    const content = (
      <>
        <i
          className={`fas ${
            problem ? 'fa-circle-exclamation text-warning' : 'fa-circle-check text-success'
          } fa-lg`}
          title={problem ?? 'Ready'}
          aria-label={problem ?? 'Ready'}
          data-testid={`${rowId}-status`}
        />
        <span className="d-block flex-grow-1 text-truncate">
          <span className="d-block fw-bold">
            Query {idx + 1}
            <Badge
              tone="secondary"
              size="sm"
              className="ms-2"
              prefix={<i className={`fas ${type.icon}`} aria-hidden="true" />}
              value={type.label}
              data-testid={`${rowId}-type`}
            />
          </span>
          {problem ? (
            <small className="text-muted d-block text-truncate" title={problem}>
              {problem}
            </small>
          ) : (
            <small
              className="text-muted d-block text-truncate"
              title={`${registry} · ${names.join(', ')}`}
            >
              {registry} · <span data-testid={`${rowId}-authorities`}>{authorities}</span>
            </small>
          )}
        </span>
      </>
    );
    return { key: q.id || `idx-${idx}`, rowId, content, idx };
  });

  if (onSelect) {
    return (
      <div className="list-group list-group-flush" data-testid={`${area}-list`}>
        {rows.map(({ key, rowId, content, idx }) => (
          <button
            key={key}
            type="button"
            className={`list-group-item list-group-item-action d-flex align-items-center gap-2${
              selected === idx ? ' list-group-item-primary' : ''
            }`}
            aria-current={selected === idx ? 'true' : undefined}
            onClick={() => onSelect(idx)}
            data-testid={rowId}
          >
            {content}
          </button>
        ))}
      </div>
    );
  }

  return (
    <ul className="list-group mb-2" data-testid={`${area}-list`}>
      {rows.map(({ key, rowId, content }) => (
        <li
          key={key}
          className="list-group-item d-flex align-items-center gap-2"
          data-testid={rowId}
        >
          {content}
        </li>
      ))}
      {remaining > 0 && (
        <li className="list-group-item small text-muted" data-testid={`${area}-more`}>
          +{remaining} more
        </li>
      )}
    </ul>
  );
};

export default TrustCheckQueryList;
