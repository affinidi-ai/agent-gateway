import React from 'react';
import { formatDateTime, timeAgo } from '../../utils/stringUtils';
import { callerDidOf, policyDecision, trustCheck } from './auditHelpers';
import { describeEntry } from './eventNarrative';
import type { AuditEntry } from './types';

interface AuditListItemProps {
  entry: AuditEntry;
  idx: number;
  isSelected: boolean;
  onSelect: () => void;
}

/** Short "actor" label for the footnote: caller name → caller DID → auth method. */
function actorOf(entry: AuditEntry): string {
  return (
    entry.caller?.name ||
    entry.caller?.name_redacted ||
    callerDidOf(entry) ||
    entry.caller?.auth_method ||
    'system'
  );
}

function shortHash(hash: string): string {
  if (hash.length <= 24) return hash;
  return `${hash.slice(0, 14)}…${hash.slice(-8)}`;
}

/**
 * One governance event in the master list. The whole row is a button; the title
 * is tone-coloured (green allow / red deny / amber warn), followed by the plain
 * message, an optional detail line, and a "timestamp · actor" footnote. A
 * trailing arrow turns accent-blue when the row is selected.
 */
const AuditListItem: React.FC<AuditListItemProps> = ({ entry, idx, isSelected, onSelect }) => {
  const { title, tone, summary, detail } = describeEntry(entry);
  const pd = policyDecision(entry);
  const tc = trustCheck(entry);
  const verdict = pd?.decision ?? (tc ? (tc.ok ? 'allow' : 'deny') : undefined);
  const isAllow = verdict === 'allow' || verdict === 'Allow';

  return (
    <li className="audit-item-wrap">
      <button
        type="button"
        className={`audit-item audit-item--${tone} ${isSelected ? 'audit-item--selected' : ''}`}
        aria-current={isSelected}
        data-testid={`audit-item-${idx}`}
        onClick={onSelect}
      >
        <span className="audit-item-body">
          <span className="audit-item-headline">
            <span className={`audit-item-title audit-item-title--${tone}`}>{title}</span>
            {verdict !== undefined && (
              <span
                className={`audit-decision ${isAllow ? 'audit-decision--allow' : 'audit-decision--deny'}`}
              >
                <i className={`fas fa-${isAllow ? 'check' : 'xmark'}`} aria-hidden="true" />
                {isAllow ? 'Allow' : 'Deny'}
              </span>
            )}
            {typeof pd?.policy_version === 'number' && (
              <span className="audit-policy-evidence-chip" title="Enforced policy version">
                v{pd.policy_version}
              </span>
            )}
            {pd?.policy_content_hash && (
              <span
                className="audit-policy-evidence-chip audit-policy-evidence-chip--hash"
                title={`Policy SHA: ${pd.policy_content_hash}`}
              >
                {shortHash(pd.policy_content_hash)}
              </span>
            )}
          </span>
          <span className="audit-item-summary">{summary}</span>
          {detail && <span className="audit-item-detail">{detail}</span>}
          <span className="audit-item-foot" title={formatDateTime(entry.timestamp, true)}>
            <span className="audit-item-foot-time">{timeAgo(entry.timestamp)}</span>
            <span aria-hidden="true"> · </span>
            <span className="audit-item-foot-actor">{actorOf(entry)}</span>
          </span>
        </span>
        <i
          className={`fas fa-arrow-right audit-item-arrow ${isSelected ? 'audit-item-arrow--active' : ''}`}
          aria-hidden="true"
        />
      </button>
    </li>
  );
};

export default AuditListItem;
