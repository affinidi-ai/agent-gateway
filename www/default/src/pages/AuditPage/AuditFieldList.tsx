import React from 'react';
import { Link } from 'react-router-dom';
import type { FieldGroup } from './fieldGroups';

interface AuditFieldListProps {
  groups: FieldGroup[];
}

/** Grouped key/value list for an event's raw fields — stacked term over value. */
const AuditFieldList: React.FC<AuditFieldListProps> = ({ groups }) => {
  const nonEmpty = groups.filter(g => g.items.length > 0);
  if (nonEmpty.length === 0) {
    return <p className="small text-muted mb-0">No additional fields.</p>;
  }
  return (
    <div className="audit-fieldgroups" data-testid="audit-fields">
      {nonEmpty.map(group => (
        <section key={group.label} className="audit-fieldgroup">
          <div className="audit-fieldgroup-label">{group.label}</div>
          <dl className="audit-kv">
            {group.items.map(item => (
              <div key={item.term} className="audit-kv-row">
                <dt className="audit-kv-term">{item.term}</dt>
                <dd className={`audit-kv-val ${item.mono ? 'audit-kv-val--mono' : ''}`}>
                  {item.href ? <Link to={item.href}>{item.value}</Link> : item.value}
                </dd>
              </div>
            ))}
          </dl>
        </section>
      ))}
    </div>
  );
};

export default AuditFieldList;
