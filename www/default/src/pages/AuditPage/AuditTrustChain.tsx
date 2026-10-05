import React from 'react';
import type { TrustRung, TrustRungKind } from './trustChain';

interface AuditTrustChainProps {
  rungs: TrustRung[];
}

function rungIcon(kind: TrustRungKind): string {
  switch (kind) {
    case 'root':
      return 'fa-fingerprint';
    case 'provider':
      return 'fa-key';
    default:
      return 'fa-shield-halved';
  }
}

/** Root-of-trust ladder: recognition edges, provider, and the signing gateway. */
const AuditTrustChain: React.FC<AuditTrustChainProps> = ({ rungs }) => {
  if (rungs.length === 0) return null;
  return (
    <ul className="audit-trustchain" data-testid="audit-trust-chain">
      {rungs.map((rung, i) => (
        <li key={i} className={`audit-trust-rung audit-trust-rung--${rung.kind}`}>
          <i className={`fas ${rungIcon(rung.kind)} audit-trust-icon`} aria-hidden="true" />
          <span className="audit-trust-body">
            <span className="audit-trust-role">{rung.role}</span>
            <span className="audit-trust-title">
              {rung.title}
              {rung.ok !== undefined && (
                <i
                  className={`fas ms-1 ${rung.ok ? 'fa-circle-check audit-check-icon--pass' : 'fa-circle-xmark audit-check-icon--fail'}`}
                  aria-hidden="true"
                />
              )}
            </span>
            {rung.detail && <span className="audit-trust-detail">{rung.detail}</span>}
          </span>
        </li>
      ))}
    </ul>
  );
};

export default AuditTrustChain;
