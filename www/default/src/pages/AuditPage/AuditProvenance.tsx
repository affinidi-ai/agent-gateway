import React from 'react';
import { decodeJwtPayload } from '../../components/shared/VpViewer';
import FieldHelp from '../../components/shared/FieldHelp';
import type { NameResolver } from './trustChain';
import type { AuditEntry } from './types';

interface AuditProvenanceProps {
  vpEntry: AuditEntry | null;
  decisionsCount: number;
  resolveName: NameResolver;
}

/**
 * Root-of-trust callout for the signed presentation: names the signing gateway
 * and states what the VP cryptographically attests. Renders nothing when the
 * request produced no signed VP.
 */
const AuditProvenance: React.FC<AuditProvenanceProps> = ({
  vpEntry,
  decisionsCount,
  resolveName,
}) => {
  if (!vpEntry?.vp_jwt) return null;
  const payload = decodeJwtPayload(vpEntry.vp_jwt);
  const issuer = typeof payload?.iss === 'string' && payload.iss ? payload.iss : null;
  const decisions =
    decisionsCount > 0
      ? `${decisionsCount} policy decision${decisionsCount === 1 ? '' : 's'} and `
      : '';

  return (
    <div className="audit-provenance" data-testid="audit-provenance">
      <i className="fas fa-certificate audit-provenance-icon" aria-hidden="true" />
      <div className="audit-provenance-body">
        <div className="audit-provenance-title">
          Signed by {issuer ? resolveName(issuer) : 'the gateway'}
          <span className="audit-provenance-badge">root of trust</span>
          <FieldHelp testId="field-help-root-of-trust" ariaLabel="About root of trust">
            A Verifiable Presentation (VP) signed by the identity named above, proving the decisions
            below actually happened and weren't altered after the fact.
          </FieldHelp>
        </div>
        <div className="audit-provenance-detail">
          Cryptographically attests {decisions}the caller identity, independently verifiable via the
          fingerprint below.
        </div>
      </div>
    </div>
  );
};

export default AuditProvenance;
