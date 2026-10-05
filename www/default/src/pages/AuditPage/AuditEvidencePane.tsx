import React from 'react';
import { VpJwtRow } from '../../components/shared/VpViewer';
import FieldHelp from '../../components/shared/FieldHelp';
import AuditFieldList from './AuditFieldList';
import AuditJourney from './AuditJourney';
import AuditProvenance from './AuditProvenance';
import AuditTrustChain from './AuditTrustChain';
import { extractEmbeddedDecisions, policyDecision, trustCheck } from './auditHelpers';
import { signedVpEntry, traceSiblings } from './evidence';
import { fieldGroups } from './fieldGroups';
import { buildJourney } from './journey';
import { buildTrustChain } from './trustChain';
import { useDidNames } from './useDidNames';
import type { AuditEntry } from './types';

interface AuditEvidencePaneProps {
  entry: AuditEntry;
  filteredEntries: AuditEntry[];
  onQuickFilter: (term: string, cat?: string) => void;
}

/**
 * Drawer body for a selected event, correlated across the whole request by
 * `trace_id`: the request **journey** (ordered pipeline events), the
 * **root-of-trust** ladder (recognition edges + signing gateway, with
 * human-readable names), the real **signed presentation** (decoded VP +
 * fingerprint), and a grouped list of the remaining raw fields.
 */
const AuditEvidencePane: React.FC<AuditEvidencePaneProps> = ({
  entry,
  filteredEntries,
  onQuickFilter,
}) => {
  const resolveName = useDidNames();
  const pd = policyDecision(entry);
  const tc = trustCheck(entry);

  const siblings = traceSiblings(filteredEntries, entry);
  const journey = buildJourney(siblings);
  const trustChain = buildTrustChain(siblings, resolveName);
  // Prefer the selected event's own presentation so a specific `vp_injected`
  // row (e.g. the MA→TP leg carrying the workloadBinding VP) shows its own VP,
  // not the trace's first one. Non-VP rows fall back to the trace's signed VP.
  const vpEntry = entry.vp_jwt || entry.vp_fingerprint ? entry : signedVpEntry(siblings);
  const decisionsCount = vpEntry ? (extractEmbeddedDecisions(vpEntry)?.length ?? 0) : 0;
  const groups = fieldGroups(entry, pd, tc);

  return (
    <div className="audit-evidence" data-testid="audit-evidence">
      <section className="audit-evidence-block">
        <div className="audit-evidence-label">Request journey</div>
        <AuditJourney steps={journey} />
      </section>

      {trustChain.length > 0 && (
        <section className="audit-evidence-block">
          <div className="audit-evidence-label">
            Root of trust{' '}
            <FieldHelp testId="field-help-audit-trust-chain" ariaLabel="About Root of trust">
              Each rung is a step in establishing trust for this request on its way to the signing
              gateway. Trust-check rungs show what vouched for the caller and whether that check
              succeeded; the credential provider and signing-gateway rungs just show who they are,
              with no pass/fail verdict of their own.
            </FieldHelp>
          </div>
          <AuditTrustChain rungs={trustChain} />
        </section>
      )}

      <section className="audit-evidence-block">
        <div className="audit-evidence-label">Signed presentation</div>
        <AuditProvenance
          vpEntry={vpEntry}
          decisionsCount={decisionsCount}
          resolveName={resolveName}
        />
        {vpEntry?.vp_jwt ? (
          <table className="table table-sm table-borderless mb-0" style={{ fontSize: '0.85rem' }}>
            <tbody>
              <VpJwtRow vpJwt={vpEntry.vp_jwt} />
            </tbody>
          </table>
        ) : vpEntry?.vp_fingerprint ? (
          <div className="d-flex align-items-center flex-wrap" style={{ gap: '0.35rem' }}>
            <i className="fas fa-fingerprint text-primary" aria-hidden="true" />
            <code style={{ fontSize: '0.75rem', wordBreak: 'break-all' }}>
              {vpEntry.vp_fingerprint}
            </code>
            <button
              type="button"
              className="btn btn-xs btn-outline-secondary"
              style={{ fontSize: '0.72rem', padding: '0.1rem 0.35rem' }}
              title="Filter by this VP fingerprint"
              onClick={() => onQuickFilter(vpEntry.vp_fingerprint!)}
            >
              <i className="fas fa-filter me-1" aria-hidden="true" />
              This hash
            </button>
          </div>
        ) : (
          <p className="small text-muted mb-0">
            No signed presentation was recorded for this request.
          </p>
        )}
      </section>

      <section className="audit-evidence-block">
        <div className="audit-evidence-label">Details</div>
        <AuditFieldList groups={groups} />
      </section>
    </div>
  );
};

export default AuditEvidencePane;
