import React from 'react';
import InfoBanner from '../../../shared/InfoBanner';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import type { MissingAuthority } from './authorityReference';

type AnchorElement = 'trust-check' | 'trust-recorder';

const COPY: Record<AnchorElement, { subject: string; consequence: string; remove: string }> = {
  'trust-check': {
    subject: 'this Trust Check uses',
    consequence: 'so the check fails with AUTHORITY_NOT_FOUND until this is fixed.',
    remove: 'remove the Trust Check',
  },
  'trust-recorder': {
    subject: 'this entry uses',
    consequence: 'so the entry writes no records until this is fixed.',
    remove: 'remove the entry',
  },
};

interface MissingAuthorityWarningProps {
  testid: string;
  element: AnchorElement;
  missing: readonly MissingAuthority[];
  /** Label of each affected query or entry ("Query", "Entry"); omit when the list has one item. */
  itemLabel?: string;
}

/**
 * "Configuration required" banner for a Trust Check or Trust Recorder entry whose Authority was
 * deleted from the Authorities register, naming the stored DID and the ways to fix it.
 */
const MissingAuthorityWarning: React.FC<MissingAuthorityWarningProps> = ({
  testid,
  element,
  missing,
  itemLabel,
}) => {
  if (missing.length === 0) return null;
  const copy = COPY[element];
  return (
    <div role="alert" data-testid={testid}>
      <InfoBanner
        title="Configuration required"
        icon="fa-exclamation-triangle"
        variant="danger"
        collapsible={false}
        className="mt-2"
        summary={
          <>
            The Authority {copy.subject} no longer exists, {copy.consequence} Pick another
            Authority,{' '}
            <AddResourceLink to={deepLinks.authority} testid={`${testid}-add-authority-link`}>
              add an Authority
            </AddResourceLink>{' '}
            with the same DID, or {copy.remove}.
            <ul className="list-unstyled mb-0 mt-1" data-testid={`${testid}-dids`}>
              {missing.map(m => (
                <li key={`${m.index}-${m.did}`} style={{ wordBreak: 'break-all' }}>
                  {itemLabel ? `${itemLabel} ${m.index + 1}: ` : 'Authority DID: '}
                  <code>{m.did}</code>
                </li>
              ))}
            </ul>
          </>
        }
      />
    </div>
  );
};

export default MissingAuthorityWarning;
