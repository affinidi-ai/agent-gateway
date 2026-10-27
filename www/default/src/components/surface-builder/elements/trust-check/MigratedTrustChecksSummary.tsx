import React from 'react';
import InfoBanner from '../../../shared/InfoBanner';
import { countMigratedTrustChecks } from './definition';

interface MigratedTrustChecksSummaryProps {
  nodes: ReadonlyArray<{ type: string; config?: any }>;
}

const MigratedTrustChecksSummary: React.FC<MigratedTrustChecksSummaryProps> = ({ nodes }) => {
  const count = countMigratedTrustChecks(nodes);
  if (count === 0) return null;
  const title =
    count === 1
      ? '1 Transit Point has migrated Trust Checks to review'
      : `${count} Transit Points have migrated Trust Checks to review`;
  return (
    <div role="status" data-testid="surface-migrated-trust-checks-summary">
      <InfoBanner
        title={title}
        icon="fa-exclamation-triangle"
        variant="warning"
        collapsible={false}
        className=""
        summary="Open each Trust Check marked with a warning to keep or remove it."
      />
    </div>
  );
};

export default MigratedTrustChecksSummary;
