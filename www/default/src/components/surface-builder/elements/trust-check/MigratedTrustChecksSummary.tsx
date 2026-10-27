import React from 'react';
import InfoBanner from '../../../shared/InfoBanner';
import { countTrustCheckReviews, countTrustCheckReviewsInPayload } from './definition';

interface MigratedTrustChecksSummaryProps {
  nodes: ReadonlyArray<{ id: string; type: string; parentId?: string; config?: any }>;
  /** Stored snapshots of the variants not shown on the canvas. */
  otherVariantSnapshots?: ReadonlyArray<unknown>;
}

const MigratedTrustChecksSummary: React.FC<MigratedTrustChecksSummaryProps> = ({
  nodes,
  otherVariantSnapshots = [],
}) => {
  const inOtherVariants = otherVariantSnapshots.reduce<number>(
    (sum, snapshot) => sum + countTrustCheckReviewsInPayload(snapshot),
    0
  );
  const count = countTrustCheckReviews(nodes) + inOtherVariants;
  if (count === 0) return null;
  const title =
    count === 1
      ? '1 Transit Point needs Trust Check review'
      : `${count} Transit Points need Trust Check review`;
  const variantsNote =
    inOtherVariants === 0
      ? ''
      : inOtherVariants === 1
        ? ' 1 of them is in another variant; switch to it to review.'
        : ` ${inOtherVariants} of them are in other variants; switch to each to review.`;
  return (
    <div role="status" data-testid="surface-migrated-trust-checks-summary">
      <InfoBanner
        title={title}
        icon="fa-exclamation-triangle"
        variant="warning"
        collapsible={false}
        className=""
        summary={`Open each Trust Check or Transit Point marked with a warning to review it.${variantsNote}`}
      />
    </div>
  );
};

export default MigratedTrustChecksSummary;
