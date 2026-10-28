import React from 'react';
import { AppButton } from '../../../shared/AppButton';
import InfoBanner from '../../../shared/InfoBanner';

interface MigratedTrustCheckWarningProps {
  testid: string;
  onKeep?: () => void;
}

const MigratedTrustCheckWarning: React.FC<MigratedTrustCheckWarningProps> = ({
  testid,
  onKeep,
}) => (
  <div role="status" data-testid={testid}>
    <InfoBanner
      title="Review this migrated Trust Check"
      icon="fa-exclamation-triangle"
      variant="warning"
      collapsible={false}
      className="mt-2"
      summary="This list was copied from the surface-wide Trust Check list, which used to run on every Transit Point. Remove this Trust Check if this Transit Point does not need it, or keep it."
    >
      <AppButton
        variant="secondary"
        size="sm"
        className="mt-2"
        onClick={onKeep}
        disabled={!onKeep}
        data-testid={`${testid}-keep`}
      >
        Keep
      </AppButton>
    </InfoBanner>
  </div>
);

export default MigratedTrustCheckWarning;
