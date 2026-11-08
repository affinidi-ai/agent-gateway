import React from 'react';
import { Badge } from '../shared/Badge';
import type { TrustRecorderState } from '../../types';
import { trustRecorderStateLabel, trustRecorderStateTone } from '../../utils/trustRecorderStatus';

interface TrustRecorderStateBadgeProps {
  state: TrustRecorderState;
  testId?: string;
}

export const TrustRecorderStateBadge: React.FC<TrustRecorderStateBadgeProps> = ({
  state,
  testId,
}) => (
  <Badge
    tone={trustRecorderStateTone(state)}
    size="sm"
    value={trustRecorderStateLabel(state)}
    data-testid={testId}
  />
);

export default TrustRecorderStateBadge;
