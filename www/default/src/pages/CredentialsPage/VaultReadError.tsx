import React from 'react';
import { AppButton } from '../../components/shared/AppButton';

interface VaultReadErrorProps {
  /** Why the vault could not be read. */
  error: string;
  onRetry: () => void;
  testId: string;
}

/**
 * What a delegation tab shows in place of its list while the vault cannot be read: the reason and
 * a Retry, never its empty state, since a failed read says nothing about what the vault holds.
 */
const VaultReadError: React.FC<VaultReadErrorProps> = ({ error, onRetry, testId }) => (
  <div className="alert alert-danger mb-0" role="alert" data-testid={testId}>
    <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
    Failed to load delegations: {error}
    <AppButton
      variant="outline-danger"
      size="sm"
      className="ms-3"
      data-testid={`${testId}-retry`}
      onClick={onRetry}
    >
      Retry
    </AppButton>
    <div className="small mt-2 mb-0">
      No delegations could be read. That is not the same as there being none.
    </div>
  </div>
);

export default VaultReadError;
