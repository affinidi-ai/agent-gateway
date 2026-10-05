import React from 'react';
import { AppButton } from '../../components/shared/AppButton';

interface AccessTokenEditHeaderProps {
  title: string;
  subtitle: string;
  saving?: boolean;
  saveDisabled?: boolean;
  onBack: () => void;
  onSave?: () => void;
}

const AccessTokenEditHeader: React.FC<AccessTokenEditHeaderProps> = ({
  title,
  subtitle,
  saving = false,
  saveDisabled = false,
  onBack,
  onSave,
}) => (
  <>
    <div className="mb-3">
      <AppButton
        variant="secondary"
        onClick={onBack}
        disabled={saving}
        aria-label="Back to access tokens"
        data-testid="access-token-back-button"
      >
        <i className="fas fa-arrow-left" aria-hidden="true" />
      </AppButton>
    </div>
    <div className="d-sm-flex align-items-center justify-content-between gap-3 mb-4">
      <div>
        <h1 className="h3 mb-0 text-gray-800">
          <i className="fas fa-user-lock me-2" aria-hidden="true" />
          {title}
        </h1>
        <p className="text-muted mt-2 mb-0">{subtitle}</p>
      </div>
      {onSave && (
        <AppButton
          variant="primary"
          onClick={onSave}
          loading={saving}
          loadingLabel="Saving..."
          disabled={saveDisabled}
          iconStart={<i className="fas fa-save me-1" aria-hidden="true" />}
          data-testid="access-token-save-button"
        >
          Save
        </AppButton>
      )}
    </div>
  </>
);

export default AccessTokenEditHeader;
