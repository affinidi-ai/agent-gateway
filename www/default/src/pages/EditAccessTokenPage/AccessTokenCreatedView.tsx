import React from 'react';
import { Alert, Form, InputGroup } from 'react-bootstrap';
import type { AccessTokenCreated } from '../../types';
import { AppButton } from '../../components/shared/AppButton';
import { CopyButton } from '../../components/shared/CopyButton';
import { showToast } from '../../utils/toaster';
import AccessTokenEditHeader from './AccessTokenEditHeader';

interface AccessTokenCreatedViewProps {
  token: AccessTokenCreated;
  onDone: () => void;
}

const AccessTokenCreatedView: React.FC<AccessTokenCreatedViewProps> = ({ token, onDone }) => (
  <div className="container-fluid" data-testid="page-access-token-created">
    <AccessTokenEditHeader
      title="Access Token Created"
      subtitle="Copy the token secret now. It is shown only once."
      onBack={onDone}
    />
    <div className="row">
      <div className="col-lg-8">
        <div className="card shadow mb-4" data-testid="access-token-created-view">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">Token Secret</h6>
          </div>
          <div className="card-body">
            <Alert variant="success">
              <i className="fas fa-check-circle me-2" aria-hidden="true" />
              Access token <strong>{token.name}</strong> created.
            </Alert>
            <Form.Group controlId="access-token-secret-input">
              <Form.Label>Token secret</Form.Label>
              <InputGroup>
                <Form.Control
                  className="font-monospace"
                  value={token.token}
                  readOnly
                  onFocus={event => event.currentTarget.select()}
                  data-testid="access-token-secret"
                />
                <CopyButton
                  text={token.token}
                  variant="outline-primary"
                  size="md"
                  label="Copy"
                  title="Copy access token secret"
                  onCopyError={() =>
                    showToast(
                      'error',
                      'Could not copy the token. Select the secret and copy it manually.'
                    )
                  }
                  data-testid="access-token-copy-secret-button"
                />
              </InputGroup>
            </Form.Group>
            <Alert variant="warning" className="small mt-3">
              <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
              Copy this now. It cannot be retrieved later. Send it as an{' '}
              <code>Authorization: Bearer</code> credential to the management API.
            </Alert>
            <div className="d-flex justify-content-end">
              <AppButton variant="primary" onClick={onDone} data-testid="access-token-done-button">
                Done
              </AppButton>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
);

export default AccessTokenCreatedView;
