import React from 'react';
import { Alert, Form, InputGroup } from 'react-bootstrap';
import { AppButton } from '../../components/shared/AppButton';
import { CopyButton } from '../../components/shared/CopyButton';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { showToast } from '../../utils/toaster';
import AccessTokenResourceScopeField from '../SecretsPage/AccessTokenResourceScopeField';
import AccessTokenScopesField from '../SecretsPage/AccessTokenScopesField';
import type { AccessTokenEditor } from './useAccessTokenEditor';

interface AccessTokenFormCardProps {
  editor: AccessTokenEditor;
  availableScopes: string[];
  canRevoke: boolean;
}

const AccessTokenFormCard: React.FC<AccessTokenFormCardProps> = ({
  editor,
  availableScopes,
  canRevoke,
}) => {
  const submit = (event: React.FormEvent) => {
    event.preventDefault();
    void editor.save();
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          {editor.isEditMode ? 'Access Token Details' : 'New Access Token'}
        </h6>
      </div>
      <div className="card-body">
        {editor.error && (
          <div className="alert alert-danger" role="alert" data-testid="access-token-error-alert">
            <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
            {editor.error}
          </div>
        )}
        {editor.validationAttempted && !editor.canSave && !editor.revoked && (
          <div
            className="alert alert-danger"
            role="alert"
            data-testid="access-token-validation-alert"
          >
            <i
              className="fas fa-exclamation-triangle me-2"
              aria-hidden="true"
              data-testid="access-token-validation-alert-icon"
            />
            Please correct the highlighted fields before saving.
          </div>
        )}
        {editor.revoked && <Alert variant="warning">Revoked tokens are immutable.</Alert>}
        <Form noValidate onSubmit={submit}>
          <Form.Group className="mb-3" controlId="access-token-name-input">
            <Form.Label>
              Name <span className="text-danger">*</span>
            </Form.Label>
            <Form.Control
              value={editor.form.name}
              onChange={event => editor.updateField('name', event.target.value)}
              maxLength={120}
              placeholder="e.g. external"
              required
              isInvalid={editor.validationAttempted && Boolean(editor.nameError)}
              disabled={editor.revoked}
              autoFocus={!editor.isEditMode}
              data-testid="access-token-name"
            />
            <Form.Control.Feedback type="invalid" data-testid="access-token-name-error">
              {editor.nameError}
            </Form.Control.Feedback>
          </Form.Group>

          {editor.token && (
            <Form.Group className="mb-3" controlId="access-token-id-input">
              <Form.Label>Token ID</Form.Label>
              <InputGroup>
                <Form.Control className="font-monospace" value={editor.token.id} readOnly />
                <CopyButton
                  text={editor.token.id}
                  variant="outline-primary"
                  size="md"
                  title="Copy token ID"
                  onCopyError={() => showToast('error', 'Could not copy the token ID.')}
                  data-testid="access-token-copy-id-button"
                />
              </InputGroup>
            </Form.Group>
          )}

          <Form.Group className="mb-3" controlId="access-token-description-input">
            <Form.Label>Description</Form.Label>
            <Form.Control
              type="text"
              value={editor.form.description}
              onChange={event => editor.updateField('description', event.target.value)}
              maxLength={280}
              placeholder="What is this token used for?"
              disabled={editor.revoked}
              data-testid="access-token-description"
            />
          </Form.Group>

          <AccessTokenScopesField
            availableScopes={availableScopes}
            selectedScopes={editor.form.scopes}
            unavailableScopes={editor.unavailableScopes}
            onChange={scopes => editor.updateField('scopes', scopes)}
            disabled={editor.revoked}
          />
          <AccessTokenResourceScopeField
            pattern={editor.form.resourcePattern}
            headers={editor.form.requiredHeaders}
            onPatternChange={pattern => editor.updateField('resourcePattern', pattern)}
            onHeadersChange={headers => editor.updateField('requiredHeaders', headers)}
            disabled={editor.revoked}
            showValidation={editor.validationAttempted}
          />

          {!editor.isEditMode && (
            <Form.Group className="mb-3">
              <div className="d-flex align-items-center justify-content-between gap-3 mb-2">
                <Form.Label className="mb-0" htmlFor="access-token-expiry-date-time-input">
                  Expires at {!editor.form.neverExpires && <span className="text-danger">*</span>}
                </Form.Label>
                <Form.Check
                  type="switch"
                  id="access-token-never-expires"
                  label="Never expires"
                  checked={editor.form.neverExpires}
                  onChange={event => editor.updateField('neverExpires', event.target.checked)}
                  data-testid="access-token-never-expires"
                />
              </div>
              {editor.form.neverExpires ? (
                <Form.Control
                  id="access-token-expiry-date-time-input"
                  type="text"
                  value="Never"
                  readOnly
                  disabled
                  data-testid="access-token-expiry-date-time"
                />
              ) : (
                <Form.Control
                  id="access-token-expiry-date-time-input"
                  type="datetime-local"
                  value={editor.form.expiresAt}
                  onChange={event => editor.updateField('expiresAt', event.target.value)}
                  min={editor.expiryBounds.min}
                  max={editor.expiryBounds.max}
                  required
                  isInvalid={Boolean(editor.expiryError)}
                  data-testid="access-token-expiry-date-time"
                />
              )}
              <Form.Control.Feedback type="invalid" data-testid="access-token-expiry-error">
                {editor.expiryError}
              </Form.Control.Feedback>
              <Form.Text muted>The date and time use your local timezone.</Form.Text>
            </Form.Group>
          )}

          <hr />
          <div className="d-flex justify-content-between align-items-center gap-3">
            {editor.isEditMode && canRevoke && !editor.revoked ? (
              <DeleteButton
                variant="danger"
                onDelete={editor.revoke}
                title="Revoke this token"
                data-testid="access-token-revoke-button"
              >
                Revoke token
              </DeleteButton>
            ) : (
              <span />
            )}
            <AppButton
              variant="primary"
              type="submit"
              loading={editor.saving}
              loadingLabel="Saving..."
              disabled={editor.saving || editor.revoked}
              iconStart={<i className="fas fa-save me-1" aria-hidden="true" />}
              data-testid="access-token-form-save-button"
            >
              {editor.isEditMode ? 'Save changes' : 'Create token'}
            </AppButton>
          </div>
        </Form>
      </div>
    </div>
  );
};

export default AccessTokenFormCard;
