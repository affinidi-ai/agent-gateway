import React from 'react';
import { Alert, Form } from 'react-bootstrap';
import { AppButton } from '../../components/shared/AppButton';
import { Link } from '../../components/shared/Link';
import { CustomerTermsDraft, TermsVersion } from '../../termsApi';

interface CustomerTermsSectionProps {
  current?: TermsVersion;
  draft: CustomerTermsDraft;
  setDraft: React.Dispatch<React.SetStateAction<CustomerTermsDraft>>;
  versionAlreadyPublished: boolean;
  canEdit: boolean;
  saving: boolean;
  onPublish: () => void;
  onDeactivate: () => void | Promise<void>;
}

export const CustomerTermsSection: React.FC<CustomerTermsSectionProps> = ({
  current,
  draft,
  setDraft,
  versionAlreadyPublished,
  canEdit,
  saving,
  onPublish,
  onDeactivate,
}) => {
  const [confirmingDeactivation, setConfirmingDeactivation] = React.useState(false);

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">Customer T&amp;C</h6>
        {current && canEdit && (
          <AppButton
            variant="outline-danger"
            onClick={() => setConfirmingDeactivation(true)}
            disabled={saving || confirmingDeactivation}
            title="Deactivate Customer T&C"
            aria-expanded={confirmingDeactivation}
            data-testid="terms-deactivate-button"
          >
            Deactivate
          </AppButton>
        )}
      </div>
      <div className="card-body">
        {confirmingDeactivation && (
          <Alert variant="warning" data-testid="terms-deactivate-confirmation">
            <p>
              Stop requiring the current Customer T&amp;C? Published versions and Acceptance Records
              will be retained. To require Customer T&amp;C again, publish a new version.
            </p>
            <div className="d-flex gap-2">
              <AppButton
                variant="outline-secondary"
                onClick={() => setConfirmingDeactivation(false)}
                disabled={saving}
                data-testid="terms-cancel-deactivation-button"
              >
                Cancel
              </AppButton>
              <AppButton
                variant="danger"
                onClick={() => {
                  setConfirmingDeactivation(false);
                  void onDeactivate();
                }}
                disabled={saving}
                data-testid="terms-confirm-deactivate-button"
              >
                Confirm deactivation
              </AppButton>
            </div>
          </Alert>
        )}
        {current && (
          <Alert variant="info">
            Current: {current.title} · version {current.version} ·{' '}
            <Link href={current.url} external variant="inline" testId="terms-customer-current-link">
              View Terms
            </Link>
          </Alert>
        )}
        {canEdit && (
          <Form
            onSubmit={event => {
              event.preventDefault();
              onPublish();
            }}
          >
            <Form.Group className="mb-3">
              <Form.Label>Title</Form.Label>
              <Form.Control
                required
                value={draft.title}
                onChange={event => setDraft({ ...draft, title: event.target.value })}
                data-testid="terms-customer-title"
              />
            </Form.Group>
            <Form.Group className="mb-3">
              <Form.Label>Version</Form.Label>
              <Form.Control
                required
                value={draft.version}
                isInvalid={versionAlreadyPublished}
                onChange={event => setDraft({ ...draft, version: event.target.value })}
                data-testid="terms-customer-version"
              />
              <Form.Control.Feedback type="invalid">
                This version has already been published. Enter a new version.
              </Form.Control.Feedback>
              <Form.Text muted>
                Enter a new version when the Terms content or URL changes.
              </Form.Text>
            </Form.Group>
            <Form.Group className="mb-3">
              <Form.Label>HTTPS document URL</Form.Label>
              <Form.Control
                required
                type="url"
                value={draft.url}
                onChange={event => setDraft({ ...draft, url: event.target.value })}
                data-testid="terms-customer-url"
              />
            </Form.Group>
            <Form.Check
              type="switch"
              className="mb-3"
              checked={draft.requires_reconsent}
              onChange={event => setDraft({ ...draft, requires_reconsent: event.target.checked })}
              label="Require existing users to accept this version at their next login"
              data-testid="terms-customer-reconsent"
            />
            <AppButton
              type="submit"
              disabled={saving || versionAlreadyPublished}
              data-testid="terms-publish-button"
            >
              Publish
            </AppButton>
          </Form>
        )}
      </div>
    </div>
  );
};
