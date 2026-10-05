import React from 'react';
import { Alert, Form, Spinner } from 'react-bootstrap';
import { AppButton } from '../../components/shared/AppButton';
import { Link } from '../../components/shared/Link';
import '../../dashboard.css';
import styles from './TermsConsentPage.module.css';
import { termsSelectionKey, useTermsConsent } from './useTermsConsent';

interface TermsConsentPageProps {
  onAccepted: () => void;
  onLogout: () => void;
}

const TermsConsentPage: React.FC<TermsConsentPageProps> = ({ onAccepted, onLogout }) => {
  const consent = useTermsConsent(onAccepted);

  return (
    <main className={styles.page} data-testid="page-terms-consent">
      <section className={`card shadow ${styles.card}`} aria-labelledby="terms-consent-title">
        <div className="card-body p-4 p-md-5">
          <div className="text-center mb-4">
            <i className="fas fa-file-signature fa-3x text-primary mb-3" aria-hidden="true" />
            <h1 id="terms-consent-title" className="h3 text-gray-800">
              Review the Terms
            </h1>
            <p className="text-muted mb-0">Accept every applicable document to continue.</p>
          </div>

          {consent.error && <Alert variant="danger">{consent.error}</Alert>}
          {consent.loading ? (
            <div className="text-center py-4">
              <Spinner animation="border" variant="primary" role="status" />
            </div>
          ) : (
            <Form
              onSubmit={event => {
                event.preventDefault();
                void consent.submit();
              }}
            >
              {consent.required.map(term => (
                <div className={styles.term} key={termsSelectionKey(term)}>
                  <Form.Check
                    id={`terms-${term.terms_type}-${term.version_id}`}
                    checked={consent.selected.has(termsSelectionKey(term))}
                    onChange={event => consent.toggle(term, event.target.checked)}
                    label={
                      <span>
                        I agree to {term.title} (version {term.version}).{' '}
                        <Link
                          href={term.url}
                          external
                          variant="inline"
                          testId={`terms-consent-${term.terms_type}-link`}
                        >
                          View Terms
                        </Link>
                      </span>
                    }
                    data-testid={`terms-consent-${term.terms_type}`}
                  />
                </div>
              ))}
              <div className="d-grid gap-2 mt-4">
                <AppButton
                  type="submit"
                  disabled={!consent.allSelected || consent.submitting}
                  data-testid="terms-consent-submit-button"
                >
                  {consent.submitting ? 'Recording acceptance…' : 'Accept and continue'}
                </AppButton>
                <AppButton
                  type="button"
                  variant="secondary"
                  onClick={onLogout}
                  disabled={consent.submitting}
                  data-testid="terms-consent-logout-button"
                >
                  Sign out
                </AppButton>
              </div>
            </Form>
          )}
        </div>
      </section>
    </main>
  );
};

export default TermsConsentPage;
