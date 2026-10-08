import React from 'react';
import { Alert, Spinner } from 'react-bootstrap';
import { AppButton } from '../../components/shared/AppButton';
import '../../dashboard.css';
import loginStyles from '../LoginPage.module.css';
import styles from './CliConsentPage.module.css';
import { useCliConsent } from './useCliConsent';

const CliConsentPage: React.FC = () => {
  const { request, status, username, error, allow, cancel } = useCliConsent(window.location.search);

  const renderBody = () => {
    if (!request) {
      return (
        <>
          <h1 className={loginStyles.formHeading}>This sign-in link is not valid</h1>
          <Alert variant="danger" data-testid="cli-consent-invalid">
            The link is missing details or has been changed. Run{' '}
            <code>fabric agent-gateway login</code> again.
          </Alert>
        </>
      );
    }
    if (status === 'loading') {
      return (
        <div className="text-center py-5">
          <Spinner animation="border" variant="primary" role="status" />
        </div>
      );
    }
    if (status === 'cancelled') {
      return (
        <>
          <h1 className={loginStyles.formHeading}>Sign-in cancelled</h1>
          <p className={loginStyles.formSubtext} data-testid="cli-consent-cancelled">
            The CLI was not given access. You can close this tab.
          </p>
        </>
      );
    }
    if (status === 'not_approved') {
      return (
        <>
          <h1 className={loginStyles.formHeading}>Your account is not approved yet</h1>
          <p className={loginStyles.formSubtext} data-testid="cli-consent-not-approved">
            Ask an administrator to approve your account, then run{' '}
            <code>fabric agent-gateway login</code> again.
          </p>
        </>
      );
    }
    if (status === 'redirecting') {
      return (
        <>
          <h1 className={loginStyles.formHeading}>Returning to the CLI</h1>
          <p className={loginStyles.formSubtext} data-testid="cli-consent-redirecting">
            You can close this tab once the CLI confirms the sign-in.
          </p>
        </>
      );
    }
    const busy = status === 'submitting';
    return (
      <>
        <h1 className={loginStyles.formHeading}>Allow the CLI to sign in as you?</h1>
        <p className={loginStyles.formSubtext}>
          A program on this computer is asking to use your account through the <code>fabric</code>{' '}
          command line tool.
        </p>
        <div className={styles.details}>
          {username && (
            <p data-testid="cli-consent-username">
              Signed in as <strong>{username}</strong>
            </p>
          )}
          <p data-testid="cli-consent-target">
            Return to <strong>127.0.0.1:{request.port}</strong>
          </p>
        </div>
        <Alert variant="warning">
          Only allow this if you just ran <code>fabric agent-gateway login</code> yourself.
        </Alert>
        {error && (
          <Alert variant="danger" role="alert" data-testid="cli-consent-error">
            {error}
          </Alert>
        )}
        <div className="d-flex gap-2">
          <AppButton
            variant="secondary"
            className="flex-fill"
            onClick={cancel}
            disabled={busy}
            data-testid="cli-consent-cancel-button"
          >
            Cancel
          </AppButton>
          <AppButton
            variant="primary"
            className="flex-fill"
            onClick={() => void allow()}
            disabled={busy || !username}
            data-testid="cli-consent-allow-button"
          >
            {busy ? 'Allowing…' : 'Allow'}
          </AppButton>
        </div>
        <p className={styles.note}>You can close this tab after you choose.</p>
      </>
    );
  };

  return (
    <main className={styles.page} data-testid="page-cli-consent">
      <div className={loginStyles.formPanel}>
        <div className={loginStyles.formLogo}>
          <img
            src="/dashboard/agent-gateway-logo-light-mode.svg"
            alt="Agent Gateway"
            className={loginStyles.formLogoWordmark}
          />
        </div>
        {renderBody()}
      </div>
    </main>
  );
};

export default CliConsentPage;
