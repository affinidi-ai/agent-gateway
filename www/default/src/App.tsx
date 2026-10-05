import React, { Suspense, lazy } from 'react';
import { BrowserRouter as Router } from 'react-router-dom';

import { AppButton } from './components/shared/AppButton';
import LoginPage from './pages/LoginPage';
import {
  apiClient,
  sessionManager,
  TERMS_ACCEPTANCE_REQUIRED_EVENT,
  TERMS_OPERATIONAL_FAILURE_EVENT,
} from './api';

const AuthenticatedApp = lazy(() => import('./pages/AuthenticatedApp'));
const TermsConsentPage = lazy(() => import('./pages/TermsConsentPage'));

type AppAuthState =
  | 'loading'
  | 'signed_out'
  | 'consent_pending'
  | 'authenticated'
  | 'authentication_failure'
  | 'operational_failure';

const PageLoader: React.FC = () => (
  <div
    style={{
      display: 'flex',
      justifyContent: 'center',
      alignItems: 'center',
      minHeight: '100vh',
      fontSize: '18px',
      color: '#6b7280',
    }}
  >
    <div className="spinner-border text-primary" role="status"></div>
  </div>
);

interface BlockingFailureProps {
  pageTestId: string;
  title: string;
  message: string;
  retryTestId: string;
  onRetry: () => void;
}

const BlockingFailure: React.FC<BlockingFailureProps> = ({
  pageTestId,
  title,
  message,
  retryTestId,
  onRetry,
}) => (
  <main className="container py-5" data-testid={pageTestId}>
    <div className="alert alert-danger mx-auto" style={{ maxWidth: '640px' }}>
      <h1 className="h4">{title}</h1>
      <p>{message}</p>
      <AppButton variant="outline-danger" onClick={onRetry} data-testid={retryTestId}>
        Try again
      </AppButton>
    </div>
  </main>
);

const OperationalFailure: React.FC<{ onRetry: () => void }> = ({ onRetry }) => (
  <BlockingFailure
    pageTestId="page-terms-operational-error"
    title="Access cannot be verified"
    message="The appliance cannot verify Terms acceptance. Product access remains blocked."
    retryTestId="terms-retry-button"
    onRetry={onRetry}
  />
);

const AuthenticationFailure: React.FC<{ onRetry: () => void }> = ({ onRetry }) => (
  <BlockingFailure
    pageTestId="page-authentication-error"
    title="Authentication cannot be checked"
    message="The appliance did not respond to the authentication check."
    retryTestId="authentication-retry-button"
    onRetry={onRetry}
  />
);

const App: React.FC = () => {
  const [authState, setAuthState] = React.useState<AppAuthState>('loading');

  const checkAuth = React.useCallback(async () => {
    setAuthState('loading');
    try {
      const response = await apiClient.fetch('/api/auth/check');
      if (response.status === 404) {
        setAuthState('authenticated');
        return;
      }
      if (response.status === 503) {
        const body = (await response
          .clone()
          .json()
          .catch(() => null)) as { code?: string } | null;
        if (body?.code === 'TERMS_OPERATIONAL_FAILURE') {
          setAuthState('operational_failure');
          return;
        }
      }
      if (response.status >= 500) {
        setAuthState('authentication_failure');
        return;
      }
      if (!response.ok) {
        setAuthState('signed_out');
        return;
      }
      const data = (await response.json()) as {
        authenticated?: boolean;
        consent_required?: boolean;
      };
      if (!data.authenticated) {
        setAuthState('signed_out');
      } else if (data.consent_required) {
        setAuthState('consent_pending');
      } else {
        setAuthState('authenticated');
      }
    } catch (error) {
      console.error('[Auth] Authentication check failed:', error);
      setAuthState('authentication_failure');
    }
  }, []);

  React.useEffect(() => {
    void checkAuth();
  }, [checkAuth]);

  React.useEffect(() => {
    const requireTermsAcceptance = () => setAuthState('consent_pending');
    const reportTermsOperationalFailure = () => setAuthState('operational_failure');
    window.addEventListener(TERMS_ACCEPTANCE_REQUIRED_EVENT, requireTermsAcceptance);
    window.addEventListener(TERMS_OPERATIONAL_FAILURE_EVENT, reportTermsOperationalFailure);
    return () => {
      window.removeEventListener(TERMS_ACCEPTANCE_REQUIRED_EVENT, requireTermsAcceptance);
      window.removeEventListener(TERMS_OPERATIONAL_FAILURE_EVENT, reportTermsOperationalFailure);
    };
  }, []);

  const handleLogout = () =>
    sessionManager.logout().then(() => {
      setAuthState('signed_out');
    });

  if (authState === 'loading') return <PageLoader />;

  return (
    <Router>
      <Suspense fallback={<PageLoader />}>
        {authState === 'authenticated' && <AuthenticatedApp onLogout={handleLogout} />}
        {authState === 'consent_pending' && (
          <TermsConsentPage onAccepted={checkAuth} onLogout={handleLogout} />
        )}
        {authState === 'signed_out' && <LoginPage onLogin={checkAuth} />}
        {authState === 'authentication_failure' && <AuthenticationFailure onRetry={checkAuth} />}
        {authState === 'operational_failure' && <OperationalFailure onRetry={checkAuth} />}
      </Suspense>
    </Router>
  );
};

export default App;
