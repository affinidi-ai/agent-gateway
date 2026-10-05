import React, { useState, useEffect } from 'react';
import { Alert, Button, Form, Spinner } from 'react-bootstrap';
import {
  isWebAuthnSupported,
  isPlatformAuthenticatorAvailable,
  registerPasskey,
  authenticateWithPasskey,
} from '../utils/passkeys';
import styles from './LoginPage.module.css';
import { apiClient, sessionManager } from '../api';
import { ROUTES } from '../routes';
import { RegistrationTerms } from './RegistrationTerms';
import { useRegistrationTerms } from './useRegistrationTerms';

interface LoginPageProps {
  onLogin: () => void;
}

const COPY = {
  login: {
    heading: 'Sign in',
    subtext: 'Enter your username to continue with your passkey.',
    buttonLabel: 'Sign in with passkey',
    buttonIcon: 'fa-fingerprint',
    secondaryText: 'New here?',
    secondaryLink: 'Create an account',
    ariaLabel: 'Sign in with passkey',
  },
  register: {
    heading: 'Create your account',
    subtext: 'Register a passkey to secure your Agent Gateway account.',
    buttonLabel: 'Register Passkey',
    buttonIcon: 'fa-user-plus',
    secondaryText: 'Already have an account?',
    secondaryLink: 'Sign in',
    ariaLabel: 'Register a new passkey',
  },
};

const FEATURES = [
  {
    icon: 'fas fa-layer-group',
    label: 'Agent Surfaces',
    desc: 'Visually create and manage agent workflows across protocols.',
  },
  {
    icon: 'fas fa-chart-line',
    label: 'Observability',
    desc: 'Monitor, trace, and audit all agent activity for compliance.',
  },
  {
    icon: 'fas fa-user-shield',
    label: 'Authentication',
    desc: 'Flexible security with mTLS, API keys, JWT, and DID Auth.',
  },
  {
    icon: 'fas fa-gavel',
    label: 'Policy enforcement',
    desc: 'Apply fine-grained access controls with OPA.',
  },
  {
    icon: 'fas fa-id-card',
    label: 'Agent Identity',
    desc: 'Automatic, verifiable decentralised identities (W3C DID).',
  },
];

const LeftPanel: React.FC = () => {
  return (
    <div
      className={styles.leftCol}
      style={{
        backgroundImage:
          'linear-gradient(160deg, rgba(20, 12, 40, 0.72) 0%, rgba(30, 18, 60, 0.5) 100%), url(/dashboard/images/aff_flythrough_bgnd.jpg)',
        backgroundSize: 'cover',
        backgroundPosition: 'center',
        backgroundRepeat: 'no-repeat',
      }}
    >
      <h2 className={styles.leftHeadline}>Welcome!</h2>
      <p className={styles.leftSubheading}>
        Design, secure and scale AI agent interactions from a single platform:
      </p>
      <div className={styles.featureList}>
        {FEATURES.map(f => (
          <div key={f.label} className={styles.featureRow}>
            <div className={styles.featureIcon}>
              <i className={f.icon} />
            </div>
            <div className={styles.featureText}>
              <span className={styles.featureLabel}>{f.label}</span>
              <span className={styles.featureDesc}>{f.desc}</span>
            </div>
          </div>
        ))}
      </div>
      <div className={styles.wordmark}>
        <img src="/dashboard/images/aff_logo_dark_mode.svg" alt="Affinidi" />
      </div>
    </div>
  );
};

const LoginPage: React.FC<LoginPageProps> = ({ onLogin }) => {
  const [mode, setMode] = useState<'login' | 'register'>('login');
  const [username, setUsername] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [supported, setSupported] = useState(false);
  const [platformAuthAvailable, setPlatformAuthAvailable] = useState(false);
  const [authMode, setAuthMode] = useState<'passkey' | 'saml' | null>(null);
  const [initializing, setInitializing] = useState(true);
  const registrationTerms = useRegistrationTerms(mode === 'register', setError);

  useEffect(() => {
    if (sessionManager.didSessionExpire()) {
      sessionManager.clearSessionExpiredError();
      setError('Your session has expired. Please sign in again.');
    }

    const checkAuthAndMode = async () => {
      if (sessionManager.getSessionToken()) {
        try {
          const authCheck = await apiClient.fetch('/api/auth/check');
          if (authCheck.ok) {
            await authCheck.json();
            window.location.href = ROUTES.DASHBOARD;
            return;
          }
        } catch {
          // Not authenticated, continue to login
        }
      }

      try {
        const response = await apiClient.fetch('/api/v1/auth/mode');
        const data = await response.json();
        setAuthMode(data.mode);
        if (data.mode === 'passkey') {
          setSupported(isWebAuthnSupported());
          isPlatformAuthenticatorAvailable().then(setPlatformAuthAvailable);
        }
      } catch (err) {
        console.error('Failed to fetch auth mode:', err);
        setAuthMode('passkey');
        setSupported(isWebAuthnSupported());
        isPlatformAuthenticatorAvailable().then(setPlatformAuthAvailable);
      } finally {
        setInitializing(false);
      }
    };

    checkAuthAndMode();

    const savedUsername = sessionManager.getCookie('lastUsername');
    if (savedUsername) setUsername(savedUsername);
  }, []);

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);
    try {
      await registerPasskey(username, registrationTerms.requirements);
      setSuccess('Passkey registered successfully! You can now log in.');
      setMode('login');
      setUsername('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Registration failed');
      try {
        await registrationTerms.reload();
      } catch {
        setError('The current Terms could not be loaded. Registration remains blocked.');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);
    setLoading(true);

    if (authMode === 'saml') {
      await new Promise(resolve => setTimeout(resolve, 100));
      window.location.href = '/api/saml/login';
      return;
    }

    try {
      await authenticateWithPasskey(username);
      onLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
      setLoading(false);
    }
  };

  const RightContent = () => {
    if (authMode === null || initializing) {
      return (
        <div className="text-center py-5">
          <Spinner animation="border" variant="primary" />
        </div>
      );
    }

    if (!supported && authMode === 'passkey') {
      return (
        <>
          <h2 className="h5 fw-bold mb-3">WebAuthn Not Supported</h2>
          <Alert variant="danger">
            Your browser doesn't support WebAuthn/Passkeys. Please use a modern browser like Chrome,
            Edge, Safari, or Firefox.
          </Alert>
        </>
      );
    }

    if (authMode === 'saml') {
      return (
        <>
          {error && <Alert variant="danger">{error}</Alert>}
          <Form onSubmit={handleLogin}>
            <div className="d-grid">
              <Button
                variant="primary"
                type="submit"
                style={{ height: '48px' }}
                disabled={loading}
                className={`d-flex align-items-center justify-content-center gap-2 ${styles.submitBtn}`}
              >
                {loading ? (
                  <>
                    <Spinner animation="border" size="sm" />
                    Redirecting...
                  </>
                ) : (
                  <>
                    <i className="fas fa-sign-in-alt" />
                    Sign in with SSO
                  </>
                )}
              </Button>
            </div>
          </Form>
        </>
      );
    }

    return (
      <>
        <h2 className={styles.formHeading}>{COPY[mode].heading}</h2>
        <p className={styles.formSubtext}>{COPY[mode].subtext}</p>

        {error && (
          <Alert variant="danger" role="alert">
            {error}
          </Alert>
        )}
        {success && (
          <Alert variant="success" role="alert">
            {success}
          </Alert>
        )}

        <Form onSubmit={mode === 'login' ? handleLogin : handleRegister}>
          <Form.Group className="mb-3">
            <Form.Label htmlFor="username">Username</Form.Label>
            <Form.Control
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="Enter your username"
              required
              disabled={loading}
              autoComplete="username"
              autoFocus
              data-testid="login-username"
              aria-describedby="username-help"
            />
          </Form.Group>

          {mode === 'register' && (
            <RegistrationTerms
              requirements={registrationTerms.requirements}
              selected={registrationTerms.selected}
              onToggle={registrationTerms.toggle}
            />
          )}

          <div className="d-grid">
            <Button
              variant="primary"
              type="submit"
              disabled={
                loading ||
                !username.trim() ||
                (mode === 'register' && !registrationTerms.allAccepted)
              }
              className={`d-flex align-items-center justify-content-center gap-2 ${styles.submitBtn} ${styles.submitBtnGradient}`}
              data-testid={mode === 'login' ? 'login-authenticate-button' : 'login-register-button'}
              aria-label={COPY[mode].ariaLabel}
            >
              {loading ? (
                <>
                  <Spinner animation="border" size="sm" />
                  {mode === 'login' ? 'Authenticating...' : 'Registering...'}
                </>
              ) : (
                <>
                  <i className={`fas ${COPY[mode].buttonIcon}`} aria-hidden="true" />
                  {COPY[mode].buttonLabel}
                </>
              )}
            </Button>
          </div>
        </Form>

        <div className={styles.dividerSection}>
          <p className={styles.secondaryText}>
            {COPY[mode].secondaryText}{' '}
            <button
              className={styles.secondaryLink}
              type="button"
              onClick={() => {
                setMode(mode === 'login' ? 'register' : 'login');
                setError(null);
                setSuccess(null);
              }}
              disabled={loading}
              data-testid="login-mode-toggle"
              aria-label={`Switch to ${mode === 'login' ? 'register' : 'login'} mode`}
            >
              {COPY[mode].secondaryLink}
            </button>
          </p>
        </div>

        {platformAuthAvailable && (
          <p className={styles.biometricCaption} role="note" aria-live="polite">
            <i className="fas fa-check" style={{ marginRight: '0.35rem' }} aria-hidden="true" />
            Biometric authentication available
          </p>
        )}
      </>
    );
  };

  return (
    <div className={styles.loginPage} data-testid="page-login">
      <LeftPanel />
      <div className={styles.rightCol}>
        <div className={styles.formPanel}>
          <div className={styles.formLogo}>
            <img
              src="/dashboard/agent-gateway-logo-light-mode.svg"
              alt="Agent Gateway"
              className={styles.formLogoWordmark}
            />
          </div>
          <RightContent />
        </div>
        <footer className={styles.formFooterBottom}>
          <p className={styles.formFooterText}>
            Having trouble?{' '}
            <a
              href="https://www.affinidi.com/contact"
              className={styles.footerLink}
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Contact Affinidi support (opens in new tab)"
            >
              Contact us
            </a>
          </p>
        </footer>
      </div>
    </div>
  );
};

export default LoginPage;
