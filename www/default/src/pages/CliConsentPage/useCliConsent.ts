import { useCallback, useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../api';
import type { CliLoginRequest } from '../../types';

const MIN_LOOPBACK_PORT = 1024;
const MAX_LOOPBACK_PORT = 65535;
const MAX_STATE_LENGTH = 256;
const CHALLENGE_PATTERN = /^[A-Za-z0-9_-]{43}$/;

export type CliConsentStatus =
  | 'loading'
  | 'ready'
  | 'submitting'
  | 'redirecting'
  | 'cancelled'
  | 'not_approved';

/** The CLI's loopback callback for `port`, which is already checked to be 1024 to 65535. */
export function loopbackCallbackUrl(port: number, params: Record<string, string>): string {
  return `http://127.0.0.1:${port}/callback?${new URLSearchParams(params).toString()}`;
}

/**
 * Tells the waiting CLI that the user did not grant access, the RFC 6749 section 4.1.2.1 error
 * response, so it stops instead of waiting for its timeout.
 */
function accessDeniedUrl(request: CliLoginRequest, description: string): string {
  return loopbackCallbackUrl(request.port, {
    error: 'access_denied',
    error_description: description,
    state: request.state,
  });
}

export function parseCliLoginRequest(search: string): CliLoginRequest | null {
  const params = new URLSearchParams(search);
  const portParam = params.get('port') ?? '';
  const state = params.get('state') ?? '';
  const challenge = params.get('challenge') ?? '';
  if (!/^\d{1,5}$/.test(portParam)) {
    return null;
  }
  const port = Number(portParam);
  if (port < MIN_LOOPBACK_PORT || port > MAX_LOOPBACK_PORT) {
    return null;
  }
  if (!state || state.length > MAX_STATE_LENGTH || !CHALLENGE_PATTERN.test(challenge)) {
    return null;
  }
  return { port, state, challenge };
}

function consentFailureMessage(status: number): string {
  if (status === 401) return 'Your session has expired. Sign in again and retry from the CLI.';
  if (status === 429) return 'Too many sign-ins are waiting. Wait a minute and try again.';
  return 'The sign-in could not be completed. Run the CLI command again.';
}

export function useCliConsent(search: string) {
  const request = useMemo(() => parseCliLoginRequest(search), [search]);
  const [status, setStatus] = useState<CliConsentStatus>('loading');
  const [username, setUsername] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!request) return;
    let active = true;
    (async () => {
      try {
        const response = await apiClient.fetch('/api/auth/check');
        const data = response.ok ? await response.json() : null;
        if (!active) return;
        if (data?.authenticated && data.username) {
          setUsername(data.username);
          setStatus('ready');
        } else {
          setError('You are not signed in. Run the CLI command again.');
          setStatus('ready');
        }
      } catch {
        if (!active) return;
        setError('Could not check your sign-in. Reload this page to try again.');
        setStatus('ready');
      }
    })();
    return () => {
      active = false;
    };
  }, [request]);

  const allow = useCallback(async () => {
    if (!request) return;
    setError(null);
    setStatus('submitting');
    try {
      const response = await apiClient.cliConsent(request);
      if (response.status === 403) {
        setStatus('not_approved');
        window.location.href = accessDeniedUrl(request, 'account not approved');
        return;
      }
      if (!response.ok) {
        setError(consentFailureMessage(response.status));
        setStatus('ready');
        return;
      }
      const { redirect_url: redirectUrl } = (await response.json()) as { redirect_url?: string };
      if (!redirectUrl || !redirectUrl.startsWith(loopbackCallbackUrl(request.port, {}))) {
        setError(consentFailureMessage(500));
        setStatus('ready');
        return;
      }
      setStatus('redirecting');
      window.location.href = redirectUrl;
    } catch {
      setError(consentFailureMessage(500));
      setStatus('ready');
    }
  }, [request]);

  const cancel = useCallback(() => {
    if (!request) return;
    setStatus('cancelled');
    window.location.href = accessDeniedUrl(request, 'cancelled by the user');
  }, [request]);

  return { request, status, username, error, allow, cancel };
}
