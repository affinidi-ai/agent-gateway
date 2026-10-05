/**
 * WebAuthn Passkey Utilities
 *
 * This module provides utilities for passkey registration and authentication
 * using the WebAuthn API.
 */

import { apiClient, sessionManager } from '../api';
import { formatApiError } from './apiError';
import { TermsRequirement } from '../termsApi';

/**
 * Check if WebAuthn is supported in the current browser
 */
export function isWebAuthnSupported(): boolean {
  return !!(navigator.credentials && (window as any).PublicKeyCredential);
}

/**
 * Check if platform authenticator (biometric) is available
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false;
  }

  try {
    // Check if conditional UI is available (newer API)
    if ((window as any).PublicKeyCredential?.isConditionalMediationAvailable) {
      return await (window as any).PublicKeyCredential.isConditionalMediationAvailable();
    }

    // Fallback to platform authenticator check
    return await (
      window as any
    ).PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/**
 * Check if conditional mediation (autofill) is available
 */
export async function isConditionalMediationAvailable(): Promise<boolean> {
  if (!isWebAuthnSupported()) {
    return false;
  }

  try {
    if ((window as any).PublicKeyCredential?.isConditionalMediationAvailable) {
      return await (window as any).PublicKeyCredential.isConditionalMediationAvailable();
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Base64URL encode helper
 */
function base64urlEncode(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Base64URL decode helper
 */
function base64urlDecode(str: string): ArrayBuffer {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4;
  if (pad) {
    str += '='.repeat(4 - pad);
  }
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Register a new passkey
 */
export async function registerPasskey(
  username: string,
  acceptedTerms: TermsRequirement[] = []
): Promise<{ success: true }> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // Start registration
  const startResponse = await apiClient.fetch('/api/auth/register/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });

  if (!startResponse.ok) {
    const error = await startResponse.text();
    throw new Error(
      `Registration failed: ${formatApiError(startResponse.status, error, startResponse.statusText)}`
    );
  }

  const { challenge_id, creation_options } = await startResponse.json();

  // Convert challenge and user.id from base64url to ArrayBuffer
  const publicKeyOptions = {
    ...creation_options.publicKey,
    challenge: base64urlDecode(creation_options.publicKey.challenge),
    user: {
      ...creation_options.publicKey.user,
      id: base64urlDecode(creation_options.publicKey.user.id),
    },
  };

  // Create credential
  const credential = (await navigator.credentials.create({
    publicKey: publicKeyOptions,
  })) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Failed to create credential');
  }

  // Serialize credential for sending to server
  const credentialData = serializeCredential(credential);

  // Complete registration
  const finishResponse = await apiClient.fetch('/api/auth/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challenge_id,
      credential: credentialData,
      accepted_terms: acceptedTerms.map(term => ({
        terms_type: term.terms_type,
        version_id: term.version_id,
        accepted: true,
      })),
    }),
  });

  if (!finishResponse.ok) {
    const error = await finishResponse.text();
    throw new Error(
      `Registration completion failed: ${formatApiError(finishResponse.status, error, finishResponse.statusText)}`
    );
  }

  return { success: true };
}

/**
 * Authenticate with passkey (supports conditional mediation/autofill)
 */
export async function authenticateWithPasskey(
  username: string,
  useConditionalMediation: boolean = false
): Promise<void> {
  if (!isWebAuthnSupported()) {
    throw new Error('WebAuthn is not supported in this browser');
  }

  // Start authentication
  const startResponse = await apiClient.fetch('/api/auth/login/start', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username }),
  });

  if (!startResponse.ok) {
    const error = await startResponse.text();
    throw new Error(
      `Authentication failed: ${formatApiError(startResponse.status, error, startResponse.statusText)}`
    );
  }

  const { challenge_id, request_options } = await startResponse.json();

  // Convert challenge and allowCredentials from base64url
  const publicKeyOptions = {
    ...request_options.publicKey,
    challenge: base64urlDecode(request_options.publicKey.challenge),
    allowCredentials: request_options.publicKey.allowCredentials.map((cred: any) => ({
      ...cred,
      id: base64urlDecode(cred.id),
    })),
  };

  // Get credential with optional conditional mediation
  const getOptions: any = {
    publicKey: publicKeyOptions,
  };

  // Add conditional mediation if supported and requested
  if (useConditionalMediation) {
    getOptions.mediation = 'conditional';
  }

  const credential = (await navigator.credentials.get(getOptions)) as PublicKeyCredential;

  if (!credential) {
    throw new Error('Failed to get credential');
  }

  // Serialize credential for sending to server
  const credentialData = serializeCredential(credential);

  // Complete authentication
  const finishResponse = await apiClient.fetch('/api/auth/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      challenge_id,
      credential: credentialData,
    }),
  });

  if (!finishResponse.ok) {
    const error = await finishResponse.text();
    throw new Error(
      `Authentication completion failed: ${formatApiError(finishResponse.status, error, finishResponse.statusText)}`
    );
  }

  const { session_token } = await finishResponse.json();
  sessionManager.login(username, session_token);
}

/**
 * Start conditional authentication (autofill) - listens for passkey selection
 * This allows the browser to suggest passkeys when the user focuses on the username field
 */
export async function startConditionalAuthentication(
  // onSuccess: (sessionToken: string) => void,
  onSuccess: () => void,
  onError: (error: Error) => void
): Promise<AbortController | null> {
  if (!isWebAuthnSupported()) {
    return null;
  }

  // Check if conditional mediation is available
  const conditionalAvailable = await isConditionalMediationAvailable();
  if (!conditionalAvailable) {
    return null;
  }

  const abortController = new AbortController();

  try {
    // Get credential with conditional mediation (no username required)
    // This will wait for the user to select a passkey from the browser's autofill UI
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: new Uint8Array(32), // Dummy challenge for conditional UI
        timeout: 60000,
        userVerification: 'preferred',
      } as any,
      mediation: 'conditional' as any,
      signal: abortController.signal,
    })) as PublicKeyCredential;

    if (!credential) {
      return abortController;
    }

    // Extract username from credential to start proper authentication
    // Note: In a real implementation, you'd need to map credential ID to username
    // For now, we'll use the credential response to complete authentication

    // Serialize credential
    serializeCredential(credential);

    // We need to get the username from the credential
    // This is a simplified version - in production you'd store username mapping
    const response = credential.response as AuthenticatorAssertionResponse;
    const userHandle = response.userHandle;

    if (!userHandle) {
      throw new Error('No user handle in credential');
    }

    // Decode username from userHandle
    const username = new TextDecoder().decode(userHandle);

    // Now do the full authentication flow
    await authenticateWithPasskey(username, false);
    onSuccess();
  } catch (error) {
    if ((error as any).name !== 'AbortError') {
      onError(error as Error);
    }
  }

  return abortController;
}

/**
 * Serialize PublicKeyCredential for sending to server
 */
function serializeCredential(credential: PublicKeyCredential): any {
  const response = credential.response as
    | AuthenticatorAttestationResponse
    | AuthenticatorAssertionResponse;

  const baseCredential = {
    id: credential.id,
    rawId: base64urlEncode(credential.rawId),
    type: credential.type,
  };

  if (response instanceof AuthenticatorAttestationResponse) {
    // Registration response
    return {
      ...baseCredential,
      response: {
        attestationObject: base64urlEncode(response.attestationObject),
        clientDataJSON: base64urlEncode(response.clientDataJSON),
      },
    };
  } else {
    // Authentication response
    const assertionResponse = response as AuthenticatorAssertionResponse;
    return {
      ...baseCredential,
      response: {
        authenticatorData: base64urlEncode(assertionResponse.authenticatorData),
        clientDataJSON: base64urlEncode(assertionResponse.clientDataJSON),
        signature: base64urlEncode(assertionResponse.signature),
        userHandle: assertionResponse.userHandle
          ? base64urlEncode(assertionResponse.userHandle)
          : null,
      },
    };
  }
}
