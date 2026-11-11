import React, { useCallback, useState } from 'react';
import { apiClient } from '../../api';
import { AppButton } from '../../components/shared/AppButton';
import { CopyButton } from '../../components/shared/CopyButton';
import { showToast } from '../../utils/toaster';
import type { VtaControlKeyStatus } from './types';

interface ControlKeyCardProps {
  controlKey: VtaControlKeyStatus;
  /** Whether the user may edit key management. */
  canRotate: boolean;
  /** Called after a rotation, so the page reads the new status. */
  onRotated: () => void | Promise<void>;
}

const ROTATE_URL = '/api/v1/vta/control-key/rotate';

function shortDid(did: string): string {
  return did.length > 34 ? `${did.slice(0, 22)}…${did.slice(-8)}` : did;
}

function when(iso: string): string {
  return new Date(iso).toLocaleString();
}

async function refusal(response: Response): Promise<string> {
  if (response.status === 429) {
    const seconds = Number(response.headers.get('retry-after'));
    if (Number.isFinite(seconds) && seconds > 0) {
      const minutes = Math.max(1, Math.ceil(seconds / 60));
      return `Try again in ${minutes} ${minutes === 1 ? 'minute' : 'minutes'}.`;
    }
  }
  try {
    const body = await response.json();
    if (body && typeof body.error === 'string') return body.error;
  } catch {
    // A body that is not JSON says nothing an operator can act on.
  }
  return response.statusText || 'The control key could not be rotated.';
}

/**
 * The key the gateway signs in to its trust agent with: which it is, when it
 * last rotated, when it rotates next, and a way to rotate it now.
 * Rotation moves only this key; signing keys and issuer DIDs stay as they are.
 */
export const ControlKeyCard: React.FC<ControlKeyCardProps> = ({
  controlKey,
  canRotate,
  onRotated,
}) => {
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);

  const rotate = useCallback(async () => {
    setBusy(true);
    try {
      const response = await apiClient.fetch(ROTATE_URL, { method: 'POST' });
      if (!response.ok) {
        showToast('error', await refusal(response));
        return;
      }
      const body = await response.json();
      showToast(
        'success',
        `Control key rotated. The gateway now uses ${shortDid(body.control_did)}.`
      );
      setConfirming(false);
      await onRotated();
    } catch (e) {
      showToast('error', e instanceof Error ? e.message : 'The control key could not be rotated.');
    } finally {
      setBusy(false);
    }
  }, [onRotated]);

  return (
    <div className="card shadow mb-4" data-testid="vta-control-key">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-key me-2" aria-hidden="true" />
          Control key
        </h6>
      </div>
      <div className="card-body">
        <p className="small text-muted mb-3">
          The key this gateway signs in to its trust agent with. It is not a signing key: rotating
          it changes nothing about the keys that sign credentials.
        </p>
        <div className="d-flex align-items-center mb-2">
          <code title={controlKey.control_did} data-testid="vta-control-key-did">
            {shortDid(controlKey.control_did)}
          </code>
          <CopyButton text={controlKey.control_did} title="Copy the DID" />
        </div>
        <div className="small mb-1" data-testid="vta-control-key-rotated-at">
          {controlKey.rotated_at ? `Rotated ${when(controlKey.rotated_at)}` : 'Never rotated'}
        </div>
        <div className="small mb-3" data-testid="vta-control-key-next">
          {controlKey.rotation_days === 0
            ? 'Automatic rotation is off'
            : controlKey.next_rotation_at
              ? `Next automatic rotation ${when(controlKey.next_rotation_at)}`
              : `Rotates automatically every ${controlKey.rotation_days} days`}
        </div>

        {canRotate && !confirming && (
          <AppButton
            variant="outline-primary"
            onClick={() => setConfirming(true)}
            data-testid="vta-control-key-rotate"
          >
            Rotate control key
          </AppButton>
        )}

        {canRotate && confirming && (
          <div className="alert alert-warning mb-0" role="alertdialog">
            <p className="mb-2" data-testid="vta-control-key-confirm-text">
              The gateway moves its access on the trust agent to a new key. Signing keys and issuer
              DIDs do not change, and requests in flight keep working.
            </p>
            <AppButton
              variant="primary"
              className="me-2"
              loading={busy}
              loadingLabel="Rotating…"
              onClick={() => void rotate()}
              data-testid="vta-control-key-confirm"
            >
              Rotate now
            </AppButton>
            <AppButton
              variant="outline-secondary"
              disabled={busy}
              onClick={() => setConfirming(false)}
              data-testid="vta-control-key-cancel"
            >
              Cancel
            </AppButton>
          </div>
        )}
      </div>
    </div>
  );
};
