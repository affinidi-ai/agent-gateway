import React from 'react';
import { AppButton } from '../../components/shared/AppButton';
import { CopyButton } from '../../components/shared/CopyButton';
import { isOverPrivileged, isPayloadExpired } from './vtaConnectionHelpers';
import type { PairingPayload, VtaConnection } from './types';

interface PairStepProps {
  payload: PairingPayload | null;
  error: string | null;
  onReissue: () => void;
}

export const PairStep: React.FC<PairStepProps> = ({ payload, error, onReissue }) => {
  if (error) {
    return (
      <div className="alert alert-danger" role="alert">
        <i className="fas fa-triangle-exclamation me-2" aria-hidden="true" />
        {error}
      </div>
    );
  }
  if (!payload) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border text-primary" role="status" />
      </div>
    );
  }

  const expired = isPayloadExpired(payload.expires_at);
  return (
    <div>
      <p>
        Run this once on your own VTA. It grants this gateway the{' '}
        <strong>{payload.requested_role}</strong> role in{' '}
        <strong>{payload.context_id ?? 'one context'}</strong> — enough to sign, and nothing else.
        It does <strong>not</strong> grant administration.
      </p>
      <div className="d-flex align-items-start gap-2 mb-3">
        <pre className="flex-grow-1 mb-0 p-3 bg-light rounded small">
          <code>{payload.grant_command}</code>
        </pre>
        <CopyButton text={payload.grant_command} label="Copy" />
      </div>
      <dl className="row small mb-3">
        <dt className="col-sm-4">This gateway&apos;s identity</dt>
        <dd className="col-sm-8">
          <code>{payload.control_did}</code>
        </dd>
        <dt className="col-sm-4">Your agent</dt>
        <dd className="col-sm-8">
          <code>{payload.vta_did}</code>
        </dd>
      </dl>
      {/* An expired payload offers a re-issue, never a dead end. */}
      {expired ? (
        <div className="alert alert-warning d-flex justify-content-between align-items-center">
          <span>This pairing request has expired.</span>
          <AppButton variant="outline-primary" size="sm" onClick={onReissue}>
            Issue a new one
          </AppButton>
        </div>
      ) : (
        <p className="small text-muted mb-0">
          This request is short-lived. If it expires before you finish, issue a new one.
        </p>
      )}
    </div>
  );
};

interface VerifyStepProps {
  checking: boolean;
  error: string | null;
  connection: VtaConnection | null;
  onRetry: () => void;
}

export const VerifyStep: React.FC<VerifyStepProps> = ({ checking, error, connection, onRetry }) => {
  if (checking) {
    return (
      <div className="text-center py-4">
        <div className="spinner-border text-primary mb-3" role="status" />
        <p className="text-muted mb-0">
          Authenticating, checking the grant is sign-only, and pinning the agent&apos;s identity…
        </p>
      </div>
    );
  }
  if (error) {
    return (
      <div>
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-triangle-exclamation me-2" aria-hidden="true" />
          {error}
        </div>
        {connection && isOverPrivileged(connection.pairing) && (
          <div className="alert alert-warning" role="alert">
            <strong>The grant is broader than it needs to be.</strong> This gateway was granted{' '}
            <code>{connection.pairing.granted_role}</code>
            {(connection.pairing.granted_contexts ?? []).length !== 1 && (
              <> across {(connection.pairing.granted_contexts ?? []).length} contexts</>
            )}
            . Re-grant with a sign-only role in exactly one context, then verify again.
          </div>
        )}
        <AppButton variant="primary" onClick={onRetry}>
          Verify again
        </AppButton>
      </div>
    );
  }
  return (
    <p className="text-muted mb-0">
      Once you have run the grant command, verify to complete the connection.
    </p>
  );
};
