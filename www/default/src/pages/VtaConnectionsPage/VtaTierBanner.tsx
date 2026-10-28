import React from 'react';
import type { VtaDeploymentStatus } from './types';

interface VtaTierBannerProps {
  deployment: VtaDeploymentStatus | null;
}

/**
 * States the active signing tier, and — when the deployment does not support
 * one — says so instead of leaving the absence of a custody claim to be
 * inferred.
 *
 * The backend computes `custody_claim`; the UI never derives it. A bundled
 * sidecar shares a host, a disk and an operator with the gateway, so implying
 * the keys are held by a separate party would be the most damaging thing this
 * screen could do.
 */
export const VtaTierBanner: React.FC<VtaTierBannerProps> = ({ deployment }) => {
  if (!deployment) return null;

  if (!deployment.enabled) {
    return (
      <div className="alert alert-secondary d-flex align-items-start" role="status">
        <i className="fas fa-key me-2 mt-1" aria-hidden="true" />
        <div>
          <strong>Signing locally.</strong> This gateway signs with its own in-process key. Connect
          a Verifiable Trust Agent below to move signing to an agent instead.
        </div>
      </div>
    );
  }

  return (
    <div
      className={`alert ${deployment.custody_claim ? 'alert-info' : 'alert-warning'} d-flex align-items-start`}
      role="status"
    >
      <i
        className={`fas ${deployment.custody_claim ? 'fa-shield-halved' : 'fa-circle-info'} me-2 mt-1`}
        aria-hidden="true"
      />
      <div>
        <strong>Deployment: {deployment.tier}.</strong>{' '}
        {deployment.custody_claim ? (
          <>
            Signing keys are held by a separately-operated agent, so this deployment supports a key
            custody claim.
          </>
        ) : (
          <>
            This is <strong>not</strong> a key custody tier. The agent runs in this gateway&apos;s
            own deployment unit — same host, same disk, same operator — so the keys are not held by
            a separate party. Connect your own VTA for that.
          </>
        )}
        {deployment.reserved_origins.length > 0 && (
          <div className="small text-muted mt-1">
            Reserved as control-plane addresses and refused as proxy targets:{' '}
            <code>{deployment.reserved_origins.join(', ')}</code>
          </div>
        )}
      </div>
    </div>
  );
};
