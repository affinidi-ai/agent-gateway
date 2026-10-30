import React from 'react';
import { CopyButton } from '../shared/CopyButton';
import {
  DENY_FAILED_CALLERS_CONDITION,
  DENY_FAILED_CALLERS_REGO,
  GATEWAY_DENY_FAILED_CALLERS_REGO,
} from '../../utils/denyRule';
import {
  FAIL_OPEN_WARNING_CODES,
  GATEWAY_DENY_WARNING_CODES,
  type SurfaceWarning,
} from '../../utils/surfaceDeclarations';

interface SurfaceWarningsAlertProps {
  warnings: SurfaceWarning[];
  offersDiscovery?: boolean;
}

const SurfaceWarningsAlert: React.FC<SurfaceWarningsAlertProps> = ({
  warnings,
  offersDiscovery = false,
}) => {
  const failsOpen = warnings.some(w => FAIL_OPEN_WARNING_CODES.includes(w.code));
  const needsGatewayDeny = warnings.some(w => GATEWAY_DENY_WARNING_CODES.includes(w.code));

  return (
    <div aria-live="polite" data-testid="surface-warnings-live">
      {warnings.length > 0 && (
        <div
          className="alert alert-warning surface-page-alert mb-2"
          role="region"
          aria-label="Surface warnings"
          data-testid="surface-warnings-alert"
        >
          <div className="fw-bold mb-1">
            <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
            {warnings.length === 1 ? '1 warning' : `${warnings.length} warnings`}
          </div>
          <ul className="mb-0 ps-3">
            {warnings.map((w, i) => (
              <li
                key={`${w.code}-${w.variant ?? 'base'}-${i}`}
                data-testid={`surface-warning-${w.code}`}
              >
                {w.message}
                {w.variant && <span className="text-muted"> (variant {w.variant})</span>}
              </li>
            ))}
          </ul>
          {failsOpen && (
            <div className="mt-2">
              <CopyButton
                text={DENY_FAILED_CALLERS_REGO}
                variant="outline-primary"
                label="Copy deny rule"
                data-testid="surface-warnings-copy-rule"
              />
              <small className="text-muted ms-2" data-testid="surface-warnings-copy-rule-hint">
                If the Managed Agent has no policy, save this as a policy definition and attach it
                to the Managed Agent (target.policy), so callers arriving over Fabric are denied
                too. If it already has a policy, do not paste this whole policy: add{' '}
                <code>{DENY_FAILED_CALLERS_CONDITION}</code> to each of its allow rules.
              </small>
              {offersDiscovery && (
                <p className="mt-2 mb-0 small" data-testid="surface-warnings-discovery-hint">
                  Or turn on <strong>Authorization server discovery</strong> in the Caller Context
                  editor: the gateway then refuses a caller without a valid token itself, before any
                  policy runs, for direct and Fabric callers alike.
                </p>
              )}
            </div>
          )}
          {needsGatewayDeny && (
            <div className="mt-2">
              <CopyButton
                text={GATEWAY_DENY_FAILED_CALLERS_REGO}
                variant="outline-primary"
                label="Copy gateway deny rule"
                data-testid="surface-warnings-copy-gateway-rule"
              />
              <small
                className="text-muted ms-2"
                data-testid="surface-warnings-copy-gateway-rule-hint"
              >
                Payment runs before surface policy, so deny failed callers in the gateway policy. If
                the gateway has no policy, save this as a policy definition and select it as the
                gateway policy. If it already has one, do not paste this whole policy: add{' '}
                <code>{DENY_FAILED_CALLERS_CONDITION}</code> to each of its allow rules.
              </small>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SurfaceWarningsAlert;
