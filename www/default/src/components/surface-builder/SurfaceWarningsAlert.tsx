import React from 'react';
import { CopyButton } from '../shared/CopyButton';
import { DENY_FAILED_CALLERS_REGO } from '../../utils/denyRule';
import { FAIL_OPEN_WARNING_CODES, type SurfaceWarning } from '../../utils/surfaceDeclarations';

interface SurfaceWarningsAlertProps {
  warnings: SurfaceWarning[];
}

const SurfaceWarningsAlert: React.FC<SurfaceWarningsAlertProps> = ({ warnings }) => {
  const failsOpen = warnings.some(w => FAIL_OPEN_WARNING_CODES.includes(w.code));

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
                Add it to this surface&apos;s policy to deny callers whose authentication failed.
              </small>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default SurfaceWarningsAlert;
