import React from 'react';
import { useOptionalSurfaceMeta } from '../../SurfaceMetaContext';
import {
  ACCESS_POINT_NOT_READY_TEXT,
  ACCESS_POINT_SAVE_TO_ACTIVATE_TEXT,
  CONFIGURE_AUTHENTICATION_LABEL,
} from './readiness';

interface AccessPointReadinessNoticeProps {
  /** `data-testid` of the notice; its button gets `<testId>-configure-authentication-button`. */
  testId: string;
}

/**
 * Shown under the Access Point URL while the Access Point is not ready for
 * external access. Reads the notice and the "Configure Authentication" action
 * from `SurfaceMetaContext`; renders nothing while the Access Point is ready.
 */
const AccessPointReadinessNotice: React.FC<AccessPointReadinessNoticeProps> = ({ testId }) => {
  const meta = useOptionalSurfaceMeta();
  const notice = meta?.accessPointNotice;
  if (!notice) return null;
  const showAction = notice === 'not_ready' && !!meta?.onConfigureAuthentication && !meta?.readOnly;
  return (
    <div className="access-point-readiness" role="status" data-testid={testId}>
      <span className="access-point-readiness__text">
        <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
        {notice === 'not_ready' ? ACCESS_POINT_NOT_READY_TEXT : ACCESS_POINT_SAVE_TO_ACTIVATE_TEXT}
      </span>
      {showAction && (
        <button
          type="button"
          className="btn btn-sm access-point-readiness__action"
          data-testid={`${testId}-configure-authentication-button`}
          onClick={meta?.onConfigureAuthentication}
        >
          {CONFIGURE_AUTHENTICATION_LABEL}
        </button>
      )}
    </div>
  );
};

export default AccessPointReadinessNotice;
