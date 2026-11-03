import React from 'react';

interface TargetAuthProblemNoticeProps {
  testId: string;
  errors: string[];
  warnings: string[];
  advisories?: string[];
}

/**
 * What blocks the save (errors), what the gateway keeps as stored (warnings) and what the
 * gateway saves with a warning unless its rule is `enforce` (advisories).
 */
const TargetAuthProblemNotice: React.FC<TargetAuthProblemNoticeProps> = ({
  testId,
  errors,
  warnings,
  advisories = [],
}) => (
  <>
    {errors.length > 0 && (
      <div className="alert alert-danger py-2 small" role="alert" data-testid={`${testId}-errors`}>
        {errors.map(message => (
          <div key={message}>{message}</div>
        ))}
      </div>
    )}
    {advisories.length > 0 && (
      <div
        className="alert alert-warning py-2 small"
        role="status"
        data-testid={`${testId}-advisories`}
      >
        {advisories.map(message => (
          <div key={message}>
            {message}. Save is allowed: the gateway saves it with a warning, and refuses it only
            while its rule is set to enforce.
          </div>
        ))}
      </div>
    )}
    {warnings.length > 0 && (
      <div
        className="alert alert-warning py-2 small"
        role="status"
        data-testid={`${testId}-warnings`}
      >
        {warnings.map(message => (
          <div key={message}>{message}. The gateway keeps it as stored until you change it.</div>
        ))}
      </div>
    )}
  </>
);

export default TargetAuthProblemNotice;
