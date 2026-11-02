import React from 'react';

interface TargetAuthProblemNoticeProps {
  testId: string;
  errors: string[];
  warnings: string[];
}

/** What blocks the save (errors) and what the gateway keeps as stored (warnings). */
const TargetAuthProblemNotice: React.FC<TargetAuthProblemNoticeProps> = ({
  testId,
  errors,
  warnings,
}) => (
  <>
    {errors.length > 0 && (
      <div className="alert alert-danger py-2 small" role="alert" data-testid={`${testId}-errors`}>
        {errors.map(message => (
          <div key={message}>{message}</div>
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
