import React from 'react';

interface TargetAuthProblemNoticeProps {
  testId: string;
  errors: string[];
  advisories?: string[];
  notes?: string[];
}

/** The id of the notice's error list, for the `aria-describedby` of the inputs it is about. */
export const targetAuthErrorsId = (testId: string) => `${testId}-errors`;

/**
 * What blocks the save (errors), what the gateway saves with a warning unless its rule is
 * `enforce` (advisories) and advice with no rule behind it (notes). Each kind opens with its
 * name, so colour is not the only thing that tells them apart, and sits in a live region that
 * stays mounted, so a message that appears is announced.
 */
const TargetAuthProblemNotice: React.FC<TargetAuthProblemNoticeProps> = ({
  testId,
  errors,
  advisories = [],
  notes = [],
}) => (
  <>
    <div role="alert">
      {errors.length > 0 && (
        <div
          className="alert alert-danger py-2 small"
          id={targetAuthErrorsId(testId)}
          data-testid={`${testId}-errors`}
        >
          {errors.map(message => (
            <div key={message}>
              <strong>Error:</strong> {message}
            </div>
          ))}
        </div>
      )}
    </div>
    <div role="status">
      {advisories.length + notes.length > 0 && (
        <div className="alert alert-warning py-2 small" data-testid={`${testId}-advisories`}>
          {advisories.map(message => (
            <div key={message}>
              <strong>Advisory:</strong> {message}. Save is allowed: the gateway saves it with a
              warning, and refuses it only while its rule is set to enforce.
            </div>
          ))}
          {notes.map(message => (
            <div key={message}>
              <strong>Advisory:</strong> {message}. Save is allowed.
            </div>
          ))}
        </div>
      )}
    </div>
  </>
);

export default TargetAuthProblemNotice;
