import React, { useState } from 'react';

interface Props {
  /** Every warning the last save answered with. A new array on each save. */
  warnings: readonly string[] | null | undefined;
}

/**
 * Lists every warning the last save drew until the operator dismisses it or
 * the next save replaces it. The toast that follows a save disappears, and
 * only the Transit Point a warning names shows it in its panel.
 */
const SaveWarningsBanner: React.FC<Props> = ({ warnings }) => {
  const [dismissedFor, setDismissedFor] = useState<readonly string[] | null>(null);
  if (!warnings || warnings.length === 0 || dismissedFor === warnings) return null;
  return (
    <div
      className="alert alert-warning surface-page-alert mb-2"
      role="status"
      data-testid="surface-save-warnings"
    >
      <button
        type="button"
        className="btn-close float-end"
        aria-label="Dismiss warnings"
        onClick={() => setDismissedFor(warnings)}
      />
      <strong>The last save drew {warnings.length === 1 ? 'a warning' : 'warnings'}</strong>
      <ul className="mb-0">
        {warnings.map(w => (
          <li key={w}>{w}</li>
        ))}
      </ul>
    </div>
  );
};

export default SaveWarningsBanner;
