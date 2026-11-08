import React from 'react';
import { Form } from 'react-bootstrap';

const PatternAdvice: React.FC<{ testId: string; text: string }> = ({ testId, text }) => (
  <Form.Text className="text-warning d-block mb-2" data-testid={testId}>
    <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
    {text}
  </Form.Text>
);

interface PatternListProps {
  patterns: string[];
  onChange: (patterns: string[]) => void;
  placeholder: string;
  icon: string;
  testIdPrefix: string;
  /** What a row is called: a regular expression or plain text. */
  label: 'Pattern' | 'Text';
  /** The browser's doubt about a row, shown as a warning; it never blocks Save. */
  advise?: (value: string) => string | null;
  /** The last row can be removed too, leaving the list empty. */
  allowEmpty?: boolean;
}

export const PatternList: React.FC<PatternListProps> = ({
  patterns,
  onChange,
  placeholder,
  icon,
  testIdPrefix,
  label,
  advise,
  allowEmpty = false,
}) => {
  const rows = patterns.length === 0 ? [''] : patterns;
  return (
    <>
      {rows.map((pattern, idx) => {
        const advice = advise && pattern.trim() !== '' ? advise(pattern) : null;
        return (
          <React.Fragment key={idx}>
            <div className="input-group input-group-sm mb-2">
              <span className="input-group-text">
                <i className={`fas ${icon}`} aria-hidden="true" />
              </span>
              <input
                type="text"
                className={`form-control${label === 'Pattern' ? ' font-monospace' : ''}`}
                value={pattern}
                aria-label={`${label} ${idx + 1}`}
                data-testid={`${testIdPrefix}-pattern-${idx}`}
                onChange={e => {
                  const next = [...rows];
                  next[idx] = e.target.value;
                  onChange(next);
                }}
                placeholder={placeholder}
              />
              {(allowEmpty || rows.length > 1) && (
                <button
                  className="btn btn-outline-danger"
                  type="button"
                  aria-label={`Remove ${label.toLowerCase()}`}
                  data-testid={`${testIdPrefix}-remove-pattern-button-${idx}`}
                  onClick={() => onChange(rows.filter((_, i) => i !== idx))}
                >
                  <i className="fas fa-times" aria-hidden="true" />
                </button>
              )}
            </div>
            {advice && (
              <PatternAdvice testId={`${testIdPrefix}-pattern-warning-${idx}`} text={advice} />
            )}
          </React.Fragment>
        );
      })}
      <button
        className="btn btn-sm btn-outline-secondary"
        type="button"
        data-testid={`${testIdPrefix}-add-pattern-button`}
        onClick={() => onChange([...rows, ''])}
      >
        <i className="fas fa-plus me-1" aria-hidden="true" />
        Add {label}
      </button>
    </>
  );
};
