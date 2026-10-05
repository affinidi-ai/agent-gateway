import React from 'react';
import FieldHelp from './shared/FieldHelp';

interface TestNotifierModalProps {
  show: boolean;
  integrationName: string;
  variables: Record<string, string>;
  isTesting: boolean;
  testResult?: {
    message: string;
    isSuccess: boolean;
  } | null;
  onVariableChange: (varName: string, value: string) => void;
  onCancel: () => void;
  onTest: () => void;
}

/**
 * Shared modal component for testing integrations with template variables
 * Used by both IntegrationsPage and EditIntegrationPage for consistency
 */
const TestNotifierModal: React.FC<TestNotifierModalProps> = ({
  show,
  integrationName,
  variables,
  isTesting,
  testResult,
  onVariableChange,
  onCancel,
  onTest,
}) => {
  if (!show) return null;

  return (
    <>
      <div className="modal fade show" style={{ display: 'block' }} tabIndex={-1}>
        <div
          className="modal-dialog modal-lg modal-dialog-centered"
          style={{ maxHeight: '70vh', display: 'flex', alignItems: 'center' }}
        >
          <div
            className="modal-content"
            style={{ maxHeight: '70vh', display: 'flex', flexDirection: 'column' }}
          >
            <div className="modal-header" style={{ flexShrink: 0 }}>
              <h5 className="modal-title">
                <i className="fas fa-vial me-2"></i>
                Test {integrationName}{' '}
                <FieldHelp testId="field-help-test-notifier" ariaLabel="About the Test action">
                  This sends a real notification using the values below, it isn't a preview.
                </FieldHelp>
              </h5>
              <button type="button" className="btn-close" onClick={onCancel} aria-label="Close" />
            </div>
            <div className="modal-body" style={{ overflowY: 'auto', flex: '1 1 auto' }}>
              {Object.keys(variables).length > 0 ? (
                <>
                  <div className="alert alert-info mb-3" role="alert">
                    <i className="fas fa-info-circle me-2"></i>
                    Your integration template uses variables - you can customise their values here
                  </div>
                  {Object.keys(variables).map(varName => (
                    <div className="mb-3" key={varName}>
                      <label className="form-label" htmlFor={`test-var-${varName}`}>
                        <code className="text-primary">${'{' + varName + '}'}</code>
                      </label>
                      <input
                        type="text"
                        id={`test-var-${varName}`}
                        className="form-control font-monospace"
                        value={variables[varName]}
                        onChange={e => onVariableChange(varName, e.target.value)}
                        placeholder={`Value for ${varName}`}
                        disabled={isTesting}
                      />
                    </div>
                  ))}
                </>
              ) : (
                <>
                  <div className="alert alert-success mb-3" role="alert">
                    <i className="fas fa-check-circle me-2"></i>
                    There are no variables in this integration - it is ready to test
                  </div>
                </>
              )}
            </div>
            <div className="modal-footer d-flex align-items-center" style={{ flexShrink: 0 }}>
              {testResult && (
                <div
                  className={`small ${testResult.isSuccess ? 'text-success' : 'text-danger'}`}
                  style={{
                    maxWidth: '50%',
                    overflow: 'hidden',
                    wordWrap: 'break-word',
                    flex: '0 1 auto',
                  }}
                >
                  <i
                    className={`fas ${testResult.isSuccess ? 'fa-check-circle' : 'fa-exclamation-circle'} me-1`}
                  ></i>
                  {testResult.message}
                </div>
              )}
              <div className="ms-auto d-flex" style={{ gap: '0.5rem' }}>
                <button type="button" className="btn btn-sm btn-secondary" onClick={onCancel}>
                  Close
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-primary"
                  onClick={onTest}
                  disabled={isTesting}
                >
                  {isTesting ? (
                    <>
                      <i className="fas fa-spinner fa-spin me-2"></i>
                      Sending...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-paper-plane me-2"></i>
                      Send Test
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div className="modal-backdrop fade show"></div>
    </>
  );
};

export default TestNotifierModal;
