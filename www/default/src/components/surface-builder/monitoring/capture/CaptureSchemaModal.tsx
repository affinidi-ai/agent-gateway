import React from 'react';
import { extractAgentIdentitySchema } from '../../../../utils/schemaUtils';

interface CaptureSchemaModalProps {
  title: string;
  schema: string;
  sourcePayload: any;
  identityFieldName: string;
  protocol?: 'a2a' | 'ap2' | 'mcp';
  onClose: () => void;
}

const CaptureSchemaModal: React.FC<CaptureSchemaModalProps> = ({
  title,
  schema,
  sourcePayload,
  identityFieldName,
  protocol,
  onClose,
}) => {
  const copyAll = async () => {
    try {
      await navigator.clipboard.writeText(schema);
    } catch (e) {
      console.error('Failed to copy to clipboard:', e);
    }
  };
  const copyIdentity = async () => {
    try {
      const text = extractAgentIdentitySchema(sourcePayload, identityFieldName, protocol as any);
      await navigator.clipboard.writeText(text);
    } catch (e) {
      console.error('Failed to copy to clipboard:', e);
    }
  };
  return (
    <>
      <div className="modal fade show modal-show modal-z-high" tabIndex={-1}>
        <div className="modal-dialog modal-lg modal-dialog-scrollable">
          <div className="modal-content modal-content-flex">
            <div className="modal-header">
              <h5 className="modal-title">
                <i className="fas fa-file-code"></i> {title}
              </h5>
              <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
            </div>
            <div className="modal-body modal-body-flex">
              <p className="text-muted mb-3">
                This JSON schema was automatically derived from the payload structure. You can use
                it for validation or documentation purposes.
              </p>
              <label className="form-label fw-bold mb-2">
                <i className="fas fa-code"></i> Generated JSON Schema
              </label>
              <div className="schema-property-card border-primary d-flex flex-column modal-json-card">
                <textarea
                  className="form-control schema-raw-json payload-textarea modal-json-textarea"
                  style={{
                    minHeight: '500px',
                    resize: 'vertical',
                    fontFamily: 'monospace',
                    fontSize: '12px',
                  }}
                  value={schema}
                  readOnly
                />
              </div>
            </div>
            <div className="modal-footer">
              <button
                className="btn btn-outline-primary me-2"
                onClick={copyIdentity}
                title={`Copy only the ${identityFieldName} schema in surface configuration format`}
              >
                <i className="fas fa-user-tag"></i> Copy {identityFieldName} Schema to Clipboard
              </button>
              <button className="btn btn-outline-secondary me-2" onClick={copyAll}>
                <i className="fas fa-copy"></i> Copy All to Clipboard
              </button>
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
      <div className="modal-backdrop fade show modal-backdrop-z"></div>
    </>
  );
};

export default CaptureSchemaModal;
