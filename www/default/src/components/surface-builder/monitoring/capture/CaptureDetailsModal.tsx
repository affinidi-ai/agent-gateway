import React from 'react';
import { formatDateTime } from '../../../../utils/stringUtils';
import { CapturedPayload } from './types';

interface CaptureDetailsModalProps {
  capture: CapturedPayload;
  onClose: () => void;
}

const statusBadgeClass = (status: string) =>
  status === 'success'
    ? 'text-bg-success'
    : status === 'method_not_allowed' || status === 'mcp_error'
      ? 'text-bg-warning'
      : 'text-bg-danger';

const statusLabel = (status: string) => {
  if (status === 'success') return { icon: 'fa-check-circle', text: 'Success' };
  if (status === 'method_not_allowed')
    return { icon: 'fa-exclamation-triangle', text: 'Method Not Allowed' };
  if (status === 'mcp_error') return { icon: 'fa-exclamation-circle', text: 'MCP Error' };
  return { icon: 'fa-exclamation-triangle', text: 'Failed Validation' };
};

const CaptureDetailsModal: React.FC<CaptureDetailsModalProps> = ({ capture, onClose }) => {
  const label = statusLabel(capture.validation_status);
  const handleCopy = async () => {
    try {
      const text = capture.response_payload
        ? `Request:\n${JSON.stringify(capture.payload, null, 2)}\n\nResponse:\n${JSON.stringify(capture.response_payload, null, 2)}`
        : JSON.stringify(capture.payload, null, 2);
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
                <i className="fas fa-eye"></i> Captured Payload Details
              </h5>
              <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
            </div>
            <div className="modal-body modal-body-flex">
              <div className="row mb-3">
                <div className="col-md-4">
                  <strong>Channel:</strong>
                  <span className="badge text-bg-secondary ms-2">{capture.channel}</span>
                </div>
                <div className="col-md-8">
                  <strong>Timestamp:</strong> {formatDateTime(capture.timestamp, true)}
                </div>
              </div>
              <div className="row mb-3">
                <div className="col-md-12">
                  <strong>Validation Status:</strong>
                  <span className={`badge ms-2 ${statusBadgeClass(capture.validation_status)}`}>
                    <i className={`fas ${label.icon}`}></i> {label.text}
                  </span>
                </div>
              </div>
              {capture.validation_error && (
                <div className="mb-3">
                  <label className="form-label fw-bold text-danger">
                    <i className="fas fa-exclamation-circle"></i> Validation Error Details
                  </label>
                  <div className="alert alert-danger">
                    <small className="font-monospace">{capture.validation_error}</small>
                  </div>
                </div>
              )}
              <div className="modal-json-container">
                <div className="row">
                  <div className={capture.response_payload ? 'col-md-6' : 'col-md-12'}>
                    <label className="form-label fw-bold mb-2">
                      <i className="fas fa-arrow-right text-primary"></i> Request Payload JSON
                    </label>
                    <div className="schema-property-card border-info d-flex flex-column modal-json-card">
                      <textarea
                        className="form-control schema-raw-json payload-textarea modal-json-textarea"
                        value={JSON.stringify(capture.payload, null, 2)}
                        readOnly
                      />
                    </div>
                  </div>
                  {capture.response_payload && (
                    <div className="col-md-6">
                      <label className="form-label fw-bold mb-2">
                        <i className="fas fa-arrow-left text-success"></i> Response Payload JSON
                      </label>
                      <div className="schema-property-card border-success d-flex flex-column modal-json-card">
                        <textarea
                          className="form-control schema-raw-json payload-textarea modal-json-textarea"
                          value={JSON.stringify(capture.response_payload, null, 2)}
                          readOnly
                        />
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button className="btn btn-outline-secondary me-2" onClick={handleCopy}>
                <i className="fas fa-copy"></i> Copy to Clipboard
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

export default CaptureDetailsModal;
