import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { formatDateTime } from '../utils/stringUtils';
import { apiClient } from '../api';

interface IdentityDetailsModalProps {
  identity: any;
  onClose: () => void;
}

const IdentityDetailsModal: React.FC<IdentityDetailsModalProps> = ({ identity, onClose }) => {
  const navigate = useNavigate();
  const [didDocumentContent, setDidDocumentContent] = useState<any>(null);
  const [loadingDidDocument, setLoadingDidDocument] = useState(false);

  // Load DID document for identity
  const loadDidDocumentForIdentity = async (did: string) => {
    setLoadingDidDocument(true);
    try {
      const response = await apiClient.fetch(
        `/api/v1/identity/resolve-did?did=${encodeURIComponent(did)}`
      );
      if (!response.ok) {
        throw new Error(`Failed to fetch DID document: ${response.status}`);
      }
      const didDoc = await response.json();
      setDidDocumentContent(didDoc);
    } catch (error) {
      console.error('Error loading DID document:', error);
      setDidDocumentContent({ error: 'Failed to load DID document' });
    } finally {
      setLoadingDidDocument(false);
    }
  };

  // Initialize Bootstrap collapse when modal opens
  useEffect(() => {
    // Setup event listener for DID document accordion using jQuery
    const $ = (window as any).$;
    if ($) {
      $('#collapseDidDocument').on('show.bs.collapse', function () {
        if (!didDocumentContent && !loadingDidDocument) {
          loadDidDocumentForIdentity(identity.did);
        }
      });

      return () => {
        $('#collapseDidDocument').off('show.bs.collapse');
      };
    }
  }, [identity.did, didDocumentContent, loadingDidDocument]);

  return (
    <>
      <div className="modal fade show" style={{ display: 'block' }} tabIndex={-1}>
        <div className="modal-dialog modal-lg">
          <div className="modal-content">
            <div className="modal-header">
              <h5 className="modal-title">
                <i className="fas fa-fingerprint"></i> Agent Identity Details
              </h5>
              <button type="button" className="btn-close" onClick={onClose} aria-label="Close" />
            </div>
            <div className="modal-body p-0">
              <div className="accordion" id="identityAccordion">
                {/* Basic Information */}
                <div className="card">
                  <div className="card-header" id="headingBasicInfo">
                    <h2 className="mb-0">
                      <button
                        className="btn btn-link w-100 text-start"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#collapseBasicInfo"
                        aria-expanded="true"
                        aria-controls="collapseBasicInfo"
                      >
                        <i className="fas fa-info-circle"></i> Summary
                      </button>
                    </h2>
                  </div>
                  <div
                    id="collapseBasicInfo"
                    className="collapse show"
                    aria-labelledby="headingBasicInfo"
                    data-parent="#identityAccordion"
                  >
                    <div className="card-body">
                      <div className="detail-row mb-2">
                        <span className="detail-label font-weight-bold">DID:</span>
                        <span className="detail-value ms-2">
                          <code>{identity.did}</code>
                        </span>
                      </div>
                      <div className="detail-row mb-2">
                        <span className="detail-label font-weight-bold">Identity Hash:</span>
                        <span className="detail-value ms-2">{identity.identity_hash}</span>
                      </div>
                      {identity.channel_name && identity.channel_config_id && (
                        <div className="detail-row mb-2">
                          <span className="detail-label font-weight-bold">Surface:</span>
                          <span className="detail-value ms-2">
                            <a
                              href={`#/surfaces/${identity.channel_config_id}`}
                              onClick={e => {
                                e.preventDefault();
                                onClose();
                                navigate(`/surfaces/${identity.channel_config_id}`);
                              }}
                              className="text-primary"
                            >
                              {identity.channel_name}
                            </a>
                          </span>
                        </div>
                      )}
                      <div className="detail-row mb-2">
                        <span className="detail-label font-weight-bold">Created:</span>
                        <span className="detail-value ms-2">
                          {identity.created_at
                            ? formatDateTime(identity.created_at, true)
                            : 'Never'}
                        </span>
                      </div>
                      <div className="detail-row mb-2">
                        <span className="detail-label font-weight-bold">Usage Count:</span>
                        <span className="detail-value ms-2">
                          <strong>{identity.usage_count || identity.use_count || 0}</strong>{' '}
                          {(identity.usage_count || identity.use_count || 0) === 1
                            ? 'time'
                            : 'times'}
                        </span>
                      </div>
                      <div className="detail-row mb-2">
                        <span className="detail-label font-weight-bold">Last Used:</span>
                        <span className="detail-value ms-2">
                          {identity.last_used_at || identity.last_used
                            ? formatDateTime(identity.last_used_at || identity.last_used, true)
                            : 'Never'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Identity Field Values */}
                {identity.agent_identity && (
                  <div className="card">
                    <div className="card-header" id="headingIdentityFields">
                      <h2 className="mb-0">
                        <button
                          className="btn btn-link w-100 text-start collapsed"
                          type="button"
                          data-bs-toggle="collapse"
                          data-bs-target="#collapseIdentityFields"
                          aria-expanded="false"
                          aria-controls="collapseIdentityFields"
                        >
                          <i className="fas fa-id-badge"></i> Identity Field Values
                        </button>
                      </h2>
                    </div>
                    <div
                      id="collapseIdentityFields"
                      className="collapse"
                      aria-labelledby="headingIdentityFields"
                      data-parent="#identityAccordion"
                    >
                      <div className="card-body">
                        <p className="text-muted small mb-3">
                          <i className="fas fa-info-circle"></i> These fields marked with x-identity
                          were used to create this identity mapping
                        </p>
                        {(() => {
                          // agent_identity now contains the identity_fields (flat map with dot-notation keys)
                          const identityFields = identity.agent_identity;

                          if (
                            !identityFields ||
                            typeof identityFields !== 'object' ||
                            Object.keys(identityFields).length === 0
                          ) {
                            return (
                              <p className="text-muted">
                                <i className="fas fa-exclamation-circle"></i> No identity fields
                                stored for this identity
                              </p>
                            );
                          }

                          // Convert the flat object to array of {key, value} entries
                          const fieldEntries = Object.entries(identityFields).map(
                            ([key, value]) => ({ key, value })
                          );

                          return (
                            <table className="table table-sm table-borderless">
                              <tbody>
                                {fieldEntries.map(({ key, value }) => (
                                  <tr key={key}>
                                    <td style={{ width: '40%', verticalAlign: 'middle' }}>
                                      <strong className="text-primary">{key}</strong>
                                    </td>
                                    <td style={{ width: '60%', verticalAlign: 'middle' }}>
                                      <code className="text-body">
                                        {typeof value === 'object'
                                          ? JSON.stringify(value, null, 2)
                                          : String(value)}
                                      </code>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          );
                        })()}
                      </div>
                    </div>
                  </div>
                )}

                {/* Identity Field Values (Full JSON) */}
                {identity.agent_identity && (
                  <div className="card">
                    <div className="card-header" id="headingAgentDetails">
                      <h2 className="mb-0">
                        <button
                          className="btn btn-link w-100 text-start collapsed"
                          type="button"
                          data-bs-toggle="collapse"
                          data-bs-target="#collapseAgentDetails"
                          aria-expanded="false"
                          aria-controls="collapseAgentDetails"
                        >
                          <i className="fas fa-robot"></i> Identity Field Values (Full JSON)
                        </button>
                      </h2>
                    </div>
                    <div
                      id="collapseAgentDetails"
                      className="collapse"
                      aria-labelledby="headingAgentDetails"
                      data-parent="#identityAccordion"
                    >
                      <div className="card-body">
                        <pre>
                          <code>{JSON.stringify(identity.agent_identity, null, 2)}</code>
                        </pre>
                      </div>
                    </div>
                  </div>
                )}

                {/* DID Document */}
                <div className="card">
                  <div className="card-header" id="headingDidDocument">
                    <h2 className="mb-0">
                      <button
                        className="btn btn-link w-100 text-start collapsed"
                        type="button"
                        data-bs-toggle="collapse"
                        data-bs-target="#collapseDidDocument"
                        aria-expanded="false"
                        aria-controls="collapseDidDocument"
                      >
                        <i className="fas fa-file-alt"></i> DID Document
                      </button>
                    </h2>
                  </div>
                  <div
                    id="collapseDidDocument"
                    className="collapse"
                    aria-labelledby="headingDidDocument"
                    data-parent="#identityAccordion"
                  >
                    <div className="card-body">
                      {loadingDidDocument ? (
                        <div className="text-center text-muted">
                          <i className="fas fa-spinner fa-spin"></i> Loading DID document...
                        </div>
                      ) : didDocumentContent?.error ? (
                        <div className="text-center text-danger">
                          <i className="fas fa-exclamation-triangle"></i> {didDocumentContent.error}
                        </div>
                      ) : didDocumentContent ? (
                        <pre>
                          <code>{JSON.stringify(didDocumentContent, null, 2)}</code>
                        </pre>
                      ) : (
                        <div className="text-center text-muted">Click to load DID document</div>
                      )}
                    </div>
                  </div>
                </div>
              </div>
            </div>
            <div className="modal-footer">
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                Close
              </button>
            </div>
          </div>
        </div>
      </div>
      <div className="modal-backdrop fade show"></div>
    </>
  );
};

export default IdentityDetailsModal;
