import React, { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { topAndTail } from '../../utils/stringUtils';
import { AppButton } from '../shared/AppButton';
import { CopyButton } from '../shared/CopyButton';

interface ResolveStepProps {
  did: string;
  onResolved: (didDocument: any) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ResolveStep: React.FC<ResolveStepProps> = ({ did, onResolved, onBack, onCancel }) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [didDocument, setDidDocument] = useState<any>(null);
  const [checkingAuth, setCheckingAuth] = useState(false);
  const [authCompatible, setAuthCompatible] = useState<boolean | null>(null);
  const [authCheckError, setAuthCheckError] = useState<string>('');

  // Check if the DID document has a DIDCommMessaging service
  const hasDIDCommMessaging = (doc: any): boolean => {
    if (!doc || !doc.service || !Array.isArray(doc.service)) return false;
    return doc.service.some(
      (service: any) =>
        service.type === 'DIDCommMessaging' ||
        (Array.isArray(service.type) && service.type.includes('DIDCommMessaging'))
    );
  };

  // Check if authentication endpoints are accessible using backend
  const checkAuthEndpoints = async (doc: any) => {
    setCheckingAuth(true);
    setAuthCheckError('');

    try {
      const response = await apiClient.post('/mediators/check-auth', {
        did_document: doc,
      });

      if (response.data.compatible) {
        setAuthCompatible(true);
      } else {
        setAuthCompatible(false);
        setAuthCheckError(response.data.error || 'Authentication endpoint check failed');
      }
    } catch (err: any) {
      console.error('Authentication check failed:', err);
      setAuthCompatible(false);
      setAuthCheckError(err.message || 'Failed to check authentication endpoints');
    } finally {
      setCheckingAuth(false);
    }
  };

  const resolveDid = async () => {
    try {
      setLoading(true);
      setError('');

      // Call the DID resolution endpoint
      const response = await apiClient.get(`/identity/resolve-did?did=${encodeURIComponent(did)}`);
      setDidDocument(response.data);

      // After successful resolution, check authentication endpoints
      await checkAuthEndpoints(response.data);
    } catch (err: any) {
      console.error('Failed to resolve DID:', err);
      setError(err.message || 'Failed to resolve DID. Please check the DID and try again.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    resolveDid();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [did]);

  const handleRetry = () => {
    resolveDid();
  };

  const handleProceed = () => {
    if (didDocument) {
      onResolved(didDocument);
    }
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-search me-2"></i> Resolving Mediator DID
        </h6>
      </div>
      <div className="card-body">
        {loading && (
          <div>
            <div className="text-center py-5">
              <div className="spinner-border text-primary mb-3" role="status">
                <span className="visually-hidden"></span>
              </div>
              <p className="text-muted">Resolving DID document...</p>
              <small className="text-muted">
                <code>{topAndTail(did, 16, 16)}</code>
                <CopyButton text={did} />
              </small>
            </div>
          </div>
        )}

        {!loading && error && (
          <div>
            <div className="alert alert-danger">
              <h5 className="mb-2">
                <i className="fas fa-exclamation-triangle"></i>
                Resolution Failed
              </h5>
              <h6>{error}</h6>
            </div>
            <div className="d-flex justify-content-between">
              <AppButton
                type="button"
                variant="secondary"
                size="md"
                onClick={onCancel}
                iconStart={<i className="fas fa-times"></i>}
              >
                Cancel
              </AppButton>
              <div className="d-flex gap-2">
                <AppButton
                  type="button"
                  variant="secondary"
                  size="md"
                  onClick={onBack}
                  iconStart={<i className="fas fa-arrow-left"></i>}
                >
                  Back
                </AppButton>
                <AppButton
                  type="button"
                  variant="primary"
                  size="md"
                  onClick={handleRetry}
                  iconStart={<i className="fas fa-redo"></i>}
                >
                  Retry
                </AppButton>
              </div>
            </div>
          </div>
        )}

        {!loading && !error && didDocument && (
          <div>
            {/* DIDComm Messaging Check */}
            {hasDIDCommMessaging(didDocument) ? (
              <div className="alert alert-success">
                <i className="fas fa-check-circle me-2"></i>
                <strong>Compatible Mediator!</strong> This DID has a DIDCommMessaging service and
                can be used as a mediator.
              </div>
            ) : (
              <div className="alert alert-warning">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Warning:</strong> This DID does not have a DIDCommMessaging service. It may
                not be compatible as a mediator.
              </div>
            )}

            {/* Authentication Endpoint Check */}
            {checkingAuth && (
              <div className="alert alert-info">
                <div className="d-flex align-items-center">
                  <div className="spinner-border spinner-border-sm me-2" role="status">
                    <span className="visually-hidden"></span>
                  </div>
                  <span>Checking authentication endpoint compatibility...</span>
                </div>
              </div>
            )}

            {!checkingAuth && authCompatible === true && (
              <div className="alert alert-success">
                <i className="fas fa-check-circle me-2"></i>
                <strong>Authentication Compatible!</strong> The mediator's authentication endpoints
                are accessible.
              </div>
            )}

            {!checkingAuth && authCompatible === false && (
              <div className="alert alert-danger">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Authentication Incompatible!</strong> The mediator's authentication
                endpoints cannot be reached.
                {authCheckError && (
                  <div className="mt-2">
                    <small>
                      <strong>Details:</strong> {authCheckError}
                    </small>
                  </div>
                )}
                <div className="mt-2">
                  <small>
                    This mediator will not work for creating connection points with authenticated
                    OOB invitations.
                  </small>
                </div>
              </div>
            )}

            <div className="mb-4">
              <h6 className="font-weight-bold mb-2">DID Document Details:</h6>
              <div className="card bg-light">
                <div className="card-body">
                  <dl className="row mb-0">
                    <dt className="col-sm-3">DID:</dt>
                    <dd className="col-sm-9">
                      <code style={{ fontSize: '0.85rem' }}>
                        {topAndTail(didDocument.id, 16, 16)}
                      </code>
                      <CopyButton text={didDocument.id} />
                    </dd>
                  </dl>
                </div>
              </div>
            </div>

            {/* Services Section */}
            {didDocument.service && didDocument.service.length > 0 && (
              <div className="mb-4">
                <h6 className="font-weight-bold mb-2">
                  <i className="fas fa-network-wired me-2"></i>
                  Services ({didDocument.service.length})
                </h6>
                <div className="card bg-light">
                  <div className="card-body">
                    {didDocument.service.map((service: any, index: number) => {
                      const isDIDComm =
                        service.type === 'DIDCommMessaging' ||
                        (Array.isArray(service.type) && service.type.includes('DIDCommMessaging'));
                      return (
                        <div
                          key={index}
                          className={`mb-3 ${index < didDocument.service.length - 1 ? 'pb-3 border-bottom' : ''}`}
                        >
                          <div className="row">
                            <div className="col-sm-3 text-muted small">ID:</div>
                            <div className="col-sm-9">
                              <code style={{ fontSize: '0.75rem' }}>
                                {topAndTail(service.id, 16, 16)}
                              </code>
                              <CopyButton text={service.id} />
                            </div>
                          </div>
                          <div className="row mt-1">
                            <div className="col-sm-3 text-muted small">Type:</div>
                            <div className="col-sm-9">
                              <span
                                className={`badge ${isDIDComm ? 'text-bg-success' : 'text-bg-secondary'}`}
                              >
                                {Array.isArray(service.type)
                                  ? service.type.join(', ')
                                  : service.type}
                              </span>
                              {isDIDComm && (
                                <span className="ms-2 text-success small">
                                  <i className="fas fa-check-circle"></i> Mediator Compatible
                                </span>
                              )}
                            </div>
                          </div>
                          {service.serviceEndpoint && (
                            <div className="row mt-1">
                              <div className="col-sm-3 text-muted small">Endpoint:</div>
                              <div className="col-sm-9">
                                {typeof service.serviceEndpoint === 'string' ? (
                                  <code style={{ fontSize: '0.75rem' }}>
                                    {service.serviceEndpoint}
                                  </code>
                                ) : (
                                  <details>
                                    <summary
                                      className="cursor-pointer text-primary"
                                      style={{ cursor: 'pointer', fontSize: '0.75rem' }}
                                    >
                                      View endpoint details
                                    </summary>
                                    <pre
                                      className="mt-1 p-2 bg-white border rounded"
                                      style={{ fontSize: '0.7rem' }}
                                    >
                                      {JSON.stringify(service.serviceEndpoint, null, 2)}
                                    </pre>
                                  </details>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* Verification Methods Section */}
            {didDocument.verificationMethod && didDocument.verificationMethod.length > 0 && (
              <div className="mb-4">
                <h6 className="font-weight-bold mb-2">
                  <i className="fas fa-key me-2"></i>
                  Verification Methods ({didDocument.verificationMethod.length})
                </h6>
                <div className="card bg-light">
                  <div className="card-body">
                    {didDocument.verificationMethod.map((method: any, index: number) => (
                      <div
                        key={index}
                        className={`mb-3 ${index < didDocument.verificationMethod.length - 1 ? 'pb-3 border-bottom' : ''}`}
                      >
                        <div className="row">
                          <div className="col-sm-3 text-muted small">ID:</div>
                          <div className="col-sm-9">
                            <code style={{ fontSize: '0.75rem' }}>
                              {topAndTail(method.id, 16, 16)}
                            </code>
                            <CopyButton text={method.id} />
                          </div>
                        </div>
                        <div className="row mt-1">
                          <div className="col-sm-3 text-muted small">Type:</div>
                          <div className="col-sm-9">
                            <span className="badge text-bg-primary">{method.type}</span>
                          </div>
                        </div>
                        {method.controller && (
                          <div className="row mt-1">
                            <div className="col-sm-3 text-muted small">Controller:</div>
                            <div className="col-sm-9">
                              <code style={{ fontSize: '0.75rem' }}>
                                {topAndTail(method.controller, 16, 16)}
                              </code>
                              <CopyButton text={method.controller} />
                            </div>
                          </div>
                        )}
                        {method.publicKeyJwk && (
                          <div className="row mt-1">
                            <div className="col-sm-3 text-muted small">Public Key:</div>
                            <div className="col-sm-9">
                              <details>
                                <summary
                                  className="cursor-pointer text-primary"
                                  style={{ cursor: 'pointer', fontSize: '0.75rem' }}
                                >
                                  View JWK
                                </summary>
                                <pre
                                  className="mt-1 p-2 bg-white border rounded"
                                  style={{ fontSize: '0.7rem' }}
                                >
                                  {JSON.stringify(method.publicKeyJwk, null, 2)}
                                </pre>
                              </details>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Additional Details */}
            <div className="mb-4">
              <h6 className="font-weight-bold mb-2">Additional Details</h6>
              <div className="card bg-light">
                <div className="card-body">
                  <dl className="row mb-0">
                    <dt className="col-sm-3">DID:</dt>
                    <dd className="col-sm-9">
                      <code style={{ fontSize: '0.85rem' }}>
                        {topAndTail(didDocument.id, 16, 16)}
                      </code>
                      <CopyButton text={didDocument.id} />
                    </dd>

                    {didDocument['@context'] && (
                      <>
                        <dt className="col-sm-3">Context:</dt>
                        <dd className="col-sm-9">
                          <small className="text-muted">
                            {Array.isArray(didDocument['@context'])
                              ? didDocument['@context'].join(', ')
                              : didDocument['@context']}
                          </small>
                        </dd>
                      </>
                    )}
                  </dl>

                  <details className="mt-3">
                    <summary className="cursor-pointer text-primary" style={{ cursor: 'pointer' }}>
                      <small>View full DID document</small>
                    </summary>
                    <pre
                      className="mt-2 p-2 bg-white border rounded"
                      style={{ fontSize: '0.75rem', maxHeight: '300px', overflow: 'auto' }}
                    >
                      {JSON.stringify(didDocument, null, 2)}
                    </pre>
                  </details>
                </div>
              </div>
            </div>

            <div className="d-flex justify-content-between">
              <AppButton
                type="button"
                variant="secondary"
                size="md"
                onClick={onCancel}
                iconStart={<i className="fas fa-times"></i>}
              >
                Cancel
              </AppButton>
              <div className="d-flex gap-2">
                <AppButton
                  type="button"
                  variant="secondary"
                  size="md"
                  onClick={onBack}
                  iconStart={<i className="fas fa-arrow-left"></i>}
                >
                  Back
                </AppButton>
                <AppButton
                  type="button"
                  variant="primary"
                  size="md"
                  onClick={handleProceed}
                  iconEnd={<i className="fas fa-arrow-right"></i>}
                >
                  Next
                </AppButton>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ResolveStep;
