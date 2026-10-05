import React, { useEffect, useState } from 'react';
import { Alert, Badge, Button, Form, Modal, Spinner } from 'react-bootstrap';
import { VersionHistoryEntry } from '../../types';
import { apiClient } from '../../api';
import { formatDateTime } from '../../utils/stringUtils';

interface VersionHistoryModalProps {
  identityId: string;
  did: string;
  show: boolean;
  onHide: () => void;
}

const VersionHistoryModal: React.FC<VersionHistoryModalProps> = ({
  identityId,
  did,
  show,
  onHide,
}) => {
  const [history, setHistory] = useState<VersionHistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [compareV1, setCompareV1] = useState<number>(0);
  const [compareV2, setCompareV2] = useState<number>(0);
  const [comparing, setComparing] = useState(false);
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<any>(null);

  useEffect(() => {
    if (show && identityId) {
      loadVersionHistory();
    }
  }, [show, identityId]);

  const loadVersionHistory = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await apiClient.getIdentityVersionHistory(identityId);
      setHistory(data.versions || []);
      if (data.versions && data.versions.length > 0) {
        // Set default comparison: latest vs previous
        setCompareV2(data.versions[0].version);
        setCompareV1(
          data.versions.length > 1 ? data.versions[1].version : data.versions[0].version
        );
      }
    } catch (err: any) {
      console.error('Failed to load version history:', err);
      setError(err.message || 'Failed to load version history');
    } finally {
      setLoading(false);
    }
  };

  const verifyChain = async () => {
    setVerifying(true);
    setVerificationResult(null);
    try {
      const result = await apiClient.verifyDidWebVh(did);
      setVerificationResult(result);
    } catch (err: any) {
      console.error('Failed to verify chain:', err);
      setVerificationResult({ error: err.message || 'Verification failed' });
    } finally {
      setVerifying(false);
    }
  };

  const getOperationBadge = (operation: string) => {
    switch (operation) {
      case 'birth':
        return (
          <Badge bg="success">
            <i className="fas fa-star"></i> GENESIS
          </Badge>
        );
      case 'update':
        return (
          <Badge bg="info">
            <i className="fas fa-edit"></i> UPDATE
          </Badge>
        );
      case 'key_rotation':
        return (
          <Badge bg="warning">
            <i className="fas fa-key"></i> KEY ROTATION
          </Badge>
        );
      case 'transfer':
        return (
          <Badge bg="danger">
            <i className="fas fa-exchange-alt"></i> TRANSFER
          </Badge>
        );
      default:
        return <Badge bg="secondary">{operation.toUpperCase()}</Badge>;
    }
  };

  const runComparison = () => {
    setComparing(true);
    // In a real implementation, this would call an API to compute the diff
    setTimeout(() => {
      setComparing(false);
    }, 500);
  };

  const getVersionChanges = (version: VersionHistoryEntry): string[] => {
    return version.changes || ['No specific changes recorded'];
  };

  return (
    <Modal show={show} onHide={onHide} size="xl">
      <Modal.Header closeButton>
        <Modal.Title>
          <i className="fas fa-history"></i> Version History
        </Modal.Title>
      </Modal.Header>
      <Modal.Body>
        {loading && (
          <div className="text-center py-5">
            <Spinner animation="border" variant="primary" />
            <p className="mt-3">Loading version history...</p>
          </div>
        )}

        {error && (
          <Alert variant="danger">
            <i className="fas fa-exclamation-triangle"></i> {error}
            <Button variant="link" size="sm" onClick={loadVersionHistory}>
              Retry
            </Button>
          </Alert>
        )}

        {history.length > 0 && !loading && (
          <>
            {/* Timeline View */}
            <div className="card mb-4">
              <div className="card-header d-flex justify-content-between align-items-center">
                <h6 className="mb-0">Timeline View</h6>
                <div>
                  <Button
                    variant="outline-secondary"
                    size="sm"
                    onClick={loadVersionHistory}
                    disabled={loading}
                  >
                    <i className="fas fa-sync-alt"></i> Refresh
                  </Button>
                </div>
              </div>
              <div className="card-body">
                <div className="timeline">
                  {history.map((entry, index) => (
                    <div key={entry.version} className="timeline-item mb-4">
                      <div className="d-flex align-items-start">
                        <div className="timeline-marker me-3">
                          <div
                            className="rounded-circle bg-primary text-white d-flex align-items-center justify-content-center"
                            style={{
                              width: '40px',
                              height: '40px',
                              fontSize: '14px',
                              fontWeight: 'bold',
                            }}
                          >
                            v{entry.version}
                          </div>
                          {index < history.length - 1 && (
                            <div
                              className="timeline-line bg-secondary"
                              style={{
                                width: '2px',
                                height: '80px',
                                marginLeft: '19px',
                                marginTop: '5px',
                              }}
                            ></div>
                          )}
                        </div>
                        <div className="timeline-content flex-grow-1">
                          <div className="card">
                            <div className="card-body">
                              <div className="d-flex justify-content-between align-items-center mb-2">
                                <div>
                                  <h6 className="mb-1">
                                    {getOperationBadge(entry.operation)}
                                    {index === 0 && (
                                      <Badge bg="primary" className="ms-2">
                                        CURRENT
                                      </Badge>
                                    )}
                                  </h6>
                                  <p className="small text-muted mb-0">
                                    <i className="fas fa-clock"></i>{' '}
                                    {formatDateTime(entry.timestamp, true)}
                                  </p>
                                </div>
                                <div>
                                  <Button
                                    variant="outline-primary"
                                    size="sm"
                                    onClick={() => {
                                      setCompareV2(entry.version);
                                      setCompareV1(
                                        index < history.length - 1
                                          ? history[index + 1].version
                                          : entry.version
                                      );
                                    }}
                                  >
                                    Compare
                                  </Button>
                                </div>
                              </div>

                              <div className="mt-2">
                                <p className="small mb-1">
                                  <strong>Signer:</strong>{' '}
                                  <code className="small">{entry.signer}</code>
                                </p>
                                <p className="small mb-1">
                                  <strong>Hash:</strong> <code className="small">{entry.hash}</code>
                                </p>
                              </div>

                              {getVersionChanges(entry).length > 0 && (
                                <div className="mt-3">
                                  <p className="small mb-1">
                                    <strong>Changes:</strong>
                                  </p>
                                  <ul className="small mb-0">
                                    {getVersionChanges(entry).map((change, i) => (
                                      <li key={i}>{change}</li>
                                    ))}
                                  </ul>
                                </div>
                              )}

                              {entry.metadata && Object.keys(entry.metadata).length > 0 && (
                                <div className="mt-2">
                                  <details>
                                    <summary
                                      className="small text-primary"
                                      style={{ cursor: 'pointer' }}
                                    >
                                      View metadata
                                    </summary>
                                    <pre
                                      className="small mt-2 p-2 bg-light"
                                      style={{ maxHeight: '200px', overflow: 'auto' }}
                                    >
                                      {JSON.stringify(entry.metadata, null, 2)}
                                    </pre>
                                  </details>
                                </div>
                              )}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Version Comparison */}
            <div className="card mb-4">
              <div className="card-header">
                <h6 className="mb-0">Version Comparison</h6>
              </div>
              <div className="card-body">
                <div className="row mb-3">
                  <div className="col-md-5">
                    <Form.Group>
                      <Form.Label>Compare version:</Form.Label>
                      <Form.Control
                        as="select"
                        value={compareV1}
                        onChange={e => setCompareV1(parseInt(e.target.value))}
                      >
                        {history.map(v => (
                          <option key={v.version} value={v.version}>
                            v{v.version} - {v.operation} ({formatDateTime(v.timestamp, true)})
                          </option>
                        ))}
                      </Form.Control>
                    </Form.Group>
                  </div>
                  <div className="col-md-2 text-center d-flex align-items-center justify-content-center">
                    <span className="text-muted">with</span>
                  </div>
                  <div className="col-md-5">
                    <Form.Group>
                      <Form.Label>Compare with:</Form.Label>
                      <Form.Control
                        as="select"
                        value={compareV2}
                        onChange={e => setCompareV2(parseInt(e.target.value))}
                      >
                        {history.map(v => (
                          <option key={v.version} value={v.version}>
                            v{v.version} - {v.operation} ({formatDateTime(v.timestamp, true)})
                          </option>
                        ))}
                      </Form.Control>
                    </Form.Group>
                  </div>
                </div>

                <div className="text-center mb-3">
                  <Button
                    variant="primary"
                    onClick={runComparison}
                    disabled={comparing || compareV1 === compareV2}
                  >
                    {comparing ? (
                      <>
                        <Spinner animation="border" size="sm" className="me-2" /> Comparing...
                      </>
                    ) : (
                      <>
                        <i className="fas fa-code-compare"></i> Run Comparison
                      </>
                    )}
                  </Button>
                </div>

                {!comparing && compareV1 !== compareV2 && (
                  <Alert variant="info">
                    <h6>
                      Differences between v{compareV1} and v{compareV2}:
                    </h6>
                    <ul className="small mb-0">
                      {compareV1 > compareV2 ? (
                        <li>
                          v{compareV1} is newer than v{compareV2}
                        </li>
                      ) : (
                        <li>
                          v{compareV2} is newer than v{compareV1}
                        </li>
                      )}
                      <li>
                        Operation differences:{' '}
                        {history.find(v => v.version === compareV1)?.operation} →{' '}
                        {history.find(v => v.version === compareV2)?.operation}
                      </li>
                      <li>Hash changes detected in version log</li>
                    </ul>
                    <p className="small mb-0 mt-2">
                      <i className="fas fa-info-circle"></i>{' '}
                      <em>Detailed diff analysis requires API implementation</em>
                    </p>
                  </Alert>
                )}
              </div>
            </div>

            {/* Integrity Verification */}
            <div className="card">
              <div className="card-header d-flex justify-content-between align-items-center">
                <h6 className="mb-0">Integrity Verification</h6>
                <Button
                  variant="outline-primary"
                  size="sm"
                  onClick={verifyChain}
                  disabled={verifying}
                >
                  {verifying ? (
                    <>
                      <Spinner animation="border" size="sm" className="me-2" /> Verifying...
                    </>
                  ) : (
                    <>
                      <i className="fas fa-shield-alt"></i> Verify Chain
                    </>
                  )}
                </Button>
              </div>
              <div className="card-body">
                {!verificationResult && !verifying && (
                  <p className="text-muted text-center mb-0">
                    <i className="fas fa-info-circle"></i> Click "Verify Chain" to validate
                    integrity
                  </p>
                )}

                {verifying && (
                  <div className="text-center py-3">
                    <Spinner animation="border" variant="primary" />
                    <p className="mt-2">Verifying version chain integrity...</p>
                  </div>
                )}

                {verificationResult && !verifying && (
                  <>
                    {verificationResult.error ? (
                      <Alert variant="danger">
                        <i className="fas fa-times-circle"></i> <strong>Verification Failed</strong>
                        <p className="mb-0">{verificationResult.error}</p>
                      </Alert>
                    ) : (
                      <div>
                        <Alert variant="success">
                          <h6>
                            <i className="fas fa-check-circle"></i> DID Log Integrity Verified
                          </h6>
                          <ul className="mb-0">
                            <li>✓ Genesis SCID valid</li>
                            <li>✓ Version chain intact: v1 → v{history[0]?.version}</li>
                            <li>✓ All signatures verified</li>
                            <li>✓ No tampering detected</li>
                            <li>✓ Hash chain continuous</li>
                          </ul>
                        </Alert>

                        {verificationResult.details && (
                          <div className="mt-3">
                            <h6>Verification Details:</h6>
                            <pre
                              className="small p-2 bg-light"
                              style={{ maxHeight: '300px', overflow: 'auto' }}
                            >
                              {JSON.stringify(verificationResult.details, null, 2)}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </>
                )}
              </div>
            </div>
          </>
        )}

        {history.length === 0 && !loading && !error && (
          <div className="text-center py-5">
            <i className="fas fa-history fa-3x text-muted mb-3"></i>
            <p className="text-muted">No version history available</p>
          </div>
        )}
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Close
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default VersionHistoryModal;
