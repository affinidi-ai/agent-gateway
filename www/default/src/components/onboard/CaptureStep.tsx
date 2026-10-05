import React, { useState, useEffect, useRef } from 'react';
import { useApp } from '../../context/AppContext';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { formatDateTime } from '../../utils/stringUtils';

interface CaptureStepProps {
  protocol: 'a2a' | 'ap2' | 'mcp';
  onPayloadCaptured: (payload: any, derivedSchema: any) => void;
  onBack: () => void;
  /**
   * Render without the outer `card shadow / card-body / h5` chrome so the
   * step can be embedded inside a host panel that already provides its
   * own container (e.g. the identity element fullscreen editor).
   */
  bare?: boolean;
}

interface TempChannelInfo {
  configId: string;
  channelName: string;
  endpointUrl: string;
  ttlSeconds: number;
}

const CaptureStep: React.FC<CaptureStepProps> = ({ protocol, onPayloadCaptured, onBack, bare }) => {
  const { state, actions } = useApp();
  const [tempChannel, setTempChannel] = useState<TempChannelInfo | null>(null);
  const [isCreatingChannel, setIsCreatingChannel] = useState(true);
  const [capturedPayloads, setCapturedPayloads] = useState<
    Array<{
      timestamp: Date;
      payload: any;
      channel: string;
      validation_status: string;
      validation_error?: string;
      derived_schema?: any;
    }>
  >([]);
  const [isCapturing, setIsCapturing] = useState(true);
  const [latestPayload, setLatestPayload] = useState<string>('');
  const [latestDerivedSchema, setLatestDerivedSchema] = useState<string>('');
  const [latestValidationStatus, setLatestValidationStatus] = useState<string>('success');
  const [latestValidationError, setLatestValidationError] = useState<string | undefined>(undefined);
  const [payloadCount, setPayloadCount] = useState(0);
  const [selectedIndex, setSelectedIndex] = useState<number>(0);
  const [channelExpired, setChannelExpired] = useState(false);
  const [hasCapturedPayload, setHasCapturedPayload] = useState(false);
  const [timeRemaining, setTimeRemaining] = useState<number | null>(null);
  const latestPayloadRef = useRef<HTMLTextAreaElement>(null);
  const tempChannelRef = useRef<TempChannelInfo | null>(null);
  const hasCapturedPayloadRef = useRef(false);

  // Keep the WebSocket alive while this component is mounted so we don't
  // miss payload_captured events when the user switches browser tabs.
  useEffect(() => {
    actions.setWsKeepAlive(true);
    return () => {
      actions.setWsKeepAlive(false);
    };
  }, [actions]);

  // Create temporary onboarding channel on mount
  useEffect(() => {
    let channelConfigId: string | null = null;
    let isCancelled = false;

    const createChannel = async () => {
      try {
        setIsCreatingChannel(true);
        const response = await apiClient.createTempOnboardChannel(protocol);
        if (isCancelled) {
          // Cleanup channel created by a stale effect run (e.g. React StrictMode)
          apiClient
            .deleteTempOnboardChannel(response.config_id)
            .catch(err => console.error('Failed to cleanup stale temp channel:', err));
          return;
        }
        channelConfigId = response.config_id;
        const info = {
          configId: response.config_id,
          channelName: response.channel_name,
          endpointUrl: response.endpoint_url,
          ttlSeconds: response.ttl_seconds,
        };
        setTempChannel(info);
        tempChannelRef.current = info;
        setTimeRemaining(response.ttl_seconds);
      } catch (error: any) {
        if (!isCancelled) {
          showToast('error', error.message || 'Failed to create onboarding channel');
        }
      } finally {
        if (!isCancelled) {
          setIsCreatingChannel(false);
        }
      }
    };

    createChannel();

    // Cleanup: delete temp channel when component unmounts
    return () => {
      isCancelled = true;
      if (channelConfigId) {
        // Try to delete the temp channel
        // Note: This may not complete if browser is closing/refreshing
        // Backend auto-expiration timer will clean up after TTL expires
        apiClient
          .deleteTempOnboardChannel(channelConfigId)
          .catch(err => console.error('Failed to cleanup temp channel:', err));
      }
    };
  }, [protocol]); // Include protocol in deps

  // Countdown timer effect
  useEffect(() => {
    if (timeRemaining === null || timeRemaining <= 0) {
      return;
    }

    const intervalId = setInterval(() => {
      setTimeRemaining(prev => {
        if (prev === null || prev <= 1) {
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(intervalId);
  }, [timeRemaining]);

  useEffect(() => {
    // Set up WebSocket listener for payload capture events
    const handleWebSocketMessage = (event: Event) => {
      const customEvent = event as CustomEvent;
      const data = customEvent.detail;
      // Read from ref to always get the latest tempChannel value,
      // avoiding stale closures when the effect re-registers the listener.
      const tc = tempChannelRef.current;

      // Check if this channel expired — only show expired UI if no payload was captured
      if (data.type === 'channel_expired' && tc && data.config_id === tc.configId) {
        if (!hasCapturedPayloadRef.current) {
          setChannelExpired(true);
          setTempChannel(null);
          tempChannelRef.current = null;
          setTimeRemaining(null);
        }
      }

      // Only capture payloads for this specific temporary onboarding channel - filter by config_id
      if (data.type === 'payload_captured' && tc && data.config_id === tc.configId) {
        const newPayload = {
          timestamp: new Date(data.timestamp || new Date()),
          payload: data.payload,
          channel: data.channel,
          validation_status: data.validation_status || 'success',
          validation_error: data.validation_error,
          derived_schema: data.derived_schema,
        };

        setCapturedPayloads(prev => [newPayload, ...prev.slice(0, 9)]); // Keep last 10 payloads
        setSelectedIndex(0); // Auto-select the newest capture
        setLatestPayload(JSON.stringify(data.payload, null, 2));
        setLatestDerivedSchema(JSON.stringify(data.derived_schema, null, 2));
        setLatestValidationStatus(data.validation_status || 'Validation OK');
        setLatestValidationError(data.validation_error);
        setPayloadCount(prev => prev + 1);
        hasCapturedPayloadRef.current = true;
        setHasCapturedPayload(true);
      }
    };

    // Listen to custom event instead of raw WebSocket message
    window.addEventListener('ws-message', handleWebSocketMessage);

    return () => {
      window.removeEventListener('ws-message', handleWebSocketMessage);
      setIsCapturing(false);
    };
  }, [state.wsConnection]);

  const clearPayloads = () => {
    setCapturedPayloads([]);
    setLatestPayload('');
    setLatestDerivedSchema('');
    setLatestValidationStatus('success');
    setLatestValidationError(undefined);
    setPayloadCount(0);
    setSelectedIndex(0);
  };

  const selectCapture = (index: number) => {
    const capture = capturedPayloads[index];
    if (!capture) return;
    setSelectedIndex(index);
    setLatestPayload(JSON.stringify(capture.payload, null, 2));
    setLatestDerivedSchema(JSON.stringify(capture.derived_schema, null, 2));
    setLatestValidationStatus(capture.validation_status || 'success');
    setLatestValidationError(capture.validation_error);
  };

  const handleUseLatestPayload = async () => {
    if (capturedPayloads.length > 0) {
      // Delete the temporary channel before proceeding
      if (tempChannel?.configId) {
        try {
          await apiClient.deleteTempOnboardChannel(tempChannel.configId);
          showToast('success', 'Onboarding channel closed');
        } catch (error: any) {
          console.error('Failed to delete temp channel:', error);
          // Continue anyway
        }
      }
      const selected = capturedPayloads[selectedIndex] || capturedPayloads[0];
      onPayloadCaptured(selected.payload, selected.derived_schema);
    }
  };

  const handleRestartCapture = async () => {
    setChannelExpired(false);
    setIsCreatingChannel(true);
    hasCapturedPayloadRef.current = false;
    setHasCapturedPayload(false);
    clearPayloads();

    try {
      const response = await apiClient.createTempOnboardChannel(protocol);
      const info = {
        configId: response.config_id,
        channelName: response.channel_name,
        endpointUrl: response.endpoint_url,
        ttlSeconds: response.ttl_seconds,
      };
      setTempChannel(info);
      tempChannelRef.current = info;
      setTimeRemaining(response.ttl_seconds);
      showToast('success', 'New onboarding channel created');
    } catch (error: any) {
      showToast('error', error.message || 'Failed to create onboarding channel');
    } finally {
      setIsCreatingChannel(false);
    }
  };

  const body = (
    <>
      {!bare && (
        <h5 className="mb-3">
          <i className="fas fa-satellite-dish me-2"></i>
          Capture Agent Payload
        </h5>
      )}

      {/* Status Messages */}
      {channelExpired ? (
        <div className="mb-4">
          <div className="border rounded p-3 bg-light">
            <h6 className="mb-2 text-danger">
              <i className="fas fa-hourglass-end me-2"></i>
              Onboarding Timeout Expired
            </h6>
            <p className="mb-3" style={{ fontSize: '14px' }}>
              The onboarding timeout has expired, and the temporary onboarding channel has been
              closed.
              <br />
              Try restarting the capture process again - note that the onboarding channel details
              will be different!
            </p>
            <button className="btn btn-primary" onClick={handleRestartCapture}>
              <i className="fas fa-redo me-2"></i>
              Restart Capture
            </button>
          </div>
        </div>
      ) : isCreatingChannel ? (
        <div className="alert alert-info">
          <i className="fas fa-spinner fa-spin me-2"></i>
          Creating temporary onboarding endpoint...
        </div>
      ) : !tempChannel ? (
        <div className="alert alert-danger">
          <i className="fas fa-exclamation-triangle me-2"></i>
          Failed to create onboarding endpoint. Please try again.
        </div>
      ) : null}

      {/* Onboarding Endpoint Section */}
      {!channelExpired && tempChannel && (
        <div className="mb-4">
          <div className="border rounded p-3 bg-light">
            <h6 className={`mb-2 ${hasCapturedPayload ? 'text-success' : 'text-primary'}`}>
              <i
                className={`fas ${hasCapturedPayload ? 'fa-check-circle' : 'fa-satellite-dish'} me-2`}
              ></i>
              {hasCapturedPayload ? 'Schema Derived' : 'Waiting for Agent Connection'}
            </h6>
            <p className="mb-2" style={{ fontSize: '14px' }}>
              {hasCapturedPayload
                ? `Your ${protocol.toUpperCase()} agent has connected. You can send additional requests or proceed with the captured schema.`
                : `Point your ${protocol.toUpperCase()} agent to this temporary endpoint within the timeout:`}
            </p>
            <div className="d-flex align-items-center mb-2 flex-wrap gap-2">
              {timeRemaining !== null && timeRemaining > 0 && (
                <span
                  className="badge text-bg-warning"
                  style={{ fontSize: '11px', padding: '3px 6px', whiteSpace: 'nowrap' }}
                >
                  <i className="fas fa-clock me-1"></i>
                  Capture stops in: {timeRemaining}s
                </span>
              )}
              <div className="input-group input-group-sm flex-grow-1" style={{ minWidth: 0 }}>
                <button
                  className="btn btn-outline-secondary"
                  type="button"
                  onClick={e => {
                    navigator.clipboard.writeText(tempChannel.endpointUrl);
                    showToast('success', 'Endpoint URL copied to clipboard');
                    const btn = e.currentTarget as HTMLButtonElement;
                    const originalHtml = btn.innerHTML;
                    btn.innerHTML = '<i class="fas fa-check"></i>';
                    setTimeout(() => {
                      btn.innerHTML = originalHtml;
                    }, 2000);
                  }}
                  title="Copy to clipboard"
                  style={{ padding: '2px 8px', fontSize: '11px' }}
                >
                  <i className="fas fa-copy"></i>
                </button>
                <input
                  title="Onboarding Endpoint URL"
                  type="text"
                  className="form-control form-control-sm"
                  value={tempChannel.endpointUrl}
                  readOnly
                  style={{ fontSize: '12px' }}
                />
              </div>
            </div>
            <small className="text-muted">
              This endpoint will only be available for a short time for security reasons, and will
              automatically close when you proceed to the next step, or the timer expires.
            </small>
          </div>
        </div>
      )}

      {!channelExpired && (
        <>
          {/* Latest Payload Display */}
          <div className="mb-3" style={{ display: latestPayload.length === 0 ? 'none' : 'block' }}>
            <div className="d-flex justify-content-between align-items-center mb-2">
              <div className="d-flex align-items-center">
                <h6 className="m-0 font-weight-bold text-success me-3" style={{ fontSize: '15px' }}>
                  <i className="fas fa-file-code"></i> Most Recent Agent Payload
                </h6>
                {latestPayload && (
                  <span
                    className={`badge rounded-pill ${latestValidationStatus === 'success' ? 'text-bg-success' : 'text-bg-danger'}`}
                  >
                    {latestValidationStatus === 'success' ? (
                      <>
                        <i className="fas fa-check-circle"></i> Validation OK
                      </>
                    ) : (
                      <>
                        <i className="fas fa-exclamation-triangle"></i> Failed Validation
                      </>
                    )}
                  </span>
                )}
              </div>
              {latestPayload && (
                <button
                  className="btn btn-sm btn-outline-secondary"
                  onClick={clearPayloads}
                  title="Clear all payloads"
                >
                  <i className="fas fa-trash"></i> Clear
                </button>
              )}
            </div>

            {!latestPayload ? (
              <div className="text-center text-muted py-4 border rounded">
                <i className="fas fa-hourglass-half fa-2x mb-2"></i>
                <p className="mb-1">Waiting for agent requests...</p>
                <small>
                  Make a request to any channel to the temporary channel to capture the payload
                  here.
                </small>
              </div>
            ) : (
              <div>
                {latestValidationError && (
                  <div className="alert alert-danger mb-3">
                    <h6>
                      <i className="fas fa-exclamation-circle"></i> Validation Error
                    </h6>
                    <small className="font-monospace">{latestValidationError}</small>
                  </div>
                )}
                <div className="row">
                  <div className="col-md-6">
                    <h6 className="font-weight-bold mb-2" style={{ fontSize: '14px' }}>
                      <i className="fas fa-file-code me-2"></i>
                      Captured Payload
                    </h6>
                    <textarea
                      title="Captured Payload"
                      ref={latestPayloadRef}
                      className={`form-control ${latestValidationStatus === 'success' ? 'is-valid' : 'is-invalid'}`}
                      rows={15}
                      value={latestPayload}
                      readOnly
                      style={{ fontFamily: 'monospace', fontSize: '11px' }}
                    />
                  </div>
                  <div className="col-md-6">
                    <h6 className="font-weight-bold mb-2" style={{ fontSize: '14px' }}>
                      <i className="fas fa-project-diagram me-2"></i>
                      Derived Schema
                    </h6>
                    <textarea
                      title="Derived Schema"
                      className="form-control border-info"
                      rows={15}
                      value={latestDerivedSchema}
                      style={{
                        fontFamily: 'monospace',
                        fontSize: '11px',
                      }}
                    />
                    <small className="form-text text-muted">
                      This schema was automatically derived from the agentIdentity metadata in the
                      captured payload
                    </small>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Payload History */}
          {capturedPayloads.length > 1 && (
            <div className="mb-3">
              <h6 className="font-weight-bold text-info mb-2" style={{ fontSize: '15px' }}>
                <i className="fas fa-history"></i> Payload History ({capturedPayloads.length}/10)
                <small className="text-muted ms-2">Click a row to select it</small>
              </h6>
              <div className="table-responsive">
                <table className="table table-hover table-sm">
                  <thead>
                    <tr>
                      <th></th>
                      <th>Timestamp</th>
                      <th>Channel</th>
                      <th>Validation Status</th>
                      <th>Payload Preview</th>
                    </tr>
                  </thead>
                  <tbody>
                    {capturedPayloads.map((capture, index) => (
                      <tr
                        key={index}
                        onClick={() => selectCapture(index)}
                        className={index === selectedIndex ? 'table-primary' : ''}
                        style={{ cursor: 'pointer' }}
                      >
                        <td style={{ width: '30px', textAlign: 'center' }}>
                          {index === selectedIndex && <i className="fas fa-check text-primary"></i>}
                        </td>
                        <td style={{ fontSize: '12px' }}>
                          {formatDateTime(capture.timestamp, true)}
                        </td>
                        <td>
                          <span className="badge text-bg-secondary">{capture.channel}</span>
                        </td>
                        <td>
                          <span
                            className={`badge ${capture.validation_status === 'success' ? 'text-bg-success' : 'text-bg-danger'}`}
                          >
                            {capture.validation_status === 'success' ? (
                              <>
                                <i className="fas fa-check-circle"></i> OK
                              </>
                            ) : (
                              <>
                                <i className="fas fa-exclamation-triangle"></i> Failed
                              </>
                            )}
                          </span>
                        </td>
                        <td>
                          <code style={{ fontSize: '11px' }}>
                            {JSON.stringify(capture.payload).substring(0, 80)}
                            {JSON.stringify(capture.payload).length > 80 && '...'}
                          </code>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}

      {/* Step Navigation */}
      <div className="step-navigation">
        <button className="btn btn-sm btn-secondary" onClick={onBack}>
          <i className="fas fa-arrow-left me-2"></i>
          Back
        </button>
        <button
          className="btn btn-sm btn-primary"
          onClick={handleUseLatestPayload}
          disabled={!latestPayload || latestValidationStatus !== 'success'}
        >
          Use This Schema
          <i className="fas fa-arrow-right ms-2"></i>
        </button>
      </div>
    </>
  );

  if (bare) return body;
  return (
    <div className="card shadow">
      <div className="card-body">{body}</div>
    </div>
  );
};

export default CaptureStep;
