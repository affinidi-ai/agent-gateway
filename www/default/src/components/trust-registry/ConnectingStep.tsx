import React, { useEffect, useRef, useState } from 'react';
import { apiClient } from '../../api';

interface ConnectingStepProps {
  name: string;
  description: string;
  oobUrl: string;
  didMethod: string;
  onComplete: (trustRegistry: any) => void;
  onError: (error: string) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ConnectingStep: React.FC<ConnectingStepProps> = ({
  name,
  description,
  oobUrl,
  didMethod,
  onComplete,
  onError,
  onBack,
  onCancel,
}) => {
  const [progress, setProgress] = useState(10);
  const [statusMessage, setStatusMessage] = useState('Initiating connection...');
  const [failed, setFailed] = useState(false);
  const onCompleteRef = useRef(onComplete);
  const onErrorRef = useRef(onError);
  onCompleteRef.current = onComplete;
  onErrorRef.current = onError;

  useEffect(() => {
    let cancelled = false;

    const connect = async () => {
      try {
        setProgress(20);
        setStatusMessage('Parsing OOB invitation...');
        await new Promise(resolve => setTimeout(resolve, 400));

        if (cancelled) return;
        setProgress(40);
        setStatusMessage('Establishing secure DIDComm connection...');

        const response = await apiClient.post('/trust-registries', {
          name,
          description,
          oob_url: oobUrl,
          did_method: didMethod,
        });

        if (cancelled) return;
        setProgress(80);
        setStatusMessage('Verifying connection...');

        await new Promise(resolve => setTimeout(resolve, 400));

        if (cancelled) return;
        setProgress(100);

        const connStatus = response.data?.connection_status;
        if (connStatus === 'awaiting_approval' || connStatus === 'connecting') {
          setStatusMessage('Setup sent! Awaiting trust registry admin approval.');
        } else {
          setStatusMessage('Connection established!');
        }

        await new Promise(resolve => setTimeout(resolve, 500));

        if (cancelled) return;
        onCompleteRef.current(response.data);
      } catch (err: any) {
        if (cancelled) return;
        setFailed(true);
        const message = err.message || 'Failed to connect to trust registry';
        setStatusMessage(message);
        onErrorRef.current(message);
      }
    };

    connect();

    return () => {
      cancelled = true;
    };
  }, [name, description, oobUrl, didMethod]);

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-plug me-2"></i> Connecting to Trust Registry
        </h6>
      </div>
      <div className="card-body">
        <div className="text-center py-5">
          {!failed ? (
            <div className="mb-4">
              <div
                className="spinner-border text-primary"
                style={{ width: '3rem', height: '3rem' }}
                role="status"
              >
                <span className="visually-hidden"></span>
              </div>
            </div>
          ) : (
            <div className="mb-4">
              <i className="fas fa-exclamation-triangle hero-status-icon danger"></i>
            </div>
          )}

          <h5 className="mb-3">{statusMessage}</h5>

          {!failed && (
            <div className="progress mb-3 mx-auto" style={{ height: '25px', maxWidth: '500px' }}>
              <div
                className="progress-bar progress-bar-striped progress-bar-animated"
                role="progressbar"
                style={{ width: `${progress}%` }}
                aria-valuenow={progress}
                aria-valuemin={0}
                aria-valuemax={100}
              >
                {progress}%
              </div>
            </div>
          )}

          {failed && (
            <div className="mt-4 d-flex justify-content-center" style={{ gap: '0.5rem' }}>
              <button className="btn btn-secondary" onClick={onCancel}>
                <i className="fas fa-times me-1"></i> Cancel
              </button>
              <button className="btn btn-secondary" onClick={onBack}>
                <i className="fas fa-arrow-left me-1"></i> Back
              </button>
            </div>
          )}
        </div>

        <div className="alert alert-info" role="alert">
          <i className="fas fa-info-circle me-2"></i>
          <strong>What's happening?</strong>
          <p className="mb-0 mt-2">
            The gateway is accepting the OOB invitation, creating a per-registry identity, and
            establishing a secure DIDComm connection with the trust registry. This may take a few
            seconds.
          </p>
        </div>
      </div>
    </div>
  );
};

export default ConnectingStep;
