import React, { useEffect, useRef, useState } from 'react';
import { apiClient } from '../../api';
import { AppButton } from '../shared/AppButton';

interface ConnectStepProps {
  oobLink: string;
  secret: string;
  name: string;
  description: string;
  didMethod?: string;
  onConnected: (gateway: any) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ConnectStep: React.FC<ConnectStepProps> = ({
  oobLink,
  secret,
  name,
  description,
  didMethod,
  onConnected,
  onBack,
  onCancel,
}) => {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);
  const [statusMessage, setStatusMessage] = useState('Initializing connection...');

  const connectCalledRef = useRef(false);

  useEffect(() => {
    if (connectCalledRef.current) return;
    connectCalledRef.current = true;
    connectToGateway();
  }, [oobLink]);

  const connectToGateway = async () => {
    try {
      setLoading(true);
      setError('');
      setProgress(10);
      setStatusMessage('Parsing connection point link...');

      await new Promise(resolve => setTimeout(resolve, 500));
      setProgress(30);
      setStatusMessage('Establishing DIDComm connection...');

      // Call the backend API to accept the OOB invitation and connect to the gateway
      const response = await apiClient.post('/gateways/connect-via-oob', {
        oob_url: oobLink,
        secret: secret,
        name: name,
        description: description,
        did_method: didMethod || 'web',
      });

      setProgress(70);
      setStatusMessage('Retrieving gateway details...');

      await new Promise(resolve => setTimeout(resolve, 500));
      setProgress(100);
      setStatusMessage('Connection established successfully!');

      // Wait a moment before transitioning
      await new Promise(resolve => setTimeout(resolve, 800));

      onConnected(response.data.gateway);
    } catch (err: any) {
      console.error('Failed to connect to gateway:', err);
      setError(
        err.response?.data?.error ||
          err.message ||
          'Failed to connect to gateway. Please check the link and try again.'
      );
      setLoading(false);
    }
  };

  const handleRetry = () => {
    connectToGateway();
  };

  return (
    <div className="card shadow">
      <div className="card-header py-3">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-plug me-2"></i> Connecting to Gateway
        </h6>
      </div>
      <div className="card-body">
        {error ? (
          <>
            <div className="alert alert-danger" role="alert">
              <i className="fas fa-exclamation-circle me-2"></i>
              <strong>Connection Failed</strong>
              <p className="mb-0 mt-2">{error}</p>
            </div>

            <div className="alert alert-info" role="alert">
              <i className="fas fa-info-circle me-2"></i>
              <strong>Troubleshooting Tips:</strong>
              <ul className="mb-0 mt-2">
                <li>Verify that the connection point link is correct and hasn't expired</li>
                <li>Ensure your network connection is stable</li>
                <li>Check that the gateway's mediator is accessible</li>
                <li>Contact the gateway owner if the problem persists</li>
              </ul>
            </div>

            <div className="d-flex justify-content-between mt-4">
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
          </>
        ) : (
          <>
            <div className="text-center py-5">
              <div className="mb-4">
                <div
                  className="spinner-border text-primary"
                  style={{ width: '3rem', height: '3rem' }}
                  role="status"
                >
                  <span className="visually-hidden"></span>
                </div>
              </div>

              <h5 className="mb-3">{statusMessage}</h5>

              <div className="progress mb-3" style={{ height: '25px' }}>
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

              <p className="text-muted small">
                <i className="fas fa-link me-2"></i>
                Connecting to: {new URL(oobLink).origin}
              </p>
            </div>

            <div className="alert alert-info" role="alert">
              <i className="fas fa-info-circle me-2"></i>
              <strong>What's happening?</strong>
              <p className="mb-0 mt-2">
                We're using the connection point link to establish a secure DIDComm connection with
                the gateway. This process authenticates both parties and sets up encrypted
                communication channels.
              </p>
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default ConnectStep;
