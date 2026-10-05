import React, { useState } from 'react';
import FieldHelp from '../shared/FieldHelp';
import { fieldHasMissingVariables } from '../../utils/fieldValidation';

export interface StreamConfiguration {
  platform: string;
  topic: string;
  brokers?: string;
  region?: string;
  redis_url?: string;
  auth_type?: string;
  sasl_username?: string;
  sasl_password?: string;
  access_key?: string;
  secret_key?: string;
}

export interface StreamContent {
  [key: string]: any;
}

interface StreamIntegrationFormProps {
  configuration: StreamConfiguration;
  content: StreamContent;
  onConfigurationChange: (config: StreamConfiguration) => void;
  onContentChange: (content: StreamContent) => void;
  disabled?: boolean;
  validRuntimeVars?: Set<string>;
}

const StreamIntegrationForm: React.FC<StreamIntegrationFormProps> = ({
  configuration,
  content,
  onConfigurationChange,
  onContentChange,
  disabled = false,
  validRuntimeVars = new Set(),
}) => {
  const [platform, setPlatform] = useState(configuration.platform || 'kafka');
  const [topic, setTopic] = useState(configuration.topic || '');
  const [brokers, setBrokers] = useState(configuration.brokers || '');
  const [region, setRegion] = useState(configuration.region || '');
  const [redisUrl, setRedisUrl] = useState(configuration.redis_url || '');
  const [authType, setAuthType] = useState(configuration.auth_type || 'none');
  const [saslUsername, setSaslUsername] = useState(configuration.sasl_username || '');
  const [saslPassword, setSaslPassword] = useState(configuration.sasl_password || '');
  const [accessKey, setAccessKey] = useState(configuration.access_key || '');
  const [secretKey, setSecretKey] = useState(configuration.secret_key || '');

  const [payloadTemplate, setPayloadTemplate] = useState(JSON.stringify(content, null, 2));
  const [payloadError, setPayloadError] = useState('');

  // console.log('[StreamIntegrationForm] Rendering with topic:', topic, 'disabled:', disabled);

  // Build configuration object from current state
  const buildConfiguration = (
    overrides: Partial<{
      platform: string;
      topic: string;
      brokers: string;
      region: string;
      redisUrl: string;
      authType: string;
      saslUsername: string;
      saslPassword: string;
      accessKey: string;
      secretKey: string;
    }> = {}
  ): StreamConfiguration => {
    const currentPlatform = overrides.platform ?? platform;
    const currentTopic = overrides.topic ?? topic;
    const currentBrokers = overrides.brokers ?? brokers;
    const currentRegion = overrides.region ?? region;
    const currentRedisUrl = overrides.redisUrl ?? redisUrl;
    const currentAuthType = overrides.authType ?? authType;
    const currentSaslUsername = overrides.saslUsername ?? saslUsername;
    const currentSaslPassword = overrides.saslPassword ?? saslPassword;
    const currentAccessKey = overrides.accessKey ?? accessKey;
    const currentSecretKey = overrides.secretKey ?? secretKey;

    const config: StreamConfiguration = {
      platform: currentPlatform,
      topic: currentTopic,
    };

    if (currentPlatform === 'kafka' || currentPlatform === 'pulsar') {
      if (currentBrokers) config.brokers = currentBrokers;
      if (currentAuthType !== 'none') {
        config.auth_type = currentAuthType;
        if (currentAuthType === 'sasl' && currentSaslUsername) {
          config.sasl_username = currentSaslUsername;
          config.sasl_password = currentSaslPassword;
        }
      }
    } else if (currentPlatform === 'kinesis') {
      if (currentRegion) config.region = currentRegion;
      if (currentAccessKey) {
        config.access_key = currentAccessKey;
        config.secret_key = currentSecretKey;
      }
    } else if (currentPlatform === 'redis') {
      if (currentRedisUrl) config.redis_url = currentRedisUrl;
    }

    return config;
  };

  const handlePayloadTemplateChange = (value: string) => {
    setPayloadTemplate(value);
    try {
      const parsed = JSON.parse(value);
      setPayloadError('');
      onContentChange(parsed);
    } catch (e) {
      setPayloadError('Invalid JSON');
    }
  };

  return (
    <div className="stream-integration-form">
      {/* Configuration Section */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-cog me-2"></i>
            Stream Configuration
          </h6>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label className="form-label">
              Streaming Platform <span className="text-danger">*</span>{' '}
              <FieldHelp testId="field-help-stream-platform" ariaLabel="About Streaming Platform">
                Pick whichever platform your infrastructure team already runs. Kafka and Pulsar call
                the destination a topic, Kinesis and Redis Streams call it a stream, both mean the
                same thing here.
              </FieldHelp>
            </label>
            <select
              className="form-control dropdown-styling"
              value={platform}
              onChange={e => {
                const newPlatform = e.target.value;
                setPlatform(newPlatform);
                onConfigurationChange(buildConfiguration({ platform: newPlatform }));
              }}
              disabled={disabled}
              required
            >
              <option value="kafka">Apache Kafka</option>
              <option value="kinesis">AWS Kinesis</option>
              <option value="pulsar">Apache Pulsar</option>
              <option value="redis">Redis Streams</option>
            </select>
            <small className="form-text text-muted">The streaming platform to send events to</small>
          </div>

          <div className="mb-3">
            <label className="form-label">
              Topic/Stream Name <span className="text-danger">*</span>
            </label>
            <input
              type="text"
              className={`form-control ${!topic.trim() ? 'is-invalid' : ''}`}
              value={topic}
              data-testid="stream-topic-input"
              onChange={e => {
                const newTopic = e.target.value;
                // console.log('[StreamIntegrationForm] Topic changed to:', newTopic);
                setTopic(newTopic);
                onConfigurationChange(buildConfiguration({ topic: newTopic }));
              }}
              disabled={disabled}
              required
            />
            {!topic.trim() && <div className="invalid-feedback">Topic/Stream Name is required</div>}
            <small className="form-text text-muted">
              The {platform === 'redis' ? 'stream' : 'topic'} name to publish events to
            </small>
          </div>

          {/* Kafka/Pulsar specific fields */}
          {(platform === 'kafka' || platform === 'pulsar') && (
            <>
              <div className="mb-3">
                <label className="form-label">
                  Broker URLs <span className="text-danger">*</span>{' '}
                  <FieldHelp testId="field-help-stream-brokers" ariaLabel="About Broker URLs">
                    A broker is one server in your Kafka/Pulsar cluster. List more than one so the
                    integration can still connect if any single broker is down.
                  </FieldHelp>
                </label>
                <input
                  type="text"
                  className={`form-control ${(platform === 'kafka' || platform === 'pulsar') && !brokers.trim() ? 'is-invalid' : ''}`}
                  value={brokers}
                  data-testid="stream-brokers-input"
                  onChange={e => {
                    const newBrokers = e.target.value;
                    setBrokers(newBrokers);
                    onConfigurationChange(buildConfiguration({ brokers: newBrokers }));
                  }}
                  disabled={disabled}
                  required
                />
                <small className="form-text text-muted">
                  Comma-separated list of broker addresses
                </small>
              </div>

              <div className="mb-3">
                <label className="form-label">
                  Authentication Type{' '}
                  <FieldHelp
                    testId="field-help-stream-auth-type"
                    ariaLabel="About Authentication Type"
                  >
                    SASL/PLAIN sends a username and password to authenticate with the broker. Choose
                    None only if your cluster doesn't require authentication (uncommon outside local
                    development).
                  </FieldHelp>
                </label>
                <select
                  className="form-control dropdown-styling"
                  value={authType}
                  onChange={e => {
                    const newAuthType = e.target.value;
                    setAuthType(newAuthType);
                    onConfigurationChange(buildConfiguration({ authType: newAuthType }));
                  }}
                  disabled={disabled}
                >
                  <option value="none">None</option>
                  <option value="sasl">SASL/PLAIN</option>
                </select>
              </div>

              {authType === 'sasl' && (
                <>
                  <div className="mb-3">
                    <label className="form-label">SASL Username</label>
                    <input
                      type="text"
                      className="form-control"
                      value={saslUsername}
                      onChange={e => {
                        const newUsername = e.target.value;
                        setSaslUsername(newUsername);
                        onConfigurationChange(buildConfiguration({ saslUsername: newUsername }));
                      }}
                      placeholder="kafka-user"
                      disabled={disabled}
                    />
                  </div>
                  <div className="mb-3">
                    <label className="form-label">SASL Password</label>
                    <input
                      type="password"
                      className="form-control"
                      value={saslPassword}
                      onChange={e => {
                        const newPassword = e.target.value;
                        setSaslPassword(newPassword);
                        onConfigurationChange(buildConfiguration({ saslPassword: newPassword }));
                      }}
                      placeholder="••••••••"
                      disabled={disabled}
                    />
                  </div>
                </>
              )}
            </>
          )}

          {/* Kinesis specific fields */}
          {platform === 'kinesis' && (
            <>
              <div className="mb-3">
                <label className="form-label">
                  AWS Region <span className="text-danger">*</span>
                </label>
                <input
                  type="text"
                  className={`form-control ${platform === 'kinesis' && !region.trim() ? 'is-invalid' : ''}`}
                  value={region}
                  onChange={e => {
                    const newRegion = e.target.value;
                    setRegion(newRegion);
                    onConfigurationChange(buildConfiguration({ region: newRegion }));
                  }}
                  disabled={disabled}
                  required
                />
                <small className="form-text text-muted">
                  AWS region where the Kinesis stream is located
                </small>
              </div>

              <div className="mb-3">
                <label className="form-label">
                  AWS Access Key{' '}
                  <span className="text-muted">(Optional - uses IAM role if not provided)</span>{' '}
                  <FieldHelp testId="field-help-stream-access-key" ariaLabel="About AWS Access Key">
                    An IAM role is AWS's built-in way to grant this gateway permission without a
                    stored key or secret. Leave this blank if the gateway is already running with a
                    role that can write to Kinesis.
                  </FieldHelp>
                </label>
                <input
                  type="text"
                  className="form-control"
                  value={accessKey}
                  onChange={e => {
                    const newAccessKey = e.target.value;
                    setAccessKey(newAccessKey);
                    onConfigurationChange(buildConfiguration({ accessKey: newAccessKey }));
                  }}
                  placeholder="AKIAIOSFODNN7EXAMPLE"
                  disabled={disabled}
                />
              </div>

              <div className="mb-3">
                <label className="form-label">AWS Secret Key</label>
                <input
                  type="password"
                  className="form-control"
                  value={secretKey}
                  onChange={e => {
                    const newSecretKey = e.target.value;
                    setSecretKey(newSecretKey);
                    onConfigurationChange(buildConfiguration({ secretKey: newSecretKey }));
                  }}
                  placeholder="••••••••"
                  disabled={disabled}
                />
              </div>
            </>
          )}

          {/* Redis specific fields */}
          {platform === 'redis' && (
            <div className="mb-3">
              <label className="form-label">
                Redis URL <span className="text-danger">*</span>{' '}
                <FieldHelp testId="field-help-stream-redis-url" ariaLabel="About Redis URL">
                  Use redis:// for a plain connection, or rediss:// (with two s's) for a
                  TLS-encrypted one.
                </FieldHelp>
              </label>
              <input
                type="text"
                className={`form-control ${platform === 'redis' && !redisUrl.trim() ? 'is-invalid' : ''}`}
                value={redisUrl}
                onChange={e => {
                  const newRedisUrl = e.target.value;
                  setRedisUrl(newRedisUrl);
                  onConfigurationChange(buildConfiguration({ redisUrl: newRedisUrl }));
                }}
                disabled={disabled}
                required
              />
              <small className="form-text text-muted">
                Redis connection URL (supports redis:// and rediss:// protocols)
              </small>
            </div>
          )}
        </div>
      </div>

      {/* Content Template Section */}
      <div className="card shadow mb-4">
        <div className="card-header py-3">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-file-code me-2"></i>
            Content Template (JSON)
          </h6>
        </div>
        <div className="card-body">
          <div className="mb-3">
            <label className="form-label">
              Event Payload Template <span className="text-danger">*</span>
            </label>
            <textarea
              className={`form-control font-monospace ${payloadError || fieldHasMissingVariables(payloadTemplate, validRuntimeVars) ? 'is-invalid' : ''}`}
              rows={18}
              value={payloadTemplate}
              data-testid="stream-payload-template"
              onChange={e => handlePayloadTemplateChange(e.target.value)}
              style={{ fontSize: '0.875rem' }}
              disabled={disabled}
              required
            />
            {payloadError && <div className="invalid-feedback">{payloadError}</div>}
            <small className="form-text text-muted">
              <i className="fas fa-code me-1"></i>
              JSON template for events published to the stream. Use variables like{' '}
              <code>
                ${'{'}EVENT_TYPE{'}'}
              </code>{' '}
              or{' '}
              <code>
                ${'{'}CP_NAME:Label{'}'}
              </code>{' '}
              for runtime substitution.
            </small>
          </div>
        </div>
      </div>
    </div>
  );
};

export default StreamIntegrationForm;
