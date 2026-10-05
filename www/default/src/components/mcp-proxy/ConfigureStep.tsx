import React, { useState, useEffect, useMemo } from 'react';
import FieldHelp from '../shared/FieldHelp';
import { showToast } from '../../utils/toaster';
import { generateRandomPath } from '../../utils/stringUtils';
import { apiClient } from '../../api';
import { validateUrl } from '../../utils/urlValidation';
import { DirectAccessSwitch } from './exposure';

interface ChannelPrefixInfo {
  id: string;
  name: string;
  prefix: string;
}

interface ChannelRoutingConfig {
  available_listen_addresses: string[];
  mcp_proxy_path_prefix: ChannelPrefixInfo[];
}

interface ConfigureStepProps {
  initialSelectedHostPort?: string;
  initialSelectedPrefix?: string;
  initialCustomPath?: string;
  initialBaseUrl?: string;
  initialDirectAccess?: boolean;
  onNext: (
    selectedHostPort: string,
    selectedPrefix: string,
    customPath: string,
    baseUrl: string,
    directAccess: boolean
  ) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ConfigureStep: React.FC<ConfigureStepProps> = ({
  initialSelectedHostPort = '',
  initialSelectedPrefix = '',
  initialCustomPath = '',
  initialBaseUrl = '',
  initialDirectAccess = true,
  onNext,
  onBack,
  onCancel,
}) => {
  const [routingConfig, setRoutingConfig] = useState<ChannelRoutingConfig | null>(null);
  const [selectedHostPort, setSelectedHostPort] = useState<string>(initialSelectedHostPort);
  const [selectedPrefix, setSelectedPrefix] = useState<string>(initialSelectedPrefix);
  const [customPath, setCustomPath] = useState<string>(initialCustomPath || generateRandomPath());
  const [baseUrl, setBaseUrl] = useState(initialBaseUrl);
  const [directAccess, setDirectAccess] = useState(initialDirectAccess);
  const [error, setError] = useState('');

  // Compute full route for display
  const fullRouteDisplay = useMemo(() => {
    if (selectedHostPort && selectedPrefix && customPath && customPath.trim()) {
      const normalizedPath = customPath.startsWith('/') ? customPath : `/${customPath}`;
      return `${selectedHostPort}${selectedPrefix}${normalizedPath}`;
    }
    return '(select address, prefix, and enter custom path)';
  }, [selectedHostPort, selectedPrefix, customPath]);

  // Fetch routing configuration on mount
  useEffect(() => {
    const fetchRoutingConfig = async () => {
      try {
        const response = await apiClient.fetch('/api/v1/config/surface-routing');
        if (!response.ok) {
          throw new Error('Failed to fetch routing configuration');
        }
        const config: ChannelRoutingConfig = await response.json();
        setRoutingConfig(config);

        // Auto-select first options if not already set
        if (!initialSelectedHostPort && config.available_listen_addresses.length > 0) {
          setSelectedHostPort(config.available_listen_addresses[0]);
        }
        if (!initialSelectedPrefix && config.mcp_proxy_path_prefix.length > 0) {
          setSelectedPrefix(config.mcp_proxy_path_prefix[0].prefix);
        }
      } catch (error: any) {
        showToast('error', error.message || 'Failed to load routing configuration');
      }
    };

    fetchRoutingConfig();
  }, [initialSelectedHostPort, initialSelectedPrefix]);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    // The listen address only builds the displayed route, which a surface-only
    // proxy does not have.
    if (directAccess && !selectedHostPort) {
      setError('Please select a listen address');
      return;
    }

    if (!selectedPrefix) {
      setError('Please select a path prefix');
      return;
    }

    if (!customPath.trim()) {
      setError('Please enter a custom endpoint path');
      return;
    }

    if (!baseUrl.trim()) {
      setError('Please enter the base URL');
      return;
    }

    // Validate URL format
    const baseCheck = validateUrl(baseUrl);
    if (!baseCheck.valid) {
      setError(`Base URL: ${baseCheck.error}`);
      return;
    }

    // Normalize endpoint path - automatically add leading slash if missing
    const normalizedPath = customPath.trim().startsWith('/')
      ? customPath.trim()
      : `/${customPath.trim()}`;

    onNext(selectedHostPort, selectedPrefix, normalizedPath, baseUrl.trim(), directAccess);
  };

  return (
    <div className="card shadow">
      <div className="card-body">
        <h4 className="mb-3">
          <i className="fas fa-cog me-2"></i>
          Configure Connection
        </h4>

        <p className="text-muted mb-4">
          Configure the network settings and backend URL for your MCP proxy.
        </p>

        {error && <div className="alert alert-danger">{error}</div>}

        <form onSubmit={handleSubmit}>
          {/* Network Configuration */}
          <div className="card shadow mb-4">
            <div className="card-body">
              <h6 className="mb-3">
                <i className="fas fa-network-wired me-2"></i>
                Network Configuration
              </h6>
              <DirectAccessSwitch
                id="wizard-direct-access"
                checked={directAccess}
                onChange={setDirectAccess}
              />
              <fieldset disabled={!directAccess}>
                <div className="row">
                  <div className="col-md-6 mb-3">
                    <label className="form-label font-weight-bold">
                      Listen Address (Host:Port) <span className="text-danger">*</span>{' '}
                      <FieldHelp
                        testId="field-help-mcp-configure-listen-address"
                        ariaLabel="About Listen Address (Host:Port)"
                      >
                        Choose which network address the gateway listens on for calls to this proxy.
                        We pick one for you automatically, change it only if your setup needs a
                        specific address.
                      </FieldHelp>
                    </label>
                    <select
                      className="form-control dropdown-styling"
                      value={selectedHostPort}
                      onChange={e => setSelectedHostPort(e.target.value)}
                      disabled={
                        !routingConfig || routingConfig.available_listen_addresses.length === 0
                      }
                    >
                      {!routingConfig ? (
                        <option value="">Loading...</option>
                      ) : routingConfig.available_listen_addresses.length === 0 ? (
                        <option value="">No addresses available</option>
                      ) : (
                        <>
                          <option value="">-- Select listen address --</option>
                          {routingConfig.available_listen_addresses.map(addr => (
                            <option key={addr} value={addr}>
                              {addr}
                            </option>
                          ))}
                        </>
                      )}
                    </select>
                  </div>

                  <div className="col-md-6 mb-3">
                    <label className="form-label font-weight-bold">
                      Path Prefix <span className="text-danger">*</span>{' '}
                      <FieldHelp
                        testId="field-help-mcp-configure-path-prefix"
                        ariaLabel="About Path Prefix"
                      >
                        Picks the shared base path this proxy&apos;s URL lives under, like choosing
                        which folder it&apos;s filed in. This list comes from this gateway&apos;s
                        own deployment configuration.
                      </FieldHelp>
                    </label>
                    <select
                      className="form-control dropdown-styling"
                      value={selectedPrefix}
                      onChange={e => setSelectedPrefix(e.target.value)}
                      disabled={!routingConfig || routingConfig.mcp_proxy_path_prefix.length === 0}
                    >
                      {!routingConfig ? (
                        <option value="">Loading...</option>
                      ) : routingConfig.mcp_proxy_path_prefix.length === 0 ? (
                        <option value="">No prefixes available</option>
                      ) : (
                        <>
                          <option value="">-- Select prefix --</option>
                          {routingConfig.mcp_proxy_path_prefix.map(item => (
                            <option key={item.id} value={item.prefix}>
                              {item.name}
                            </option>
                          ))}
                        </>
                      )}
                    </select>
                  </div>
                </div>

                <div className="row">
                  <div className="col-md-12 mb-3">
                    <label className="form-label font-weight-bold">
                      Custom Endpoint Path <span className="text-danger">*</span>
                    </label>
                    <input
                      type="text"
                      className="form-control"
                      value={customPath.startsWith('/') ? customPath.substring(1) : customPath}
                      onChange={e => setCustomPath(e.target.value)}
                      placeholder="my-mcp-endpoint"
                    />
                    <small className="form-text text-muted">
                      The unique last part of this proxy&apos;s web address, prefixed with{' '}
                      {selectedPrefix || 'prefix'}/. We&apos;ve filled in a random placeholder path
                      so you can save right away. Change it to something memorable before sharing
                      this proxy&apos;s URL with anyone.
                    </small>
                  </div>
                </div>
              </fieldset>
              {directAccess ? (
                <div className="alert alert-info" style={{ fontSize: '16px' }}>
                  <i className="fas fa-info-circle me-2"></i>
                  <strong>MCP Proxy Route:</strong> {fullRouteDisplay}
                </div>
              ) : null}
            </div>
          </div>

          {/* Backend Configuration */}
          <div className="mb-3">
            <label htmlFor="baseUrl">
              Base URL <span className="text-danger">*</span>
            </label>
            <input
              type="url"
              className="form-control"
              id="baseUrl"
              value={baseUrl}
              onChange={e => setBaseUrl(e.target.value)}
              placeholder="https://api.example.com"
            />
            <small className="form-text text-muted">
              The real address of the API this proxy protects (e.g. https://api.example.com). The
              gateway forwards every tool call here.
            </small>
          </div>

          <div className="d-flex justify-content-between mt-4">
            <button type="button" className="btn btn-secondary" onClick={onBack}>
              <i className="fas fa-arrow-left me-1"></i>
              Back
            </button>
            <button type="submit" className="btn btn-primary">
              Next
              <i className="fas fa-arrow-right ms-1"></i>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ConfigureStep;
