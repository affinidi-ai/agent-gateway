import React, { useMemo } from 'react';
import FieldHelp from '../../../components/shared/FieldHelp';
import { McpProxyFormData, ChannelPrefix } from '../types';
import {
  DirectAccessSwitch,
  FrontingSurface,
  SurfaceOnlyNotice,
} from '../../../components/mcp-proxy/exposure';

interface RoutingTabProps {
  formData: McpProxyFormData;
  handleChange: (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => void;
  availablePrefixes: ChannelPrefix[];
  availableListenAddresses: string[];
  selectedHostPort: string;
  onHostPortChange: (hostPort: string) => void;
  onDirectAccessChange: (directAccess: boolean) => void;
  frontingSurfaces: FrontingSurface[] | null;
}

export const RoutingTab: React.FC<RoutingTabProps> = ({
  formData,
  handleChange,
  availablePrefixes,
  availableListenAddresses,
  selectedHostPort,
  onHostPortChange,
  onDirectAccessChange,
  frontingSurfaces,
}) => {
  // Compute full route for display
  const fullRouteDisplay = useMemo(() => {
    if (selectedHostPort && formData.channel_prefix && formData.endpoint_path) {
      const normalizedPath = formData.endpoint_path.startsWith('/')
        ? formData.endpoint_path
        : `/${formData.endpoint_path}`;
      return `${selectedHostPort}${formData.channel_prefix}${normalizedPath}`;
    }
    return '(select address, prefix, and enter custom path)';
  }, [selectedHostPort, formData.channel_prefix, formData.endpoint_path]);

  return (
    <>
      {/* Proxy Route Info - only when the proxy has a route of its own */}
      {formData.direct_access ? (
        <div className="alert alert-success mb-3" style={{ fontSize: '14px' }}>
          <i className="fas fa-info-circle me-2"></i>
          <strong>Proxy Route:</strong> {fullRouteDisplay}
          <button
            type="button"
            className="btn btn-xs ms-2"
            style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
            onClick={e => {
              if (selectedHostPort && formData.channel_prefix && formData.endpoint_path) {
                const normalizedPath = formData.endpoint_path.startsWith('/')
                  ? formData.endpoint_path
                  : `/${formData.endpoint_path}`;
                navigator.clipboard.writeText(
                  `${selectedHostPort}${formData.channel_prefix}${normalizedPath}`
                );
                const btn = e.currentTarget as HTMLButtonElement;
                const originalHtml = btn.innerHTML;
                btn.innerHTML = '<i class="fas fa-check"></i>';
                setTimeout(() => {
                  btn.innerHTML = originalHtml;
                }, 2000);
              }
            }}
            title="Copy to clipboard"
          >
            <i className="fas fa-copy"></i>
          </button>
        </div>
      ) : (
        <SurfaceOnlyNotice surfaces={frontingSurfaces} />
      )}

      {/* Target Endpoint Info */}
      <div className="alert alert-info mb-3" style={{ fontSize: '14px' }}>
        <i className="fas fa-route me-2"></i>
        <strong>Target Endpoint:</strong> {formData.base_url || '(not configured)'}
        <button
          type="button"
          className="btn btn-xs ms-2"
          style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
          onClick={e => {
            if (formData.base_url) {
              navigator.clipboard.writeText(formData.base_url);
              const btn = e.currentTarget as HTMLButtonElement;
              const originalHtml = btn.innerHTML;
              btn.innerHTML = '<i class="fas fa-check"></i>';
              setTimeout(() => {
                btn.innerHTML = originalHtml;
              }, 2000);
            }
          }}
          title="Copy to clipboard"
          disabled={!formData.base_url}
        >
          <i className="fas fa-copy"></i>
        </button>
      </div>

      {/* Network Configuration */}
      <div className="card shadow mb-4">
        <div className="card-body">
          <h6 className="mb-3">
            <i className="fas fa-network-wired me-2"></i>
            Network Configuration
          </h6>
          <DirectAccessSwitch
            id="direct_access"
            checked={formData.direct_access}
            onChange={onDirectAccessChange}
          />
          {/* Disabled rather than hidden: the values are kept, and come back
              into use if the route is switched on again. */}
          <fieldset disabled={!formData.direct_access}>
            <div className="row">
              <div className="col-md-6 mb-3">
                <label className="form-label font-weight-bold">
                  Listen Address (Host:Port) <span className="text-danger">*</span>{' '}
                  <FieldHelp
                    testId="field-help-mcp-routing-listen-address"
                    ariaLabel="About Listen Address (Host:Port)"
                  >
                    Choose which network address the gateway listens on for calls to this proxy. We
                    pick one for you automatically, change it only if your setup needs a specific
                    address.
                  </FieldHelp>
                </label>
                <select
                  className="form-control dropdown-styling"
                  value={selectedHostPort}
                  onChange={e => onHostPortChange(e.target.value)}
                  disabled={availableListenAddresses.length === 0}
                >
                  {availableListenAddresses.length === 0 ? (
                    <option value="">No addresses available</option>
                  ) : (
                    <>
                      <option value="">-- Select listen address --</option>
                      {availableListenAddresses.map(addr => (
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
                    testId="field-help-mcp-routing-path-prefix"
                    ariaLabel="About Path Prefix"
                  >
                    Picks the shared base path this proxy&apos;s URL lives under, like choosing
                    which folder it&apos;s filed in. This list comes from this gateway&apos;s own
                    deployment configuration.
                  </FieldHelp>
                </label>
                <select
                  className="form-control dropdown-styling"
                  id="channel_prefix"
                  name="channel_prefix"
                  value={formData.channel_prefix}
                  onChange={handleChange}
                  disabled={availablePrefixes.length === 0}
                  required
                >
                  {availablePrefixes.length === 0 ? (
                    <option value="">No prefixes available</option>
                  ) : (
                    <>
                      <option value="">-- Select prefix --</option>
                      {availablePrefixes.map(prefix => (
                        <option key={prefix.id} value={prefix.prefix}>
                          {prefix.name}
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
                  id="endpoint_path"
                  name="endpoint_path"
                  value={
                    formData.endpoint_path.startsWith('/')
                      ? formData.endpoint_path.substring(1)
                      : formData.endpoint_path
                  }
                  onChange={e => {
                    const event = {
                      ...e,
                      target: { ...e.target, value: e.target.value, name: 'endpoint_path' },
                    };
                    handleChange(event as any);
                  }}
                  required
                  placeholder="my-mcp-endpoint"
                />
                <small className="form-text text-muted">
                  The last part of this proxy&apos;s web address (e.g. <code>my-api/v1</code>),
                  prefixed with {formData.channel_prefix || 'prefix'}/. Once saved, this becomes a
                  real URL other systems can call.
                </small>
              </div>
            </div>
          </fieldset>
        </div>
      </div>

      {/* Target Configuration */}
      <div className="card shadow mb-4">
        <div className="card-body">
          <h6 className="mb-3">
            <i className="fas fa-bullseye me-2"></i>
            Target Configuration
          </h6>
          <div className="mb-3">
            <label htmlFor="base_url">
              Base URL <span className="text-danger">*</span>{' '}
              <FieldHelp testId="field-help-mcp-routing-base-url" ariaLabel="About Base URL">
                The address of the real API behind this proxy. Every MCP tool call gets forwarded
                here.
              </FieldHelp>
            </label>
            <input
              type="url"
              className="form-control"
              id="base_url"
              name="base_url"
              value={formData.base_url}
              onChange={handleChange}
              required
              placeholder="https://api.example.com"
            />
            <small className="form-text text-muted">
              The real address of the API this proxy protects, e.g. https://api.example.com
            </small>
          </div>
        </div>
      </div>
    </>
  );
};

export default RoutingTab;
