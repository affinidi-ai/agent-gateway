import React from 'react';
import InfoBanner from '../../../components/shared/InfoBanner';
import { DOCS_URL } from '../../../config/docs';
import { McpProxyFormData } from '../types';
import {
  FrontingSurface,
  ManagedByBanner,
  SurfaceOnlyNotice,
} from '../../../components/mcp-proxy/exposure';

interface OverviewTabProps {
  formData: McpProxyFormData;
  handleChange: (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => void;
  isEditMode: boolean;
  frontingSurfaces: FrontingSurface[] | null;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  formData,
  handleChange,
  isEditMode,
  frontingSurfaces,
}) => {
  return (
    <>
      {formData.managed_by ? <ManagedByBanner managedBy={formData.managed_by} /> : null}

      <InfoBanner
        title="What is an MCP Proxy?"
        testIdPrefix="mcp-proxy-overview"
        docLink={DOCS_URL.mcpProxy}
      >
        <p className="mb-0">
          AI assistants like Claude, Copilot, or ChatGPT can&apos;t call a REST API out of the box.
          The Model Context Protocol (MCP) fixes that by turning your API into tools an AI agent can
          call directly. This proxy reads the OpenAPI specification you provide and automatically
          generates one MCP tool per endpoint, so agents can use your backend without any manual
          mapping.
        </p>
      </InfoBanner>

      {/* Proxy Route Info - only when the proxy has a route of its own */}
      {formData.direct_access ? (
        <div className="alert alert-success mb-3" style={{ fontSize: '14px' }}>
          <i className="fas fa-info-circle me-2"></i>
          <strong>Proxy Route:</strong> {window.location.origin}
          {formData.channel_prefix || '(select prefix)'}
          {formData.endpoint_path || '/(enter path)'}
          <button
            type="button"
            className="btn btn-xs ms-2"
            style={{ padding: '2px 6px', fontSize: '11px', outline: 'none' }}
            onClick={e => {
              navigator.clipboard.writeText(
                `${window.location.origin}${formData.channel_prefix || '(select prefix)'}${formData.endpoint_path || '/(enter path)'}`
              );
              const btn = e.currentTarget as HTMLButtonElement;
              const originalHtml = btn.innerHTML;
              btn.innerHTML = '<i class="fas fa-check"></i>';
              setTimeout(() => {
                btn.innerHTML = originalHtml;
              }, 2000);
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

      <div className="mb-3">
        <label htmlFor="name">
          Name <span className="text-danger">*</span>
        </label>
        <input
          type="text"
          className="form-control"
          id="name"
          name="name"
          value={formData.name}
          onChange={handleChange}
          required
          placeholder="e.g., My API Proxy"
        />
        <small className="form-text text-muted">
          Give your MCP Proxy a name to help identify it in the Gateway.
        </small>
      </div>

      <div className="mb-3">
        <label htmlFor="description">Description</label>
        <input
          className="form-control"
          id="description"
          name="description"
          value={formData.description}
          onChange={handleChange}
          placeholder="A brief description of this MCP Proxy"
        />
        <small className="form-text text-muted">
          Provide an optional description that reminds you of what the proxy does.
        </small>
      </div>

      {isEditMode && (
        <div className="mb-4">
          <div className="form-check">
            <input
              type="checkbox"
              className="form-check-input"
              id="enabled"
              name="enabled"
              checked={formData.status === 'active'}
              onChange={handleChange}
            />
            <label className="form-check-label" htmlFor="enabled">
              <strong>MCP Proxy Enabled</strong> - When unchecked, this MCP Proxy will be stopped
              and not loaded at startup
            </label>
          </div>
        </div>
      )}
    </>
  );
};

export default OverviewTab;
