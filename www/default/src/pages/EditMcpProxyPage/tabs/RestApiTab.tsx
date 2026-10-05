import React from 'react';
import FieldHelp from '../../../components/shared/FieldHelp';
import InfoBanner from '../../../components/shared/InfoBanner';
import { DOCS_URL } from '../../../config/docs';
import { McpProxyFormData, ValidationResult } from '../types';

interface RestApiTabProps {
  formData: McpProxyFormData;
  handleChange: (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement | HTMLSelectElement>
  ) => void;
  validationResult: ValidationResult | null;
  validating: boolean;
  handleValidate: () => Promise<void>;
}

export const RestApiTab: React.FC<RestApiTabProps> = ({
  formData,
  handleChange,
  validationResult,
  validating,
  handleValidate,
}) => {
  return (
    <>
      <InfoBanner
        title="Writing an OpenAPI specification"
        testIdPrefix="mcp-proxy-restapi"
        docLink={DOCS_URL.mcpProxy}
      >
        <p>
          OpenAPI is a standard way of describing what an API can do, and most API tools can export
          one automatically. Paste yours below; each operation in it becomes an MCP tool an AI agent
          can call.
        </p>
        <ul className="mb-0 small">
          <li>Must be valid YAML format</li>
          <li>Use OpenAPI 3.0.x specification</li>
          <li>Include all endpoints you want to expose as MCP tools</li>
          <li>Each operation will become an MCP tool that agents can call</li>
        </ul>
      </InfoBanner>

      <div className="mb-3">
        <label htmlFor="openapi_spec">
          OpenAPI Specification (YAML) <span className="text-danger">*</span>
          <small className="form-text text-muted">
            Paste your OpenAPI 3.0 specification in YAML format
          </small>
        </label>
        <textarea
          className="form-control font-monospace"
          id="openapi_spec"
          name="openapi_spec"
          value={formData.openapi_spec}
          onChange={handleChange}
          required
          rows={15}
          style={{ fontSize: '0.875rem' }}
          placeholder={`openapi: 3.0.0
info:
  title: My API
  version: 1.0.0
paths:
  /items:
    get:
      summary: List items
      responses:
        '200':
          description: Success`}
        />
      </div>

      <div className="mb-4">
        <div className="form-check">
          <input
            type="checkbox"
            className="form-check-input"
            id="flatten_post_params"
            name="flatten_post_params"
            checked={formData.flatten_post_params}
            onChange={handleChange}
          />
          <label className="form-check-label" htmlFor="flatten_post_params">
            <strong>Flatten POST Parameters</strong>{' '}
            <FieldHelp
              testId="field-help-mcp-restapi-flatten-post-params"
              ariaLabel="About Flatten POST Parameters"
            >
              Controls how this API&apos;s inputs are packaged for AI agents to use. Leave this off
              (the default) unless an agent integration tells you it expects flat, unwrapped
              parameters instead of a nested request body.
            </FieldHelp>
          </label>
        </div>
      </div>

      <div className="mb-3">
        <button
          type="button"
          className="btn btn-secondary"
          onClick={handleValidate}
          disabled={validating || !formData.openapi_spec || !formData.base_url}
        >
          {validating ? (
            <>
              <span
                className="spinner-border spinner-border-sm me-2"
                role="status"
                aria-hidden="true"
              ></span>
              Validating...
            </>
          ) : (
            <>
              <i className="fas fa-check-circle me-2"></i>
              Validate Specification
            </>
          )}
        </button>
        <small className="form-text text-muted d-block mt-1">
          Checks that your spec is valid. This doesn&apos;t test that your API is actually
          reachable, try the Sandbox tab after saving for that.
        </small>

        {validationResult && (
          <div
            className={`alert mt-3 ${validationResult.valid ? 'alert-success' : 'alert-danger'}`}
          >
            {validationResult.valid ? (
              <>
                <i className="fas fa-check-circle me-2"></i>
                <strong>Valid!</strong>
                {validationResult.tools_count !== undefined && validationResult.tools_count > 0 && (
                  <span> Found {validationResult.tools_count} tool(s).</span>
                )}
              </>
            ) : (
              <>
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Invalid:</strong> {validationResult.error}
              </>
            )}
          </div>
        )}
      </div>
    </>
  );
};

export default RestApiTab;
