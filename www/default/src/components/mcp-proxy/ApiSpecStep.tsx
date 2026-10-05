import React, { useState } from 'react';
import { validateOpenApiSpecBasic, isYamlFile } from '../../utils/yamlValidation';

interface ApiSpecStepProps {
  initialSpec?: string;
  baseUrl: string;
  onNext: (openApiSpec: string) => void;
  onBack: () => void;
  onCancel: () => void;
}

const ApiSpecStep: React.FC<ApiSpecStepProps> = ({
  initialSpec = '',
  baseUrl,
  onNext,
  onBack,
  onCancel,
}) => {
  const [openApiSpec, setOpenApiSpec] = useState(initialSpec);
  const [error, setError] = useState('');
  const [validating, setValidating] = useState(false);
  const [isDragging, setIsDragging] = useState(false);

  const exampleSpec = `openapi: 3.0.0
info:
  title: Example API
  version: 1.0.0
servers:
  - url: ${baseUrl}
paths:
  /users:
    get:
      summary: List users
      operationId: listUsers
      responses:
        '200':
          description: Successful response
          content:
            application/json:
              schema:
                type: array
                items:
                  type: object`;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!openApiSpec.trim()) {
      setError('Please enter an OpenAPI specification');
      return;
    }

    // Validate using shared utility
    try {
      setValidating(true);

      const validationResult = validateOpenApiSpecBasic(openApiSpec);
      if (!validationResult.valid) {
        setError(validationResult.error || 'Invalid OpenAPI specification');
        setValidating(false);
        return;
      }

      onNext(openApiSpec.trim());
    } catch (err: any) {
      setError(err.message || 'Failed to validate OpenAPI specification');
    } finally {
      setValidating(false);
    }
  };

  const handleFileRead = (file: File) => {
    const reader = new FileReader();
    reader.onload = e => {
      const content = e.target?.result as string;
      setOpenApiSpec(content);
      setError('');
    };
    reader.onerror = () => {
      setError('Failed to read file');
    };
    reader.readAsText(file);
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length === 0) return;

    const file = files[0];
    const fileName = file.name.toLowerCase();

    // Check file extension using shared utility
    if (!isYamlFile(fileName)) {
      setError('Only .txt, .yml, or .yaml files are accepted');
      return;
    }

    handleFileRead(file);
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files && files.length > 0) {
      handleFileRead(files[0]);
    }
  };

  return (
    <div className="card shadow">
      <div className="card-body">
        <h4 className="mb-3">
          <i className="fas fa-file-code me-2"></i>
          OpenAPI Specification
        </h4>

        <p className="text-muted mb-4">
          OpenAPI is a standard way of describing what an API can do, and most API tools can export
          one automatically. Paste yours below; each operation in it becomes an MCP tool an AI agent
          can call.
        </p>

        {error && <div className="alert alert-danger">{error}</div>}

        <form onSubmit={handleSubmit}>
          <div className="mb-3">
            <label htmlFor="openApiSpec">
              OpenAPI Spec (YAML) <span className="text-danger">*</span>
            </label>
            <div
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onDrop={handleDrop}
              style={{
                border: isDragging ? '2px dashed var(--accent-blue)' : '2px dashed transparent',
                borderRadius: '0.375rem',
                backgroundColor: isDragging ? 'rgba(74, 144, 226, 0.08)' : 'transparent',
                padding: '0.25rem',
                transition: 'all 0.2s ease',
              }}
            >
              <textarea
                className="form-control font-monospace"
                id="openApiSpec"
                rows={15}
                value={openApiSpec}
                onChange={e => setOpenApiSpec(e.target.value)}
                placeholder="Paste your OpenAPI 3.0 specification in YAML format..."
                style={{ fontSize: '0.85rem', border: 'none', backgroundColor: '#ffffff' }}
                autoFocus
              />
            </div>
            <small className="form-text text-muted">
              Paste your OpenAPI 3.0 specification in YAML format, or drag and drop a .txt, .yml, or
              .yaml file here.
            </small>
          </div>

          <div className="alert alert-info mt-3">
            <h6 className="font-weight-bold mb-2">
              <i className="fas fa-lightbulb me-2"></i>
              Tips
            </h6>
            <ul className="mb-0 small">
              <li>Must be valid YAML format</li>
              <li>Use OpenAPI 3.0.x specification</li>
              <li>Include all endpoints you want to expose as MCP tools</li>
              <li>Each operation will become an MCP tool that agents can call</li>
            </ul>
          </div>

          <div className="d-flex justify-content-between mt-4">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={onBack}
              disabled={validating}
            >
              <i className="fas fa-arrow-left me-1"></i>
              Back
            </button>
            <button type="submit" className="btn btn-primary" disabled={validating}>
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
                  Next
                  <i className="fas fa-arrow-right ms-1"></i>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export default ApiSpecStep;
