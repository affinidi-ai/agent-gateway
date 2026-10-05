import React, { useState } from 'react';
import { DOCS_URL } from '../../config/docs';

interface NameStepProps {
  initialName?: string;
  initialDescription?: string;
  onNext: (name: string, description: string) => void;
  onCancel: () => void;
}

const NameStep: React.FC<NameStepProps> = ({
  initialName = '',
  initialDescription = '',
  onNext,
  onCancel,
}) => {
  const [name, setName] = useState(initialName);
  const [description, setDescription] = useState(initialDescription);
  const [error, setError] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');

    if (!name.trim()) {
      setError('Please enter a name for the MCP Proxy');
      return;
    }

    onNext(name.trim(), description.trim());
  };

  return (
    <div className="card shadow">
      <div className="card-body">
        <div className="welcome-screen">
          <h2>Add New MCP Proxy</h2>
          <p>
            The Model Context Protocol (MCP) lets AI assistants like Claude, Copilot, or ChatGPT
            call your API safely, using a standard every AI tool understands. This proxy reads your
            OpenAPI specification and automatically converts it into MCP tools those agents can call
            directly.
          </p>
          <div className="surface-info-panel-doclink">
            <a href={DOCS_URL.mcpProxy} target="_blank" rel="noopener noreferrer">
              Learn more about MCP Proxies{' '}
              <i className="fas fa-arrow-right ms-1" aria-hidden="true" />
            </a>
          </div>

          {error && <div className="alert alert-danger">{error}</div>}

          <form onSubmit={handleSubmit}>
            <div className="mb-3">
              <label htmlFor="name">
                Give your MCP Proxy a name to help identify it in the Gateway.{' '}
                <span className="text-danger">*</span>
              </label>
              <input
                type="text"
                className="form-control"
                id="name"
                value={name}
                onChange={e => setName(e.target.value)}
                placeholder="e.g., My REST API Service"
                autoFocus
              />
            </div>

            <div className="mb-3">
              <label htmlFor="description">
                Provide an optional description that reminds you of what the proxy does
              </label>
              <input
                className="form-control"
                id="description"
                value={description}
                onChange={e => setDescription(e.target.value)}
                placeholder="Optional description of what this proxy does..."
              />
            </div>

            <div className="d-flex justify-content-between mt-4">
              <button type="button" className="btn btn-secondary" onClick={onCancel}>
                <i className="fas fa-times me-1"></i>
                Cancel
              </button>
              <button type="submit" className="btn btn-primary" disabled={!name.trim()}>
                Next
                <i className="fas fa-arrow-right ms-1"></i>
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default NameStep;
