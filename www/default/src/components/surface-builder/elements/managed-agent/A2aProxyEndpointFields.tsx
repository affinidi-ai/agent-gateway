import React from 'react';
import { Form } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';

export interface A2aProxyOption {
  id: string;
  name: string;
  status?: 'active' | 'disabled';
}

interface A2aProxyEndpointFieldsProps {
  selectedProxyId?: string;
  a2aProxies: A2aProxyOption[];
  updateFields: (fields: Record<string, unknown>) => void;
}

const A2aProxyEndpointFields: React.FC<A2aProxyEndpointFieldsProps> = ({
  selectedProxyId = '',
  a2aProxies,
  updateFields,
}) => {
  const navigate = useNavigate();
  const selectedA2aProxy = a2aProxies.find(proxy => proxy.id === selectedProxyId);

  return (
    <>
      <Form.Group className="mb-2">
        <Form.Label className="small text-muted mb-1">A2A Proxy</Form.Label>
        <Form.Select
          size="sm"
          data-testid="managed-agent-a2a-proxy-select"
          value={selectedProxyId}
          onChange={e => {
            const id = e.target.value;
            updateFields({
              a2a_proxy_id: id,
              endpoint: id ? `a2a-proxy://${id}` : '',
            });
          }}
        >
          <option value="">Select an A2A proxy…</option>
          {a2aProxies.map(proxy => (
            <option key={proxy.id} value={proxy.id}>
              {proxy.name || proxy.id}
              {proxy.status === 'disabled' ? ' (disabled)' : ''}
            </option>
          ))}
          {selectedProxyId && !a2aProxies.some(proxy => proxy.id === selectedProxyId) && (
            <option value={selectedProxyId}>{selectedProxyId} (not found)</option>
          )}
        </Form.Select>
        <Form.Text className="text-muted" style={{ fontSize: '10px' }}>
          Managed A2A proxy that adapts this surface to a non-A2A backend.
        </Form.Text>
      </Form.Group>
      <div
        className="alert alert-info py-2 mb-2"
        style={{ fontSize: '10px' }}
        data-testid="managed-agent-a2a-proxy-protocol-hint"
      >
        <div className="fw-semibold mb-1">A2A 1.0 only, JSON-RPC envelope validation only.</div>
        <div>
          An A2A proxy serves A2A 1.0, so callers must send the <code>A2A-Version: 1.0</code>{' '}
          header. Only the JSON-RPC envelope is checked, not the A2A message fields, so lenient
          callers keep working. The Access Point&apos;s A2A Protocol settings are locked to these
          values.
        </div>
      </div>
      <div
        className="alert alert-info py-2 mb-2"
        style={{ fontSize: '10px' }}
        data-testid="managed-agent-a2a-proxy-identity-hint"
      >
        <div className="fw-semibold mb-1">Identity comes from the selected A2A Proxy.</div>
        <div>
          For Copilot Studio, configure the proxy with the same Entra Agent ID and Client Tenant ID
          used by Header Metadata Mapping.
        </div>
        {selectedProxyId && (
          <button
            type="button"
            className="btn btn-link btn-sm p-0 mt-1"
            onClick={() => navigate(`/proxies/a2a-proxies/${selectedProxyId}`)}
            data-testid="managed-agent-a2a-proxy-edit-link"
          >
            Edit {selectedA2aProxy?.name || 'A2A Proxy'}
          </button>
        )}
      </div>
    </>
  );
};

export default A2aProxyEndpointFields;
