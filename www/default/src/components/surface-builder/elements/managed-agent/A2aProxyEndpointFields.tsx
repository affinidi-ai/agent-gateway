import React from 'react';
import { Form } from 'react-bootstrap';
import { a2aProxyEndpoint } from '../_shared/a2aProxyEndpoint';

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
}) => (
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
          endpoint: id ? a2aProxyEndpoint(id) : '',
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
);

export default A2aProxyEndpointFields;
