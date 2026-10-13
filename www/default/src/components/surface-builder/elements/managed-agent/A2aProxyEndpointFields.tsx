import React from 'react';
import { Form } from 'react-bootstrap';
import { useNavigate } from 'react-router-dom';
import { a2aProxyEndpoint } from '../_shared/a2aProxyEndpoint';
import { A2A_PROXY_0_3_REASON, A2A_PROXY_SETTINGS } from '../access-point/a2aSettings';

export interface A2aProxyOption {
  id: string;
  name: string;
  status?: 'active' | 'disabled';
}

interface A2aProxyEndpointFieldsProps {
  selectedProxyId?: string;
  a2aProxies: A2aProxyOption[];
  updateFields: (fields: Record<string, unknown>) => void;
  /** The surface's fixed A2A versions, as the Access Point shows them. */
  acceptedVersions?: string[];
}

const A2aProxyEndpointFields: React.FC<A2aProxyEndpointFieldsProps> = ({
  selectedProxyId = '',
  a2aProxies,
  updateFields,
  acceptedVersions = A2A_PROXY_SETTINGS.accepted_versions,
}) => {
  const accepts0_3 = acceptedVersions.includes('0.3');
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
      <div
        className="alert alert-info py-2 mb-2"
        style={{ fontSize: '10px' }}
        data-testid="managed-agent-a2a-proxy-protocol-hint"
      >
        <div className="fw-semibold mb-1" data-testid="managed-agent-a2a-proxy-versions">
          {accepts0_3 ? 'Accepts A2A 0.3 and 1.0' : 'Accepts A2A 1.0 only'}
        </div>
        {accepts0_3 && (
          <div className="mb-1" data-testid="managed-agent-a2a-proxy-0-3-reason">
            {A2A_PROXY_0_3_REASON}
          </div>
        )}
        <ul className="mb-0 ps-3">
          <li>
            {accepts0_3 ? (
              <>
                Callers may send <code>A2A-Version: 1.0</code> or <code>0.3</code>, or no header
                (read as 0.3).
              </>
            ) : (
              <>
                Callers must send <code>A2A-Version: 1.0</code>. A request without it is refused.
              </>
            )}
          </li>
          <li>
            The reply follows the method: <code>SendMessage</code> gets an A2A 1.0 reply,{' '}
            <code>message/send</code> an A2A 0.3 reply.
          </li>
          <li>Only the JSON-RPC envelope is checked, not the A2A message fields.</li>
          <li>These versions are fixed.</li>
        </ul>
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
