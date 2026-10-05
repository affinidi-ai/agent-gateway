import React, { useEffect, useState } from 'react';
import { Form, Button } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import { apiClient } from '../../../../api';

interface Gateway {
  id: string;
  name: string;
  did?: string;
  gateway_type?: string;
}

interface McpProxy {
  id: string;
  name: string;
  base_url?: string;
  description?: string;
}

/**
 * Read-only sidebar panel for the synthesised `remote-gateway` node.
 * Two flavours:
 *  - `kind === 'fabric'` (default): resolves `gateway_id` to a gateway
 *    name and links to the gateway dashboard.
 *  - `kind === 'proxy'`: resolves `mcp_proxy_id` to a managed MCP
 *    proxy and links to the proxy editor. The downstream of the proxy
 *    is a REST API (the proxy's `base_url`).
 */
const RemoteGatewayPanel: React.FC<ConfigPanelProps> = ({ config }) => {
  const kind: 'fabric' | 'proxy' = config?.kind === 'proxy' ? 'proxy' : 'fabric';
  const gatewayId: string = config?.gateway_id || '';
  const proxyId: string = config?.mcp_proxy_id || '';

  const [gateway, setGateway] = useState<Gateway | null>(null);
  const [proxy, setProxy] = useState<McpProxy | null>(null);

  useEffect(() => {
    if (kind !== 'fabric' || !gatewayId) return;
    apiClient
      .get('/gateways')
      .then(res => {
        const list: Gateway[] = res.data || [];
        setGateway(list.find(g => g.id === gatewayId) ?? null);
      })
      .catch(() => setGateway(null));
  }, [kind, gatewayId]);

  useEffect(() => {
    if (kind !== 'proxy' || !proxyId) return;
    apiClient
      .get(`/mcp-proxies/${proxyId}`)
      .then(res => setProxy(res.data || null))
      .catch(() => setProxy(null));
  }, [kind, proxyId]);

  if (kind === 'proxy') {
    return (
      <>
        <div className="config-section">
          <label>REST API</label>
          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-1">Backend URL</Form.Label>
            <Form.Control size="sm" type="text" readOnly value={proxy?.base_url || '—'} />
          </Form.Group>
          <Form.Group className="mb-2">
            <Form.Label className="small text-muted mb-1">Fronted by proxy</Form.Label>
            <Form.Control size="sm" type="text" readOnly value={proxy?.name || proxyId || '—'} />
          </Form.Group>
          <div className="d-flex gap-2 mt-2">
            {proxyId && (
              <Button
                size="sm"
                variant="outline-secondary"
                onClick={() =>
                  window.open(`/proxies/mcp-proxies/${proxyId}`, '_blank', 'noopener,noreferrer')
                }
              >
                <i className="fas fa-external-link-alt me-1" /> Open proxy
              </Button>
            )}
          </div>
        </div>
        <div className="config-section">
          <Form.Text className="text-muted" style={{ fontSize: '11px' }}>
            The REST API the MCP proxy translates tool calls into. Synthesised from a{' '}
            <code>proxy://</code> target endpoint on the parent transit point or managed agent — to
            change it, edit that node's destination.
          </Form.Text>
        </div>
      </>
    );
  }

  return (
    <>
      <div className="config-section">
        <label>Remote Gateway</label>
        <Form.Group className="mb-2">
          <Form.Label className="small text-muted mb-1">Gateway</Form.Label>
          <Form.Control size="sm" type="text" readOnly value={gateway?.name || gatewayId || '—'} />
        </Form.Group>
        <div className="d-flex gap-2 mt-2">
          {gatewayId && (
            <Button
              size="sm"
              variant="outline-secondary"
              onClick={() => window.open(`/gateways/${gatewayId}`, '_blank', 'noopener,noreferrer')}
            >
              <i className="fas fa-external-link-alt me-1" /> Open gateway
            </Button>
          )}
        </div>
      </div>
      <div className="config-section">
        <Form.Text className="text-muted" style={{ fontSize: '11px' }}>
          This destination is synthesised from a <code>fabric://</code> target endpoint on the
          parent transit point or target. To change it, edit that node's destination.
        </Form.Text>
      </div>
    </>
  );
};

export default RemoteGatewayPanel;
