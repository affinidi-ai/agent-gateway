import { useState } from 'react';
import { apiClient } from '../../../../api';

export interface DiscoveredMcpTool {
  name: string;
  description?: string;
  read_only?: boolean;
}

interface DiscoveryTargetAuth {
  enabled: true;
  method: 'static_secret';
  secret_id: string;
  header_name: string;
  header_format: string;
  fallback: string;
}

export type McpToolDiscoveryRequest =
  | { mcp_proxy_id: string }
  | { surface_id: string; target_endpoint: string }
  | { target_endpoint: string; target_auth?: DiscoveryTargetAuth };

/** The Target node fields discovery reads, as the Managed Agent panel stores them. */
export interface DiscoveryTargetConfig {
  endpoint_type?: string;
  endpoint?: string;
  mcp_proxy_id?: string;
  target_auth_enabled?: boolean;
  target_auth_secret_id?: string;
  target_auth_header_name?: string;
  target_auth_header_format?: string;
  target_auth_fallback?: string;
}

export type McpToolDiscoverySource =
  | { request: McpToolDiscoveryRequest; label: string }
  | { unavailable: string };

const NO_GATEWAY_DISCOVERY =
  'Tools cannot be discovered through a gateway connection. Enter patterns instead.';

const trimmed = (value: unknown): string => (typeof value === 'string' ? value.trim() : '');

function proxySource(id: string): McpToolDiscoverySource {
  return id
    ? { request: { mcp_proxy_id: id }, label: `MCP Proxy ${id}` }
    : { unavailable: 'Choose the MCP Proxy on the Target first.' };
}

/**
 * What `POST /mcp-proxies/discover-tools` is asked for this Target, or why it cannot be.
 * A saved surface's Direct URL Target is asked by surface id, so the gateway dials its saved
 * Target and auth under the forward step's egress policy (a local or private Target works);
 * a URL alone is dialled under the strict policy, which refuses local and private hosts.
 */
export function mcpToolDiscoverySource(
  target: DiscoveryTargetConfig | undefined,
  surfaceId?: string
): McpToolDiscoverySource {
  const type = target?.endpoint_type || 'url';
  if (type === 'mcp-proxy') return proxySource(trimmed(target?.mcp_proxy_id));
  if (type === 'gateway') return { unavailable: NO_GATEWAY_DISCOVERY };
  if (type !== 'url') {
    return { unavailable: 'Tool discovery needs a Direct URL or MCP Proxy Target.' };
  }
  const endpoint = trimmed(target?.endpoint);
  if (!endpoint) return { unavailable: 'Set the Target endpoint first.' };
  if (endpoint.startsWith('fabric://')) return { unavailable: NO_GATEWAY_DISCOVERY };
  if (endpoint.startsWith('proxy://')) return proxySource(endpoint.slice('proxy://'.length).trim());
  if (surfaceId)
    return { request: { surface_id: surfaceId, target_endpoint: endpoint }, label: endpoint };
  const secretId = trimmed(target?.target_auth_secret_id);
  return {
    request: {
      target_endpoint: endpoint,
      ...(target?.target_auth_enabled && secretId
        ? {
            target_auth: {
              enabled: true,
              method: 'static_secret',
              secret_id: secretId,
              header_name: target.target_auth_header_name || 'Authorization',
              header_format: target.target_auth_header_format || '{value}',
              fallback: target.target_auth_fallback || 'reject',
            },
          }
        : {}),
    },
    label: endpoint,
  };
}

function readTools(raw: unknown): DiscoveredMcpTool[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter(
      (t): t is { name: string; description?: unknown; read_only?: unknown } =>
        !!t && typeof t === 'object' && typeof t.name === 'string' && t.name !== ''
    )
    .map(t => ({
      name: t.name,
      ...(typeof t.description === 'string' ? { description: t.description } : {}),
      ...(typeof t.read_only === 'boolean' ? { read_only: t.read_only } : {}),
    }));
}

interface DiscoveryResult {
  key: string;
  tools: DiscoveredMcpTool[] | null;
  error: string | null;
}

/**
 * Lists the Target's MCP tools on demand. A result belongs to the request that
 * produced it, so a changed Target never shows another Target's tools.
 */
export function useMcpToolDiscovery(request: McpToolDiscoveryRequest | null) {
  const key = request ? JSON.stringify(request) : '';
  const [result, setResult] = useState<DiscoveryResult | null>(null);
  const [loadingKey, setLoadingKey] = useState<string | null>(null);

  const discover = async () => {
    if (!request) return;
    setLoadingKey(key);
    try {
      const res = await apiClient.post('/mcp-proxies/discover-tools', request);
      setResult({ key, tools: readTools(res.data?.tools), error: null });
    } catch (err) {
      const message = err instanceof Error && err.message ? err.message : 'Failed to load tools';
      setResult({ key, tools: null, error: message });
    } finally {
      setLoadingKey(current => (current === key ? null : current));
    }
  };

  const current = result?.key === key ? result : null;
  return {
    tools: current?.tools ?? null,
    error: current?.error ?? null,
    loading: loadingKey === key,
    discover,
  };
}
