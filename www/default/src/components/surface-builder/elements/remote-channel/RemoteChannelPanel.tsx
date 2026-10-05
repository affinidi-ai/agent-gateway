import React, { useEffect, useState } from 'react';
import { Form, Spinner } from 'react-bootstrap';
import type { ConfigPanelProps } from '../types';
import { apiClient } from '../../../../api';

interface DiscoveredTool {
  name: string;
}

/**
 * Sidebar panel for the synthesised `remote-channel` external actor.
 *
 * For `kind === 'fabric'` (default) the panel just describes what the
 * element represents — the channel name is already surfaced via the
 * default Name field above.
 *
 * For `kind === 'proxy'` the actor stands for the tools exposed by a
 * managed MCP proxy, so the panel lists those tools by calling the
 * existing `/mcp-proxies/discover-tools` admin endpoint.
 */
const RemoteChannelPanel: React.FC<ConfigPanelProps> = ({ config }) => {
  const kind: 'fabric' | 'proxy' = config?.kind === 'proxy' ? 'proxy' : 'fabric';
  const proxyId: string = config?.mcp_proxy_id || '';

  const [tools, setTools] = useState<DiscoveredTool[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState(false);
  const [filter, setFilter] = useState('');

  useEffect(() => {
    if (kind !== 'proxy' || !proxyId) {
      setTools(null);
      return;
    }
    let cancelled = false;
    setLoading(true);
    setError(null);
    apiClient
      .post('/mcp-proxies/discover-tools', { mcp_proxy_id: proxyId })
      .then(res => {
        if (cancelled) return;
        const list: DiscoveredTool[] = Array.isArray(res.data?.tools) ? res.data.tools : [];
        setTools(list);
      })
      .catch(err => {
        if (cancelled) return;
        setTools([]);
        setError(err?.message || 'Failed to load tools');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [kind, proxyId]);

  if (kind === 'proxy') {
    const count = tools?.length ?? 0;
    const filterLower = filter.trim().toLowerCase();
    const visibleTools = filterLower
      ? (tools ?? []).filter(t => t.name.toLowerCase().includes(filterLower))
      : (tools ?? []);

    return (
      <>
        <div className="config-section">
          {/* Header row — always visible */}
          <div
            className="d-flex align-items-center justify-content-between"
            style={{ cursor: loading ? 'default' : 'pointer', userSelect: 'none' }}
            onClick={() => !loading && tools && tools.length > 0 && setExpanded(e => !e)}
          >
            <label className="mb-0" style={{ cursor: 'inherit' }}>
              Exposed Tools
              {!loading && tools !== null && (
                <span
                  className="badge bg-secondary ms-2"
                  style={{ fontSize: '10px', fontWeight: 500 }}
                >
                  {count}
                </span>
              )}
            </label>
            {!loading && tools && tools.length > 0 && (
              <i
                className={`fas fa-chevron-${expanded ? 'up' : 'down'} text-muted`}
                style={{ fontSize: '10px' }}
              />
            )}
          </div>

          {/* Loading state */}
          {loading && (
            <div className="text-muted small d-flex align-items-center gap-2 mt-2">
              <Spinner animation="border" size="sm" /> Discovering tools…
            </div>
          )}

          {/* Error state */}
          {!loading && error && (
            <div className="text-danger small mt-1">Could not load tools: {error}</div>
          )}

          {/* Empty state */}
          {!loading && !error && tools && tools.length === 0 && (
            <div className="text-muted small mt-1">No tools exposed by this proxy.</div>
          )}

          {/* Expanded tools list */}
          {!loading && !error && tools && tools.length > 0 && expanded && (
            <div className="mt-2">
              {tools.length > 8 && (
                <div className="position-relative mb-2">
                  <i
                    className="fas fa-search position-absolute text-muted"
                    style={{ left: 7, top: '50%', transform: 'translateY(-50%)', fontSize: '10px' }}
                  />
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    placeholder="Filter tools…"
                    value={filter}
                    onChange={e => setFilter(e.target.value)}
                    style={{ paddingLeft: 24, fontSize: '11px' }}
                  />
                </div>
              )}
              {visibleTools.length === 0 ? (
                <div className="text-muted small">No tools match "{filter}"</div>
              ) : (
                <ul className="list-unstyled mb-0" style={{ maxHeight: 240, overflowY: 'auto' }}>
                  {visibleTools.map(t => (
                    <li key={t.name} className="d-flex align-items-center py-1" style={{ gap: 8 }}>
                      <i
                        className="fas fa-wrench text-muted"
                        style={{ width: 14, fontSize: '10px' }}
                      />
                      <span className="small">{t.name}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}

          {/* Collapsed hint */}
          {!loading && !error && tools && tools.length > 0 && !expanded && (
            <div className="text-muted mt-1" style={{ fontSize: '10px' }}>
              Click to view {count} tool{count !== 1 ? 's' : ''}
            </div>
          )}
          <Form.Text className="text-muted d-block mt-2" style={{ fontSize: '10px' }}>
            Represents the tools exposed by the managed MCP proxy. The list is discovered live from
            the proxy.
          </Form.Text>
        </div>
      </>
    );
  }

  return (
    <div className="config-section">
      <Form.Text className="text-muted" style={{ fontSize: '11px' }}>
        Represents the channel on the remote gateway that this <code>fabric://</code> route targets.
        The display name above is pre-filled with the channel&apos;s name on the remote gateway —
        edit it to give it a meaningful name on this surface.
      </Form.Text>
    </div>
  );
};

export default RemoteChannelPanel;
