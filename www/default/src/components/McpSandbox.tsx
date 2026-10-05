import React, { useState } from 'react';
import { apiClient } from '../api';

interface McpTool {
  name: string;
  description?: string;
  inputSchema: {
    type: string;
    properties?: Record<string, any>;
    required?: string[];
  };
}

interface McpSandboxProps {
  endpointUrl: string;
  endpointName: string;
  endpointDescription?: string;
  flattenPostParams?: boolean;
}

/**
 * Parse an MCP response that may be JSON or SSE (text/event-stream).
 * For SSE, extracts the last JSON-RPC response from the stream.
 */
async function parseMcpResponse(response: Response): Promise<any> {
  const contentType = response.headers.get('content-type') || '';

  if (contentType.includes('text/event-stream')) {
    // SSE response — read the stream and extract JSON-RPC data events
    const text = await response.text();
    const lines = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n').split('\n');
    let lastJsonRpc: any = null;

    let currentData: string[] = [];
    for (const line of lines) {
      if (line.startsWith('data:')) {
        currentData.push(line.substring(5).trimStart());
      } else if (line === '' && currentData.length > 0) {
        // End of event
        const data = currentData.join('\n');
        currentData = [];
        try {
          const parsed = JSON.parse(data);
          if (parsed.result !== undefined || parsed.error !== undefined) {
            lastJsonRpc = parsed;
          }
        } catch {
          // Not JSON, skip
        }
      }
    }
    // Handle trailing data without final blank line
    if (currentData.length > 0) {
      const data = currentData.join('\n');
      try {
        const parsed = JSON.parse(data);
        if (parsed.result !== undefined || parsed.error !== undefined) {
          lastJsonRpc = parsed;
        }
      } catch {
        // Not JSON
      }
    }

    if (lastJsonRpc) return lastJsonRpc;
    throw new Error(`No JSON-RPC response found in SSE stream`);
  }

  // Plain JSON response
  const responseText = await response.text();
  try {
    return JSON.parse(responseText);
  } catch {
    throw new Error(`Invalid JSON response: ${responseText.substring(0, 200)}`);
  }
}

interface CustomHeader {
  key: string;
  value: string;
}

const McpSandbox: React.FC<McpSandboxProps> = ({
  endpointUrl,
  endpointName,
  endpointDescription,
  flattenPostParams = false,
}) => {
  const [availableTools, setAvailableTools] = useState<McpTool[]>([]);
  const [selectedTool, setSelectedTool] = useState<McpTool | null>(null);
  const [toolParams, setToolParams] = useState<Record<string, any>>({});
  const [isConnecting, setIsConnecting] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState<'disconnected' | 'connected' | 'error'>(
    'disconnected'
  );
  const [toolResponse, setToolResponse] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);
  const [customHeaders, setCustomHeaders] = useState<CustomHeader[]>([]);
  const [headersExpanded, setHeadersExpanded] = useState(false);

  const buildCustomHeaders = (): Record<string, string> =>
    Object.fromEntries(
      customHeaders.filter(h => h.key.trim() !== '').map(h => [h.key.trim(), h.value])
    );

  const addHeader = () => setCustomHeaders(prev => [...prev, { key: '', value: '' }]);

  const removeHeader = (index: number) =>
    setCustomHeaders(prev => prev.filter((_, i) => i !== index));

  const updateHeader = (index: number, field: 'key' | 'value', val: string) =>
    setCustomHeaders(prev => prev.map((h, i) => (i === index ? { ...h, [field]: val } : h)));

  const connectToEndpoint = async () => {
    setIsConnecting(true);
    setError(null);
    setToolResponse(null);

    try {
      const extraHeaders = buildCustomHeaders();

      // Step 1: MCP Initialize handshake
      const initResponse = await apiClient.fetch(endpointUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream, application/json',
          ...extraHeaders,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2024-11-05',
            capabilities: {},
            clientInfo: { name: 'agent-gateway-sandbox', version: '1.0.0' },
          },
        }),
      });

      if (!initResponse.ok) {
        const errorText = await initResponse.text();
        throw new Error(
          `Initialize failed: ${initResponse.statusText}${errorText ? ` - ${errorText.substring(0, 200)}` : ''}`
        );
      }

      const initData = await parseMcpResponse(initResponse);
      if (initData.error) {
        throw new Error(
          `Initialize error: ${initData.error.message || JSON.stringify(initData.error)}`
        );
      }

      // Step 2: Send initialized notification (fire-and-forget)
      apiClient
        .fetch(endpointUrl, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Accept: 'text/event-stream, application/json',
            ...extraHeaders,
          },
          body: JSON.stringify({
            jsonrpc: '2.0',
            method: 'notifications/initialized',
          }),
        })
        .catch(() => {}); // Notification — ignore errors

      // Step 3: List tools
      const response = await apiClient.fetch(endpointUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream, application/json',
          ...extraHeaders,
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/list',
          params: {},
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Failed to connect: ${response.statusText}${errorText ? ` - ${errorText.substring(0, 200)}` : ''}`
        );
      }

      const data = await parseMcpResponse(response);

      if (data.result && data.result.tools && Array.isArray(data.result.tools)) {
        setAvailableTools(data.result.tools);
        setConnectionStatus('connected');
      } else if (data.error) {
        throw new Error(`MCP Error: ${data.error.message || JSON.stringify(data.error)}`);
      } else {
        throw new Error('Invalid response format');
      }
    } catch (err: any) {
      setError(err.message || 'Failed to connect to MCP endpoint');
      setConnectionStatus('error');
      setAvailableTools([]);
    } finally {
      setIsConnecting(false);
    }
  };

  const disconnect = () => {
    setAvailableTools([]);
    setSelectedTool(null);
    setToolParams({});
    setConnectionStatus('disconnected');
    setToolResponse(null);
    setError(null);
  };

  const getDefaultValue = (prop: any): any => {
    // 1. Use example if available
    if (prop.example !== undefined) return prop.example;
    // 2. Use default if available
    if (prop.default !== undefined) return prop.default;
    // 3. Use first enum value if available
    if (prop.enum && prop.enum.length > 0) return prop.enum[0];

    // 4. Handle oneOf/anyOf — pick the first variant's default
    const variants = prop.oneOf || prop.anyOf;
    if (variants && variants.length > 0) {
      for (const v of variants) {
        if (v.enum && v.enum.length > 0) return v.enum[0];
      }
      return getDefaultValue(variants[0]);
    }

    // 5. Type-specific defaults
    if (prop.type === 'boolean') return false;
    if (prop.type === 'number' || prop.type === 'integer') {
      if (prop.minimum !== undefined) return prop.minimum;
      if (prop.maximum !== undefined) return Math.min(0, prop.maximum);
      return 0;
    }
    if (prop.type === 'array') return [];
    if (prop.type === 'object') return buildObjectScaffold(prop);
    return '';
  };

  const buildObjectScaffold = (schema: any): any => {
    const obj: Record<string, any> = {};
    if (schema.properties) {
      Object.keys(schema.properties).forEach(key => {
        obj[key] = getDefaultValue(schema.properties[key]);
      });
    }
    return obj;
  };

  const selectTool = (tool: McpTool) => {
    setSelectedTool(tool);
    setToolResponse(null);
    setError(null);

    const initialParams: Record<string, any> = {};
    if (tool.inputSchema.properties) {
      Object.keys(tool.inputSchema.properties).forEach(key => {
        const prop = tool.inputSchema.properties![key];
        const val = key === 'timeout_seconds' ? 10 : getDefaultValue(prop);
        if (prop.type === 'object' || prop.type === 'array') {
          initialParams[key] = JSON.stringify(val, null, 2);
        } else {
          initialParams[key] = val;
        }
      });
    }
    setToolParams(initialParams);
  };

  const handleToolChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const toolName = e.target.value;
    if (toolName) {
      const tool = availableTools.find(t => t.name === toolName);
      if (tool) {
        selectTool(tool);
      }
    } else {
      setSelectedTool(null);
      setToolParams({});
      setToolResponse(null);
      setError(null);
    }
  };

  const executeTool = async () => {
    if (!selectedTool) return;

    setIsExecuting(true);
    setError(null);
    setToolResponse(null);

    try {
      const response = await apiClient.fetch(endpointUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'text/event-stream, application/json',
          ...buildCustomHeaders(),
        },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: Date.now(),
          method: 'tools/call',
          params: {
            name: selectedTool.name,
            arguments: Object.fromEntries(
              Object.entries(toolParams)
                .map(([key, val]) => {
                  if (typeof val === 'string') {
                    const propSchema = selectedTool.inputSchema.properties?.[key];
                    if (
                      propSchema &&
                      (propSchema.type === 'object' || propSchema.type === 'array')
                    ) {
                      try {
                        return [key, JSON.parse(val)];
                      } catch {
                        return [key, val];
                      }
                    }
                  }
                  return [key, val];
                })
                .filter(([key, val]) => {
                  const required = selectedTool.inputSchema.required || [];
                  if (required.includes(key as string)) return true;
                  if (val === '' || val === null || val === undefined) return false;
                  if (typeof val === 'number' && val === 0) {
                    const propSchema = selectedTool.inputSchema.properties?.[key as string];
                    if (
                      propSchema &&
                      propSchema.default === undefined &&
                      propSchema.example === undefined
                    )
                      return false;
                  }
                  return true;
                })
            ),
          },
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(
          `Tool execution failed: ${response.statusText}${errorText ? ` - ${errorText.substring(0, 200)}` : ''}`
        );
      }

      const data = await parseMcpResponse(response);

      if (data.error) {
        // Handle MCP protocol errors
        const errorMsg = data.error.message || JSON.stringify(data.error);
        const errorDetails = data.error.data
          ? ` - Details: ${JSON.stringify(data.error.data)}`
          : '';
        throw new Error(`MCP Error: ${errorMsg}${errorDetails}`);
      }

      setToolResponse(data);
    } catch (err: any) {
      setError(err.message || 'Failed to execute tool');
    } finally {
      setIsExecuting(false);
    }
  };

  const handleParamChange = (paramName: string, value: any) => {
    setToolParams(prev => ({
      ...prev,
      [paramName]: value,
    }));
  };

  const parseResultContent = (response: any) => {
    try {
      if (response?.result?.content && Array.isArray(response.result.content)) {
        return response.result.content.map((item: any, index: number) => {
          if (item.type === 'text' && item.text) {
            try {
              const parsed = JSON.parse(item.text);
              return { ...item, parsedJson: parsed };
            } catch {
              return item;
            }
          }
          return item;
        });
      }
      return null;
    } catch {
      return null;
    }
  };

  const renderParamInput = (paramName: string, paramSchema: any) => {
    const value = toolParams[paramName];
    const isRequired = selectedTool?.inputSchema.required?.includes(paramName);

    if (paramSchema.type === 'boolean') {
      return (
        <div className="mb-3">
          <div className="form-check">
            <input
              type="checkbox"
              className="form-check-input"
              id={paramName}
              checked={value || false}
              onChange={e => handleParamChange(paramName, e.target.checked)}
            />
            <label className="form-check-label" htmlFor={paramName}>
              {paramName} {isRequired && <span className="text-danger">*</span>}
            </label>
          </div>
          {paramSchema.description && (
            <small className="form-text text-muted">{paramSchema.description}</small>
          )}
        </div>
      );
    }

    if (paramSchema.type === 'object' || paramSchema.type === 'array') {
      return (
        <div className="form-group">
          <label htmlFor={paramName}>
            {paramName} {isRequired && <span className="text-danger">*</span>}
          </label>
          <textarea
            className="form-control font-monospace"
            id={paramName}
            value={typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
            onChange={e => handleParamChange(paramName, e.target.value)}
            rows={8}
            style={{ fontSize: '0.875rem' }}
            placeholder={paramSchema.description}
          />
          {paramSchema.description && (
            <small className="form-text text-muted">{paramSchema.description}</small>
          )}
        </div>
      );
    }

    return (
      <div className="mb-3">
        <label htmlFor={paramName}>
          {paramName} {isRequired && <span className="text-danger">*</span>}
        </label>
        <input
          type={paramSchema.type === 'number' || paramSchema.type === 'integer' ? 'number' : 'text'}
          className="form-control"
          id={paramName}
          value={value || ''}
          onChange={e =>
            handleParamChange(
              paramName,
              paramSchema.type === 'number' || paramSchema.type === 'integer'
                ? parseFloat(e.target.value)
                : e.target.value
            )
          }
          placeholder={paramSchema.description}
        />
        {paramSchema.description && (
          <small className="form-text text-muted">{paramSchema.description}</small>
        )}
      </div>
    );
  };

  return (
    <div className="mcp-sandbox">
      {/* Header with endpoint info */}

      <div className="alert alert-warning mb-4" role="alert">
        <i className="fas fa-exclamation-triangle me-2" aria-hidden="true" />
        This runs real calls against your live backend, it isn't a safe/mock test environment. If a
        tool changes data (like a delete or update), running it here has the same effect as running
        it in production.
      </div>

      {/* Connection Panel */}
      <div className="card shadow-sm mb-4">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-plug me-2"></i>
            Connection
          </h6>
          {connectionStatus === 'connected' && (
            <span className="badge text-bg-success">
              <i className="fas fa-check-circle me-1"></i>
              Connected ({availableTools.length} tools)
            </span>
          )}
        </div>
        <div className="card-body">
          {connectionStatus === 'disconnected' && (
            <button
              className="btn btn-primary w-100"
              onClick={connectToEndpoint}
              disabled={isConnecting}
            >
              {isConnecting ? (
                <>
                  <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                  Connecting...
                </>
              ) : (
                <>
                  <i className="fas fa-plug me-2"></i>
                  Connect & List Tools
                </>
              )}
            </button>
          )}
          {connectionStatus === 'connected' && (
            <button className="btn btn-secondary w-100" onClick={disconnect}>
              <i className="fas fa-times me-2"></i>
              Disconnect
            </button>
          )}
          {connectionStatus === 'error' && error && (
            <>
              <div className="alert alert-danger mb-3">
                <i className="fas fa-exclamation-triangle me-2"></i>
                {error}
              </div>
              <button
                className="btn btn-primary w-100"
                onClick={connectToEndpoint}
                disabled={isConnecting}
              >
                <i className="fas fa-redo me-2"></i>
                Retry Connection
              </button>
            </>
          )}
        </div>
      </div>

      {/* Tool Selection Dropdown - Horizontal Layout */}
      {connectionStatus === 'connected' && availableTools.length > 0 && (
        <div className="card shadow-sm mb-4">
          <div className="card-body">
            <div className="mb-3 mb-0">
              <label htmlFor="tool-select" className="font-weight-bold">
                <i className="fas fa-wrench me-2"></i>
                Select Tool
              </label>
              <select
                id="tool-select"
                className="form-control dropdown-styling"
                value={selectedTool?.name || ''}
                onChange={handleToolChange}
              >
                <option value="">-- Choose a tool to test --</option>
                {availableTools.map(tool => (
                  <option key={tool.name} value={tool.name}>
                    {tool.name} {tool.description ? `- ${tool.description}` : ''}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>
      )}

      {/* Custom Headers Panel */}
      {connectionStatus === 'connected' && (
        <div className="card shadow-sm mb-4">
          <div
            className="card-header py-3 d-flex justify-content-between align-items-center"
            style={{ cursor: 'pointer' }}
            onClick={() => setHeadersExpanded(prev => !prev)}
          >
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-sliders-h me-2"></i>
              Custom Headers
              {customHeaders.filter(h => h.key.trim() !== '').length > 0 && (
                <span className="badge text-bg-secondary ms-2">
                  {customHeaders.filter(h => h.key.trim() !== '').length}
                </span>
              )}
            </h6>
            <i className={`fas fa-chevron-${headersExpanded ? 'up' : 'down'} text-muted`}></i>
          </div>
          {headersExpanded && (
            <div className="card-body">
              {customHeaders.map((header, index) => (
                <div key={index} className="d-flex gap-2 mb-2">
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Header name"
                    value={header.key}
                    onChange={e => updateHeader(index, 'key', e.target.value)}
                  />
                  <input
                    type="text"
                    className="form-control"
                    placeholder="Value"
                    value={header.value}
                    onChange={e => updateHeader(index, 'value', e.target.value)}
                  />
                  <button
                    className="btn btn-outline-danger"
                    onClick={() => removeHeader(index)}
                    title="Remove header"
                  >
                    <i className="fas fa-times"></i>
                  </button>
                </div>
              ))}
              <button className="btn btn-outline-secondary btn-sm mt-1" onClick={addHeader}>
                <i className="fas fa-plus me-1"></i>
                Add Header
              </button>
            </div>
          )}
        </div>
      )}

      {/* Tool Execution Panel */}
      {selectedTool && (
        <div className="card shadow-sm mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-wrench me-2"></i>
              {selectedTool.name}
            </h6>
          </div>
          <div className="card-body">
            {selectedTool.description && (
              <p className="text-muted mb-3">{selectedTool.description}</p>
            )}

            <h6 className="font-weight-bold mb-3">Parameters</h6>
            {selectedTool.inputSchema.properties &&
            Object.keys(selectedTool.inputSchema.properties).length > 0 ? (
              <div>
                {Object.entries(selectedTool.inputSchema.properties).map(([name, schema]) => (
                  <div key={name} className="mb-3">
                    {renderParamInput(name, schema)}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-muted">No parameters required</p>
            )}

            <button
              className="btn btn-primary btn-lg w-100 mt-3"
              onClick={executeTool}
              disabled={isExecuting}
            >
              {isExecuting ? (
                <>
                  <span className="spinner-border spinner-border-sm me-2" role="status"></span>
                  Running...
                </>
              ) : (
                <>
                  <i className="fas fa-play me-2"></i>
                  Run Tool
                </>
              )}
            </button>
          </div>
        </div>
      )}

      {/* Response Panel */}
      {(toolResponse || error) && selectedTool && (
        <div className="card shadow-sm">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-terminal me-2"></i>
              Response
            </h6>
          </div>
          <div className="card-body">
            {error && (
              <div className="alert alert-danger">
                <i className="fas fa-exclamation-triangle me-2"></i>
                {error}
              </div>
            )}
            {toolResponse && (
              <div>
                {(() => {
                  const parsedContent = parseResultContent(toolResponse);

                  if (parsedContent && parsedContent.length > 0) {
                    return parsedContent.map((item: any, index: number) => (
                      <div key={index} className="mb-3">
                        {item.type === 'text' && (
                          <div>
                            <small className="text-muted d-block mb-2">
                              <i className="fas fa-file-alt me-1"></i>
                              Text Content{' '}
                              {parsedContent.length > 1
                                ? `(${index + 1}/${parsedContent.length})`
                                : ''}
                            </small>
                            {item.parsedJson ? (
                              <div>
                                <div className="d-flex justify-content-between align-items-center mb-2">
                                  <small className="text-success">
                                    <i className="fas fa-check-circle me-1"></i>
                                    Valid JSON - Structured View
                                  </small>
                                </div>
                                <pre
                                  className="bg-light p-3 rounded"
                                  style={{ maxHeight: '400px', overflowY: 'auto' }}
                                >
                                  <code>{JSON.stringify(item.parsedJson, null, 2)}</code>
                                </pre>
                              </div>
                            ) : (
                              <pre
                                className="bg-light p-3 rounded"
                                style={{
                                  maxHeight: '400px',
                                  overflowY: 'auto',
                                  whiteSpace: 'pre-wrap',
                                }}
                              >
                                {item.text}
                              </pre>
                            )}
                          </div>
                        )}
                        {item.type === 'image' && (
                          <div>
                            <small className="text-muted d-block mb-2">
                              <i className="fas fa-image me-1"></i>
                              Image Content
                            </small>
                            <img src={item.data} alt="Response" className="img-fluid rounded" />
                          </div>
                        )}
                        {item.type !== 'text' && item.type !== 'image' && (
                          <div>
                            <small className="text-muted d-block mb-2">
                              <i className="fas fa-code me-1"></i>
                              {item.type} Content
                            </small>
                            <pre
                              className="bg-light p-3 rounded"
                              style={{ maxHeight: '400px', overflowY: 'auto' }}
                            >
                              <code>{JSON.stringify(item, null, 2)}</code>
                            </pre>
                          </div>
                        )}
                      </div>
                    ));
                  }

                  return (
                    <div>
                      <small className="text-muted d-block mb-2">
                        <i className="fas fa-code me-1"></i>
                        Raw Response
                      </small>
                      <pre
                        className="bg-light p-3 rounded"
                        style={{ maxHeight: '400px', overflowY: 'auto' }}
                      >
                        <code>{JSON.stringify(toolResponse, null, 2)}</code>
                      </pre>
                    </div>
                  );
                })()}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Empty state when no tool selected */}
      {connectionStatus === 'connected' && !selectedTool && availableTools.length > 0 && (
        <div className="card shadow-sm">
          <div className="card-body text-center py-5">
            <i className="fas fa-arrow-up fa-3x text-muted mb-3"></i>
            <h5 className="text-muted">Select a tool from the dropdown above</h5>
            <p className="text-muted">Choose a tool to configure its parameters and execute it.</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default McpSandbox;
