import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../../../api';
import type { ConfigPanelProps } from '../types';

// Local type definitions for the x402 payment config panel.

export interface A2AMethodFilter {
  method: string;
  message_patterns?: string[];
}

interface X402TokenConfig {
  contract_address: string;
  symbol: string;
  decimals?: number;
  denomination?: string;
  description?: string;
  version?: string;
  asset_transfer_method?: string;
}

interface X402NetworkConfig {
  id: string;
  name: string;
  description?: string;
  rpc_endpoint: string;
  block_explorer?: string;
  x402_tokens: X402TokenConfig[];
}

interface X402PaymentScheme {
  id: string;
  name: string;
}

interface X402VerificationMode {
  id: string;
  name: string;
  description?: string;
}

interface X402SettlementMode {
  id: string;
  name: string;
  description?: string;
}

interface X402RecipientAddress {
  id: string;
  name: string;
  addresses: Record<string, string>;
}

interface X402DefaultsConfig {
  verification_mode: string;
  settlement_mode: string;
  min_confirmations: number;
  facilitator_timeout_secs: number;
}

interface X402ConfigType {
  networks: X402NetworkConfig[];
  payment_schemes: X402PaymentScheme[];
  verification_modes: X402VerificationMode[];
  settlement_modes: X402SettlementMode[];
  recipient_addresses: X402RecipientAddress[];
  defaults: X402DefaultsConfig;
}

interface GatewayOption {
  id: string;
  name: string;
}

// Available A2A control message methods (non-message operations)
const A2A_CONTROL_METHODS = [
  'tasks/get',
  'tasks/list',
  'tasks/cancel',
  'tasks/resubscribe',
  'tasks/pushNotificationConfig/set',
  'tasks/pushNotificationConfig/get',
  'tasks/pushNotificationConfig/list',
  'tasks/pushNotificationConfig/delete',
  'agent/getAuthenticatedExtendedCard',
];

interface A2AMethodFilterEditorProps {
  filters: A2AMethodFilter[];
  onChange: (filters: A2AMethodFilter[]) => void;
}

export const A2AMethodFilterEditor: React.FC<A2AMethodFilterEditorProps> = ({
  filters,
  onChange,
}) => {
  const [showCommandMessages, setShowCommandMessages] = React.useState(true);
  const [showControlMessages, setShowControlMessages] = React.useState(false);

  const getMethodFilter = (methodName: string): A2AMethodFilter | undefined => {
    return filters.find(f => f.method === methodName);
  };

  const isMethodEnabled = (methodName: string) => {
    return filters.some(f => f.method === methodName);
  };

  const toggleMethod = (methodName: string) => {
    if (isMethodEnabled(methodName)) {
      onChange(filters.filter(f => f.method !== methodName));
    } else {
      onChange([...filters, { method: methodName, message_patterns: [] }]);
    }
  };

  const updatePatterns = (methodName: string, patterns: string[]) => {
    const nonEmptyPatterns = patterns.filter(p => p.trim() !== '');
    const methodExists = filters.some(f => f.method === methodName);
    if (!methodExists) {
      onChange([...filters, { method: methodName, message_patterns: nonEmptyPatterns }]);
    } else {
      onChange(
        filters.map(f =>
          f.method === methodName ? { ...f, message_patterns: nonEmptyPatterns } : f
        )
      );
    }
  };

  const sendMessageFilter = getMethodFilter('message/send') || {
    method: 'message/send',
    message_patterns: [''],
  };
  const streamingMessageFilter = getMethodFilter('message/stream') || {
    method: 'message/stream',
    message_patterns: [''],
  };

  React.useEffect(() => {
    const hasSendMessage = filters.some(f => f.method === 'message/send');
    const hasStreamingMessage = filters.some(f => f.method === 'message/stream');
    if (!hasSendMessage || !hasStreamingMessage) {
      const newFilters = [...filters];
      if (!hasSendMessage) {
        newFilters.push({ method: 'message/send', message_patterns: [''] });
      }
      if (!hasStreamingMessage) {
        newFilters.push({ method: 'message/stream', message_patterns: [''] });
      }
      onChange(newFilters);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div>
      <div className="card mb-3">
        <div
          className="card-header bg-light"
          onClick={() => setShowCommandMessages(!showCommandMessages)}
          style={{ cursor: 'pointer' }}
        >
          <i className={`fas fa-chevron-${showCommandMessages ? 'down' : 'right'} me-2`}></i>
          <strong>Command Messages</strong>
          <small className="text-muted ms-2">(message/send, message/stream)</small>
        </div>
        {showCommandMessages && (
          <div className="card-body">
            <div className="mb-4">
              <label className="form-label fw-bold">
                <i className="fas fa-comment me-2"></i>message/send
                <small className="text-muted fw-normal ms-2">(JSON-RPC) / SendMessage (gRPC)</small>
              </label>
              <small className="text-muted d-block mb-2">
                Add regex patterns to match specific message content. If no patterns are specified,
                payment is required for ALL message/send requests.
              </small>
              {(sendMessageFilter.message_patterns && sendMessageFilter.message_patterns.length > 0
                ? sendMessageFilter.message_patterns
                : ['']
              ).map((pattern, idx) => (
                <div key={idx} className="input-group input-group-sm mb-2">
                  <span className="input-group-text">
                    <i className="fas fa-code"></i>
                  </span>
                  <input
                    type="text"
                    className="form-control font-monospace"
                    value={pattern}
                    onChange={e => {
                      const currentPatterns = sendMessageFilter.message_patterns || [''];
                      const newPatterns = [...currentPatterns];
                      newPatterns[idx] = e.target.value;
                      updatePatterns('message/send', newPatterns);
                    }}
                    placeholder="e.g., generate.*report|create.*analysis"
                  />
                  {(sendMessageFilter.message_patterns || []).length > 1 && (
                    <button
                      className="btn btn-outline-danger"
                      onClick={() => {
                        updatePatterns(
                          'message/send',
                          (sendMessageFilter.message_patterns || []).filter((_, i) => i !== idx)
                        );
                      }}
                      title="Remove pattern"
                    >
                      <i className="fas fa-times"></i>
                    </button>
                  )}
                </div>
              ))}
              <button
                className="btn btn-sm btn-outline-secondary"
                onClick={() => {
                  updatePatterns('message/send', [
                    ...(sendMessageFilter.message_patterns || ['']),
                    '',
                  ]);
                }}
              >
                <i className="fas fa-plus me-1"></i>Add Pattern
              </button>
            </div>

            <div className="mb-0">
              <label className="form-label fw-bold">
                <i className="fas fa-stream me-2"></i>message/stream
                <small className="text-muted fw-normal ms-2">
                  (JSON-RPC) / SendStreamingMessage (gRPC)
                </small>
              </label>
              <small className="text-muted d-block mb-2">
                Add regex patterns to match specific message content. If no patterns are specified,
                payment is required for ALL message/stream requests.
              </small>
              {(streamingMessageFilter.message_patterns &&
              streamingMessageFilter.message_patterns.length > 0
                ? streamingMessageFilter.message_patterns
                : ['']
              ).map((pattern, idx) => (
                <div key={idx} className="input-group input-group-sm mb-2">
                  <span className="input-group-text">
                    <i className="fas fa-code"></i>
                  </span>
                  <input
                    type="text"
                    className="form-control font-monospace"
                    value={pattern}
                    onChange={e => {
                      const currentPatterns = streamingMessageFilter.message_patterns || [''];
                      const newPatterns = [...currentPatterns];
                      newPatterns[idx] = e.target.value;
                      updatePatterns('message/stream', newPatterns);
                    }}
                    placeholder="e.g., stream.*video|realtime.*data"
                  />
                  {(streamingMessageFilter.message_patterns || []).length > 1 && (
                    <button
                      className="btn btn-outline-danger"
                      onClick={() => {
                        updatePatterns(
                          'message/stream',
                          (streamingMessageFilter.message_patterns || []).filter(
                            (_, i) => i !== idx
                          )
                        );
                      }}
                      title="Remove pattern"
                    >
                      <i className="fas fa-times"></i>
                    </button>
                  )}
                </div>
              ))}
              <button
                className="btn btn-sm btn-outline-secondary"
                onClick={() => {
                  updatePatterns('message/stream', [
                    ...(streamingMessageFilter.message_patterns || ['']),
                    '',
                  ]);
                }}
              >
                <i className="fas fa-plus me-1"></i>Add Pattern
              </button>
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div
          className="card-header bg-light"
          onClick={() => setShowControlMessages(!showControlMessages)}
          style={{ cursor: 'pointer' }}
        >
          <i className={`fas fa-chevron-${showControlMessages ? 'down' : 'right'} me-2`}></i>
          <strong>Control Messages</strong>
          <small className="text-muted ms-2">(Optional: tasks/get, tasks/cancel, etc.)</small>
        </div>
        {showControlMessages && (
          <div className="card-body">
            <small className="text-muted d-block mb-3">
              Select which control operations require payment. These methods don't have message
              content to match.
            </small>
            <div className="row">
              {A2A_CONTROL_METHODS.map(methodName => (
                <div key={methodName} className="col-md-6 mb-2">
                  <div className="form-check">
                    <input
                      className="form-check-input"
                      type="checkbox"
                      checked={isMethodEnabled(methodName)}
                      onChange={() => toggleMethod(methodName)}
                      id={`method-${methodName}`}
                    />
                    <label className="form-check-label small" htmlFor={`method-${methodName}`}>
                      {methodName}
                    </label>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * Fullscreen editor for the Payment (x402 Paywall) element. Mirrors the
 * "x402 Paywall" section of the channels editor — same field layout, same
 * wire shape (X402Config flattened into the payment node's config).
 */
const PaymentX402Fullscreen: React.FC<ConfigPanelProps> = ({
  config,
  updateFields,
  protocol,
  closeFullscreenEditor,
  hasAttemptedSave = false,
}) => {
  const [x402Config, setX402Config] = useState<X402ConfigType | null>(null);
  const [gateways, setGateways] = useState<GatewayOption[]>([]);

  useEffect(() => {
    apiClient
      .get<X402ConfigType>('/config/x402')
      .then(({ data }) => setX402Config(data))
      .catch(() => setX402Config(null));
  }, []);

  useEffect(() => {
    apiClient
      .get<any[]>('/gateways')
      .then(({ data }) => {
        const userGateways = (data || []).filter(
          (gw: any) => gw.gateway_type === 'remote' && gw.creation_type === 'user'
        );
        setGateways(userGateways as GatewayOption[]);
      })
      .catch(() => setGateways([]));
  }, []);

  // Adapter: bridge ConfigPanelProps (config + updateFields) to the
  // formData/setFormData/setIsModified shape used verbatim by the channel
  // editor's x402 paywall section. Letting us paste the original JSX
  // unchanged below.
  const formData: any = useMemo(
    () => ({
      payment_policy: config,
      protocol,
    }),
    [config, protocol]
  );
  const setFormData = (next: any) => {
    const obj = typeof next === 'function' ? next(formData) : next;
    const newPp: Record<string, any> = obj.payment_policy ?? {};
    const merged: Record<string, any> = {};
    const allKeys = new Set([...Object.keys(config), ...Object.keys(newPp)]);
    for (const k of allKeys) merged[k] = newPp[k];
    updateFields(merged);
  };
  const setIsModified = (_: boolean) => {
    // No-op: the surface builder tracks modification state itself via
    // `updateFields`. This stub keeps the pasted JSX below identical to
    // the original.
  };
  const isX402Supported = protocol === 'mcp' || protocol === 'a2a';

  // The presence of this node in the surface means x402 is enabled —
  // seed required defaults the first time the editor opens so the rest
  // of the form (which was originally gated by an `enabled` checkbox)
  // has something to render against.
  useEffect(() => {
    if (!isX402Supported) return;
    if (config && (config as any).verification_mode) return;
    updateFields({
      enabled: true,
      verification_mode: 'mock',
      settlement_mode: 'none',
      supported_schemes: ['exact'],
      supported_networks: ['base'],
      payment_requirements: [],
      rpc_endpoints: {},
      min_confirmations: 0,
      accept_mempool_tx: true,
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isX402Supported]);

  return (
    <div>
      <div className="d-flex justify-content-end mb-2">
        {closeFullscreenEditor && (
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            onClick={closeFullscreenEditor}
          >
            <i className="fas fa-times me-1" /> Close tab
          </button>
        )}
      </div>

      {/* x402 Payment Configuration Section - MCP and A2A Protocols Only */}
      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <div className="d-flex justify-content-between align-items-center">
            <h6 className="m-0 font-weight-bold text-primary">
              <i className="fas fa-coins"></i> x402 Paywall
            </h6>
          </div>
        </div>
        {!isX402Supported && (
          <div className="card-body">
            <div className="alert alert-info mb-0" role="alert">
              <i className="fas fa-info-circle"></i>{' '}
              <strong>x402 Paywall is only available for MCP and A2A protocols.</strong>
              <br />
              <small>
                The selected protocol ({formData.protocol?.toUpperCase() || 'unknown'}) does not
                support payment integration. Please use MCP or A2A protocol to enable x402 paywall
                features.
              </small>
            </div>
          </div>
        )}
        {isX402Supported && (
          <div className="card-body">
            <p className="text-muted small mb-3">
              <b>
                <i>x402 (HTTP Native Payments Protocol)</i>
              </b>{' '}
              is an open standard for blockchain-based payments using HTTP 402 "Payment Required"
              status code. Enable this to require payment verification before processing requests on
              this channel. Works as a payment layer on top of any protocol (A2A, MCP, etc.).
            </p>

            {hasAttemptedSave && formData.payment_policy?.settlement_mode === 'none' && (
              <div className="alert alert-danger" role="alert">
                <i className="fas fa-exclamation-triangle me-2"></i>
                <strong>Warning:</strong> No fund settlement will be performed - settlement mode is
                set to 'none'
              </div>
            )}

            {hasAttemptedSave &&
              (formData.payment_policy?.verification_mode === 'mock' ||
                formData.payment_policy?.verification_mode === 'signature') && (
                <div className="alert alert-warning" role="alert">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  <strong>Warning:</strong> No verification on chain will be performed due to
                  verification mode
                </div>
              )}

            <div className="row mb-3">
              <div className="col-md-6">
                <label className="form-label">Verification Mode</label>
                <select
                  className="form-control dropdown-styling"
                  value={
                    formData.payment_policy?.verification_mode ||
                    x402Config?.defaults.verification_mode ||
                    'mock'
                  }
                  onChange={e => {
                    setFormData({
                      ...formData,
                      payment_policy: {
                        ...formData.payment_policy!,
                        verification_mode: e.target.value,
                      },
                    });
                    setIsModified(true);
                  }}
                >
                  {x402Config ? (
                    x402Config.verification_modes.map(mode => (
                      <option key={mode.id} value={mode.id}>
                        {mode.name}
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="mock">Mock (Accept All - Testing)</option>
                      <option value="local">Local (On-Chain Verification)</option>
                      <option value="external_facilitator">Use external facilitator</option>
                      <option value="fabric_gateway">Use connected gateway facilitator</option>
                      <option value="signature">Verify cryptographic signature</option>
                    </>
                  )}
                </select>
                <small className="text-muted">
                  {x402Config &&
                    formData.payment_policy?.verification_mode &&
                    x402Config.verification_modes.find(
                      m => m.id === formData.payment_policy?.verification_mode
                    )?.description}
                </small>
              </div>

              <div className="col-md-6">
                <label className="form-label">Settlement Mode</label>
                <select
                  className="form-control dropdown-styling"
                  value={
                    formData.payment_policy?.verification_mode === 'mock'
                      ? 'none'
                      : formData.payment_policy?.settlement_mode ||
                        x402Config?.defaults.settlement_mode ||
                        'none'
                  }
                  disabled={formData.payment_policy?.verification_mode === 'mock'}
                  onChange={e => {
                    setFormData({
                      ...formData,
                      payment_policy: {
                        ...formData.payment_policy!,
                        settlement_mode: e.target.value,
                      },
                    });
                    setIsModified(true);
                  }}
                >
                  {x402Config ? (
                    x402Config.settlement_modes.map(mode => (
                      <option key={mode.id} value={mode.id}>
                        {mode.name}
                      </option>
                    ))
                  ) : (
                    <>
                      <option value="none">None</option>
                      <option value="deferred">Deferred (Batch Processing)</option>
                      <option value="immediate">Immediate (Not Recommended)</option>
                      <option value="external_facilitator">External Facilitator</option>
                      <option value="fabric_gateway">Fabric Gateway</option>
                    </>
                  )}
                </select>
                <small className="text-muted">
                  {x402Config &&
                    formData.payment_policy?.settlement_mode &&
                    x402Config.settlement_modes.find(
                      m => m.id === formData.payment_policy?.settlement_mode
                    )?.description}
                </small>
              </div>
            </div>

            {formData.payment_policy?.verification_mode === 'local' && (
              <div className="mb-3">
                <div className="row">
                  <div className="col-md-6">
                    <label className="form-label">Minimum Confirmations</label>
                    <input
                      type="number"
                      className="form-control"
                      min="0"
                      max="100"
                      value={formData.payment_policy?.min_confirmations ?? 0}
                      onChange={e => {
                        const value = parseInt(e.target.value) || 0;
                        setFormData({
                          ...formData,
                          payment_policy: {
                            ...formData.payment_policy!,
                            min_confirmations: Math.max(0, Math.min(100, value)),
                          },
                        });
                        setIsModified(true);
                      }}
                    />
                    <small className="text-muted">
                      Number of block confirmations required. 0 = accept mempool transactions
                      (instant but risky), 1+ = wait for confirmations (slower but safer).
                    </small>
                  </div>
                  <div className="col-md-6">
                    <label className="form-label">Accept Mempool Transactions</label>
                    <div className="form-check mt-2">
                      <input
                        type="checkbox"
                        className="form-check-input"
                        id="accept-mempool"
                        checked={formData.payment_policy?.accept_mempool_tx ?? true}
                        disabled={formData.payment_policy?.min_confirmations !== 0}
                        onChange={e => {
                          setFormData({
                            ...formData,
                            payment_policy: {
                              ...formData.payment_policy!,
                              accept_mempool_tx: e.target.checked,
                            },
                          });
                          setIsModified(true);
                        }}
                      />
                      <label className="form-check-label" htmlFor="accept-mempool">
                        {formData.payment_policy?.min_confirmations !== 0
                          ? 'Not available (confirmations > 0)'
                          : 'Accept unconfirmed transactions'}
                      </label>
                    </div>
                    <small className="text-muted">
                      Only applies when min_confirmations = 0. Enables instant payments but
                      transactions could be reversed.
                    </small>
                  </div>
                </div>
              </div>
            )}

            {(formData.payment_policy?.verification_mode === 'external_facilitator' ||
              formData.payment_policy?.settlement_mode === 'external_facilitator') && (
              <div className="mb-3">
                <label className="form-label">Facilitator URL</label>
                <input
                  type="text"
                  className="form-control"
                  value={
                    formData.payment_policy?.facilitator_url || 'https://www.x402.org/facilitator'
                  }
                  onChange={e => {
                    setFormData({
                      ...formData,
                      payment_policy: {
                        ...formData.payment_policy!,
                        facilitator_url: e.target.value,
                      },
                    });
                    setIsModified(true);
                  }}
                />
                <br />
                <div className="alert alert-info mb-0">
                  <i className="fas fa-info-circle me-2"></i>A facilitator in the x402 protocol is a
                  specialized, optional service that acts as an intermediary to manage on-chain
                  payment verification and settlement between clients (agents/users) and servers.
                  https://www.x402.org/facilitator is a public facilitator service run by the x402
                  protocol team that can be used for testing and small-scale applications. Note that
                  it only supports Base Sepolia and Solana Devnet.
                </div>
              </div>
            )}

            {(formData.payment_policy?.verification_mode === 'fabric_gateway' ||
              formData.payment_policy?.settlement_mode === 'fabric_gateway') && (
              <div className="mb-3">
                <label className="form-label">Facilitator Gateway</label>
                <select
                  className="form-control dropdown-styling"
                  value={formData.payment_policy?.facilitator_gateway_id || ''}
                  onChange={e => {
                    setFormData({
                      ...formData,
                      payment_policy: {
                        ...formData.payment_policy!,
                        facilitator_gateway_id: e.target.value,
                        settlement_gateway_id: e.target.value,
                      },
                    });
                    setIsModified(true);
                  }}
                >
                  <option value="">Select a connected gateway...</option>
                  {gateways.map(gw => (
                    <option key={gw.id} value={gw.id}>
                      {gw.name}
                    </option>
                  ))}
                </select>
                <small className="text-muted">
                  Select a connected gateway to handle payment verification and/or settlement via
                  DIDComm messages. The selected gateway must have x402 facilitator service enabled
                  in its configuration.
                </small>
              </div>
            )}

            <div className="mb-3">
              <label className="form-label">Crypto Network Payment Options</label>
              <div className="card bg-light">
                <div className="card-body">
                  <small className="text-muted mb-2 d-block">
                    Configure blockchain networks for accepting payments:
                  </small>
                  {Object.entries(formData.payment_policy?.rpc_endpoints || {}).map(
                    ([network, _url]) => {
                      const networkConfig = x402Config?.networks.find(n => n.id === network);
                      const networkName = networkConfig?.name || network;
                      const networkDesc = networkConfig?.description || '';
                      const tokens = networkConfig?.x402_tokens || [];

                      return (
                        <div key={network} className="mb-2 p-3 bg-white rounded border">
                          <div className="d-flex align-items-center justify-content-between">
                            <div className="flex-grow-1">
                              <div className="fw-semibold">{networkName}</div>
                              {networkDesc && (
                                <small className="text-muted d-block">{networkDesc}</small>
                              )}
                            </div>

                            {tokens.length > 0 && (
                              <div
                                className="d-flex flex-wrap align-items-center me-2"
                                style={{ gap: '10px' }}
                              >
                                {tokens.map(token => {
                                  const hasRequirement = (
                                    formData.payment_policy?.payment_requirements || []
                                  ).some(
                                    (req: any) =>
                                      req.network === network &&
                                      req.asset === token.contract_address
                                  );

                                  const isSolana = network.startsWith('solana:');

                                  return (
                                    <button
                                      key={token.contract_address}
                                      className={`badge border-0 px-2 py-1 text-white ${
                                        hasRequirement ? 'bg-success' : 'bg-primary'
                                      }`}
                                      onClick={() => {
                                        if (hasRequirement) {
                                          const cardId = `payment-req-${network}-${token.contract_address}`;
                                          const element = document.getElementById(cardId);
                                          if (element) {
                                            element.scrollIntoView({
                                              behavior: 'smooth',
                                              block: 'center',
                                            });
                                          }
                                          return;
                                        }

                                        const extraData = isSolana
                                          ? {
                                              name: token.symbol,
                                              decimals: token.decimals,
                                              assetTransferMethod: token.asset_transfer_method,
                                            }
                                          : {
                                              name: token.symbol,
                                              version: token.version || '2',
                                              assetTransferMethod: token.asset_transfer_method,
                                            };

                                        let defaultRecipientId = '';
                                        if (x402Config) {
                                          const availableRecipients =
                                            x402Config.recipient_addresses.filter(
                                              r => r.addresses[network]
                                            );
                                          if (availableRecipients.length === 1) {
                                            defaultRecipientId = availableRecipients[0].id;
                                          }
                                        }

                                        setFormData({
                                          ...formData,
                                          payment_policy: {
                                            ...formData.payment_policy!,
                                            payment_requirements: [
                                              ...(formData.payment_policy?.payment_requirements ||
                                                []),
                                              {
                                                scheme: 'exact',
                                                network: network,
                                                amount: '',
                                                recipient_id: defaultRecipientId,
                                                asset: token.contract_address,
                                                maxTimeoutSeconds: 60,
                                                extra: extraData,
                                              },
                                            ],
                                          },
                                        });
                                        setIsModified(true);
                                      }}
                                      title={
                                        hasRequirement
                                          ? `Click to view ${token.symbol} payment requirement`
                                          : `Click to add ${token.symbol} payment requirement`
                                      }
                                    >
                                      {token.symbol}
                                    </button>
                                  );
                                })}
                              </div>
                            )}

                            <button
                              className="btn btn-sm btn-outline-danger"
                              onClick={() => {
                                const { [network]: _removed, ...rest } =
                                  formData.payment_policy?.rpc_endpoints || {};
                                const updatedRequirements = (
                                  formData.payment_policy?.payment_requirements || []
                                ).filter((req: any) => req.network !== network);
                                setFormData({
                                  ...formData,
                                  payment_policy: {
                                    ...formData.payment_policy!,
                                    rpc_endpoints: rest,
                                    payment_requirements: updatedRequirements,
                                  },
                                });
                                setIsModified(true);
                              }}
                              title="Remove this network"
                            >
                              <i className="fas fa-trash"></i>
                            </button>
                          </div>
                        </div>
                      );
                    }
                  )}
                  {x402Config && x402Config.networks.length > 0 ? (
                    <div className="input-group mt-2">
                      <select
                        className="form-control dropdown-styling"
                        id="network-select"
                        defaultValue=""
                      >
                        <option value="" disabled>
                          Select network to add...
                        </option>
                        <optgroup label="Mainnets">
                          {x402Config.networks
                            .filter(
                              network =>
                                !network.name.toLowerCase().includes('sepolia') &&
                                !network.name.toLowerCase().includes('testnet') &&
                                !network.name.toLowerCase().includes('devnet') &&
                                !network.name.toLowerCase().includes('amoy')
                            )
                            .map(network => {
                              const isAdded =
                                network.id in (formData.payment_policy?.rpc_endpoints || {});
                              return (
                                <option
                                  key={network.id}
                                  value={network.id}
                                  title={network.description}
                                  disabled={isAdded}
                                >
                                  {network.name} - {network.description}
                                  {isAdded ? ' (Already added)' : ''}
                                </option>
                              );
                            })}
                        </optgroup>
                        <optgroup label="Testnets">
                          {x402Config.networks
                            .filter(
                              network =>
                                network.name.toLowerCase().includes('sepolia') ||
                                network.name.toLowerCase().includes('testnet') ||
                                network.name.toLowerCase().includes('devnet') ||
                                network.name.toLowerCase().includes('amoy')
                            )
                            .map(network => {
                              const isAdded =
                                network.id in (formData.payment_policy?.rpc_endpoints || {});
                              return (
                                <option
                                  key={network.id}
                                  value={network.id}
                                  title={network.description}
                                  disabled={isAdded}
                                >
                                  {network.name} - {network.description}
                                  {isAdded ? ' (Already added)' : ''}
                                </option>
                              );
                            })}
                        </optgroup>
                      </select>
                      <button
                        className="btn btn-outline-primary"
                        onClick={() => {
                          const select = document.getElementById(
                            'network-select'
                          ) as HTMLSelectElement;
                          const networkId = select.value;
                          if (networkId && x402Config) {
                            const network = x402Config.networks.find(n => n.id === networkId);
                            if (network) {
                              const tokens = network.x402_tokens || [];
                              const isSolana = network.id.startsWith('solana:');

                              let paymentRequirements =
                                formData.payment_policy?.payment_requirements || [];

                              if (tokens.length === 1) {
                                const token = tokens[0];
                                const extraData = isSolana
                                  ? {
                                      name: token.symbol,
                                      decimals: token.decimals,
                                      assetTransferMethod: token.asset_transfer_method,
                                    }
                                  : {
                                      name: token.symbol,
                                      version: token.version || '2',
                                      assetTransferMethod: token.asset_transfer_method,
                                    };

                                let defaultRecipientId = '';
                                const availableRecipients = x402Config.recipient_addresses.filter(
                                  r => r.addresses[network.id]
                                );
                                if (availableRecipients.length === 1) {
                                  defaultRecipientId = availableRecipients[0].id;
                                }

                                paymentRequirements = [
                                  ...paymentRequirements,
                                  {
                                    scheme: 'exact',
                                    network: network.id,
                                    amount: '',
                                    recipient_id: defaultRecipientId,
                                    asset: token.contract_address,
                                    maxTimeoutSeconds: 60,
                                    extra: extraData,
                                  },
                                ];
                              }

                              setFormData({
                                ...formData,
                                payment_policy: {
                                  ...formData.payment_policy!,
                                  rpc_endpoints: {
                                    ...(formData.payment_policy?.rpc_endpoints || {}),
                                    [network.id]: network.rpc_endpoint,
                                  },
                                  payment_requirements: paymentRequirements,
                                },
                              });
                              setIsModified(true);
                              select.value = '';
                            }
                          }
                        }}
                      >
                        <i className="fas fa-plus me-2"></i> Add this payment option
                      </button>
                    </div>
                  ) : (
                    <button
                      className="btn btn-sm btn-outline-primary mt-2"
                      onClick={() => {
                        const network = prompt(
                          'Enter network name (e.g., base, ethereum, solana):'
                        );
                        if (network) {
                          setFormData({
                            ...formData,
                            payment_policy: {
                              ...formData.payment_policy!,
                              rpc_endpoints: {
                                ...(formData.payment_policy?.rpc_endpoints || {}),
                                [network]: '',
                              },
                            },
                          });
                          setIsModified(true);
                        }
                      }}
                    >
                      <i className="fas fa-plus me-2"></i> Add this payment option
                    </button>
                  )}
                </div>
              </div>
            </div>

            <div className="mb-3">
              <label className="form-label">Payment Requirements</label>
              <div className="card bg-light">
                <div className="card-body">
                  <small className="text-muted mb-2 d-block">
                    Define acceptable payment options (clients can choose one):
                  </small>
                  {(formData.payment_policy?.payment_requirements || []).map(
                    (req: any, idx: number) => {
                      const networkName =
                        x402Config?.networks.find(n => n.id === req.network)?.name ||
                        req.network ||
                        'New Payment Option';
                      const networkConfig = x402Config?.networks.find(n => n.id === req.network);
                      const selectedToken = networkConfig?.x402_tokens.find(
                        t => t.contract_address === req.asset
                      );
                      const tokenSymbol = selectedToken?.symbol || 'Unknown Token';
                      const networkDenomination = selectedToken?.denomination || 'smallest unit';
                      const denominationDescription = selectedToken?.description;
                      const rpcEndpoint = req.network
                        ? formData.payment_policy?.rpc_endpoints?.[req.network]
                        : undefined;
                      const blockExplorer = networkConfig?.block_explorer;
                      return (
                        <div
                          key={idx}
                          id={`payment-req-${req.network}-${req.asset}`}
                          className="card mb-4"
                        >
                          <div className="card-header bg-light py-1 px-2 d-flex justify-content-between align-items-center">
                            <strong className="small">
                              <span className="badge border-0 px-2 py-1 text-white bg-success me-2">
                                {tokenSymbol}
                              </span>{' '}
                              {networkName}
                            </strong>
                            <button
                              className="btn btn-sm btn-outline-danger"
                              onClick={() => {
                                const updated = (
                                  formData.payment_policy?.payment_requirements || []
                                ).filter((_: any, i: number) => i !== idx);
                                setFormData({
                                  ...formData,
                                  payment_policy: {
                                    ...formData.payment_policy!,
                                    payment_requirements: updated,
                                  },
                                });
                                setIsModified(true);
                              }}
                            >
                              <i className="fas fa-trash"></i>
                            </button>
                          </div>
                          <div className="card-body p-3">
                            <div className="row g-3">
                              <div className="col-md-4">
                                <label className="form-label small">
                                  Amount in {networkDenomination}
                                </label>
                                <input
                                  type="text"
                                  className="form-control form-control-sm"
                                  value={req.amount}
                                  onChange={e => {
                                    const updated = [
                                      ...(formData.payment_policy?.payment_requirements || []),
                                    ];
                                    updated[idx] = { ...req, amount: e.target.value };
                                    setFormData({
                                      ...formData,
                                      payment_policy: {
                                        ...formData.payment_policy!,
                                        payment_requirements: updated,
                                      },
                                    });
                                    setIsModified(true);
                                  }}
                                />
                              </div>
                              <div className="col-md-4">
                                <label className="form-label small">Actual Cost</label>
                                <div className="form-control form-control-sm bg-light d-flex align-items-center">
                                  <strong style={{ fontSize: '0.95rem' }}>
                                    {(() => {
                                      const token = networkConfig?.x402_tokens.find(
                                        t => t.contract_address === req.asset
                                      );
                                      const decimals = token?.decimals || 0;
                                      const denom = token?.denomination || '';
                                      const amount = parseFloat(req.amount || '0');
                                      if (isNaN(amount) || decimals === 0) return '-';
                                      const actualValue = amount / Math.pow(10, decimals);
                                      return `$${actualValue.toFixed(2)} ${denom}`;
                                    })()}
                                  </strong>
                                </div>
                              </div>
                              <div className="col-md-4">
                                <label className="form-label small">Unit Conversion</label>
                                <div className="form-control form-control-sm bg-light d-flex align-items-center text-muted">
                                  {denominationDescription || '-'}
                                </div>
                              </div>

                              <div className="col-md-4">
                                <label className="form-label small">Recipient</label>
                                {x402Config ? (
                                  <>
                                    <select
                                      className="form-control form-control-sm dropdown-styling"
                                      value={req.recipient_id || ''}
                                      onChange={e => {
                                        const updated = [
                                          ...(formData.payment_policy?.payment_requirements || []),
                                        ];
                                        updated[idx] = { ...req, recipient_id: e.target.value };
                                        setFormData({
                                          ...formData,
                                          payment_policy: {
                                            ...formData.payment_policy!,
                                            payment_requirements: updated,
                                          },
                                        });
                                        setIsModified(true);
                                      }}
                                    >
                                      <option value="">Select recipient...</option>
                                      {x402Config.recipient_addresses.map(recipient => {
                                        const networkAddress = req.network
                                          ? recipient.addresses[req.network]
                                          : null;
                                        return (
                                          <option
                                            key={recipient.id}
                                            value={recipient.id}
                                            disabled={!networkAddress}
                                          >
                                            {recipient.name}{' '}
                                            {networkAddress
                                              ? `(${networkAddress.substring(0, 8)}...${networkAddress.substring(networkAddress.length - 6)})`
                                              : '(Not available)'}
                                          </option>
                                        );
                                      })}
                                    </select>
                                    {(() => {
                                      const selected = x402Config.recipient_addresses.find(
                                        r => r.id === req.recipient_id
                                      );
                                      const addr =
                                        selected && req.network
                                          ? selected.addresses[req.network]
                                          : null;
                                      return addr ? (
                                        <div
                                          className="text-muted small mt-1 font-monospace text-truncate"
                                          title={addr}
                                        >
                                          {addr}
                                        </div>
                                      ) : null;
                                    })()}
                                  </>
                                ) : (
                                  <div className="alert alert-warning small mb-0 py-2 px-2">
                                    Global x402 config is unavailable, so recipient addresses cannot
                                    be selected. The save will be rejected until the config loads.
                                  </div>
                                )}
                              </div>
                              <div className="col-md-4">
                                <label className="form-label small">Scheme</label>
                                <select
                                  className="form-control form-control-sm dropdown-styling"
                                  value={req.scheme}
                                  onChange={e => {
                                    const updated = [
                                      ...(formData.payment_policy?.payment_requirements || []),
                                    ];
                                    updated[idx] = { ...req, scheme: e.target.value };
                                    setFormData({
                                      ...formData,
                                      payment_policy: {
                                        ...formData.payment_policy!,
                                        payment_requirements: updated,
                                      },
                                    });
                                    setIsModified(true);
                                  }}
                                >
                                  {x402Config ? (
                                    x402Config.payment_schemes.map(scheme => (
                                      <option key={scheme.id} value={scheme.id}>
                                        {scheme.name}
                                      </option>
                                    ))
                                  ) : (
                                    <>
                                      <option value="exact">Exact</option>
                                      <option value="upto">Up To</option>
                                    </>
                                  )}
                                </select>
                              </div>
                              <div className="col-md-4">
                                <label className="form-label small">Transaction Timeout</label>
                                <select
                                  className="form-control form-control-sm dropdown-styling"
                                  value={req.maxTimeoutSeconds}
                                  onChange={e => {
                                    const updated = [
                                      ...(formData.payment_policy?.payment_requirements || []),
                                    ];
                                    updated[idx] = {
                                      ...req,
                                      maxTimeoutSeconds: parseInt(e.target.value),
                                    };
                                    setFormData({
                                      ...formData,
                                      payment_policy: {
                                        ...formData.payment_policy!,
                                        payment_requirements: updated,
                                      },
                                    });
                                    setIsModified(true);
                                  }}
                                >
                                  <option value={30}>30 seconds</option>
                                  <option value={60}>1 minute</option>
                                  <option value={120}>2 minutes</option>
                                  <option value={300}>5 minutes</option>
                                  <option value={600}>10 minutes</option>
                                </select>
                              </div>
                            </div>

                            <hr className="my-3" />

                            <div className="row g-2">
                              {rpcEndpoint && (
                                <div className="col-md-6">
                                  <small>
                                    <strong>RPC Endpoint:</strong>{' '}
                                    <a
                                      href={rpcEndpoint}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-break"
                                    >
                                      {rpcEndpoint}{' '}
                                      <i className="fas fa-external-link-alt ms-1"></i>
                                    </a>
                                  </small>
                                </div>
                              )}
                              {blockExplorer && (
                                <div className="col-md-6">
                                  <small>
                                    <strong>Block Explorer:</strong>{' '}
                                    <a
                                      href={blockExplorer}
                                      target="_blank"
                                      rel="noopener noreferrer"
                                      className="text-break"
                                    >
                                      {blockExplorer}{' '}
                                      <i className="fas fa-external-link-alt ms-1"></i>
                                    </a>
                                  </small>
                                </div>
                              )}
                              <div className="col-md-6">
                                <small>
                                  <strong>Contract Address:</strong>{' '}
                                  <span
                                    className="text-break"
                                    title={req.asset || 'No token selected'}
                                  >
                                    {req.asset || '-'}
                                  </span>
                                </small>
                              </div>
                              <div className="col-md-6">
                                <small>
                                  <strong>Transfer Method:</strong>{' '}
                                  {(() => {
                                    const token = networkConfig?.x402_tokens.find(
                                      t => t.contract_address === req.asset
                                    );
                                    return token?.asset_transfer_method || '-';
                                  })()}
                                </small>
                              </div>
                            </div>
                          </div>
                        </div>
                      );
                    }
                  )}
                </div>
              </div>
            </div>

            <div className="mb-3">
              <label className="form-label">Payment Triggers (Protocol-Specific)</label>
              <div className="card bg-light">
                <div className="card-body">
                  <small className="text-muted d-block mb-3">
                    Configure which operations require payment. If left empty, no requests will
                    require payment.
                  </small>

                  {formData.protocol === 'mcp' &&
                    (() => {
                      type TriggerMode = 'all' | 'match' | 'exclude';
                      const stored = formData.payment_policy?.mcp_payment_triggers;
                      const current: { mode: TriggerMode; patterns: string[] } = stored
                        ? stored.mode === 'all'
                          ? { mode: 'all', patterns: [] }
                          : { mode: stored.mode, patterns: stored.patterns || [] }
                        : { mode: 'match', patterns: [] };

                      const writeTriggers = (mode: TriggerMode, patterns: string[]) => {
                        const next = mode === 'all' ? { mode: 'all' as const } : { mode, patterns };
                        setFormData({
                          ...formData,
                          payment_policy: {
                            ...formData.payment_policy!,
                            mcp_payment_triggers: next,
                          },
                        });
                        setIsModified(true);
                      };

                      const showPatterns = current.mode !== 'all';
                      const hasNoEffectivePatterns =
                        showPatterns &&
                        (current.patterns.length === 0 ||
                          current.patterns.every((p: string) => !p.trim()));

                      return (
                        <div className="mb-3">
                          <label className="form-label small font-weight-bold">
                            <i className="fas fa-wrench me-1"></i> MCP Payment Trigger Mode
                          </label>
                          <small className="text-muted d-block mb-2">
                            Only <code>tools/call</code> requests can be charged. Free methods like{' '}
                            <code>tools/list</code> or <code>initialize</code> are not part of the
                            payment inspection process.
                          </small>

                          <select
                            className="form-select form-select-sm mb-3"
                            value={current.mode}
                            onChange={e => {
                              const mode = e.target.value as TriggerMode;
                              writeTriggers(mode, mode === 'all' ? [] : current.patterns);
                            }}
                            aria-label="MCP Payment Trigger Mode"
                          >
                            <option value="all">Charge all tools</option>
                            <option value="match">Charge tools matching regex</option>
                            <option value="exclude">Charge all EXCEPT regex matches</option>
                          </select>

                          {current.mode === 'all' && (
                            <div className="alert alert-success mb-0" role="alert">
                              <i className="fas fa-check-circle me-2"></i>
                              <strong>Every</strong> <code>tools/call</code> on this channel will
                              require payment.
                            </div>
                          )}

                          {showPatterns && (
                            <>
                              <small className="text-muted d-block mb-2">
                                {current.mode === 'match'
                                  ? 'A tool is charged when its name matches ANY of the patterns below. Patterns are full regex (anchor with ^ and $ for exact match).'
                                  : 'A tool is charged UNLESS its name matches at least one pattern below. Patterns are full regex.'}
                              </small>

                              {(current.patterns.length === 0 ? [''] : current.patterns).map(
                                (pattern: string, idx: number, arr: string[]) => (
                                  <div key={idx} className="input-group input-group-sm mb-2">
                                    <span className="input-group-text">
                                      <i className="fas fa-asterisk"></i>
                                    </span>
                                    <input
                                      type="text"
                                      className="form-control font-monospace"
                                      value={pattern}
                                      onChange={e => {
                                        const next = [...arr];
                                        next[idx] = e.target.value;
                                        writeTriggers(current.mode, next);
                                      }}
                                      placeholder={
                                        current.mode === 'match'
                                          ? '^paid_.*$  or  premium'
                                          : '^free_.*$  or  health_check'
                                      }
                                    />
                                    <button
                                      className="btn btn-outline-danger"
                                      type="button"
                                      onClick={() =>
                                        writeTriggers(
                                          current.mode,
                                          arr.filter((_: string, i: number) => i !== idx)
                                        )
                                      }
                                      aria-label="Remove pattern"
                                    >
                                      <i className="fas fa-trash"></i>
                                    </button>
                                  </div>
                                )
                              )}

                              <button
                                className="btn btn-sm btn-outline-primary"
                                type="button"
                                onClick={() =>
                                  writeTriggers(current.mode, [
                                    ...(current.patterns.length === 0 ? [''] : current.patterns),
                                    '',
                                  ])
                                }
                              >
                                <i className="fas fa-plus me-2"></i>Add Pattern
                              </button>

                              {hasAttemptedSave &&
                                hasNoEffectivePatterns &&
                                current.mode === 'match' && (
                                  <div className="alert alert-danger mt-3 mb-0" role="alert">
                                    <i className="fas fa-exclamation-circle me-2"></i>
                                    <strong>Error:</strong> At least one tool pattern is required
                                    when charging selected tools. Add a pattern above or switch to
                                    &ldquo;Charge all tools&rdquo;.
                                  </div>
                                )}
                              {hasAttemptedSave &&
                                hasNoEffectivePatterns &&
                                current.mode === 'exclude' && (
                                  <div className="alert alert-danger mt-3 mb-0" role="alert">
                                    <i className="fas fa-exclamation-circle me-2"></i>
                                    <strong>Error:</strong> At least one tool pattern is required
                                    when excluding tools. Add a pattern above or switch to
                                    &ldquo;Charge all tools&rdquo;.
                                  </div>
                                )}
                            </>
                          )}
                        </div>
                      );
                    })()}

                  {(formData.protocol === 'a2a' || formData.protocol === 'ap2') && (
                    <div className="mb-3">
                      <label className="form-label small font-weight-bold">
                        <i className="fas fa-exchange-alt me-1"></i>{' '}
                        {formData.protocol?.toUpperCase()} Methods Requiring Payment
                      </label>
                      <small className="text-muted d-block mb-3">
                        Configure which A2A methods require payment and optional regex patterns to
                        filter by message content.
                      </small>

                      <A2AMethodFilterEditor
                        filters={formData.payment_policy?.a2a_method_filters || []}
                        onChange={(filters: A2AMethodFilter[]) => {
                          setFormData({
                            ...formData,
                            payment_policy: {
                              ...formData.payment_policy!,
                              a2a_method_filters: filters,
                            },
                          });
                          setIsModified(true);
                        }}
                      />
                    </div>
                  )}

                  {formData.protocol !== 'mcp' &&
                    formData.protocol !== 'a2a' &&
                    formData.protocol !== 'ap2' && (
                      <div className="alert alert-info mb-0">
                        <i className="fas fa-info-circle me-2"></i>
                        Protocol-specific payment triggers not yet available for{' '}
                        {formData.protocol?.toUpperCase() || 'this protocol'}. All requests will
                        require payment.
                      </div>
                    )}
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default PaymentX402Fullscreen;
