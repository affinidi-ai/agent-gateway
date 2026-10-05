import React, { useMemo } from 'react';
import type { ConfigPanelProps } from '../types';
import { A2AMethodFilterEditor, type A2AMethodFilter } from './PaymentX402Fullscreen';
import MppSecretField from './MppSecretField';
import PaymentMethodsEditor, { type MppPaymentMethodEntry } from './PaymentMethodsEditor';

type McpTriggerMode = 'all' | 'match' | 'exclude';

/**
 * Fullscreen editor for the Payment (MPP) element's advanced settings.
 *
 * Realm, HMAC secret key, and challenge TTL live in the compact sidebar
 * panel (`PaymentPanel`) since they fit comfortably there. This editor
 * covers the fields that need more room: payment methods, Stripe card
 * charging, on-chain verification posture, and protocol-specific payment
 * triggers — mirroring the backend `MppConfig` fields (`src/mpp/types.rs`).
 */
const PaymentMppFullscreen: React.FC<ConfigPanelProps> = ({
  config,
  updateField,
  protocol,
  closeFullscreenEditor,
}) => {
  const isMppSupported = protocol === 'mcp' || protocol === 'a2a';
  const verificationMode: string = config.mpp_crypto_verification_mode || 'passthrough';
  const isOnchain = verificationMode === 'onchain' || verificationMode === 'full';

  const paymentMethods: MppPaymentMethodEntry[] = useMemo(() => {
    const v = config.mpp_payment_methods;
    if (Array.isArray(v)) return v;
    if (typeof v === 'string' && v.trim()) {
      try {
        const parsed = JSON.parse(v);
        return Array.isArray(parsed) ? parsed : [];
      } catch {
        return [];
      }
    }
    return [];
  }, [config.mpp_payment_methods]);

  const rpcEndpointsText = useMemo(() => {
    const v = config.mpp_rpc_endpoints;
    if (typeof v === 'string') return v;
    if (v && typeof v === 'object') return JSON.stringify(v, null, 2);
    return '';
  }, [config.mpp_rpc_endpoints]);

  const mcpTrigger: { mode: McpTriggerMode; patterns: string[] } = useMemo(() => {
    const stored = config.mpp_mcp_payment_triggers;
    if (!stored) return { mode: 'match', patterns: [] };
    if (stored.mode === 'all') return { mode: 'all', patterns: [] };
    return { mode: stored.mode, patterns: stored.patterns || [] };
  }, [config.mpp_mcp_payment_triggers]);

  const writeMcpTrigger = (mode: McpTriggerMode, patterns: string[]) => {
    updateField('mpp_mcp_payment_triggers', mode === 'all' ? { mode: 'all' } : { mode, patterns });
  };

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

      <div className="card shadow-sm mb-4">
        <div className="card-header bg-light">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-file-invoice-dollar"></i> MPP (Machine Payments Protocol)
          </h6>
        </div>

        {!isMppSupported && (
          <div className="card-body">
            <div className="alert alert-info mb-0" role="alert">
              <i className="fas fa-info-circle"></i>{' '}
              <strong>MPP is only available for MCP and A2A protocols.</strong>
              <br />
              <small>
                The selected protocol ({protocol?.toUpperCase() || 'unknown'}) does not support
                payment integration.
              </small>
            </div>
          </div>
        )}

        {isMppSupported && (
          <div className="card-body">
            <p className="text-muted small mb-3">
              <b>
                <i>draft-httpauth-payment-00</i>
              </b>{' '}
              Machine Payments Protocol. Realm, HMAC secret key, challenge TTL, and payment methods
              are configured in the sidebar panel; the settings below control card charging,
              on-chain settlement verification, and which requests require payment.
            </p>

            <div className="mb-3">
              <label className="form-label">Payment Methods</label>
              <small className="text-muted d-block mb-2">
                Ways this surface can accept payment. Crypto methods (<code>tempo</code>/
                <code>crypto</code>/<code>evm</code>) are verified per the Crypto Verification Mode
                below; <code>card</code>/<code>stripe</code> requires the Stripe Secret Key below.
              </small>
              <PaymentMethodsEditor
                methods={paymentMethods}
                onChange={methods => updateField('mpp_payment_methods', methods)}
              />
            </div>

            <div className="mb-3">
              <MppSecretField
                label="Stripe Secret Key"
                value={config.mpp_stripe_secret_key || ''}
                onChange={v => updateField('mpp_stripe_secret_key', v)}
                helpText={
                  <>
                    Required when a <code>card</code> payment method is configured. Pick a secret
                    from the Secrets store; it is resolved server-side and never stored in the
                    surface config.
                  </>
                }
              />
            </div>

            <div className="mb-3">
              <label className="form-label">Crypto Verification Mode</label>
              <select
                className="form-select form-select-sm"
                value={verificationMode}
                onChange={e => updateField('mpp_crypto_verification_mode', e.target.value)}
              >
                <option value="passthrough">Passthrough (dev only — no verification)</option>
                <option value="onchain">On-chain (verify receipt via RPC)</option>
                <option value="signature">Signature (offline EIP-3009 / Permit2)</option>
                <option value="full">Full (signature + on-chain)</option>
              </select>
              <small className="text-muted d-block mt-1">
                Applies to <code>tempo</code>/<code>crypto</code>/<code>evm</code> payment methods
                only; card/Stripe methods are unaffected.
              </small>
              {verificationMode === 'passthrough' && (
                <div className="alert alert-warning mt-2 mb-0 py-2" role="alert">
                  <i className="fas fa-exclamation-triangle me-1"></i>
                  Passthrough accepts any claimed proof without checking the chain. A mainnet crypto
                  payment method cannot be saved with this mode — use on-chain, signature, or full.
                </div>
              )}
            </div>

            <div className="mb-3">
              <label className="form-label">Verification Timeout (ms)</label>
              <input
                type="number"
                min={0}
                className="form-control form-control-sm"
                style={{ maxWidth: 160 }}
                value={config.mpp_verification_timeout_ms ?? 10000}
                onChange={e => updateField('mpp_verification_timeout_ms', e.target.value)}
              />
              <small className="text-muted d-block mt-1">
                How long to wait for on-chain verification before failing. Default 10000.
              </small>
            </div>

            {isOnchain && (
              <>
                <div className="mb-3">
                  <label className="form-label">Minimum Confirmations</label>
                  <input
                    type="number"
                    min={0}
                    className="form-control form-control-sm"
                    style={{ maxWidth: 160 }}
                    value={config.mpp_min_confirmations ?? 0}
                    onChange={e => updateField('mpp_min_confirmations', e.target.value)}
                  />
                  <small className="text-muted d-block mt-1">
                    A mainnet crypto method requires at least 1 confirmation.
                  </small>
                </div>

                <div className="mb-3">
                  <label className="form-label">RPC Endpoints (JSON)</label>
                  <textarea
                    className="form-control font-monospace"
                    style={{ fontSize: '12px' }}
                    rows={4}
                    placeholder={`{\n  "eip155:8453": "https://mainnet.base.org"\n}`}
                    value={rpcEndpointsText}
                    onChange={e => updateField('mpp_rpc_endpoints', e.target.value)}
                  />
                  <small className="text-muted d-block mt-1">
                    Map of CAIP-2 network id to RPC URL, used to fetch and verify the transaction
                    receipt.
                  </small>
                </div>
              </>
            )}

            <hr />

            <div className="mb-3">
              <label className="form-label">Payment Triggers (Protocol-Specific)</label>
              <div className="card bg-light">
                <div className="card-body">
                  <small className="text-muted d-block mb-3">
                    Configure which operations require payment. If left empty, no requests will
                    require payment.
                  </small>

                  {protocol === 'mcp' && (
                    <div className="mb-3">
                      <label className="form-label small font-weight-bold">
                        <i className="fas fa-wrench me-1"></i> MCP Payment Trigger Mode
                      </label>
                      <small className="text-muted d-block mb-2">
                        Only <code>tools/call</code> requests can be charged.
                      </small>

                      <select
                        className="form-select form-select-sm mb-3"
                        value={mcpTrigger.mode}
                        onChange={e => {
                          const mode = e.target.value as McpTriggerMode;
                          writeMcpTrigger(mode, mode === 'all' ? [] : mcpTrigger.patterns);
                        }}
                        aria-label="MCP Payment Trigger Mode"
                      >
                        <option value="all">Charge all tools</option>
                        <option value="match">Charge tools matching regex</option>
                        <option value="exclude">Charge all EXCEPT regex matches</option>
                      </select>

                      {mcpTrigger.mode === 'all' && (
                        <div className="alert alert-success mb-0" role="alert">
                          <i className="fas fa-check-circle me-2"></i>
                          <strong>Every</strong> <code>tools/call</code> on this surface will
                          require payment.
                        </div>
                      )}

                      {mcpTrigger.mode !== 'all' && (
                        <>
                          {(mcpTrigger.patterns.length === 0 ? [''] : mcpTrigger.patterns).map(
                            (pattern, idx, arr) => (
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
                                    writeMcpTrigger(mcpTrigger.mode, next);
                                  }}
                                  placeholder={
                                    mcpTrigger.mode === 'match'
                                      ? '^paid_.*$  or  premium'
                                      : '^free_.*$  or  health_check'
                                  }
                                />
                                <button
                                  className="btn btn-outline-danger"
                                  type="button"
                                  onClick={() =>
                                    writeMcpTrigger(
                                      mcpTrigger.mode,
                                      arr.filter((_, i) => i !== idx)
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
                              writeMcpTrigger(mcpTrigger.mode, [
                                ...(mcpTrigger.patterns.length === 0 ? [''] : mcpTrigger.patterns),
                                '',
                              ])
                            }
                          >
                            <i className="fas fa-plus me-2"></i>Add Pattern
                          </button>
                        </>
                      )}
                    </div>
                  )}

                  {protocol === 'a2a' && (
                    <div className="mb-3">
                      <label className="form-label small font-weight-bold">
                        <i className="fas fa-exchange-alt me-1"></i> A2A Methods Requiring Payment
                      </label>
                      <small className="text-muted d-block mb-3">
                        Configure which A2A methods require payment and optional regex patterns to
                        filter by message content. Leave empty to charge nothing over A2A.
                      </small>
                      <A2AMethodFilterEditor
                        filters={config.mpp_a2a_method_filters || []}
                        onChange={(filters: A2AMethodFilter[]) =>
                          updateField('mpp_a2a_method_filters', filters)
                        }
                      />
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

export default PaymentMppFullscreen;
