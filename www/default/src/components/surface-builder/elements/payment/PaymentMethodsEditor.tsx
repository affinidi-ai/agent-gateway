import React, { useState } from 'react';

export interface MppPaymentMethodEntry {
  method: string;
  intent: string;
  currency: string;
  recipient: string;
  amount: string;
  network?: string;
}

const CRYPTO_METHODS = ['tempo', 'crypto', 'evm'];

const MAINNET_PRESETS: { value: string; label: string }[] = [
  { value: 'eip155:1', label: 'Ethereum Mainnet' },
  { value: 'eip155:8453', label: 'Base' },
  { value: 'eip155:137', label: 'Polygon' },
  { value: 'eip155:42161', label: 'Arbitrum One' },
  { value: 'eip155:10', label: 'Optimism' },
  { value: 'eip155:56', label: 'BNB Smart Chain' },
];

const TESTNET_PRESETS: { value: string; label: string }[] = [
  { value: 'eip155:11155111', label: 'Sepolia' },
  { value: 'eip155:84532', label: 'Base Sepolia' },
  { value: 'eip155:80002', label: 'Polygon Amoy' },
];

const CUSTOM_NETWORK = '__custom__';

// The on-chain verifier (src/mpp/onchain.rs::parse_amount) requires an exact
// integer string in the currency's smallest unit; it never accepts a decimal.
const INTEGER_AMOUNT_RE = /^\d+$/;

const isCryptoMethod = (method: string) => CRYPTO_METHODS.includes(method);

const emptyEntry = (): MppPaymentMethodEntry => ({
  method: 'tempo',
  intent: 'charge',
  currency: '',
  recipient: '',
  amount: '',
  network: 'eip155:8453',
});

interface PaymentMethodsEditorProps {
  methods: MppPaymentMethodEntry[];
  onChange: (methods: MppPaymentMethodEntry[]) => void;
}

/**
 * Dropdown-driven editor for MPP's `payment_methods` array
 * (`src/mpp/types.rs::MppPaymentMethod`) — replaces free-text JSON entry with
 * one card per method entry (method/intent/currency/amount/recipient plus a
 * CAIP-2 network preset for crypto methods) and a read-only JSON preview.
 */
const PaymentMethodsEditor: React.FC<PaymentMethodsEditorProps> = ({ methods, onChange }) => {
  const [showJson, setShowJson] = useState(false);
  const [customNetworkAt, setCustomNetworkAt] = useState<Set<number>>(new Set());

  const update = (idx: number, patch: Partial<MppPaymentMethodEntry>) => {
    onChange(methods.map((m, i) => (i === idx ? { ...m, ...patch } : m)));
  };

  const remove = (idx: number) => {
    onChange(methods.filter((_, i) => i !== idx));
    setCustomNetworkAt(prev => {
      const next = new Set<number>();
      prev.forEach(i => {
        if (i < idx) next.add(i);
        else if (i > idx) next.add(i - 1);
      });
      return next;
    });
  };

  const add = () => onChange([...methods, emptyEntry()]);

  return (
    <div>
      {methods.length === 0 && (
        <div className="alert alert-secondary py-2 mb-3" role="alert" style={{ fontSize: '12px' }}>
          <i className="fas fa-info-circle me-1"></i>
          No payment methods configured — 402 challenges will have empty methods.
        </div>
      )}

      {methods.map((m, idx) => {
        const isCrypto = isCryptoMethod(m.method);
        const knownNetwork =
          !m.network || [...MAINNET_PRESETS, ...TESTNET_PRESETS].some(p => p.value === m.network);
        const showCustomNetwork = customNetworkAt.has(idx) || (!!m.network && !knownNetwork);

        return (
          <div className="card mb-3" key={idx}>
            <div className="card-header bg-light d-flex justify-content-between align-items-center py-2">
              <strong className="small">
                Method #{idx + 1}
                {m.method && <span className="text-muted ms-2">({m.method})</span>}
              </strong>
              <button
                type="button"
                className="btn btn-sm btn-outline-danger"
                onClick={() => remove(idx)}
                aria-label="Remove method"
                title="Remove method"
              >
                <i className="fas fa-trash"></i>
              </button>
            </div>
            <div className="card-body py-3">
              <div className="row g-2 mb-2">
                <div className="col-6">
                  <label className="form-label small">Method Type</label>
                  <select
                    className="form-select form-select-sm"
                    value={m.method}
                    onChange={e => update(idx, { method: e.target.value })}
                  >
                    <optgroup label="Crypto (on-chain)">
                      <option value="tempo">tempo</option>
                      <option value="crypto">crypto</option>
                      <option value="evm">evm</option>
                    </optgroup>
                    <optgroup label="Card">
                      {m.method === 'card' && <option value="card">card (legacy)</option>}
                      <option value="stripe">stripe</option>
                    </optgroup>
                  </select>
                </div>
                <div className="col-6">
                  <label className="form-label small">Intent</label>
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    placeholder="charge"
                    value={m.intent}
                    onChange={e => update(idx, { intent: e.target.value })}
                  />
                </div>
              </div>

              <div className="row g-2 mb-2">
                <div className="col-6">
                  <label className="form-label small">Currency</label>
                  <input
                    type="text"
                    className="form-control form-control-sm font-monospace"
                    placeholder={isCrypto ? 'USDC' : 'usd'}
                    value={m.currency}
                    onChange={e => update(idx, { currency: e.target.value })}
                  />
                </div>
                <div className="col-6">
                  <label className="form-label small">Amount</label>
                  <input
                    type="text"
                    className={`form-control form-control-sm font-monospace${
                      isCrypto && m.amount && !INTEGER_AMOUNT_RE.test(m.amount) ? ' is-invalid' : ''
                    }`}
                    placeholder={isCrypto ? '1000000000000000000' : '0.01'}
                    value={m.amount}
                    onChange={e => update(idx, { amount: e.target.value })}
                  />
                  {isCrypto ? (
                    <div className="form-text" style={{ fontSize: '11px' }}>
                      Base units only (e.g. wei for ETH, 6-decimal units for a token like USDC) —
                      the on-chain verifier matches this exactly and rejects a decimal amount.
                    </div>
                  ) : (
                    <div className="form-text" style={{ fontSize: '11px' }}>
                      Decimal major-unit amount (e.g. <code>0.01</code> = 1 cent).
                    </div>
                  )}
                  {isCrypto && m.amount && !INTEGER_AMOUNT_RE.test(m.amount) && (
                    <div className="invalid-feedback d-block">
                      Must be an integer amount in base units.
                    </div>
                  )}
                </div>
              </div>

              <div className="mb-2">
                <label className="form-label small">Recipient</label>
                <input
                  type="text"
                  className="form-control form-control-sm font-monospace"
                  placeholder={isCrypto ? '0x...' : 'acct_stripe_connected_account'}
                  value={m.recipient}
                  onChange={e => update(idx, { recipient: e.target.value })}
                />
              </div>

              {isCrypto && (
                <div className="mb-0">
                  <label className="form-label small">Network (CAIP-2)</label>
                  {!showCustomNetwork ? (
                    <select
                      className="form-select form-select-sm"
                      value={m.network || ''}
                      onChange={e => {
                        if (e.target.value === CUSTOM_NETWORK) {
                          setCustomNetworkAt(prev => new Set(prev).add(idx));
                          update(idx, { network: '' });
                        } else {
                          update(idx, { network: e.target.value });
                        }
                      }}
                    >
                      <option value="">Not set</option>
                      <optgroup label="Mainnets">
                        {MAINNET_PRESETS.map(p => (
                          <option key={p.value} value={p.value}>
                            {p.label} ({p.value})
                          </option>
                        ))}
                      </optgroup>
                      <optgroup label="Testnets">
                        {TESTNET_PRESETS.map(p => (
                          <option key={p.value} value={p.value}>
                            {p.label} ({p.value})
                          </option>
                        ))}
                      </optgroup>
                      <option value={CUSTOM_NETWORK}>Custom…</option>
                    </select>
                  ) : (
                    <div className="input-group input-group-sm">
                      <input
                        type="text"
                        className="form-control font-monospace"
                        placeholder="eip155:8453"
                        value={m.network || ''}
                        onChange={e => update(idx, { network: e.target.value })}
                      />
                      <button
                        type="button"
                        className="btn btn-outline-secondary"
                        onClick={() =>
                          setCustomNetworkAt(prev => {
                            const next = new Set(prev);
                            next.delete(idx);
                            return next;
                          })
                        }
                      >
                        Presets
                      </button>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        );
      })}

      <button type="button" className="btn btn-sm btn-outline-primary mb-3" onClick={add}>
        <i className="fas fa-plus me-2"></i>Add Method
      </button>

      {methods.length > 0 && (
        <div className="mb-0">
          <button
            type="button"
            className="btn btn-sm btn-link p-0 text-decoration-none"
            onClick={() => setShowJson(v => !v)}
          >
            <i className={`fas fa-chevron-${showJson ? 'down' : 'right'} me-1`}></i>
            View as JSON
          </button>
          {showJson && (
            <pre
              className="bg-light border rounded p-2 mt-2 mb-0"
              style={{ fontSize: '11px', maxHeight: 200, overflow: 'auto' }}
            >
              {JSON.stringify(methods, null, 2)}
            </pre>
          )}
        </div>
      )}
    </div>
  );
};

export default PaymentMethodsEditor;
