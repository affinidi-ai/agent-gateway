import React, { useState } from 'react';
import { Form } from 'react-bootstrap';
import type { A2AMethodFilter } from '../../../../types';
import type { ConfigPanelProps } from '../types';
import McpTriggerEditor from './McpTriggerEditor';
import { PatternList } from './PatternList';
import { defaultA2aFilters } from './triggers';
import type { PaymentNodeConfig } from './types';

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

const MESSAGE_METHODS: Array<{ method: string; icon: string; detail: string; example: string }> = [
  {
    method: 'message/send',
    icon: 'fa-comment',
    detail: '(JSON-RPC) / SendMessage (gRPC)',
    example: 'e.g., generate report',
  },
  {
    method: 'message/stream',
    icon: 'fa-stream',
    detail: '(JSON-RPC) / SendStreamingMessage (gRPC)',
    example: 'e.g., live feed',
  },
];

const slug = (method: string) => method.replace(/[^a-zA-Z0-9]+/g, '-').toLowerCase();

interface A2AMethodFilterEditorProps {
  filters: A2AMethodFilter[];
  onChange: (filters: A2AMethodFilter[]) => void;
}

const A2AMethodFilterEditor: React.FC<A2AMethodFilterEditorProps> = ({ filters, onChange }) => {
  const [showCommandMessages, setShowCommandMessages] = useState(true);
  const [showControlMessages, setShowControlMessages] = useState(false);

  const isMethodEnabled = (method: string) => filters.some(f => f.method === method);
  const unset = filters.length === 0;
  // Editing while nothing is set starts from the charged defaults, so the edit never un-charges them.
  const base = unset ? defaultA2aFilters() : filters;

  const toggleMethod = (method: string) => {
    onChange(
      isMethodEnabled(method)
        ? filters.filter(f => f.method !== method)
        : [...base, { method, message_patterns: [] }]
    );
  };

  const updatePatterns = (method: string, patterns: string[]) => {
    onChange(
      base.some(f => f.method === method)
        ? base.map(f => (f.method === method ? { ...f, message_patterns: patterns } : f))
        : [...base, { method, message_patterns: patterns }]
    );
  };

  return (
    <div>
      {unset && (
        <div
          className="alert alert-info py-2 px-3 mb-3 small d-flex align-items-center justify-content-between gap-2"
          role="status"
          data-testid="payment-triggers-a2a-defaults-note"
        >
          <span>No filters set: message/send and message/stream are charged.</span>
          <button
            type="button"
            className="btn btn-sm btn-outline-primary"
            data-testid="payment-triggers-a2a-add-defaults-button"
            onClick={() => onChange(defaultA2aFilters())}
          >
            Add default filters
          </button>
        </div>
      )}
      <div className="card mb-3">
        <button
          type="button"
          className="card-header bg-light text-start border-0"
          aria-expanded={showCommandMessages}
          data-testid="payment-triggers-a2a-command-toggle-button"
          onClick={() => setShowCommandMessages(v => !v)}
        >
          <i className={`fas fa-chevron-${showCommandMessages ? 'down' : 'right'} me-2`} />
          <strong>Command Messages</strong>
          <small className="text-muted ms-2">(message/send, message/stream)</small>
        </button>
        {showCommandMessages && (
          <div className="card-body">
            {MESSAGE_METHODS.map(({ method, icon, detail, example }, i) => {
              const filter = filters.find(f => f.method === method);
              const charged = unset || !!filter;
              const chargesAll = !(filter?.message_patterns ?? []).some(p => p.trim() !== '');
              const testIdPrefix = `payment-triggers-a2a-${slug(method)}`;
              return (
                <div key={method} className={i === MESSAGE_METHODS.length - 1 ? 'mb-0' : 'mb-4'}>
                  <label className="form-label fw-bold">
                    <i className={`fas ${icon} me-2`} aria-hidden="true" />
                    {method}
                    <small className="text-muted fw-normal ms-2">{detail}</small>
                  </label>
                  <small className="text-muted d-block mb-2">
                    Add text a message must contain to be charged. It is matched as plain,
                    case-sensitive text, not as a regular expression.
                  </small>
                  <PatternList
                    patterns={filter?.message_patterns ?? []}
                    onChange={patterns => updatePatterns(method, patterns)}
                    placeholder={example}
                    icon="fa-quote-left"
                    testIdPrefix={testIdPrefix}
                    label="Text"
                  />
                  <div
                    className={`alert alert-${charged && chargesAll ? 'warning' : 'info'} py-1 px-2 mt-2 mb-0 small`}
                    role="status"
                    data-testid={`${testIdPrefix}-scope`}
                  >
                    {!charged
                      ? `${method} is not charged, because it is not in the filters.`
                      : chargesAll
                        ? `Every ${method} message is charged, because no text is set.`
                        : `Only ${method} messages containing one of these texts are charged.`}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <div className="card">
        <button
          type="button"
          className="card-header bg-light text-start border-0"
          aria-expanded={showControlMessages}
          data-testid="payment-triggers-a2a-control-toggle-button"
          onClick={() => setShowControlMessages(v => !v)}
        >
          <i className={`fas fa-chevron-${showControlMessages ? 'down' : 'right'} me-2`} />
          <strong>Control Messages</strong>
          <small className="text-muted ms-2">(Optional: tasks/get, tasks/cancel, etc.)</small>
        </button>
        {showControlMessages && (
          <div className="card-body">
            <small className="text-muted d-block mb-3">
              Select which control operations require payment. These methods don&apos;t have message
              content to match.
            </small>
            <div className="row">
              {A2A_CONTROL_METHODS.map(method => (
                <div key={method} className="col-md-6 mb-2">
                  <Form.Check
                    type="checkbox"
                    id={`payment-triggers-a2a-method-${slug(method)}`}
                    data-testid={`payment-triggers-a2a-method-${slug(method)}`}
                    checked={isMethodEnabled(method)}
                    onChange={() => toggleMethod(method)}
                    label={<span className="small">{method}</span>}
                  />
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const PaymentTriggersEditor: React.FC<ConfigPanelProps> = ({
  config: panelConfig,
  updateField,
  protocol,
  allNodes,
  hasAttemptedSave = false,
}) => {
  const config: PaymentNodeConfig = panelConfig;
  return (
    <div className="mb-3" data-testid="payment-triggers-editor">
      <label className="form-label">Payment Triggers</label>
      <div className="card bg-light">
        <div className="card-body">
          {protocol === 'mcp' && (
            <fieldset>
              <McpTriggerEditor
                value={config.mcp_payment_triggers}
                target={allNodes?.find(n => n.type === 'target')?.config}
                hasAttemptedSave={hasAttemptedSave}
                onChange={next => updateField('mcp_payment_triggers', next)}
              />
            </fieldset>
          )}

          {protocol === 'a2a' && (
            <fieldset className="mb-3">
              <label className="form-label small fw-bold">
                <i className="fas fa-exchange-alt me-1" aria-hidden="true" /> A2A Methods Requiring
                Payment
              </label>
              <small className="text-muted d-block mb-3">
                Choose which A2A methods require payment, with optional text a message must contain.
              </small>
              <A2AMethodFilterEditor
                filters={Array.isArray(config.a2a_method_filters) ? config.a2a_method_filters : []}
                onChange={filters => updateField('a2a_method_filters', filters)}
              />
            </fieldset>
          )}

          {protocol !== 'mcp' && protocol !== 'a2a' && (
            <div className="alert alert-info mb-0">
              <i className="fas fa-info-circle me-2" aria-hidden="true" />
              Payment triggers are available for MCP and A2A surfaces only.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default PaymentTriggersEditor;
