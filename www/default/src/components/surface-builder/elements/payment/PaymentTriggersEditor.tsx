import React, { useState } from 'react';
import { Form } from 'react-bootstrap';
import type { A2AMethodFilter } from '../../../../types';
import type { ConfigPanelProps } from '../types';
import { defaultA2aFilters, triggerPatternAdvice, type TriggerMode } from './triggers';
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

const PatternAdvice: React.FC<{ testId: string; text: string }> = ({ testId, text }) => (
  <Form.Text className="text-warning d-block mb-2" data-testid={testId}>
    <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
    {text}
  </Form.Text>
);

interface PatternListProps {
  patterns: string[];
  onChange: (patterns: string[]) => void;
  placeholder: string;
  icon: string;
  testIdPrefix: string;
  /** What a row is called: a regular expression or plain text. */
  label: 'Pattern' | 'Text';
  /** The browser's doubt about a row, shown as a warning; it never blocks Save. */
  advise?: (value: string) => string | null;
}

const PatternList: React.FC<PatternListProps> = ({
  patterns,
  onChange,
  placeholder,
  icon,
  testIdPrefix,
  label,
  advise,
}) => {
  const rows = patterns.length === 0 ? [''] : patterns;
  return (
    <>
      {rows.map((pattern, idx) => {
        const advice = advise && pattern.trim() !== '' ? advise(pattern) : null;
        return (
          <React.Fragment key={idx}>
            <div className="input-group input-group-sm mb-2">
              <span className="input-group-text">
                <i className={`fas ${icon}`} aria-hidden="true" />
              </span>
              <input
                type="text"
                className={`form-control${label === 'Pattern' ? ' font-monospace' : ''}`}
                value={pattern}
                aria-label={`${label} ${idx + 1}`}
                data-testid={`${testIdPrefix}-pattern-${idx}`}
                onChange={e => {
                  const next = [...rows];
                  next[idx] = e.target.value;
                  onChange(next);
                }}
                placeholder={placeholder}
              />
              {rows.length > 1 && (
                <button
                  className="btn btn-outline-danger"
                  type="button"
                  aria-label={`Remove ${label.toLowerCase()}`}
                  data-testid={`${testIdPrefix}-remove-pattern-button-${idx}`}
                  onClick={() => onChange(rows.filter((_, i) => i !== idx))}
                >
                  <i className="fas fa-times" aria-hidden="true" />
                </button>
              )}
            </div>
            {advice && (
              <PatternAdvice testId={`${testIdPrefix}-pattern-warning-${idx}`} text={advice} />
            )}
          </React.Fragment>
        );
      })}
      <button
        className="btn btn-sm btn-outline-secondary"
        type="button"
        data-testid={`${testIdPrefix}-add-pattern-button`}
        onClick={() => onChange([...rows, ''])}
      >
        <i className="fas fa-plus me-1" aria-hidden="true" />
        Add {label}
      </button>
    </>
  );
};

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

interface McpTriggerEditorProps {
  value: unknown;
  hasAttemptedSave: boolean;
  onChange: (next: { mode: 'all' } | { mode: 'match' | 'exclude'; patterns: string[] }) => void;
}

const McpTriggerEditor: React.FC<McpTriggerEditorProps> = ({
  value,
  hasAttemptedSave,
  onChange,
}) => {
  const stored = (value ?? {}) as { mode?: TriggerMode; patterns?: string[] };
  const unset = stored.mode !== 'all' && stored.mode !== 'exclude' && stored.mode !== 'match';
  const mode: TriggerMode = unset ? 'all' : (stored.mode as TriggerMode);
  const patterns = mode === 'all' ? [] : Array.isArray(stored.patterns) ? stored.patterns : [];
  const write = (nextMode: TriggerMode, nextPatterns: string[]) =>
    onChange(nextMode === 'all' ? { mode: 'all' } : { mode: nextMode, patterns: nextPatterns });
  const noPatterns = patterns.every(p => !p.trim());

  return (
    <div className="mb-3">
      <label className="form-label small fw-bold" htmlFor="payment-triggers-mcp-mode">
        <i className="fas fa-wrench me-1" aria-hidden="true" /> MCP Payment Trigger Mode
      </label>
      <small className="text-muted d-block mb-2">
        Only <code>tools/call</code> requests can be charged. Free methods like{' '}
        <code>tools/list</code> or <code>initialize</code> are never charged.
      </small>
      <Form.Select
        id="payment-triggers-mcp-mode"
        size="sm"
        className="mb-3"
        value={mode}
        data-testid="payment-triggers-mcp-mode"
        onChange={e => {
          const next = e.target.value as TriggerMode;
          write(next, next === 'all' ? [] : patterns);
        }}
      >
        <option value="all">Charge all tools</option>
        <option value="match">Charge tools matching regex</option>
        <option value="exclude">Charge all EXCEPT regex matches</option>
      </Form.Select>

      {mode === 'all' ? (
        <div
          className="alert alert-success mb-0"
          role="status"
          data-testid="payment-triggers-mcp-scope"
        >
          <i className="fas fa-check-circle me-2" aria-hidden="true" />
          {unset ? 'No trigger is set, so ' : ''}
          <strong>{unset ? 'every' : 'Every'}</strong> <code>tools/call</code> on this surface will
          require payment.
        </div>
      ) : (
        <>
          <small className="text-muted d-block mb-2">
            {mode === 'match'
              ? 'A tool is charged when its name matches ANY of the patterns below. Patterns are full regex (anchor with ^ and $ for exact match).'
              : 'A tool is charged UNLESS its name matches at least one pattern below. Patterns are full regex. With no pattern, every tool is charged.'}
          </small>
          <PatternList
            patterns={patterns}
            onChange={next => write(mode, next)}
            placeholder={
              mode === 'match' ? '^paid_.*$  or  premium' : '^free_.*$  or  health_check'
            }
            icon="fa-asterisk"
            testIdPrefix="payment-triggers-mcp"
            label="Pattern"
            advise={triggerPatternAdvice}
          />
          {hasAttemptedSave && mode === 'match' && noPatterns && (
            <div
              className="alert alert-danger mt-3 mb-0"
              role="alert"
              data-testid="payment-triggers-mcp-error"
            >
              <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
              <strong>Error:</strong> At least one tool pattern is required when charging selected
              tools. Add a pattern above or switch to &ldquo;Charge all tools&rdquo;.
            </div>
          )}
        </>
      )}
    </div>
  );
};

const PaymentTriggersEditor: React.FC<ConfigPanelProps> = ({
  config: panelConfig,
  updateField,
  protocol,
  hasAttemptedSave = false,
}) => {
  const config: PaymentNodeConfig = panelConfig;
  const requireAll = config.require_all === true;
  return (
    <div className="mb-3" data-testid="payment-triggers-editor">
      <label className="form-label">Payment Triggers</label>
      <div className="card bg-light">
        <div className="card-body">
          <Form.Check
            type="switch"
            id="payment-triggers-require-all"
            data-testid="payment-triggers-require-all"
            className="mb-3"
            checked={requireAll}
            onChange={e => updateField('require_all', e.target.checked)}
            label="Charge every request on this surface, ignoring the triggers below"
          />

          {protocol === 'mcp' && (
            <fieldset disabled={requireAll}>
              <McpTriggerEditor
                value={config.mcp_payment_triggers}
                hasAttemptedSave={hasAttemptedSave}
                onChange={next => updateField('mcp_payment_triggers', next)}
              />
            </fieldset>
          )}

          {protocol === 'a2a' && (
            <fieldset disabled={requireAll} className="mb-3">
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
