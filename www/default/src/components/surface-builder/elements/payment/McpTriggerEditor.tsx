import React, { useState } from 'react';
import { Form, Spinner } from 'react-bootstrap';
import { useParams } from 'react-router-dom';
import type { McpPaymentTriggers } from '../../../../types';
import {
  mcpToolDiscoverySource,
  useMcpToolDiscovery,
  type DiscoveredMcpTool,
  type DiscoveryTargetConfig,
} from '../_shared/mcpToolDiscovery';
import { PatternList } from './PatternList';
import {
  buildMcpTriggers,
  mcpMatchHasNoPatterns,
  mcpSelectionCharged,
  normaliseMcpTriggers,
  selectedToolNames,
  setMcpSelectionCharged,
  setToolsSelected,
  storedMcpPatterns,
  toolCharge,
  triggerPatternAdvice,
  uncheckedMcpPatterns,
} from './triggers';

interface McpTriggerEditorProps {
  value: unknown;
  target: DiscoveryTargetConfig | undefined;
  hasAttemptedSave: boolean;
  onChange: (next: McpPaymentTriggers) => void;
}

interface ToolRow {
  tool: DiscoveredMcpTool;
  selected: boolean;
  charged: boolean;
  coveredBy?: string;
  missing: boolean;
}

const McpTriggerEditor: React.FC<McpTriggerEditorProps> = ({
  value,
  target,
  hasAttemptedSave,
  onChange,
}) => {
  const { surfaceId } = useParams<{ surfaceId: string }>();
  const source = mcpToolDiscoverySource(target, surfaceId);
  const request = 'request' in source ? source.request : null;
  const unsavedUrl = !!request && 'target_endpoint' in request && !('surface_id' in request);
  const { tools, error, loading, discover } = useMcpToolDiscovery(request);
  const [filter, setFilter] = useState('');
  const [newTool, setNewTool] = useState('');

  const unset = normaliseMcpTriggers(value) === undefined;
  const selectionCharged = mcpSelectionCharged(value);
  const patterns = storedMcpPatterns(value);
  const selectedNames = selectedToolNames(value);
  const discoveredNames = (tools ?? []).map(t => t.name);
  const rows: ToolRow[] = [
    ...(tools ?? []),
    ...selectedNames.filter(name => !discoveredNames.includes(name)).map(name => ({ name })),
  ].map(tool => {
    const { charged, decidedBy } = toolCharge(value, tool.name);
    return {
      tool,
      charged,
      coveredBy: decidedBy,
      selected: selectedNames.includes(tool.name),
      missing: tools !== null && !discoveredNames.includes(tool.name),
    };
  });
  const needle = filter.trim().toLowerCase();
  const visible = needle ? rows.filter(r => r.tool.name.toLowerCase().includes(needle)) : rows;
  const ticked = (r: ToolRow) => r.selected || r.coveredBy !== undefined;
  const selectable = visible.filter(r => r.selected || r.coveredBy === undefined);
  const allTicked = visible.length > 0 && visible.every(ticked);
  const someTicked = visible.some(ticked);
  const chargesEverything =
    normaliseMcpTriggers(value)?.mode !== 'match' && patterns.every(p => p.trim() === '');
  const noneCharged = mcpMatchHasNoPatterns(value);
  const unchecked = uncheckedMcpPatterns(value);
  const listWord = selectionCharged ? 'charged' : 'free';

  const select = (names: string[], selected: boolean) =>
    onChange(setToolsSelected(value, names, selected));
  const selectShown = (selected: boolean) =>
    select(
      selectable.map(r => r.tool.name),
      selected
    );
  const addTool = () => {
    const name = newTool.trim();
    if (!name) return;
    select([name], true);
    setNewTool('');
  };

  return (
    <div className="mb-3">
      <label className="form-label small fw-bold">
        <i className="fas fa-wrench me-1" aria-hidden="true" /> MCP tools requiring payment
      </label>
      <small className="text-muted d-block mb-3">
        Only <code>tools/call</code> requests can be charged. Free methods like{' '}
        <code>tools/list</code> or <code>initialize</code> are never charged.
      </small>

      <div className="d-flex align-items-center flex-wrap gap-2 mb-1">
        <span className="small fw-bold">Selected tools and patterns are</span>
        <div className="btn-group btn-group-sm" role="group" aria-label="Selected tools are">
          {[true, false].map(charged => (
            <button
              key={String(charged)}
              type="button"
              className={`btn ${charged === selectionCharged ? 'btn-primary' : 'btn-outline-primary'}`}
              aria-pressed={charged === selectionCharged}
              data-testid={`payment-triggers-mcp-selection-${charged ? 'charged' : 'free'}-button`}
              onClick={() => {
                if (charged !== selectionCharged) onChange(setMcpSelectionCharged(value, charged));
              }}
            >
              {charged ? 'Charged' : 'Free'}
            </button>
          ))}
        </div>
      </div>
      <small className="text-muted d-block mb-3" data-testid="payment-triggers-mcp-others">
        {chargesEverything ? (
          <>Nothing is selected yet, so every tool is charged.</>
        ) : (
          <>
            Every other tool, including tools the Target adds later, is{' '}
            <strong>{selectionCharged ? 'free' : 'charged'}</strong>.
          </>
        )}
      </small>

      {chargesEverything && (
        <div
          className="alert alert-success mb-3"
          role="status"
          data-testid="payment-triggers-mcp-scope"
        >
          <i className="fas fa-check-circle me-2" aria-hidden="true" />
          {unset ? 'No trigger is set, so ' : ''}
          <strong>{unset ? 'every' : 'Every'}</strong> <code>tools/call</code> on this surface will
          require payment.
        </div>
      )}
      {noneCharged && (
        <div
          className={`alert alert-${hasAttemptedSave ? 'danger' : 'warning'} mb-3`}
          role={hasAttemptedSave ? 'alert' : 'status'}
          data-testid={
            hasAttemptedSave ? 'payment-triggers-mcp-error' : 'payment-triggers-mcp-none-charged'
          }
        >
          <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
          {hasAttemptedSave && <strong>Error: </strong>}
          No tool is charged: the pattern list has only blank rows. Select a tool or fill in a
          pattern.
        </div>
      )}

      <div className="card" data-testid="payment-triggers-mcp-tools">
        <div className="card-header bg-light d-flex align-items-center justify-content-between gap-2">
          <span className="small fw-bold">
            <i className="fas fa-list me-1" aria-hidden="true" /> Tools
            {rows.length > 0 && (
              <span
                className="text-muted fw-normal ms-2"
                data-testid="payment-triggers-mcp-tool-count"
              >
                {selectedNames.length} selected · {rows.filter(r => r.charged).length} of{' '}
                {rows.length} charged
              </span>
            )}
          </span>
          <button
            type="button"
            className="btn btn-sm btn-outline-primary"
            data-testid="payment-triggers-mcp-discover-button"
            disabled={!request || loading}
            onClick={discover}
          >
            {loading ? (
              <>
                <Spinner animation="border" size="sm" className="me-1" /> Discovering…
              </>
            ) : (
              <>
                <i className="fas fa-sync-alt me-1" aria-hidden="true" />
                {tools ? 'Refresh' : 'Discover tools'}
              </>
            )}
          </button>
        </div>
        <div className="card-body">
          {'unavailable' in source ? (
            <small
              className="text-muted d-block mb-2"
              data-testid="payment-triggers-mcp-discover-unavailable"
            >
              {source.unavailable}
            </small>
          ) : (
            !tools &&
            !error && (
              <small className="text-muted d-block text-truncate mb-2" title={source.label}>
                Ask {source.label} for its tools to choose which are charged.
              </small>
            )
          )}
          {error && (
            <div
              className="alert alert-danger py-2 px-3 mb-2 small"
              role="alert"
              data-testid="payment-triggers-mcp-discover-error"
            >
              <i className="fas fa-exclamation-circle me-2" aria-hidden="true" />
              {error}
              {unsavedUrl && (
                <div className="mt-1" data-testid="payment-triggers-mcp-discover-save-hint">
                  A local or private Target can be discovered once the surface is saved.
                </div>
              )}
            </div>
          )}
          {tools && tools.length === 0 && (
            <small className="text-muted d-block mb-2" data-testid="payment-triggers-mcp-no-tools">
              The Target lists no tools.
            </small>
          )}

          {rows.length > 0 && (
            <>
              <div className="d-flex align-items-center gap-2 mb-2">
                <input
                  type="checkbox"
                  className="form-check-input mt-0"
                  aria-label="Select every tool shown"
                  data-testid="payment-triggers-mcp-select-all"
                  ref={el => {
                    if (el) el.indeterminate = someTicked && !allTicked;
                  }}
                  checked={allTicked}
                  disabled={selectable.length === 0}
                  onChange={() => selectShown(!allTicked)}
                />
                <Form.Control
                  size="sm"
                  type="search"
                  placeholder="Filter tools"
                  aria-label="Filter tools"
                  data-testid="payment-triggers-mcp-tool-filter"
                  value={filter}
                  onChange={e => setFilter(e.target.value)}
                />
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary text-nowrap"
                  data-testid="payment-triggers-mcp-select-all-button"
                  disabled={selectable.length === 0}
                  onClick={() => selectShown(true)}
                >
                  {needle ? 'Select shown' : 'Select all'}
                </button>
                <button
                  type="button"
                  className="btn btn-sm btn-outline-secondary text-nowrap"
                  data-testid="payment-triggers-mcp-clear-button"
                  disabled={!visible.some(r => r.selected)}
                  onClick={() => selectShown(false)}
                >
                  {needle ? 'Clear shown' : 'Clear'}
                </button>
              </div>
              <div className="list-group mb-2">
                {visible.map(({ tool, selected, charged, coveredBy, missing }) => (
                  <div
                    key={tool.name}
                    className="list-group-item py-2 d-flex align-items-start gap-2"
                    data-testid={`payment-triggers-mcp-tool-row-${tool.name}`}
                  >
                    <Form.Check
                      type="checkbox"
                      id={`payment-triggers-mcp-tool-${tool.name}`}
                      data-testid={`payment-triggers-mcp-tool-${tool.name}`}
                      aria-label={`Select ${tool.name}`}
                      checked={selected || coveredBy !== undefined}
                      disabled={!selected && coveredBy !== undefined}
                      onChange={e => select([tool.name], e.target.checked)}
                    />
                    <div className="flex-grow-1" style={{ minWidth: 0 }}>
                      <div className="small">
                        <span className="font-monospace">{tool.name}</span>
                        {tool.read_only && (
                          <span className="badge bg-secondary ms-2">read-only</span>
                        )}
                        {missing && (
                          <span
                            className="badge bg-warning text-dark ms-2"
                            data-testid={`payment-triggers-mcp-tool-missing-${tool.name}`}
                          >
                            not on the Target
                          </span>
                        )}
                      </div>
                      {tool.description && (
                        <small
                          className="text-muted d-block text-truncate"
                          title={tool.description}
                        >
                          {tool.description}
                        </small>
                      )}
                      {coveredBy !== undefined && (
                        <small className="text-muted d-block">
                          Matched by the pattern <code>{coveredBy}</code>
                        </small>
                      )}
                    </div>
                    <span
                      className={`badge ${charged ? 'bg-primary' : 'bg-light text-dark border'}`}
                    >
                      {charged ? 'charged' : 'free'}
                    </span>
                  </div>
                ))}
              </div>
            </>
          )}

          <div className="input-group input-group-sm">
            <input
              type="text"
              className="form-control font-monospace"
              placeholder="tool_name"
              aria-label="Add a tool by name"
              data-testid="payment-triggers-mcp-add-tool-input"
              value={newTool}
              onChange={e => setNewTool(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  addTool();
                }
              }}
            />
            <button
              type="button"
              className="btn btn-outline-secondary"
              data-testid="payment-triggers-mcp-add-tool-button"
              disabled={!newTool.trim()}
              onClick={addTool}
            >
              <i className="fas fa-plus me-1" aria-hidden="true" />
              Add tool
            </button>
          </div>
        </div>
      </div>

      <div className="mt-3" data-testid="payment-triggers-mcp-patterns">
        <label className="form-label small fw-bold mb-1">Patterns</label>
        <small className="text-muted d-block mb-2">
          A tool whose name matches a pattern is <strong>{listWord}</strong>. Selecting a tool adds{' '}
          <code>^name$</code> here and clearing it removes that row. Patterns are regular
          expressions.
        </small>
        {patterns.length > 0 ? (
          <PatternList
            patterns={patterns}
            onChange={next => onChange(buildMcpTriggers(selectionCharged, next))}
            placeholder={
              selectionCharged ? '^paid_.*$  or  premium' : '^free_.*$  or  health_check'
            }
            icon="fa-asterisk"
            testIdPrefix="payment-triggers-mcp"
            label="Pattern"
            advise={triggerPatternAdvice}
            allowEmpty
          />
        ) : (
          <button
            type="button"
            className="btn btn-sm btn-outline-secondary"
            data-testid="payment-triggers-mcp-add-pattern-button"
            onClick={() => onChange(buildMcpTriggers(selectionCharged, ['']))}
          >
            <i className="fas fa-plus me-1" aria-hidden="true" />
            Add Pattern
          </button>
        )}
        {unchecked.length > 0 && (
          <small className="text-warning d-block mt-2" data-testid="payment-triggers-mcp-unchecked">
            <i className="fas fa-exclamation-triangle me-1" aria-hidden="true" />
            The browser cannot evaluate{' '}
            {unchecked.length === 1 ? 'one pattern' : `${unchecked.length} patterns`}, so the tool
            list may not show its effect. The gateway applies it.
          </small>
        )}
      </div>
    </div>
  );
};

export default McpTriggerEditor;
