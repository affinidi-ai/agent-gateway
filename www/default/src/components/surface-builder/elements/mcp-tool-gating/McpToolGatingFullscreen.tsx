import React, { useEffect, useMemo, useState } from 'react';
import { apiClient } from '../../../../api';
import AddResourceLink from '../../../shared/AddResourceLink';
import { deepLinks } from '../../../../utils/deepLinks';
import type { ConfigPanelProps } from '../types';

interface PolicyOption {
  id: string;
  name: string;
  description?: string;
}

type Effect = 'allow' | 'deny';

interface Gate {
  id: string;
  name?: string;
  description?: string;
  condition_policy_definition_id?: string;
  action: { effect: Effect; patterns: string[] };
}

interface DryRunToolDecision {
  toolName: string;
  allowed: boolean;
  matchedAllowGateNames: string[];
  matchedDenyGateNames: string[];
}

const newId = () => `gate-${Math.random().toString(36).slice(2, 10)}`;

const MCP_TOOL_GATING_DRY_RUN_DEFAULT_TOOLS = `list_items
get_item
create_item
delete_item`;

function gateDisplayName(gate: Gate, idx: number): string {
  return gate.name?.trim() || `Tool Gate ${idx + 1}`;
}

function effectiveGatePatterns(gate: Gate): string[] {
  return gate.action.patterns.map(pattern => pattern.trim()).filter(pattern => pattern !== '');
}

function regexMatches(pattern: string, value: string): boolean {
  try {
    return new RegExp(pattern).test(value);
  } catch {
    return false;
  }
}

function sampleToolNameFromPattern(pattern: string): string | undefined {
  const source = pattern.trim().replace(/^\^/, '').replace(/\$$/, '');
  let sample = '';

  for (let idx = 0; idx < source.length; idx += 1) {
    const char = source[idx];
    const next = source[idx + 1];

    if (char === '\\' && next) {
      sample += next;
      idx += 1;
      continue;
    }

    if (char === '.' && (next === '*' || next === '+')) {
      break;
    }

    if ('[]()|*+?{'.includes(char)) {
      break;
    }

    sample += char;
  }

  return sample || undefined;
}

function patternsOverlap(leftPatterns: string[], rightPatterns: string[]): boolean {
  return leftPatterns.some(leftPattern =>
    rightPatterns.some(rightPattern => {
      if (leftPattern === rightPattern) return false;

      const leftSample = sampleToolNameFromPattern(leftPattern);
      const rightSample = sampleToolNameFromPattern(rightPattern);

      return (
        regexMatches(leftPattern, rightPattern) ||
        regexMatches(rightPattern, leftPattern) ||
        (leftSample !== undefined && regexMatches(rightPattern, leftSample)) ||
        (rightSample !== undefined && regexMatches(leftPattern, rightSample))
      );
    })
  );
}

function parseSampleTools(value: string): string[] {
  return value
    .split(/[\n,]/)
    .map(toolName => toolName.trim())
    .filter(toolName => toolName !== '');
}

function patternMatchesTool(pattern: string, toolName: string): boolean {
  try {
    return new RegExp(pattern).test(toolName);
  } catch {
    return false;
  }
}

function validateGateRegexes(gates: Gate[]): string | null {
  for (const gate of gates) {
    for (const pattern of effectiveGatePatterns(gate)) {
      try {
        new RegExp(pattern);
      } catch (e) {
        const detail = e instanceof Error ? e.message : 'Invalid regular expression';
        return `Pattern ${pattern} is not valid: ${detail}`;
      }
    }
  }
  return null;
}

function patternWarning(
  pattern: string,
  gateEffect: Effect,
  defaultEffect: Effect
): React.ReactNode | null {
  const source = pattern.trim();
  if (source === '') return null;

  const withoutBroadTokens = source
    .replace(/\^/g, '')
    .replace(/\$/g, '')
    .replace(/\.\*/g, '')
    .replace(/\.\+/g, '')
    .replace(/\[\\s\\S\]\*/g, '')
    .replace(/\[\\s\\S\]\+/g, '')
    .trim();
  if (withoutBroadTokens === '') {
    return 'This pattern can match every tool name. Use it only when the gate is intentionally broad.';
  }

  if (gateEffect === 'allow' && defaultEffect === 'deny') {
    const anchoredStart = source.startsWith('^');
    const anchoredEnd = source.endsWith('$');
    if (!anchoredStart || !anchoredEnd) {
      return (
        <>
          This Allow pattern is not fully anchored, so it can allow tools whose names merely contain
          this expression. Use{' '}
          <strong>
            <code>^tool_name$</code>
          </strong>{' '}
          for an exact match, or{' '}
          <strong>
            <code>^tool_name.*$</code>
          </strong>{' '}
          when suffixes are intentional.
        </>
      );
    }
  }

  return null;
}

function dryRunToolGating(
  toolNames: string[],
  gates: Gate[],
  defaultEffect: Effect
): DryRunToolDecision[] {
  return toolNames.map(toolName => {
    const matchedAllowGateNames: string[] = [];
    const matchedDenyGateNames: string[] = [];

    gates.forEach((gate, idx) => {
      const matched = effectiveGatePatterns(gate).some(pattern =>
        patternMatchesTool(pattern, toolName)
      );
      if (!matched) return;

      if (gate.action.effect === 'deny') {
        matchedDenyGateNames.push(gateDisplayName(gate, idx));
      } else {
        matchedAllowGateNames.push(gateDisplayName(gate, idx));
      }
    });

    return {
      toolName,
      allowed:
        matchedDenyGateNames.length === 0 &&
        (matchedAllowGateNames.length > 0 || defaultEffect === 'allow'),
      matchedAllowGateNames,
      matchedDenyGateNames,
    };
  });
}

function coerceGate(raw: unknown): Gate {
  const g = (raw ?? {}) as Record<string, unknown>;
  const action = (g.action ?? {}) as Record<string, unknown>;
  const effect: Effect = action.effect === 'allow' ? 'allow' : 'deny';
  const patterns = Array.isArray(action.patterns)
    ? (action.patterns as unknown[]).filter((p): p is string => typeof p === 'string')
    : [];
  return {
    id: typeof g.id === 'string' && g.id ? g.id : newId(),
    name: typeof g.name === 'string' ? g.name : '',
    description: typeof g.description === 'string' ? g.description : '',
    condition_policy_definition_id:
      typeof g.condition_policy_definition_id === 'string'
        ? g.condition_policy_definition_id
        : undefined,
    action: { effect, patterns },
  };
}

/**
 * Fullscreen editor for the MCP Tool Gating element. Manages an ordered list
 * of Tool Gates, each with an optional OPA condition (chosen from the
 * surface's policy definitions) and an allow/deny regex action. Mirrors the
 * Payment element's fullscreen: the sidebar shows a summary, this view owns
 * the heavy configuration.
 */
const McpToolGatingFullscreen: React.FC<ConfigPanelProps> = ({
  config,
  updateFields,
  protocol,
  closeFullscreenEditor,
}) => {
  const [policies, setPolicies] = useState<PolicyOption[]>([]);
  const [dryRunTools, setDryRunTools] = useState(MCP_TOOL_GATING_DRY_RUN_DEFAULT_TOOLS);
  const [dryRunResult, setDryRunResult] = useState<DryRunToolDecision[] | null>(null);
  const [dryRunError, setDryRunError] = useState<string | null>(null);
  const [dryRunAutoRun, setDryRunAutoRun] = useState(false);

  useEffect(() => {
    apiClient
      .fetch('/api/v1/policy-definitions?policy_type=agent_surface')
      .then(r => (r.ok ? r.json() : []))
      .then((data: PolicyOption[]) => setPolicies(Array.isArray(data) ? data : []))
      .catch(() => setPolicies([]));
  }, []);

  const gates: Gate[] = useMemo(
    () => (Array.isArray(config?.gates) ? config.gates.map(coerceGate) : []),
    [config?.gates]
  );

  const defaultEffect: Effect = config?.default_effect === 'deny' ? 'deny' : 'allow';
  const setDefaultEffect = (v: Effect) => updateFields({ default_effect: v });
  // A new rule takes the effect that carves against the default: deny rules
  // trim an allow-by-default surface; allow rules build the allow-list of a
  // deny-by-default surface.
  const seedEffect: Effect = defaultEffect === 'deny' ? 'allow' : 'deny';

  const setGates = (next: Gate[]) => updateFields({ gates: next });

  const addGate = () =>
    setGates([
      ...gates,
      { id: newId(), name: '', description: '', action: { effect: seedEffect, patterns: [''] } },
    ]);
  const removeGate = (idx: number) => setGates(gates.filter((_, i) => i !== idx));
  const patchGate = (idx: number, patch: Partial<Gate>) =>
    setGates(gates.map((g, i) => (i === idx ? { ...g, ...patch } : g)));
  const patchAction = (idx: number, patch: Partial<Gate['action']>) =>
    setGates(gates.map((g, i) => (i === idx ? { ...g, action: { ...g.action, ...patch } } : g)));

  const isMcp = protocol === 'mcp';

  const runDryRun = () => {
    const sampleTools = parseSampleTools(dryRunTools);
    if (sampleTools.length === 0) {
      setDryRunError('Enter at least one sample tool name.');
      setDryRunResult(null);
      return;
    }

    const regexError = validateGateRegexes(gates);
    if (regexError) {
      setDryRunError(regexError);
      setDryRunResult(null);
      return;
    }

    setDryRunResult(dryRunToolGating(sampleTools, gates, defaultEffect));
    setDryRunError(null);
  };

  // Seed one empty rule on first open so the user has a row ready to fill in
  // without hunting for an "Add" button. Runs once; deleting all rules does
  // not re-seed.
  useEffect(() => {
    if (isMcp && gates.length === 0) {
      updateFields({
        gates: [
          {
            id: newId(),
            name: '',
            description: '',
            action: { effect: seedEffect, patterns: [''] },
          },
        ],
      });
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!dryRunAutoRun) return;
    const timer = setTimeout(() => {
      runDryRun();
    }, 300);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dryRunAutoRun, dryRunTools, gates, defaultEffect]);

  return (
    <div>
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h5 className="m-0">
          <i className="fas fa-filter me-2 text-primary" />
          MCP Tool Gating
        </h5>
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

      {!isMcp && (
        <div className="alert alert-info" role="alert">
          <i className="fas fa-info-circle me-2" />
          MCP Tool Gating is only available for MCP surfaces.
        </div>
      )}

      <p className="text-muted small mb-3">
        Choose a <strong>default</strong> for the surface, then add <strong>tool gates</strong> as
        exceptions. Each gate pairs an optional <em>condition</em> (an OPA policy that activates the
        gate when it returns ALLOW) with an <em>action</em> (a regex over tool names). Gates apply
        to both <code>tools/list</code> and <code>tools/call</code>. A tool is hidden if any active{' '}
        <strong>Deny</strong> gate matches it; <strong>Deny</strong> overrides{' '}
        <strong>Allow</strong>.
      </p>

      <div className="card bg-light mb-3">
        <div className="card-body">
          <label className="form-label fw-bold mb-2">
            <i className="fas fa-shield-halved me-2 text-primary" />
            Default policy
          </label>
          <div className="d-flex align-items-center flex-wrap gap-2 mb-2">
            <span className="fw-semibold">By default, all tools are</span>
            <select
              className="form-select"
              style={{ width: 'auto' }}
              value={defaultEffect}
              onChange={e => setDefaultEffect(e.target.value as Effect)}
              disabled={!isMcp}
              aria-label="Default tool policy"
              data-testid="mcp-tool-gating-default-effect"
            >
              <option value="allow">Allowed, unless denied by a gate below</option>
              <option value="deny">Denied, unless allowed by a gate below</option>
            </select>
          </div>
          <div className="text-muted small mb-0">
            {defaultEffect === 'allow'
              ? 'Every tool is exposed except those a Deny gate hides. Allow gates do not change decisions while this default is selected.'
              : 'No tool is exposed unless an Allow gate matches it. Deny gates only matter as carve-outs from overlapping Allow gates.'}
          </div>
        </div>
      </div>

      <div
        className="card shadow-sm mb-3 border-left-primary"
        data-testid="mcp-tool-gating-dry-run-panel"
      >
        <div className="card-body py-3 px-3">
          <div className="d-flex justify-content-between align-items-center mb-2">
            <h6 className="font-weight-bold text-primary mb-0">
              <i className="fas fa-flask me-2" />
              Test (dry-run)
            </h6>
            <div className="d-flex align-items-center">
              <div className="d-flex align-items-center me-3">
                <input
                  className="form-check-input mt-0 me-1"
                  type="checkbox"
                  id="mcp-tool-gating-dry-run-autorun"
                  checked={dryRunAutoRun}
                  onChange={e => setDryRunAutoRun(e.target.checked)}
                  disabled={!isMcp}
                  data-testid="mcp-tool-gating-dry-run-autorun"
                />
                <label className="mb-0 small" htmlFor="mcp-tool-gating-dry-run-autorun">
                  Auto-run
                </label>
              </div>
              <button
                type="button"
                className="btn btn-sm btn-outline-primary"
                style={{ width: '13rem', whiteSpace: 'nowrap' }}
                onClick={runDryRun}
                disabled={!isMcp || dryRunAutoRun}
                data-testid="mcp-tool-gating-dry-run-run"
              >
                <i className="fas fa-play me-1" />
                Run against gates below
              </button>
            </div>
          </div>
          <p className="text-muted small mb-2">
            Tests the unsaved default and gate regexes against sample tool names. Nothing is saved
            or enforced. Condition (OPA policy) settings are not evaluated; conditional gates are
            treated as active for this local dry-run.
          </p>
          <p className="text-muted small mb-2">
            <strong>Auto-run:</strong> when on, this local test re-runs automatically (a moment
            after you stop typing) any time you change the sample tool names or edit a gate below,
            so you don't have to keep clicking "Run against gates below" yourself. It still only
            tests this unsaved dry-run, not real traffic.
          </p>
          <label className="font-weight-bold">Sample tool names</label>
          <textarea
            className="form-control font-monospace small"
            rows={4}
            style={{ fontSize: '0.8rem' }}
            value={dryRunTools}
            onChange={e => setDryRunTools(e.target.value)}
            disabled={!isMcp}
            data-testid="mcp-tool-gating-dry-run-input"
          />
          <div className="text-muted small mt-1">
            Paste or type example tool names here (comma-separated) to preview which of your
            configured gates would match them, before you save.
          </div>
          {dryRunError && (
            <div className="alert alert-danger compile-error-alert py-2 px-3 mt-2 mb-0">
              <i className="fas fa-exclamation-triangle me-2" />
              <span
                style={{
                  whiteSpace: 'pre-wrap',
                  fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                  fontSize: '0.8rem',
                }}
              >
                {dryRunError}
              </span>
            </div>
          )}
          {dryRunResult && (
            <div
              className="policy-preview-block rounded py-2 px-3 mt-2 mb-0"
              data-testid="mcp-tool-gating-dry-run-result"
            >
              {dryRunResult.map(decision => (
                <div
                  className="d-flex justify-content-between align-items-start gap-3 py-1"
                  key={decision.toolName}
                >
                  <div>
                    <code>{decision.toolName}</code>
                    <div className="small text-muted">
                      {decision.matchedDenyGateNames.length > 0
                        ? `Denied by ${decision.matchedDenyGateNames.join(', ')}`
                        : decision.matchedAllowGateNames.length > 0
                          ? `Allowed by ${decision.matchedAllowGateNames.join(', ')}`
                          : `Falls back to default ${defaultEffect.toUpperCase()}`}
                    </div>
                  </div>
                  <span
                    className={`badge ${decision.allowed ? 'text-bg-success' : 'text-bg-danger'}`}
                  >
                    {decision.allowed ? 'ALLOW' : 'DENY'}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {gates.length === 0 && (
        <div className="card bg-light mb-3">
          <div className="card-body text-center text-muted py-4">
            <i className="fas fa-filter fa-2x mb-2 d-block" />
            No tool gates yet. Add one to start filtering this surface's MCP tools.
          </div>
        </div>
      )}

      {gates.map((gate, idx) => {
        const patterns = gate.action.patterns.length === 0 ? [''] : gate.action.patterns;
        const effectivePatterns = effectiveGatePatterns(gate);
        const selectedPolicy = policies.find(p => p.id === gate.condition_policy_definition_id);
        const effectMatchesDefault = gate.action.effect === defaultEffect;
        const overlappingAllowGateNames =
          defaultEffect === 'deny' && gate.action.effect === 'deny'
            ? gates
                .map((candidate, candidateIdx) => ({ candidate, candidateIdx }))
                .filter(
                  ({ candidate, candidateIdx }) =>
                    candidateIdx !== idx &&
                    candidate.action.effect === 'allow' &&
                    patternsOverlap(effectivePatterns, effectiveGatePatterns(candidate))
                )
                .map(
                  ({ candidate, candidateIdx }) =>
                    candidate.name?.trim() || `Tool Gate ${candidateIdx + 1}`
                )
            : [];
        return (
          <div className="card shadow-sm mb-3" key={gate.id}>
            <div className="card-header bg-light d-flex justify-content-between align-items-center">
              <span className="fw-bold">
                <span
                  className={`badge me-2 ${gate.action.effect === 'allow' ? 'text-bg-success' : 'text-bg-danger'}`}
                >
                  {gate.action.effect === 'allow' ? 'ALLOW' : 'DENY'}
                </span>
                {gate.name?.trim() || `Tool Gate ${idx + 1}`}
              </span>
              <button
                type="button"
                className="btn btn-sm btn-outline-danger"
                onClick={() => removeGate(idx)}
                aria-label="Remove gate"
                data-testid={`mcp-tool-gating-remove-gate-${idx}`}
              >
                <i className="fas fa-trash" />
              </button>
            </div>
            <div className="card-body">
              <div className="row g-3 mb-3">
                <div className="col-md-6">
                  <label className="form-label small fw-bold">Name</label>
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    value={gate.name || ''}
                    onChange={e => patchGate(idx, { name: e.target.value })}
                    placeholder="e.g. Hide admin tools for external callers"
                  />
                  <small className="form-text text-muted">
                    A short, unique label for this gate so you can identify it later in logs and in
                    this list. It's purely for your own reference and has no effect on matching
                    behavior.
                  </small>
                </div>
                <div className="col-md-6">
                  <label className="form-label small fw-bold">Description</label>
                  <input
                    type="text"
                    className="form-control form-control-sm"
                    value={gate.description || ''}
                    onChange={e => patchGate(idx, { description: e.target.value })}
                    placeholder="Optional notes"
                  />
                </div>
              </div>

              <div className="mb-3">
                <label className="form-label small fw-bold">
                  <i className="fas fa-code-branch me-1" /> Condition (OPA policy)
                </label>
                <select
                  className="form-select form-select-sm"
                  value={gate.condition_policy_definition_id || ''}
                  onChange={e =>
                    patchGate(idx, {
                      condition_policy_definition_id: e.target.value || undefined,
                    })
                  }
                  data-testid={`mcp-tool-gating-condition-${idx}`}
                >
                  <option value="">Do not use a Policy: always enforce this rule</option>
                  {policies.map(p => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
                <div className="form-text" style={{ fontSize: '10px' }}>
                  {gate.condition_policy_definition_id ? (
                    <>
                      The gate is active only when this policy returns <strong>ALLOW</strong>. A
                      deny skips the action. {selectedPolicy?.description}
                    </>
                  ) : (
                    'This gate is always active (unconditional). '
                  )}
                  {policies.length === 0 && (
                    <AddResourceLink to={deepLinks.policies} testid="mcp-gating-add-policy-link">
                      Add policy
                    </AddResourceLink>
                  )}
                </div>
              </div>

              <div className="mb-3">
                <label className="form-label small fw-bold">
                  <i className="fas fa-shield-alt me-1" /> Action
                </label>
                <select
                  className="form-select form-select-sm mb-2"
                  value={gate.action.effect}
                  onChange={e => patchAction(idx, { effect: e.target.value as Effect })}
                  aria-label="Gate effect"
                  data-testid={`mcp-tool-gating-effect-${idx}`}
                >
                  <option value="deny">Deny: hide tools matching the regex</option>
                  <option value="allow">Allow: permit tools matching the regex</option>
                </select>
                <div className="text-muted mb-2" style={{ fontSize: '11px' }}>
                  {gate.action.effect === 'deny'
                    ? 'Matching tools are removed from tools/list and blocked on tools/call, as if they did not exist.'
                    : 'Explicitly permits matching tools. This forms the allow-list when the default is “Denied” (non-matching tools are hidden); under an “Allowed” default an Allow gate has no effect.'}
                </div>
                {effectMatchesDefault && overlappingAllowGateNames.length > 0 && (
                  <div className="alert alert-info py-2 mb-2" role="status">
                    <i className="fas fa-info-circle me-2" />
                    This Deny gate can affect policy decisions because its patterns overlap Allow
                    gate(s): <strong>{overlappingAllowGateNames.join(', ')}</strong>. Deny overrides
                    Allow for matching tools.
                  </div>
                )}
                {effectMatchesDefault && overlappingAllowGateNames.length === 0 && (
                  <div className="alert alert-warning py-2 mb-2" role="status">
                    <i className="fas fa-triangle-exclamation me-2" />
                    {defaultEffect === 'allow'
                      ? 'This Allow gate will not affect policy decisions while tools are allowed by default. Use a Deny gate to hide matching tools, or switch the default to Denied to build an allow-list.'
                      : 'This Deny gate only affects policy decisions as a carve-out from another Allow gate. Without an overlapping Allow gate, matching tools are already denied by default.'}
                  </div>
                )}

                <label className="form-label small">Tool name regex patterns</label>
                <div className="text-muted mb-2" style={{ fontSize: '11px' }}>
                  Each pattern is a <strong>regular expression</strong> matched against the tool
                  name. Matching is <strong>unanchored</strong>: a pattern matches if it appears
                  anywhere in the name (so{' '}
                  <strong>
                    <code>get_headlines</code>
                  </strong>{' '}
                  also matches <code>x_get_headlines_y</code>). Use <code>^</code> for the start and{' '}
                  <code>$</code> for the end:{' '}
                  <strong>
                    <code>^tool_name$</code>
                  </strong>{' '}
                  matches exactly,{' '}
                  <strong>
                    <code>^tool_name.*$</code>
                  </strong>{' '}
                  matches <code>tool_name</code> plus intentional suffixes, and <code>^get_</code>{' '}
                  matches any tool starting with <code>get_</code>. Nothing is implicit. (
                  <code>*</code> is a quantifier, not a wildcard; use <code>.*</code> for “any
                  characters”.)
                </div>
                {patterns.map((pattern, pIdx) => {
                  const warning = patternWarning(pattern, gate.action.effect, defaultEffect);
                  return (
                    <React.Fragment key={pIdx}>
                      <div className="input-group input-group-sm mb-2">
                        <span
                          className="input-group-text font-monospace"
                          title="Regular expression"
                        >
                          .*
                        </span>
                        <input
                          type="text"
                          className="form-control font-monospace"
                          value={pattern}
                          onChange={e => {
                            const next = [...patterns];
                            next[pIdx] = e.target.value;
                            patchAction(idx, { patterns: next });
                          }}
                          placeholder={
                            gate.action.effect === 'deny'
                              ? '^admin_.*$  or  delete'
                              : '^read_.*$  or  list'
                          }
                          data-testid={`mcp-tool-gating-pattern-${idx}-${pIdx}`}
                        />
                        <button
                          className="btn btn-outline-danger"
                          type="button"
                          onClick={() =>
                            patchAction(idx, { patterns: patterns.filter((_, i) => i !== pIdx) })
                          }
                          aria-label="Remove pattern"
                          data-testid={`mcp-tool-gating-remove-pattern-${idx}-${pIdx}`}
                        >
                          <i className="fas fa-trash" />
                        </button>
                      </div>
                      {warning && (
                        <div
                          className="alert alert-warning py-2 px-3 mt-0 mb-2"
                          role="status"
                          data-testid={`mcp-tool-gating-pattern-warning-${idx}-${pIdx}`}
                        >
                          <i className="fas fa-triangle-exclamation me-2" />
                          {warning}
                        </div>
                      )}
                    </React.Fragment>
                  );
                })}
                <button
                  className="btn btn-sm btn-outline-primary"
                  type="button"
                  onClick={() => patchAction(idx, { patterns: [...patterns, ''] })}
                  data-testid={`mcp-tool-gating-add-pattern-${idx}`}
                >
                  <i className="fas fa-plus me-1" /> Add Pattern
                </button>
                {effectivePatterns.length === 0 && (
                  <div className="alert alert-danger mt-2 mb-0 py-2" role="alert">
                    <i className="fas fa-exclamation-circle me-2" />
                    At least one regex pattern is required, otherwise this gate has no effect.
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}

      <button
        type="button"
        className="btn btn-sm btn-outline-primary"
        onClick={addGate}
        data-testid="mcp-tool-gating-add-gate"
      >
        <i className="fas fa-plus me-1" /> Add Tool Gate
      </button>
    </div>
  );
};

export default McpToolGatingFullscreen;
