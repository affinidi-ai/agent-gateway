import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { useSafeNavigate } from '../../hooks/useSafeNavigate';
import { usePageTitle } from '../../context/PageTitleContext';
import { useDiscardWithUndo } from '../../components/surface-builder/hooks/useDiscardWithUndo';
import FieldHelp from '../../components/shared/FieldHelp';
import { Link } from '../../components/shared/Link';
import { DOCS_URL } from '../../config/docs';
import PolicySimulatePanel, { POLICY_SIMULATE_DEFAULT_INPUT } from './PolicySimulatePanel';
import PolicyVersionHistory from './PolicyVersionHistory';

interface PolicyDefinition {
  id: string;
  name: string;
  description: string;
  policy_type: 'gateway' | 'agent_surface';
  policy: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
  sample_input?: string;
  content_hash?: string;
}

const EXPECTED_PACKAGE: Record<'gateway' | 'agent_surface', string> = {
  gateway: 'gateway.policy',
  agent_surface: 'surface.policy',
};

const DEFAULT_POLICY: Record<'gateway' | 'agent_surface', string> = {
  gateway: `package gateway.policy

# Allow all traffic by default
default allow = true`,
  agent_surface: `package surface.policy

# Allow all traffic by default
default allow = true`,
};

function extractPackage(policy: string): string | null {
  const m = policy.match(/^\s*package\s+([^\s{]+)/m);
  return m ? m[1].trim() : null;
}

const EditPolicyDefinitionPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const isCreateMode = !id || id === 'new';
  const typeFromQuery = searchParams.get('type') as 'gateway' | 'agent_surface' | null;

  const [form, setForm] = useState<PolicyDefinition>({
    id: '',
    name: '',
    description: '',
    policy_type: typeFromQuery || 'gateway',
    policy: DEFAULT_POLICY[typeFromQuery || 'gateway'],
    enabled: true,
    created_at: new Date().toISOString(),
  });

  usePageTitle(isCreateMode ? 'Create Policy Definition' : 'Edit Policy');

  const [loading, setLoading] = useState(!isCreateMode);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const baselineRef = useRef<string>(JSON.stringify(form));
  const [isDirty, setIsDirty] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [policyValid, setPolicyValid] = useState(true);
  const [policyErrors, setPolicyErrors] = useState<string[]>([]);
  const [packageMismatch, setPackageMismatch] = useState<string | null>(null);
  const [versionRefreshKey, setVersionRefreshKey] = useState(0);

  useEffect(() => {
    if (!isCreateMode && id) {
      apiClient
        .fetch(`/api/v1/policy-definitions/${encodeURIComponent(id)}`)
        .then(r => {
          if (!r.ok) throw new Error(`Failed to load: ${r.statusText}`);
          return r.json();
        })
        .then((data: PolicyDefinition) => {
          setForm(data);
          baselineRef.current = JSON.stringify(data);
          setIsDirty(false);
          setLoading(false);
        })
        .catch(e => {
          setError(e.message);
          setLoading(false);
        });
    }
  }, [id, isCreateMode]);

  // Debounced policy validation
  useEffect(() => {
    if (!form.policy?.trim()) {
      setPolicyValid(true);
      setPolicyErrors([]);
      setPackageMismatch(null);
      return;
    }
    // Check package declaration matches policy type
    const expected = EXPECTED_PACKAGE[form.policy_type];
    const actual = extractPackage(form.policy);
    if (actual && actual !== expected) {
      setPackageMismatch(
        `Package is "${actual}" but should be "${expected}" for ${form.policy_type === 'gateway' ? 'Gateway' : 'Agent Surface'} policies.`
      );
    } else {
      setPackageMismatch(null);
    }
    const timer = setTimeout(async () => {
      setIsValidating(true);
      try {
        const response = await apiClient.post('/surfaces/validate-policy', {
          policy: form.policy,
        });
        setPolicyValid((response as any).data.valid);
        setPolicyErrors((response as any).data.error ? [(response as any).data.error] : []);
      } catch {
        setPolicyValid(true);
        setPolicyErrors([]);
      } finally {
        setIsValidating(false);
      }
    }, 500);
    return () => clearTimeout(timer);
  }, [form.policy, form.policy_type]);

  const handleSave = useCallback(async () => {
    if (!form.name.trim()) {
      setError('Name is required');
      return;
    }
    if (packageMismatch) {
      setError(packageMismatch);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const payload = {
        ...form,
        id: isCreateMode ? crypto.randomUUID() : form.id,
        created_at: isCreateMode ? new Date().toISOString() : form.created_at,
      };
      const url = isCreateMode
        ? `/api/v1/policy-definitions`
        : `/api/v1/policy-definitions/${encodeURIComponent(form.id)}`;
      const resp = await apiClient.fetch(url, {
        method: isCreateMode ? 'POST' : 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      if (!resp.ok) {
        const errData = await resp.json().catch(() => ({ error: resp.statusText }));
        throw new Error(errData.error || resp.statusText);
      }
      setIsDirty(false);
      if (isCreateMode) {
        showToast('success', 'Policy created!');
        navigate(`/policy-definitions/${encodeURIComponent(payload.id)}`);
      } else {
        // Stay in the editor and surface the newly appended version.
        baselineRef.current = JSON.stringify(payload);
        setForm(payload);
        setVersionRefreshKey(k => k + 1);
        showToast('success', 'Policy updated!');
      }
    } catch (e: any) {
      setError(e.message || 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  }, [form, isCreateMode, navigate, packageMismatch]);

  // Track dirty state whenever form changes
  useEffect(() => {
    setIsDirty(JSON.stringify(form) !== baselineRef.current);
  }, [form]);

  const { discard, popPendingRestore } = useDiscardWithUndo({
    dirty: isDirty && !saving,
    // Go straight to the owning Policies sub-tab (Gateway / Agent Surfaces) —
    // `/settings?tab=policies` bounces through a legacy redirect to `/policies`
    // that drops the sub-tab, always landing back on Gateway.
    navigateTo: `/policies?tab=${form.policy_type}`,
    snapshot: {
      storageKey: `policy-draft:${id ?? 'new'}`,
      save: () => JSON.stringify(form),
      restore: saved => {
        try {
          const parsed = JSON.parse(saved) as PolicyDefinition;
          setForm(parsed);
          setIsDirty(true);
        } catch (_ignored) {
          /* ignore */
        }
      },
    },
  });

  // Apply any pending undo-restore after the load completes.
  useEffect(() => {
    if (loading) return;
    popPendingRestore();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [loading]);

  // Keyboard shortcut Ctrl+S / Cmd+S
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        if (!saving) handleSave();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [saving, handleSave]);

  if (loading) {
    return (
      <div className="container-fluid">
        <div className="text-center py-5">
          <div className="spinner-border text-primary" role="status" />
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button className="btn btn-sm btn-secondary" onClick={discard}>
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="card shadow mb-4 channel-editor-card">
        <div className="card-header py-3 d-flex justify-content-between align-items-center">
          <h6 className="m-0 font-weight-bold text-primary">
            <i className="fas fa-shield-alt"></i>{' '}
            {isCreateMode ? 'Create Policy Definition' : `Edit Policy: ${form.name}`}
          </h6>
          <div className="d-flex align-items-center">
            <button
              className={`btn btn-sm btn-primary me-2 ${saving || !policyValid || !!packageMismatch ? 'disabled' : ''}`}
              onClick={handleSave}
              disabled={saving || !policyValid || !!packageMismatch}
            >
              <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
              {saving ? ' Saving...' : isCreateMode ? ' Create' : ' Save'}
            </button>
          </div>
        </div>

        <div className="card-body-channel-editor p-3">
          {error && (
            <div className="alert alert-danger alert-dismissible fade show">
              <i className="fas fa-exclamation-triangle me-2"></i>
              <span
                style={{
                  whiteSpace: 'pre-wrap',
                  fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                  fontSize: '0.8rem',
                }}
              >
                {error}
              </span>
              <button
                type="button"
                className="btn-close"
                onClick={() => setError(null)}
                aria-label="Close"
              />
            </div>
          )}

          <p className="text-muted mb-3">
            A policy is a rule, written in Rego (a small policy language), that the gateway
            evaluates for every matching request and returns allow or deny. Changing the Rego
            content creates a new version each time you save (name, description, and
            enabled/disabled changes don&apos;t). Policies can be scoped to Gateway-wide or a
            specific Agent Surface.{' '}
            <Link href={DOCS_URL.policies} external variant="inline">
              Learn more
            </Link>
          </p>

          <div className="row">
            <div className="col-md-6">
              <div className="mb-3 mb-3">
                <label className="font-weight-bold">
                  Name{' '}
                  <FieldHelp testId="field-help-policy-definition-name" ariaLabel="About Name">
                    A short, memorable label, this is what you&apos;ll see in the policy list and in
                    audit-log entries when this policy makes a decision.
                  </FieldHelp>
                </label>
                <input
                  type="text"
                  className="form-control form-control-sm"
                  value={form.name}
                  onChange={e => {
                    setForm({ ...form, name: e.target.value });
                  }}
                  placeholder="e.g. Require Authentication"
                />
              </div>
            </div>
            <div className="col-md-3">
              <div className="mb-3 mb-3">
                <label className="font-weight-bold">
                  Type{' '}
                  <FieldHelp testId="field-help-policy-definition-type" ariaLabel="About Type">
                    Gateway policies attach to a gateway connection (your own appliance, or one
                    remote peer) and can also be enforced appliance-wide from the policy list. Agent
                    Surface policies apply only to one specific agent surface&apos;s traffic.
                  </FieldHelp>
                </label>
                <select
                  className="form-control form-control-sm dropdown-styling"
                  value={form.policy_type}
                  disabled={!isCreateMode}
                  title={!isCreateMode ? "A policy's type is fixed once created." : undefined}
                  onChange={e => {
                    const newType = e.target.value as 'gateway' | 'agent_surface';
                    const expectedPkg = EXPECTED_PACKAGE[newType];
                    const currentPkg = extractPackage(form.policy);
                    let newPolicy = form.policy;
                    if (currentPkg && currentPkg !== expectedPkg) {
                      newPolicy = form.policy.replace(
                        /^(\s*package\s+)[^\s{]+/m,
                        `$1${expectedPkg}`
                      );
                    }
                    setForm({ ...form, policy_type: newType, policy: newPolicy });
                  }}
                >
                  <option value="gateway">Gateway</option>
                  <option value="agent_surface">Agent Surfaces</option>
                </select>
                {!isCreateMode ? (
                  <small className="form-text text-muted">
                    <i className="fas fa-lock me-1"></i>A policy&apos;s type is fixed once created.
                  </small>
                ) : (
                  <small className="form-text text-muted">
                    Choose based on where you want this rule enforced, this can&apos;t be changed
                    after you save.
                  </small>
                )}
              </div>
            </div>
            <div className="col-md-3">
              <div className="mb-3 mb-3">
                <label className="font-weight-bold">Status</label>
                <div className="form-check mt-1">
                  <input
                    className="form-check-input"
                    type="checkbox"
                    id="policy-enabled"
                    checked={form.enabled}
                    onChange={e => {
                      setForm({ ...form, enabled: e.target.checked });
                    }}
                  />
                  <label className="form-check-label" htmlFor="policy-enabled">
                    Enabled
                  </label>
                </div>
                <small className="form-text text-muted d-block">
                  When off, this policy is never evaluated. If this policy is also enforced Globally
                  on the list page, turning it off will make every request in that plane fail closed
                  (denied) until it&apos;s re-enabled or removed from Global enforcement. Global
                  assignments set to Monitor only are unaffected: they just stop logging this
                  policy&apos;s decisions.
                </small>
              </div>
            </div>
          </div>

          <div className="mb-3 mb-3">
            <label className="font-weight-bold">
              Description{' '}
              <FieldHelp
                testId="field-help-policy-definition-description"
                ariaLabel="About Description"
              >
                Shown in the policy list and version history, use it to note what this policy
                enforces and why, for whoever looks at this later.
              </FieldHelp>
            </label>
            <input
              type="text"
              className="form-control form-control-sm"
              value={form.description}
              onChange={e => {
                setForm({ ...form, description: e.target.value });
              }}
              placeholder="What does this policy do?"
            />
          </div>

          {!isCreateMode && form.id && (
            <div className="mb-3 mb-3">
              <label className="font-weight-bold">Policy ID</label>
              <input
                type="text"
                className="form-control font-monospace bg-light"
                value={form.id}
                disabled
                readOnly
                style={{ cursor: 'not-allowed' }}
              />
              <small className="form-text text-muted">
                <i className="fas fa-lock me-1"></i>
                Referenced by surfaces/gateways and shown in the Audit Log (cannot be changed).
              </small>
            </div>
          )}

          {!isCreateMode && form.content_hash && (
            <div className="mb-3 mb-3">
              <label className="font-weight-bold">SHA</label>
              <input
                type="text"
                className="form-control font-monospace bg-light"
                value={form.content_hash}
                disabled
                readOnly
                style={{ cursor: 'not-allowed' }}
              />
              <small className="form-text text-muted">
                <i className="fas fa-lock me-1"></i>
                Content hash of the currently enforced revision (cannot be changed).
              </small>
            </div>
          )}

          {/* Policy Instructions */}
          <div className="card shadow-sm mb-4 border-left-primary">
            <div className="card-body">
              <div className="d-flex justify-content-between align-items-center">
                <h6 className="font-weight-bold text-primary mb-0">
                  <i className="fas fa-graduation-cap me-2"></i>
                  Policy Instructions & Examples
                </h6>
                <button
                  className="btn btn-sm btn-outline-primary"
                  type="button"
                  data-bs-toggle="collapse"
                  data-bs-target="#policyDefInstructions"
                  aria-expanded="false"
                >
                  <i className="fas fa-chevron-down"></i>
                </button>
              </div>

              <div className="collapse" id="policyDefInstructions">
                <p className="text-gray-800 mb-3 mt-3">
                  Write Rego policies to control access based on JWT claims, HTTP context, and
                  routing information.
                </p>

                <div className="card bg-light border-0">
                  <div className="card-body">
                    <h6 className="font-weight-bold text-dark mb-3">
                      <i className="fas fa-lightbulb me-2"></i>
                      Policy Structure
                    </h6>
                    <p className="mb-3 text-gray-700">
                      Policies must use the appropriate package and define an <code>allow</code>{' '}
                      rule:
                    </p>
                    <pre
                      className="p-3 rounded mb-3"
                      style={{
                        fontSize: '0.85rem',
                        backgroundColor: 'var(--gray-50)',
                        color: 'var(--gray-800)',
                        border: '1px solid var(--gray-300)',
                      }}
                    >
                      <code
                        style={{ color: 'var(--gray-800)' }}
                      >{`package ${EXPECTED_PACKAGE[form.policy_type]}

# Default decision (true = allow all, false = deny all)
default allow = false

# Rules that evaluate to true allow the request
allow if {
  # Your conditions here
}`}</code>
                    </pre>

                    <h6 className="font-weight-bold text-dark mb-3 mt-4">
                      <i className="fas fa-database me-2"></i>
                      Available Input Context
                    </h6>
                    <ul className="mb-3 text-gray-800">
                      <li>
                        <strong>input.jwt.*</strong> - JWT claims (sub, role, etc.)
                      </li>
                      <li>
                        <strong>input.http.method</strong> - HTTP method
                      </li>
                      <li>
                        <strong>input.http.path</strong> - Request path
                      </li>
                      <li>
                        <strong>input.http.headers</strong> - HTTP headers
                      </li>
                      <li>
                        <strong>input.gateway.direction</strong> - "inbound" or "outbound"
                      </li>
                      <li>
                        <strong>input.channel.config_id</strong> - Target channel config ID
                      </li>
                      <li>
                        <strong>input.channel.name</strong> - Target channel name
                      </li>
                    </ul>

                    <h6 className="font-weight-bold text-dark mb-3 mt-4">
                      <i className="fas fa-lock me-2"></i>
                      Example: Require Authentication
                    </h6>
                    <pre
                      className="p-3 rounded mb-3"
                      style={{
                        fontSize: '0.85rem',
                        backgroundColor: 'var(--gray-50)',
                        color: 'var(--gray-800)',
                        border: '1px solid var(--gray-300)',
                      }}
                    >
                      <code
                        style={{ color: 'var(--gray-800)' }}
                      >{`package ${EXPECTED_PACKAGE[form.policy_type]}

default allow = false

# Only allow authenticated requests
allow if {
  input.jwt.sub
}`}</code>
                    </pre>

                    <h6 className="font-weight-bold text-dark mb-3 mt-4">
                      <i className="fas fa-user-shield me-2"></i>
                      Example: Admin-Only Access
                    </h6>
                    <pre
                      className="p-3 rounded mb-3"
                      style={{
                        fontSize: '0.85rem',
                        backgroundColor: 'var(--gray-50)',
                        color: 'var(--gray-800)',
                        border: '1px solid var(--gray-300)',
                      }}
                    >
                      <code
                        style={{ color: 'var(--gray-800)' }}
                      >{`package ${EXPECTED_PACKAGE[form.policy_type]}

default allow = false

allow if {
  input.jwt.role == "admin"
}`}</code>
                    </pre>

                    <div className="alert alert-warning mb-0">
                      <small className="text-dark">
                        <i className="fas fa-exclamation-triangle me-2 text-warning"></i>
                        <strong>Best Practice:</strong> Start with{' '}
                        <code className="text-dark">default allow = false</code> and explicitly
                        allow what you need.
                      </small>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Rego Editor */}
          <div>
            <label className="font-weight-bold">
              Policy Content (Rego){' '}
              <FieldHelp
                testId="field-help-policy-definition-content"
                ariaLabel="About Policy Content"
              >
                Rego is the policy language OPA (Open Policy Agent) uses to evaluate these rules,
                see the Instructions above for syntax and examples.
              </FieldHelp>
              {isValidating && (
                <span className="ms-2 text-muted small">
                  <i className="fas fa-spinner fa-spin"></i> Compiling...
                </span>
              )}
              {!isValidating && form.policy.trim() && policyValid && !packageMismatch && (
                <span className="ms-2 text-success small">
                  <i className="fas fa-check-circle"></i> Valid
                </span>
              )}
              {!isValidating && form.policy.trim() && (!policyValid || !!packageMismatch) && (
                <span className="ms-2 text-danger small">
                  <i className="fas fa-circle-exclamation"></i> Invalid
                </span>
              )}
            </label>
            <textarea
              className={`form-control font-monospace small ${policyValid && !packageMismatch ? '' : 'is-invalid'}`}
              rows={16}
              style={{ fontSize: '0.875rem' }}
              value={form.policy}
              onChange={e => {
                setForm({ ...form, policy: e.target.value });
              }}
              placeholder="...add policy here..."
            />
            <small className="form-text text-muted">
              Leave empty to allow all traffic. Policy is evaluated with JWT claims, HTTP context,
              and routing information. See the Instructions above for syntax and examples.
            </small>
            {policyErrors.length > 0 && (
              <div className="alert alert-danger compile-error-alert py-2 px-3 mt-2 mb-0">
                <i className="fas fa-exclamation-triangle me-2"></i>
                {policyErrors.map((err, idx) => (
                  <span
                    key={idx}
                    style={{
                      whiteSpace: 'pre-wrap',
                      fontFamily: 'Monaco, Consolas, "Courier New", monospace',
                      fontSize: '0.8rem',
                    }}
                  >
                    {err}
                  </span>
                ))}
              </div>
            )}
            {packageMismatch && (
              <div
                className="alert alert-danger py-2 px-3 mt-2 mb-0 d-flex align-items-start"
                style={{ fontSize: '0.85rem' }}
              >
                <i className="fas fa-exclamation-triangle mr-2 mt-1 flex-shrink-0" />
                <div>
                  <strong>Package mismatch:</strong> {packageMismatch}
                  <button
                    type="button"
                    className="btn btn-sm btn-danger ml-2 py-0 px-2"
                    style={{ fontSize: '0.8rem' }}
                    onClick={() => {
                      const expected = EXPECTED_PACKAGE[form.policy_type];
                      const fixed = form.policy.replace(
                        /^(\s*package\s+)[^\s{]+/m,
                        `$1${expected}`
                      );
                      setForm({ ...form, policy: fixed });
                    }}
                  >
                    Fix it
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
      {!isCreateMode && form.id && (
        <PolicySimulatePanel
          policyId={form.id}
          policyType={form.policy_type}
          draftPolicy={form.policy}
          sampleInput={form.sample_input ?? POLICY_SIMULATE_DEFAULT_INPUT}
          onSampleInputChange={value => setForm(f => ({ ...f, sample_input: value }))}
          policyValid={policyValid && !packageMismatch}
        />
      )}
      {!isCreateMode && form.id && (
        <PolicyVersionHistory
          policyId={form.id}
          name={form.name}
          description={form.description}
          refreshKey={versionRefreshKey}
        />
      )}
    </div>
  );
};

export default EditPolicyDefinitionPage;
