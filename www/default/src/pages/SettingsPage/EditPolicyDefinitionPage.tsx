import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { apiClient } from '../../api';
import { showToast } from '../../utils/toaster';
import { useSafeNavigate } from '../../hooks/useSafeNavigate';
import { usePageTitle } from '../../context/PageTitleContext';
import { usePermissions } from '../../context/PermissionsContext';
import { useDiscardWithUndo } from '../../components/surface-builder/hooks/useDiscardWithUndo';
import { Link } from '../../components/shared/Link';
import { DOCS_URL } from '../../config/docs';
import PolicySimulatePanel, { POLICY_SIMULATE_DEFAULT_INPUT } from './PolicySimulatePanel';
import PolicyVersionHistory from './PolicyVersionHistory';
import { DEFAULT_POLICY, EXPECTED_PACKAGE } from './policyTemplates/policyDefaults';
import PolicyDetailsSection from './PolicyDetailsSection';
import { DEFAULT_POLICY_VIEW } from './policyTemplates/policyDefaults';
import PolicyEditorSection, { type PolicyView } from './policyTemplates/PolicyEditorSection';
import PolicyTemplatesPanel from './policyTemplates/PolicyTemplatesPanel';
import SaveAsTemplatePanel from './policyTemplates/SaveAsTemplatePanel';
import TemplateExamplesCheck from './policyTemplates/TemplateExamplesCheck';
import TemplateGallery from './policyTemplates/TemplateGallery';
import { BUILTIN_POLICY_TEMPLATES } from './policyTemplates/builtinPolicyTemplates';
import { parsePolicyRules } from './policyTemplates/regoRules';
import { BLANK_TEMPLATE_ID } from './policyTemplates/policyDefaults';
import type { PolicyType } from './policyTemplates/types';
import { usePolicyTemplateActions } from './policyTemplates/usePolicyTemplateActions';

interface PolicyDefinition {
  id: string;
  name: string;
  description: string;
  policy_type: PolicyType;
  policy: string;
  enabled: boolean;
  created_at: string;
  updated_at?: string;
  sample_input?: string;
  content_hash?: string;
}

const TYPE_NAME: Record<PolicyType, string> = {
  gateway: 'Gateway',
  agent_surface: 'Agent Surface',
};

/** Built-in templates in the policy, applied or inserted, that have no variant for `type`. */
function templatesWithoutType(
  policy: string,
  appliedTemplateId: string | null,
  type: PolicyType
): string[] {
  const forType = new Set(
    BUILTIN_POLICY_TEMPLATES.filter(t => t.policy_type === type).map(t => t.name)
  );
  const otherOnly = new Set(
    BUILTIN_POLICY_TEMPLATES.filter(t => !forType.has(t.name)).map(t => t.name)
  );
  const parsed = parsePolicyRules(policy);
  const names = parsed.ok
    ? parsed.groups.flatMap(g =>
        g.source.kind === 'template' && otherOnly.has(g.source.name) ? [g.source.name] : []
      )
    : [];
  const applied = BUILTIN_POLICY_TEMPLATES.find(t => t.id === appliedTemplateId);
  if (applied && otherOnly.has(applied.name)) names.unshift(applied.name);
  return Array.from(new Set(names));
}

function extractPackage(policy: string): string | null {
  const m = policy.match(/^\s*package\s+([^\s{]+)/m);
  return m ? m[1].trim() : null;
}

const EditPolicyDefinitionPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const isCreateMode = !id || id === 'new';
  const typeFromQuery: PolicyType =
    searchParams.get('type') === 'agent_surface' ? 'agent_surface' : 'gateway';

  const [form, setForm] = useState<PolicyDefinition>({
    id: '',
    name: '',
    description: '',
    policy_type: typeFromQuery,
    policy: DEFAULT_POLICY[typeFromQuery],
    enabled: true,
    created_at: new Date().toISOString(),
  });

  usePageTitle(isCreateMode ? 'Create Policy' : 'Edit Policy');

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
  const [view, setView] = useState<PolicyView>(
    DEFAULT_POLICY_VIEW[isCreateMode ? 'create' : 'edit']
  );
  const templatesColumnRef = useRef<HTMLDivElement>(null);
  const [focusAddRules, setFocusAddRules] = useState(0);
  const { hasPermission } = usePermissions();
  const canEditPolicies = hasPermission('policies.edit');
  const {
    templatePanel,
    setTemplatePanel,
    togglePanel,
    appliedTemplateId,
    setAppliedTemplateId,
    insertedTemplate,
    dismissInsertedTemplate,
    justAdded,
    regoRef,
    applyTemplate,
    editPolicy,
    pickBlank,
    insertTemplate,
    removeGroup,
    removeRule,
    denyByDefault,
    showRule,
  } = usePolicyTemplateActions(form, setForm, isCreateMode);

  const changeType = (newType: PolicyType) => {
    const expectedPkg = EXPECTED_PACKAGE[newType];
    const currentPkg = extractPackage(form.policy);
    const policy =
      currentPkg && currentPkg !== expectedPkg
        ? form.policy.replace(/^(\s*package\s+)[^\s{]+/m, `$1${expectedPkg}`)
        : form.policy;
    setForm({ ...form, policy_type: newType, policy });
    // A template with a variant for the new Type stays chosen; any other stops applying.
    const appliedKey = appliedTemplateId?.split(':')[0];
    const sameTemplate = BUILTIN_POLICY_TEMPLATES.find(t => t.id === `${appliedKey}:${newType}`);
    if (appliedTemplateId !== BLANK_TEMPLATE_ID) setAppliedTemplateId(sameTemplate?.id ?? null);
    const otherTypeOnly = templatesWithoutType(policy, appliedTemplateId, newType);
    if (otherTypeOnly.length > 0) {
      const one = otherTypeOnly.length === 1;
      const other: PolicyType = newType === 'gateway' ? 'agent_surface' : 'gateway';
      showToast(
        'warning',
        `${otherTypeOnly.join(', ')} ${one ? 'is' : 'are'} written for ${TYPE_NAME[other]} policies and ${one ? 'reads' : 'read'} input that ${TYPE_NAME[newType]} policies don't get. Check those rules before you create the policy.`
      );
    }
  };

  const addTemplateRules: typeof insertTemplate = (...args) => {
    insertTemplate(...args);
    setView('rules');
  };

  useEffect(() => {
    if (focusAddRules === 0) return;
    templatesColumnRef.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
    templatesColumnRef.current?.querySelector<HTMLInputElement>('input[type="search"]')?.focus();
  }, [focusAddRules]);

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

  const templatesPanel = (
    <PolicyTemplatesPanel
      key={form.policy_type}
      policyType={form.policy_type}
      existingPolicy={form.policy}
      onInsert={addTemplateRules}
    />
  );

  // The templates column is always there for an editor, so opening a panel never resizes the form.
  const sidePanel = !canEditPolicies ? null : templatePanel === 'save' ? (
    <SaveAsTemplatePanel
      policyId={form.id}
      policyType={form.policy_type}
      savedPolicy={(JSON.parse(baselineRef.current) as PolicyDefinition).policy}
      defaultName={form.name}
      defaultSummary={form.description}
      sampleInput={form.sample_input ?? POLICY_SIMULATE_DEFAULT_INPUT}
      onSaved={template => {
        setTemplatePanel(null);
        showToast(
          'success',
          `Template ${template.name} saved under Your organization for this browser tab.`
        );
      }}
      onClose={() => setTemplatePanel(null)}
    />
  ) : (
    templatesPanel
  );

  // Add rules brings back the Add rules panel, then moves to its search once it has rendered.
  const focusTemplatesColumn = () => {
    setTemplatePanel(null);
    setFocusAddRules(n => n + 1);
  };

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
    <div className="container-fluid" data-testid="page-policy-definition-editor">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={discard}
          data-testid="policy-definition-editor-back-button"
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="row">
        <div className={sidePanel ? 'col-xl-8' : 'col-12'}>
          <div className="card shadow mb-4 channel-editor-card">
            <div className="card-header py-3 d-flex justify-content-between align-items-center">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-shield-alt"></i>{' '}
                {isCreateMode ? 'Create Policy' : `Edit Policy: ${form.name}`}
              </h6>
              <div className="d-flex align-items-center gap-2">
                {!isCreateMode && canEditPolicies && (
                  <span title={isDirty ? 'Save the policy first' : undefined}>
                    <button
                      type="button"
                      className={`btn btn-sm btn-outline-primary${templatePanel === 'save' ? ' active' : ''}`}
                      aria-pressed={templatePanel === 'save'}
                      disabled={isDirty}
                      onClick={() => togglePanel('save')}
                      data-testid="policy-templates-save-as-button"
                    >
                      <i className="fas fa-copy me-1" aria-hidden="true" />
                      Save as template
                    </button>
                  </span>
                )}
                <button
                  className={`btn btn-sm btn-primary me-2 ${saving || !policyValid || !!packageMismatch ? 'disabled' : ''}`}
                  data-testid="policy-definition-editor-save-button"
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

              <p className="text-muted small mb-3">
                A policy is Rego the gateway evaluates for every matching request to allow or deny
                it.{' '}
                <Link href={DOCS_URL.policies} external variant="inline">
                  Learn more
                </Link>
              </p>

              {isCreateMode && canEditPolicies && (
                <TemplateGallery
                  step={1}
                  policyType={form.policy_type}
                  appliedTemplateId={appliedTemplateId}
                  onPickBlank={() => {
                    pickBlank();
                    setView('rules');
                  }}
                  onUseTemplate={(template, rego) => {
                    applyTemplate(template, rego);
                    setView('rules');
                  }}
                />
              )}

              <PolicyDetailsSection
                step={isCreateMode ? 2 : undefined}
                isCreateMode={isCreateMode}
                name={form.name}
                description={form.description}
                policyType={form.policy_type}
                enabled={form.enabled}
                policyId={form.id || undefined}
                contentHash={form.content_hash}
                onNameChange={name => setForm(f => ({ ...f, name }))}
                onDescriptionChange={description => setForm(f => ({ ...f, description }))}
                onEnabledChange={enabled => setForm(f => ({ ...f, enabled }))}
                onTypeChange={changeType}
              />

              <PolicyEditorSection
                step={isCreateMode ? 3 : undefined}
                policy={form.policy}
                policyType={form.policy_type}
                onPolicyChange={editPolicy}
                view={view}
                onViewChange={setView}
                regoRef={regoRef}
                canEdit={canEditPolicies}
                isValidating={isValidating}
                policyValid={policyValid}
                policyErrors={policyErrors}
                packageMismatch={packageMismatch}
                onFixPackage={() =>
                  setForm(f => ({
                    ...f,
                    policy: f.policy.replace(
                      /^(\s*package\s+)[^\s{]+/m,
                      `$1${EXPECTED_PACKAGE[f.policy_type]}`
                    ),
                  }))
                }
                justAdded={justAdded}
                onAdd={focusTemplatesColumn}
                onRemoveGroup={removeGroup}
                onRemoveRule={removeRule}
                onSetDefaultDeny={denyByDefault}
                onShowRule={showRule}
              />
            </div>
          </div>
          {!isCreateMode && form.id && insertedTemplate && (
            <TemplateExamplesCheck
              key={insertedTemplate.key}
              policyId={form.id}
              policyType={form.policy_type}
              draftPolicy={form.policy}
              template={insertedTemplate.template}
              usesDefaultSettings={insertedTemplate.usesDefaultSettings}
              onDismiss={dismissInsertedTemplate}
            />
          )}
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
        {sidePanel && (
          <div className="col-xl-4">
            <div
              className="policy-templates-column"
              ref={templatesColumnRef}
              data-testid="policy-templates-column"
            >
              {sidePanel}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default EditPolicyDefinitionPage;
