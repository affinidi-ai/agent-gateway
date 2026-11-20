import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { apiClient } from '../../api';
import { showToast, showUndoToast } from '../../utils/toaster';
import { useSafeNavigate } from '../../hooks/useSafeNavigate';
import { usePageTitle } from '../../context/PageTitleContext';
import { usePermissions } from '../../context/PermissionsContext';
import { useDiscardWithUndo } from '../../components/surface-builder/hooks/useDiscardWithUndo';
import { Link } from '../../components/shared/Link';
import { DOCS_URL } from '../../config/docs';
import PolicySimulatePanel, { POLICY_SIMULATE_DEFAULT_INPUT } from './PolicySimulatePanel';
import PolicyVersionHistory from './PolicyVersionHistory';
import {
  DEFAULT_POLICY,
  DEFAULT_POLICY_VIEW,
  EXPECTED_PACKAGE,
} from './policyTemplates/policyDefaults';
import PolicyDetailsSection from './PolicyDetailsSection';
import PolicyEditorSection, { type PolicyView } from './policyTemplates/PolicyEditorSection';
import PolicyTemplatesPanel from './policyTemplates/PolicyTemplatesPanel';
import TemplateExamplesCheck from './policyTemplates/TemplateExamplesCheck';
import TemplateGallery from './policyTemplates/TemplateGallery';
import TemplateGalleryDetail from './policyTemplates/TemplateGalleryDetail';
import { parsePolicyRules } from './policyTemplates/regoRules';
import { POLICY_TYPE_NAMES, type PolicyType } from './policyTemplates/types';
import { usePolicyTemplateActions } from './policyTemplates/usePolicyTemplateActions';
import { useTemplateGallery } from './policyTemplates/useTemplateGallery';
import { POLICY_TEMPLATE_LIBRARY } from './policyTemplates/builtinPolicyTemplates';
import { groupsForOtherType } from './policyTemplates/policyStart';

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

function extractPackage(policy: string): string | null {
  const m = policy.match(/^\s*package\s+([^\s{]+)/m);
  return m ? m[1].trim() : null;
}

const EditPolicyDefinitionPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const isCreateMode = !id || id === 'new';
  const typeParam = searchParams.get('type');
  const typeFromQuery: PolicyType = typeParam === 'agent_surface' ? 'agent_surface' : 'gateway';
  const typeChosen = isCreateMode && (typeParam === 'gateway' || typeParam === 'agent_surface');

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
  const [loadError, setLoadError] = useState<string | null>(null);
  const baselineRef = useRef<string>(JSON.stringify(form));
  const [isDirty, setIsDirty] = useState(false);
  const [isValidating, setIsValidating] = useState(false);
  const [policyValid, setPolicyValid] = useState(true);
  const [policyErrors, setPolicyErrors] = useState<string[]>([]);
  const [packageMismatch, setPackageMismatch] = useState<string | null>(null);
  const [versionRefreshKey, setVersionRefreshKey] = useState(0);
  const [view, setView] = useState<PolicyView>(DEFAULT_POLICY_VIEW);
  const templatesColumnRef = useRef<HTMLDivElement>(null);
  const [focusAddRules, setFocusAddRules] = useState(0);
  const { hasPermission } = usePermissions();
  const canEditPolicies = hasPermission('policies.edit');
  const showGallery = isCreateMode && canEditPolicies;
  const {
    usedTemplate,
    templatePicked,
    setTemplatePicked,
    insertedTemplate,
    dismissInsertedTemplate,
    justAdded,
    addedRules,
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
  const gallery = useTemplateGallery({
    enabled: showGallery,
    entries: POLICY_TEMPLATE_LIBRARY.entries,
    policy: form.policy,
    policyType: form.policy_type,
    templatePicked,
    usedTemplate,
    addedRules,
    onUseTemplate: (template, rego, fieldText) => {
      applyTemplate(template, rego, fieldText);
      setView('rules');
    },
    onStartCustom: () => {
      pickBlank();
      setView('rules');
    },
  });
  // A new policy shows only Start from until a template is used.
  const { choosing } = gallery;
  const otherTypeGroups = useMemo(
    () =>
      isCreateMode
        ? groupsForOtherType(
            parsePolicyRules(form.policy),
            form.policy_type,
            POLICY_TEMPLATE_LIBRARY.templates
          )
        : [],
    [isCreateMode, form.policy, form.policy_type]
  );
  const writtenForOtherType = otherTypeGroups.find((t): t is PolicyType => t !== null) ?? null;
  const simulateRef = useRef<HTMLDivElement>(null);
  const [focusTest, setFocusTest] = useState(0);
  const loadInTest = (name: string, input: Record<string, unknown>) => {
    const previous = form.sample_input;
    setForm(f => ({ ...f, sample_input: JSON.stringify(input, null, 2) }));
    setFocusTest(n => n + 1);
    showUndoToast({
      message: `Loaded ${name} into Test (dry-run). Undo restores the sample input from before.`,
      onUndo: () => setForm(f => ({ ...f, sample_input: previous })),
    });
  };

  useEffect(() => {
    if (focusTest === 0) return;
    simulateRef.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
    simulateRef.current?.querySelector<HTMLTextAreaElement>('textarea')?.focus();
  }, [focusTest]);

  const addTemplateRules: typeof insertTemplate = (...args) => {
    insertTemplate(...args);
    setView('rules');
  };

  useEffect(() => {
    if (focusAddRules === 0) return;
    templatesColumnRef.current?.scrollIntoView?.({ block: 'nearest', behavior: 'smooth' });
    templatesColumnRef.current
      ?.querySelector<HTMLInputElement>('input.search-input-field')
      ?.focus();
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
          setLoadError(e.message || 'Failed to load the policy');
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
        `Package is "${actual}" but should be "${expected}" for ${POLICY_TYPE_NAMES[form.policy_type].name} policies.`
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
    if (writtenForOtherType) {
      setError(
        `Remove the rules written for ${POLICY_TYPE_NAMES[writtenForOtherType].name} policies to create this policy.`
      );
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
        // Stay in the editor and surface the newly appended version, with its content hash.
        // Only the stored fields are merged, so an edit or Undo made during the save stays dirty.
        const stored: Partial<PolicyDefinition> | null = await apiClient
          .fetch(`/api/v1/policy-definitions/${encodeURIComponent(payload.id)}`)
          .then(r => (r.ok ? r.json() : null))
          .catch(() => null);
        const storedFields = {
          content_hash: stored?.content_hash,
          updated_at: stored?.updated_at ?? payload.updated_at,
        };
        baselineRef.current = JSON.stringify({ ...payload, ...storedFields });
        setForm(f => ({ ...f, ...storedFields }));
        setVersionRefreshKey(k => k + 1);
        showToast('success', 'Policy updated!');
      }
    } catch (e: any) {
      setError(e.message || 'Failed to save policy');
    } finally {
      setSaving(false);
    }
  }, [form, isCreateMode, navigate, packageMismatch, writtenForOtherType]);

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
      restoreOnlyOnUndo: true,
      save: () => JSON.stringify(form),
      restore: saved => {
        try {
          const parsed = JSON.parse(saved) as PolicyDefinition;
          setForm(parsed);
          setTemplatePicked(true);
          gallery.close();
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
    if (!canEditPolicies) return;
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        if (!saving && !choosing) handleSave();
      }
    };
    document.addEventListener('keydown', handler);
    return () => document.removeEventListener('keydown', handler);
  }, [saving, handleSave, canEditPolicies, choosing]);

  const templatesPanel = (
    <PolicyTemplatesPanel
      policyType={form.policy_type}
      library={POLICY_TEMPLATE_LIBRARY}
      existingPolicy={form.policy}
      isCreateMode={isCreateMode}
      onInsert={addTemplateRules}
    />
  );

  // The templates column is always there for an editor, so opening a panel never resizes the form.
  const sidePanel = !canEditPolicies ? null : showGallery && gallery.open ? (
    <TemplateGalleryDetail
      selectedKey={gallery.selectedKey}
      selected={gallery.selected}
      policyType={form.policy_type}
      policy={form.policy}
      start={gallery.start}
      templatePicked={templatePicked}
      usedTemplate={usedTemplate}
      focusKey={gallery.focusKey}
      onPickBlank={gallery.startCustom}
      onUseTemplate={gallery.pickTemplate}
    />
  ) : (
    templatesPanel
  );

  // Add rules brings back the Add rules panel, then moves to its search once it has rendered.
  const focusTemplatesColumn = () => {
    if (gallery.open) gallery.close();
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

  if (loadError) {
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
        <div className="alert alert-danger" data-testid="policy-definition-load-error">
          <i className="fas fa-exclamation-triangle me-2"></i>
          <span className="policy-error-text">{loadError}</span>
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
                {!isCreateMode
                  ? `Edit Policy: ${form.name}`
                  : typeChosen
                    ? `Create ${POLICY_TYPE_NAMES[form.policy_type].name} Policy`
                    : 'Create Policy'}
              </h6>
              <div className="d-flex align-items-center gap-2">
                {canEditPolicies && !choosing && (
                  <button
                    className={`btn btn-sm btn-primary me-2 ${saving || !policyValid || !!packageMismatch || !!writtenForOtherType ? 'disabled' : ''}`}
                    data-testid="policy-definition-editor-save-button"
                    onClick={handleSave}
                    disabled={saving || !policyValid || !!packageMismatch || !!writtenForOtherType}
                  >
                    <i className={`fas ${saving ? 'fa-spinner fa-spin' : 'fa-save'}`}></i>
                    {saving ? ' Saving...' : isCreateMode ? ' Create' : ' Save'}
                  </button>
                )}
              </div>
            </div>

            <div className="card-body-channel-editor p-3">
              {error && (
                <div className="alert alert-danger alert-dismissible fade show">
                  <i className="fas fa-exclamation-triangle me-2"></i>
                  <span className="policy-error-text">{error}</span>
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
              {!canEditPolicies && (
                <p className="text-muted small mb-3" data-testid="policy-definition-read-only-note">
                  <i className="fas fa-lock me-1" aria-hidden="true" />
                  You can view this policy but not change it.
                </p>
              )}

              {showGallery && (
                <TemplateGallery
                  cards={gallery.cards}
                  surfaceOnly={gallery.surfaceOnly}
                  start={gallery.start}
                  usedTemplate={usedTemplate}
                  expanded={gallery.open}
                  onExpand={gallery.reopen}
                  onCollapse={templatePicked ? gallery.close : undefined}
                  selectedKey={gallery.selectedKey}
                  onSelect={gallery.select}
                  onCreateCustom={gallery.createCustom}
                />
              )}

              {!choosing && (
                <>
                  <PolicyDetailsSection
                    isCreateMode={isCreateMode}
                    showType={!typeChosen}
                    readOnly={!canEditPolicies}
                    name={form.name}
                    description={form.description}
                    policyType={form.policy_type}
                    enabled={form.enabled}
                    policyId={form.id || undefined}
                    contentHash={form.content_hash}
                    onNameChange={name => setForm(f => ({ ...f, name }))}
                    onDescriptionChange={description => setForm(f => ({ ...f, description }))}
                    onEnabledChange={enabled => setForm(f => ({ ...f, enabled }))}
                  />

                  <PolicyEditorSection
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
                    otherTypeGroups={otherTypeGroups}
                    startedFrom={gallery.startedFrom}
                    onAdd={focusTemplatesColumn}
                    onRemoveGroup={removeGroup}
                    onRemoveRule={removeRule}
                    onSetDefaultDeny={denyByDefault}
                    onShowRule={showRule}
                  />
                </>
              )}
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
              onLoadInTest={loadInTest}
            />
          )}
          {!isCreateMode && form.id && canEditPolicies && (
            <div ref={simulateRef}>
              <PolicySimulatePanel
                policyId={form.id}
                policyType={form.policy_type}
                draftPolicy={form.policy}
                sampleInput={form.sample_input ?? POLICY_SIMULATE_DEFAULT_INPUT}
                onSampleInputChange={value => setForm(f => ({ ...f, sample_input: value }))}
                policyValid={policyValid && !packageMismatch}
              />
            </div>
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
