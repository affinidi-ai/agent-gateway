import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useParams, useSearchParams } from 'react-router-dom';
import { apiClient } from '../../api';
import { showToast, showUndoToast } from '../../utils/toaster';
import { useSafeNavigate } from '../../hooks/useSafeNavigate';
import { usePageTitle } from '../../context/PageTitleContext';
import { usePermissions } from '../../context/PermissionsContext';
import { useDiscardWithUndo } from '../../components/surface-builder/hooks/useDiscardWithUndo';
import { AppButton } from '../../components/shared/AppButton';
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
import TemplateGalleryDetail, { replaceText } from './policyTemplates/TemplateGalleryDetail';
import { BUILTIN_POLICY_TEMPLATES } from './policyTemplates/builtinPolicyTemplates';
import { parsePolicyRules } from './policyTemplates/regoRules';
import { BLANK_TEMPLATE_ID } from './policyTemplates/policyDefaults';
import { POLICY_TYPE_NAMES, type PolicyTemplate, type PolicyType } from './policyTemplates/types';
import { usePolicyTemplateActions } from './policyTemplates/usePolicyTemplateActions';
import {
  galleryTemplates,
  templateEntryKey,
  useAllPolicyTemplates,
} from './policyTemplates/usePolicyTemplates';
import { groupsForOtherType, policyStart } from './policyTemplates/policyStart';

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
  const [view, setView] = useState<PolicyView>(DEFAULT_POLICY_VIEW);
  const templatesColumnRef = useRef<HTMLDivElement>(null);
  const [focusAddRules, setFocusAddRules] = useState(0);
  const { hasPermission } = usePermissions();
  const canEditPolicies = hasPermission('policies.edit');
  const numbered = isCreateMode && canEditPolicies;
  const {
    templatePanel,
    setTemplatePanel,
    togglePanel,
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
  const templateEntries = useAllPolicyTemplates();
  // A new policy shows only Start from until a template is used.
  const choosing = numbered && !templatePicked;
  const [galleryOpen, setGalleryOpen] = useState(true);
  const [galleryKey, setGalleryKey] = useState<string | null>(null);
  const [focusGalleryDetail, setFocusGalleryDetail] = useState(0);
  const selectGalleryCard = (key: string) => {
    setGalleryKey(key);
    setFocusGalleryDetail(n => n + 1);
  };
  const closeGallery = () => {
    setGalleryOpen(false);
    setGalleryKey(null);
  };
  // Change reopens the gallery on the used template's card.
  const openGallery = () => {
    const used = templateEntries
      .flatMap(e => Object.values(e.variants))
      .find(t => t?.id === usedTemplate?.id);
    setGalleryKey(
      usedTemplate?.id === BLANK_TEMPLATE_ID
        ? BLANK_TEMPLATE_ID
        : used
          ? templateEntryKey(used)
          : null
    );
    setGalleryOpen(true);
  };
  // Undoing the first Use shows the gallery again.
  useEffect(() => {
    if (choosing) setGalleryOpen(true);
  }, [choosing]);
  const start = numbered
    ? policyStart(
        form.policy,
        form.policy_type,
        usedTemplate,
        templateEntries
          .flatMap(e => Object.values(e.variants))
          .filter((t): t is PolicyTemplate => !!t),
        addedRules
      )
    : null;
  const startedFrom = usedTemplate && start ? start.name : null;
  const otherTypeGroups = useMemo(
    () =>
      isCreateMode
        ? groupsForOtherType(
            parsePolicyRules(form.policy),
            form.policy_type,
            BUILTIN_POLICY_TEMPLATES
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
          closeGallery();
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

  const startCustom = () => {
    pickBlank();
    setView('rules');
    closeGallery();
  };
  // Create custom policy starts at once unless it replaces rules, which its detail asks about.
  const createCustom = () => {
    if (templatePicked && replaceText(form.policy, start)) selectGalleryCard(BLANK_TEMPLATE_ID);
    else startCustom();
  };

  const templatesPanel = (
    <PolicyTemplatesPanel
      key={form.policy_type}
      policyType={form.policy_type}
      existingPolicy={form.policy}
      isCreateMode={isCreateMode}
      onInsert={addTemplateRules}
    />
  );

  // The templates column is always there for an editor, so opening a panel never resizes the form.
  const sidePanel = !canEditPolicies ? null : numbered && galleryOpen ? (
    <TemplateGalleryDetail
      selectedKey={galleryKey}
      selected={
        galleryTemplates(templateEntries, form.policy_type).find(
          t => templateEntryKey(t) === galleryKey
        ) ?? null
      }
      policyType={form.policy_type}
      policy={form.policy}
      start={start}
      templatePicked={templatePicked}
      usedTemplate={usedTemplate}
      focusKey={focusGalleryDetail}
      onPickBlank={startCustom}
      onUseTemplate={(template, rego, fieldText) => {
        applyTemplate(template, rego, fieldText);
        setView('rules');
        closeGallery();
      }}
    />
  ) : templatePanel === 'save' ? (
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
          `Template ${template.name} saved under Organization templates for this browser tab.`
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
                  <div className="position-relative">
                    <AppButton
                      variant="outline-primary"
                      className={templatePanel === 'save' ? 'active' : ''}
                      aria-pressed={templatePanel === 'save'}
                      disabled={isDirty}
                      aria-describedby={isDirty ? 'policy-templates-save-as-hint' : undefined}
                      onClick={() => togglePanel('save')}
                      iconStart={<i className="fas fa-copy" aria-hidden="true" />}
                      data-testid="policy-templates-save-as-button"
                    >
                      Save as template
                    </AppButton>
                    {isDirty && (
                      <small
                        className="text-muted position-absolute top-100 end-0 text-nowrap"
                        id="policy-templates-save-as-hint"
                        data-testid="policy-templates-save-as-hint"
                      >
                        Save your changes first.
                      </small>
                    )}
                  </div>
                )}
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

              {numbered && (
                <TemplateGallery
                  step={1}
                  policyType={form.policy_type}
                  start={start}
                  usedTemplate={usedTemplate}
                  expanded={galleryOpen}
                  onExpand={openGallery}
                  onCollapse={templatePicked ? closeGallery : undefined}
                  selectedKey={galleryKey}
                  onSelect={selectGalleryCard}
                  onCreateCustom={createCustom}
                />
              )}

              {!choosing && (
                <>
                  <PolicyDetailsSection
                    step={numbered ? 2 : undefined}
                    isCreateMode={isCreateMode}
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
                    step={numbered ? 3 : undefined}
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
                    startedFrom={startedFrom}
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
