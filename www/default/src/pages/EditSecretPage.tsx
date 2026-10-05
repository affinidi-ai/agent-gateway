import React, { useState, useEffect, useRef } from 'react';
import { useParams } from 'react-router-dom';
import { apiClient } from '../api';
import { showToast } from '../utils/toaster';
import { getErrorMessage } from '../utils/apiError';
import { toSecretId } from '../utils/stringUtils';
import { formatDateTime } from '../utils/stringUtils';
import { DeleteButton } from '../components/shared/DeleteButton';
import FieldHelp from '../components/shared/FieldHelp';
import { Link } from '../components/shared/Link';
import { DOCS_URL } from '../config/docs';
import { useSafeNavigate } from '../hooks/useSafeNavigate';
import { KNOWN_SECRET_TAGS } from '../utils/secretTags';

interface Secret {
  id: string;
  name: string;
  secret_id: string;
  description?: string;
  value: string;
  secret_type: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

interface SecretListItem {
  id: string;
  name: string;
  secret_id: string;
  description?: string;
  secret_type: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

interface LLMProvider {
  name: string;
  enum_value: string;
  [key: string]: any;
}

interface GatewayConfig {
  pipes?: {
    paths?: Array<{ id: string; name: string; prefix: string }>;
    llm?: {
      paths?: Array<{ id: string; name: string; prefix: string }>;
      providers?: LLMProvider[];
    };
    mcp_proxies?: {
      paths?: Array<{ id: string; name: string; prefix: string }>;
    };
  };
  secrets?: {
    secret_types?: string[];
  };
}

const EditSecretPage: React.FC = () => {
  const { navigate } = useSafeNavigate();
  const { id } = useParams<{ id: string }>();
  const isEditMode = !!id;

  const [availableSecretTypes, setAvailableSecretTypes] = useState<string[]>([
    'General',
    'ApiKey',
    'DatabasePassword',
    'Certificate',
    'SshKey',
    'Token',
  ]);
  const [configLoading, setConfigLoading] = useState(true);
  const [loading, setLoading] = useState(isEditMode);
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState('');
  const [isModified, setIsModified] = useState(false);
  const [secretData, setSecretData] = useState<Secret | null>(null);
  const [isSecretIdManuallyEdited, setIsSecretIdManuallyEdited] = useState(false);
  const [secretIdError, setSecretIdError] = useState('');
  const secretIdCheckTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const [formData, setFormData] = useState({
    name: '',
    secret_id: '',
    description: '',
    value: '',
    secret_type: 'General',
    tags: [] as string[],
  });

  const [tagInput, setTagInput] = useState('');
  const [existingTags, setExistingTags] = useState<string[]>([]);
  const [updateValue, setUpdateValue] = useState(false);
  const [revealValue, setRevealValue] = useState(false);

  // Fetch gateway configuration to get available secret types
  useEffect(() => {
    const fetchGatewayConfig = async () => {
      try {
        const response = await apiClient.get('/gateway/config');
        const config: GatewayConfig = response.data;

        if (config.secrets?.secret_types && config.secrets.secret_types.length > 0) {
          setAvailableSecretTypes(config.secrets.secret_types);
        }
      } catch (err) {
        console.error('Failed to fetch gateway config:', err);
        // Keep default types if config fetch fails
      } finally {
        setConfigLoading(false);
      }
    };

    fetchGatewayConfig();
  }, []);

  // Load tags already used across secrets, to offer as click-to-add suggestions
  // alongside the known filter tags.
  useEffect(() => {
    (async () => {
      try {
        const response = await apiClient.get('/secrets/');
        const list: SecretListItem[] = response.data || [];
        const set = new Set<string>();
        list.forEach(s => (s.tags || []).forEach(t => set.add(t)));
        setExistingTags(Array.from(set).sort((a, b) => a.localeCompare(b)));
      } catch {
        // Non-fatal — suggestions just fall back to the known filter tags.
      }
    })();
  }, []);

  // Fetch secret details if in edit mode
  useEffect(() => {
    if (isEditMode && id) {
      fetchSecret(id);
    }
  }, [id, isEditMode]);

  // Auto-generate secret_id from name (only in create mode and if not manually edited)
  useEffect(() => {
    if (!isEditMode && !isSecretIdManuallyEdited && formData.name) {
      const generatedId = toSecretId(formData.name);
      setFormData(prev => ({
        ...prev,
        secret_id: generatedId,
      }));
    }
  }, [formData.name, isEditMode, isSecretIdManuallyEdited]);

  // Check for duplicate secret_id (only in create mode) - debounced
  useEffect(() => {
    if (!isEditMode && formData.secret_id) {
      // Clear existing timeout
      if (secretIdCheckTimeoutRef.current) {
        clearTimeout(secretIdCheckTimeoutRef.current);
      }

      // Set new timeout for debounced check
      secretIdCheckTimeoutRef.current = setTimeout(async () => {
        try {
          const response = await apiClient.get('/secrets/');
          const existingSecrets: SecretListItem[] = response.data;
          const isDuplicate = existingSecrets.some(s => s.secret_id === formData.secret_id);

          if (isDuplicate) {
            setSecretIdError(`Secret ID '${formData.secret_id}' is already in use`);
          } else {
            setSecretIdError('');
          }
        } catch (err) {
          console.error('[Secret ID Check] Failed to check secret_id:', err);
        }
      }, 500); // 500ms debounce
    } else if (isEditMode) {
      setSecretIdError('');
    }

    // Cleanup timeout on unmount
    return () => {
      if (secretIdCheckTimeoutRef.current) {
        clearTimeout(secretIdCheckTimeoutRef.current);
      }
    };
  }, [formData.secret_id, isEditMode]);

  // Keyboard shortcut for saving (Cmd+S / Ctrl+S)
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 's') {
        e.preventDefault();
        // Only trigger save if not already saving, form is modified (or it's create mode), and no secret_id error
        if (!isSaving && (!isEditMode || isModified) && !secretIdError) {
          const form = document.querySelector('form');
          if (form) {
            form.dispatchEvent(new Event('submit', { cancelable: true, bubbles: true }));
          }
        }
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isSaving, isModified, isEditMode, secretIdError]);

  const fetchSecret = async (secretId: string) => {
    try {
      setLoading(true);
      const response = await apiClient.get(`/secrets/${secretId}`);
      const secret: Secret = response.data;

      setSecretData(secret);
      setFormData({
        name: secret.name,
        secret_id: secret.secret_id,
        description: secret.description || '',
        value: secret.value || '',
        secret_type: secret.secret_type || 'General',
        tags: secret.tags || [],
      });

      setError('');
    } catch (err: any) {
      console.error('Failed to fetch secret:', err);
      const errorMessage = getErrorMessage(err, 'Failed to load secret');
      showToast('error', errorMessage);
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (!formData.name.trim()) {
      setError('Secret name is required');
      return;
    }

    // Value is required only in create mode OR in edit mode with updateValue checkbox checked
    if (!isEditMode && !formData.value.trim()) {
      setError('Secret value is required');
      return;
    }

    if (isEditMode && updateValue && !formData.value.trim()) {
      setError('Secret value is required when updating and "Update Secret Value" is checked');
      return;
    }

    if (!isEditMode && secretIdError) {
      setError(secretIdError);
      return;
    }

    try {
      setIsSaving(true);
      setError('');

      const payload: any = {
        name: formData.name,
        description: formData.description || undefined,
        secret_type: formData.secret_type,
        tags: formData.tags,
      };

      // Only include secret_id when creating (not when updating)
      if (!isEditMode) {
        payload.secret_id = formData.secret_id;
        payload.value = formData.value;
      } else {
        // In edit mode, include update_value flag and value only if checkbox is checked
        payload.update_value = updateValue;
        if (updateValue) {
          payload.value = formData.value;
        }
      }

      if (isEditMode && id) {
        await apiClient.put(`/secrets/${id}`, payload);
        showToast('success', 'Secret updated successfully');
        setIsModified(false);
      } else {
        await apiClient.post('/secrets/new', payload);
        showToast('success', 'Secret created successfully');
        navigate('/secrets');
      }
    } catch (err: any) {
      console.error('Failed to save secret:', err);
      const errorMessage = getErrorMessage(err, 'Failed to save secret');
      showToast('error', errorMessage);
      setError(errorMessage);
    } finally {
      setIsSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!id) return;

    try {
      await apiClient.delete(`/secrets/${id}`);
      showToast('success', 'Secret deleted successfully');
      navigate('/secrets');
    } catch (err: any) {
      console.error('Failed to delete secret:', err);
      const errorMessage = getErrorMessage(err, 'Failed to delete secret');
      showToast('error', errorMessage);
    }
  };

  const handleInputChange = (field: string, value: any) => {
    setFormData(prev => ({ ...prev, [field]: value }));
    setIsModified(true);
    // Track when user manually edits secret_id
    if (field === 'secret_id') {
      setIsSecretIdManuallyEdited(true);
    }
  };

  const addTag = (tag: string) => {
    const t = tag.trim();
    if (t && !formData.tags.includes(t)) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, t],
      }));
      setIsModified(true);
    }
  };

  // Cryptographically-random 32-char value (letters, digits, symbols), suitable
  // as a client secret. In edit mode it also enables the value update so the
  // generated value is persisted on save. Does not reveal the field.
  const generateSecretValue = () => {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+';
    const bytes = new Uint32Array(32);
    crypto.getRandomValues(bytes);
    const value = Array.from(bytes, n => charset[n % charset.length]).join('');
    setFormData(prev => ({ ...prev, value }));
    setIsModified(true);
    if (isEditMode) setUpdateValue(true);
  };

  const handleAddTag = () => {
    const tag = tagInput.trim();
    if (tag && !formData.tags.includes(tag)) {
      setFormData(prev => ({
        ...prev,
        tags: [...prev.tags, tag],
      }));
      setTagInput('');
      setIsModified(true);
    }
  };

  const handleRemoveTag = (tagToRemove: string) => {
    setFormData(prev => ({
      ...prev,
      tags: prev.tags.filter(t => t !== tagToRemove),
    }));
    setIsModified(true);
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleAddTag();
    }
  };

  const appliedTagSet = new Set(formData.tags);
  const knownTagValues = new Set(KNOWN_SECRET_TAGS.map(k => k.tag));
  const suggestedKnownTags = KNOWN_SECRET_TAGS.filter(k => !appliedTagSet.has(k.tag));
  const suggestedOtherTags = existingTags.filter(
    t => !knownTagValues.has(t) && !appliedTagSet.has(t)
  );

  if (configLoading || (isEditMode && loading)) {
    return (
      <div className="container-fluid">
        <div
          className="d-flex justify-content-center align-items-center"
          style={{ minHeight: '400px' }}
        >
          <div className="spinner-border text-primary" role="status"></div>
        </div>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <div className="mb-3">
        <button
          className="btn btn-sm btn-secondary"
          onClick={() => navigate('/secrets')}
          disabled={isSaving}
        >
          <i className="fas fa-arrow-left"></i>
        </button>
      </div>
      <div className="d-sm-flex align-items-center justify-content-between mb-4">
        <div>
          <h1 className="h3 mb-0 text-gray-800">
            <i className="fas fa-key me-2"></i>
            {isEditMode ? 'Edit Secret' : 'Create Secret'}
          </h1>
          <p className="text-muted mt-2">
            {isEditMode ? 'Update secret details and value' : 'Create a new encrypted secret'}
          </p>
        </div>
        <div>
          <button
            className="btn btn-sm btn-primary me-2"
            onClick={handleSubmit}
            disabled={isSaving || (isEditMode && !isModified) || (!isEditMode && !!secretIdError)}
          >
            {isSaving ? (
              <>
                <span
                  className="spinner-border spinner-border-sm me-1"
                  role="status"
                  aria-hidden="true"
                ></span>
                Saving...
              </>
            ) : (
              <>
                <i className="fas fa-save me-1"></i>
                Save
              </>
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className="alert alert-danger" role="alert">
          <i className="fas fa-exclamation-triangle me-2"></i>
          {error}
        </div>
      )}

      <div className="row">
        <div className="col-lg-8">
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                {isEditMode ? 'Secret Details' : 'New Secret'}
              </h6>
            </div>
            <div className="card-body">
              <form onSubmit={handleSubmit}>
                <div className="mb-3">
                  <label htmlFor="name">
                    Secret Name <span className="text-danger">*</span>
                  </label>
                  <input
                    type="text"
                    className="form-control"
                    id="name"
                    value={formData.name}
                    onChange={e => handleInputChange('name', e.target.value)}
                    placeholder="e.g., OpenAI API Key"
                    required
                  />
                </div>

                <div className="mb-3">
                  <label htmlFor="secret_id">
                    Secret ID <span className="text-danger">*</span>
                  </label>
                  <input
                    type="text"
                    className={`form-control font-monospace ${isEditMode ? 'bg-light' : ''} ${secretIdError ? 'is-invalid' : ''}`}
                    id="secret_id"
                    value={formData.secret_id}
                    onChange={e => handleInputChange('secret_id', e.target.value)}
                    placeholder="e.g., openai_api_key"
                    disabled={isEditMode}
                    readOnly={isEditMode}
                    required
                    style={{
                      fontFamily: 'monospace',
                      cursor: isEditMode ? 'not-allowed' : 'text',
                    }}
                  />
                  {secretIdError ? (
                    <small className="form-text text-danger">
                      <i className="fas fa-exclamation-triangle me-1"></i>
                      {secretIdError}
                    </small>
                  ) : (
                    <small className="form-text text-muted">
                      {isEditMode ? (
                        <>
                          <i className="fas fa-lock me-1"></i>
                          Reference: <code>$SECRET:{formData.secret_id}</code> (cannot be changed)
                        </>
                      ) : (
                        <>
                          <i className="fas fa-info-circle me-1"></i>
                          Auto-generated from name. Reference as:{' '}
                          <code>$SECRET:{formData.secret_id || 'secret_id'}</code>
                        </>
                      )}
                    </small>
                  )}
                </div>

                <div className="mb-3">
                  <label htmlFor="description">Description</label>
                  <input
                    className="form-control"
                    id="description"
                    value={formData.description}
                    onChange={e => handleInputChange('description', e.target.value)}
                    placeholder="What is this secret used for?"
                  />
                  <small className="form-text text-muted">
                    Shown in the Secrets list to help you (and teammates) recognize this secret
                    later, not used anywhere else.
                  </small>
                </div>

                <div className="mb-3">
                  <label htmlFor="secret_type">
                    Secret Type <span className="text-danger">*</span>
                  </label>
                  <select
                    className="form-control dropdown-styling"
                    id="secret_type"
                    value={formData.secret_type}
                    onChange={e => handleInputChange('secret_type', e.target.value)}
                    required
                  >
                    {availableSecretTypes.map(type => (
                      <option key={type} value={type}>
                        {type}
                      </option>
                    ))}
                  </select>
                  <small className="form-text text-muted">
                    Categorize this secret for easier filtering and management
                  </small>
                </div>

                {isEditMode && (
                  <div className="mb-3">
                    <div className="custom-control custom-checkbox">
                      <input
                        type="checkbox"
                        className="custom-control-input"
                        id="updateValueCheckbox"
                        checked={updateValue}
                        onChange={e => {
                          setUpdateValue(e.target.checked);
                          if (e.target.checked) {
                            setIsModified(true);
                          }
                        }}
                      />
                      <label className="custom-control-label" htmlFor="updateValueCheckbox">
                        <strong>Update Secret Value</strong>
                      </label>
                    </div>
                    <small className="form-text text-muted ms-4">
                      <i className="fas fa-info-circle me-1"></i>
                      Check this box to modify the secret value. Leave unchecked to preserve the
                      existing value.
                    </small>
                    <small className="form-text text-muted ms-4">
                      {isEditMode && !updateValue ? (
                        <>
                          <i className="fas fa-lock me-1"></i>
                          Value is currently unchanged. Check "Update Secret Value" above to modify
                          it.
                        </>
                      ) : null}
                    </small>
                  </div>
                )}

                <div className="mb-3">
                  <div className="field-label-with-help">
                    <label htmlFor="value" className="mb-0">
                      Secret Value <span className="text-danger">*</span>
                    </label>
                    <FieldHelp ariaLabel="About Secret Value" testId="field-help-secret-value">
                      Once saved, it's referenced by ID (<code>$SECRET:...</code>) elsewhere in the
                      product rather than by its raw value.
                    </FieldHelp>
                  </div>
                  <div className="input-group mb-2">
                    {revealValue ? (
                      <textarea
                        className="form-control font-monospace"
                        id="value"
                        rows={4}
                        value={formData.value}
                        onChange={e => handleInputChange('value', e.target.value)}
                        placeholder={`${isEditMode ? 'Modify' : 'Enter'} the secret value (API key, password, token, etc.)`}
                        required={!isEditMode || updateValue}
                        disabled={isEditMode && !updateValue}
                        style={{ fontFamily: 'monospace' }}
                      />
                    ) : (
                      <input
                        type="password"
                        className="form-control font-monospace"
                        id="value"
                        value={formData.value}
                        onChange={e => handleInputChange('value', e.target.value)}
                        placeholder={`${isEditMode ? 'Modify' : 'Enter'} the secret value (API key, password, token, etc.)`}
                        required={!isEditMode || updateValue}
                        disabled={isEditMode && !updateValue}
                        style={{ fontFamily: 'monospace' }}
                      />
                    )}
                    <button
                      type="button"
                      className="btn btn-outline-secondary"
                      onClick={generateSecretValue}
                      disabled={isSaving}
                      title="Generate a random 32-character secret value (letters, digits, symbols)"
                    >
                      <i className="fas fa-dice me-1"></i>Generate
                    </button>
                  </div>
                  <small className="form-text text-muted d-block mb-2">
                    <i className="fas fa-shield-alt me-1"></i>
                    Stored encrypted at rest. Anyone who can open this page and check &quot;Show
                    secret value&quot; can still view it in plain text. Treat this page itself as
                    sensitive.
                  </small>
                  <div className="custom-control custom-checkbox mb-2">
                    <input
                      type="checkbox"
                      className="custom-control-input"
                      id="revealValueCheckbox"
                      checked={revealValue}
                      onChange={e => setRevealValue(e.target.checked)}
                    />
                    <label className="custom-control-label" htmlFor="revealValueCheckbox">
                      {revealValue ? (
                        <>
                          <i className="fas fa-eye me-1"></i>
                          Reveal secret value
                        </>
                      ) : (
                        <>
                          <i className="fas fa-eye-slash me-1"></i>
                          Show secret value
                        </>
                      )}
                    </label>
                  </div>
                </div>

                <div className="mb-3">
                  <label htmlFor="tags">Tags</label>
                  <div className="input-group mb-2">
                    <input
                      type="text"
                      className="form-control"
                      id="tags"
                      value={tagInput}
                      onChange={e => setTagInput(e.target.value)}
                      onKeyDown={handleKeyDown}
                      placeholder="Add a tag and press Enter"
                    />
                    <div className="input-group-append">
                      <button
                        type="button"
                        className="btn btn-outline-secondary"
                        onClick={handleAddTag}
                      >
                        <i className="fas fa-plus"></i> Add
                      </button>
                    </div>
                  </div>
                  {(suggestedKnownTags.length > 0 || suggestedOtherTags.length > 0) && (
                    <div className="mb-2">
                      <small className="text-muted d-block mb-1">
                        <i className="fas fa-tags me-1"></i>Known tags, click to add. Tagging a
                        secret this way makes it appear in the matching secret picker.
                      </small>
                      {suggestedKnownTags.map(k => (
                        <button
                          key={k.tag}
                          type="button"
                          className="badge bg-transparent border text-muted font-monospace me-2 mb-2"
                          style={{
                            cursor: 'pointer',
                            fontSize: '0.9em',
                            textTransform: 'uppercase',
                          }}
                          title={k.description}
                          onClick={() => addTag(k.tag)}
                        >
                          <i className="fas fa-plus fa-xs me-1"></i>
                          {k.tag}
                        </button>
                      ))}
                      {suggestedOtherTags.map(tag => (
                        <button
                          key={tag}
                          type="button"
                          className="badge bg-transparent border text-muted font-monospace me-2 mb-2"
                          style={{
                            cursor: 'pointer',
                            fontSize: '0.9em',
                            textTransform: 'uppercase',
                          }}
                          title="Already used on other secrets"
                          onClick={() => addTag(tag)}
                        >
                          <i className="fas fa-plus fa-xs me-1"></i>
                          {tag}
                        </button>
                      ))}
                    </div>
                  )}
                  {formData.tags.length > 0 && (
                    <div className="mt-2">
                      {formData.tags.map(tag => (
                        <span
                          key={tag}
                          className="badge text-bg-primary font-monospace me-2 mb-2"
                          style={{ fontSize: '0.9em', textTransform: 'uppercase' }}
                        >
                          {tag}
                          <button
                            type="button"
                            className="btn btn-link btn-sm text-white ms-1 p-0"
                            onClick={() => handleRemoveTag(tag)}
                            style={{ textDecoration: 'none' }}
                          >
                            <i className="fas fa-times"></i>
                          </button>
                        </span>
                      ))}
                    </div>
                  )}
                </div>

                <hr />

                <div className="d-flex justify-content-between align-items-center">
                  {isEditMode && (
                    <DeleteButton
                      onDelete={handleDelete}
                      title="Delete this secret"
                      disabled={isSaving}
                      variant="danger"
                    >
                      Delete Secret
                    </DeleteButton>
                  )}
                  <div className={!isEditMode ? 'ms-auto' : ''}>
                    <button
                      type="submit"
                      className="btn btn-sm btn-primary"
                      disabled={
                        isSaving || (isEditMode && !isModified) || (!isEditMode && !!secretIdError)
                      }
                    >
                      {isSaving ? (
                        <>
                          <span
                            className="spinner-border spinner-border-sm me-2"
                            role="status"
                            aria-hidden="true"
                          ></span>
                          Saving...
                        </>
                      ) : (
                        <>
                          <i className="fas fa-save me-1"></i>
                          {isEditMode ? 'Save Changes' : 'Create Secret'}
                        </>
                      )}
                    </button>
                  </div>
                </div>
              </form>
            </div>
          </div>
        </div>

        <div className="col-lg-4">
          {isEditMode && (
            <div className="card shadow mb-4">
              <div className="card-header py-3">
                <h6 className="m-0 font-weight-bold text-primary">
                  <i className="fas fa-clock me-2"></i>
                  Metadata
                </h6>
              </div>
              <div className="card-body">
                <div className="mb-2">
                  <strong className="text-muted">Created</strong>
                  <div style={{ fontSize: '0.9em' }}>
                    {secretData?.created_at ? formatDateTime(secretData.created_at, true) : 'N/A'}
                  </div>
                </div>
                <div>
                  <strong className="text-muted">Last Updated</strong>
                  <div style={{ fontSize: '0.9em' }}>
                    {secretData?.updated_at ? formatDateTime(secretData.updated_at, true) : 'N/A'}
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="card shadow mb-4 border-danger">
            <div className="card-body">
              <h6 className="font-weight-bold text-danger">
                <i className="fas fa-exclamation-triangle me-2"></i>
                Important
              </h6>
              <p className="mb-0" style={{ fontSize: '0.85em' }}>
                Never share secret values through unsecured channels. Always use the secrets manager
                to store and reference sensitive information.
              </p>
            </div>
          </div>

          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">
                <i className="fas fa-info-circle me-2"></i>
                Secret Information
              </h6>
            </div>
            <div className="card-body">
              <h6 className="font-weight-bold">What are Secrets?</h6>
              <p style={{ fontSize: '0.9em' }}>
                Secrets are encrypted values used to store sensitive information like API keys,
                passwords, tokens, and certificates.
              </p>

              <h6 className="font-weight-bold mt-3">Using Secrets</h6>
              <p style={{ fontSize: '0.9em' }}>
                Where supported, you can reference secrets using the syntax:
              </p>
              <code className="d-block p-2 bg-light rounded mb-3">$SECRET:secret_id</code>

              <h6 className="font-weight-bold mt-3">Tags</h6>
              <p style={{ fontSize: '0.9em' }}>
                Use tags to organize and filter secrets by environment, service, or project.
              </p>

              <Link href={DOCS_URL.secrets} external>
                Learn more about Secrets
              </Link>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default EditSecretPage;
