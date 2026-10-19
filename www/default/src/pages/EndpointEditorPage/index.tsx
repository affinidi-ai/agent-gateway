import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import {
  createEndpoint,
  DefinitionStatus,
  Endpoint,
  EndpointType,
  getEndpoint,
  testEndpoint,
  updateEndpoint,
} from '../../integrationsApi';
import { useApplianceSecrets } from '../../hooks/useApplianceSecrets';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';
import EndpointConfigFields from './EndpointConfigFields';
import { buildConfiguration, EndpointForm, initialForm, missingRequired } from './endpointFields';

const ENDPOINT_TYPES: { value: EndpointType; label: string }[] = [
  { value: 'email', label: 'Email (SMTP)' },
  { value: 'slack', label: 'Slack' },
  { value: 'webhook', label: 'Webhook' },
  { value: 'stream', label: 'Stream (Kafka, Kinesis, Pulsar, Redis)' },
];

const ENDPOINTS_TAB = '/integrations?tab=endpoints';

const isEndpointType = (value: string | null): value is EndpointType =>
  ENDPOINT_TYPES.some(option => option.value === value);

/** Creates an endpoint, or changes a stored one; the type is fixed once created. */
const EndpointEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const requestedType = searchParams.get('type');
  const secretOptions = useApplianceSecrets();

  const [stored, setStored] = useState<Endpoint | null>(null);
  const [loading, setLoading] = useState(Boolean(id));
  const [loadError, setLoadError] = useState<string | null>(null);
  const [type, setType] = useState<EndpointType>(
    isEndpointType(requestedType) ? requestedType : 'email'
  );
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [status, setStatus] = useState<DefinitionStatus>('active');
  const [form, setForm] = useState<EndpointForm>(() => initialForm(type));
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) return;
    getEndpoint(id)
      .then(endpoint => {
        setStored(endpoint);
        setType(endpoint.type);
        setName(endpoint.name);
        setDescription(endpoint.description);
        setStatus(endpoint.status);
        setForm(initialForm(endpoint.type, endpoint));
      })
      .catch(failure => setLoadError(getErrorMessage(failure, 'Failed to load the endpoint')))
      .finally(() => setLoading(false));
  }, [id]);

  const changed = () => {
    setDirty(true);
    setError(null);
  };

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    const missing = [...(name.trim() ? [] : ['Name']), ...missingRequired(type, form)];
    if (missing.length) {
      setError(`Fill in: ${missing.join(', ')}`);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const saved = stored
        ? await updateEndpoint(stored.id, {
            name: name.trim(),
            description: description.trim(),
            configuration: buildConfiguration(type, form, true),
            status,
          })
        : await createEndpoint({
            name: name.trim(),
            description: description.trim(),
            type,
            configuration: buildConfiguration(type, form, false),
            status,
          });
      showToast('success', `Endpoint ${saved.name} saved`);
      navigate(ENDPOINTS_TAB);
    } catch (failure) {
      setError(getErrorMessage(failure, 'Failed to save the endpoint'));
    } finally {
      setSaving(false);
    }
  };

  const sendTest = async () => {
    if (!stored) return;
    setTesting(true);
    try {
      await testEndpoint(stored.id);
      showToast('success', `Test message sent to ${stored.name}`);
    } catch (failure) {
      showToast('error', `Test failed: ${getErrorMessage(failure)}`, { autoRemove: false });
    } finally {
      setTesting(false);
    }
  };

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <div className="spinner-border" role="status">
          <span className="visually-hidden">Loading the endpoint</span>
        </div>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="container-fluid">
        <div className="alert alert-danger" role="alert">
          {loadError}
        </div>
        <Link to={ENDPOINTS_TAB}>Back to endpoints</Link>
      </div>
    );
  }

  return (
    <div className="container-fluid" data-testid="page-endpoint-editor">
      <form onSubmit={save} noValidate>
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h1 className="h4 mb-0">{stored ? `Endpoint ${stored.name}` : 'New endpoint'}</h1>
          <div className="d-flex gap-2">
            {stored && (
              <AppButton
                variant="secondary"
                size="md"
                onClick={sendTest}
                loading={testing}
                disabled={dirty}
                title={
                  dirty ? 'Save your changes first: the test uses the saved endpoint' : undefined
                }
                iconStart={<i className="fas fa-paper-plane me-2" aria-hidden="true" />}
                data-testid="endpoint-test-button"
              >
                Send test
              </AppButton>
            )}
            <AppButton
              variant="outline-secondary"
              size="md"
              onClick={() => navigate(ENDPOINTS_TAB)}
              data-testid="endpoint-cancel-button"
            >
              Cancel
            </AppButton>
            <AppButton
              type="submit"
              variant="primary"
              size="md"
              loading={saving}
              data-testid="endpoint-save-button"
            >
              Save
            </AppButton>
          </div>
        </div>

        {error && (
          <div className="alert alert-danger" role="alert">
            {error}
          </div>
        )}

        <div className="card shadow mb-4">
          <div className="card-body">
            <div className="mb-3">
              <label htmlFor="endpoint-name" className="form-label">
                Name<span className="text-danger"> *</span>
              </label>
              <input
                id="endpoint-name"
                data-testid="endpoint-name-input"
                className="form-control"
                value={name}
                onChange={event => {
                  setName(event.target.value);
                  changed();
                }}
              />
            </div>
            <div className="mb-3">
              <label htmlFor="endpoint-description" className="form-label">
                Description
              </label>
              <input
                id="endpoint-description"
                data-testid="endpoint-description-input"
                className="form-control"
                value={description}
                onChange={event => {
                  setDescription(event.target.value);
                  changed();
                }}
              />
            </div>
            {stored ? (
              <div className="mb-3">
                <span className="form-label d-block">Type</span>
                <span className="badge text-bg-secondary">{type}</span>
                <div className="form-text">
                  An endpoint keeps its type, since its integrations’ templates are written for it.
                </div>
              </div>
            ) : (
              <div className="mb-3">
                <label htmlFor="endpoint-type" className="form-label">
                  Type<span className="text-danger"> *</span>
                </label>
                <select
                  id="endpoint-type"
                  data-testid="endpoint-type-select"
                  className="form-select"
                  value={type}
                  onChange={event => {
                    const next = event.target.value as EndpointType;
                    setType(next);
                    setForm(initialForm(next));
                    changed();
                  }}
                >
                  {ENDPOINT_TYPES.map(option => (
                    <option key={option.value} value={option.value}>
                      {option.label}
                    </option>
                  ))}
                </select>
              </div>
            )}
            <div className="form-check form-switch mb-3">
              <input
                id="endpoint-active"
                data-testid="endpoint-active-switch"
                className="form-check-input"
                type="checkbox"
                checked={status === 'active'}
                onChange={event => {
                  setStatus(event.target.checked ? 'active' : 'disabled');
                  changed();
                }}
              />
              <label htmlFor="endpoint-active" className="form-check-label">
                Active
              </label>
              <div className="form-text">A disabled endpoint receives nothing.</div>
            </div>
          </div>
        </div>

        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">Configuration</h6>
          </div>
          <div className="card-body">
            <EndpointConfigFields
              type={type}
              form={form}
              storedSecrets={stored?.secrets ?? []}
              secretOptions={secretOptions}
              onValue={(field, value) => {
                setForm(current => ({ ...current, values: { ...current.values, [field]: value } }));
                changed();
              }}
              onSecret={(field, edit) => {
                setForm(current => ({
                  ...current,
                  secrets: { ...current.secrets, [field]: edit },
                }));
                changed();
              }}
            />
          </div>
        </div>
      </form>
    </div>
  );
};

export default EndpointEditorPage;
