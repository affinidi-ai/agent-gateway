import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import AuditDeliveryLimitsSection from '../../components/integrations/AuditDeliveryLimitsSection';
import { AppButton } from '../../components/shared/AppButton';
import {
  createIntegration,
  DefinitionStatus,
  Endpoint,
  EventSet,
  getCatalog,
  getIntegration,
  Integration,
  IntegrationCatalog,
  IntegrationRequest,
  listEndpoints,
  listEventSets,
  testDraftIntegration,
  updateIntegration,
} from '../../integrationsApi';
import { ROUTES } from '../../routes';
import { getErrorMessage } from '../../utils/apiError';
import {
  AuditDeliveryLimits,
  auditDeliveryLimitsError,
  auditDeliveryLimitsOf,
  auditDeliveryLimitsPayload,
} from '../../utils/auditIntegrations';
import { showToast } from '../../utils/toaster';
import TemplateEditor from './TemplateEditor';
import { unfilledVariables, variablesForEvents } from './templateModel';

const holdsAuditEvents = (eventSet?: EventSet) =>
  Boolean(eventSet?.events.some(event => event.startsWith('audit.')));

/** Creates an integration, or changes a stored one: an endpoint, an event set and a template. */
const IntegrationEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const [catalog, setCatalog] = useState<IntegrationCatalog | null>(null);
  const [endpoints, setEndpoints] = useState<Endpoint[]>([]);
  const [eventSets, setEventSets] = useState<EventSet[]>([]);
  const [stored, setStored] = useState<Integration | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [endpointId, setEndpointId] = useState('');
  const [eventSetId, setEventSetId] = useState('');
  const [status, setStatus] = useState<DefinitionStatus>('active');
  const [content, setContent] = useState<Record<string, unknown>>({});
  const [templateValid, setTemplateValid] = useState(true);
  const [limits, setLimits] = useState<AuditDeliveryLimits>({ maxAttempts: '', dropAfterSecs: '' });
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const [loadedCatalog, loadedEndpoints, loadedEventSets, integration] = await Promise.all([
          getCatalog(),
          listEndpoints(),
          listEventSets(),
          id ? getIntegration(id) : Promise.resolve(null),
        ]);
        setCatalog(loadedCatalog);
        setEndpoints(loadedEndpoints);
        setEventSets(loadedEventSets);
        if (integration) {
          setStored(integration);
          setName(integration.name);
          setDescription(integration.description);
          setEndpointId(integration.endpoint_id);
          setEventSetId(integration.event_set_id);
          setStatus(integration.status);
          setContent(integration.content ?? {});
          setLimits(auditDeliveryLimitsOf(integration));
        }
      } catch (failure) {
        setLoadError(getErrorMessage(failure, 'Failed to load the integration'));
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id]);

  const endpoint = endpoints.find(candidate => candidate.id === endpointId);
  const eventSet = eventSets.find(candidate => candidate.id === eventSetId);
  const withAudit = holdsAuditEvents(eventSet);
  const variables = catalog && eventSet ? variablesForEvents(catalog, eventSet.events) : [];

  const chooseEndpoint = (next: string) => {
    const nextType = endpoints.find(candidate => candidate.id === next)?.type;
    if (nextType !== endpoint?.type) {
      // A template is written for one endpoint type; another type starts from its defaults.
      setContent({});
      setTemplateValid(true);
    }
    setEndpointId(next);
    setError(null);
  };

  const request = (): IntegrationRequest => ({
    name: name.trim(),
    description: description.trim(),
    endpoint_id: endpointId,
    event_set_id: eventSetId,
    content,
    status,
    ...(withAudit ? auditDeliveryLimitsPayload(limits, false) : {}),
  });

  /** Why the integration cannot be saved as it stands, or null. */
  const problem = (): string | null => {
    const missing = [
      ...(name.trim() ? [] : ['Name']),
      ...(endpointId ? [] : ['Endpoint']),
      ...(eventSetId ? [] : ['Event set']),
    ];
    if (missing.length) return `Fill in: ${missing.join(', ')}`;
    if (!templateValid) return 'The payload must be a JSON object.';
    const unfilled = unfilledVariables(content, variables);
    if (unfilled.length) {
      return `No event of the event set fills ${unfilled.join(', ')}; remove them from the template.`;
    }
    return withAudit ? auditDeliveryLimitsError(limits) : null;
  };

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    const reason = problem();
    if (reason) {
      setError(reason);
      return;
    }
    setSaving(true);
    setError(null);
    try {
      const saved = stored
        ? await updateIntegration(stored.id, request())
        : await createIntegration(request());
      showToast('success', `Integration ${saved.name} saved`);
      navigate(ROUTES.INTEGRATIONS);
    } catch (failure) {
      setError(getErrorMessage(failure, 'Failed to save the integration'));
    } finally {
      setSaving(false);
    }
  };

  // A test sends what Save would store, so it is blocked for the same reason Save would refuse.
  const blocker = problem();

  const sendTest = async () => {
    if (blocker) return;
    setTesting(true);
    try {
      const result = await testDraftIntegration(request());
      showToast('success', `Test message for ${result.event_type} sent to ${endpoint?.name}`);
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
          <span className="visually-hidden">Loading the integration</span>
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
        <Link to={ROUTES.INTEGRATIONS}>Back to integrations</Link>
      </div>
    );
  }

  return (
    <div className="container-fluid">
      <form onSubmit={save} noValidate>
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h1 className="h4 mb-0">{stored ? `Integration ${stored.name}` : 'New integration'}</h1>
          <div className="d-flex gap-2">
            <AppButton
              variant="secondary"
              size="md"
              onClick={sendTest}
              loading={testing}
              disabled={blocker !== null}
              title={
                blocker ??
                'Sends one message for the first event of the event set, with sample values'
              }
              iconStart={<i className="fas fa-paper-plane me-2" aria-hidden="true" />}
            >
              Send test
            </AppButton>
            <AppButton
              variant="outline-secondary"
              size="md"
              onClick={() => navigate(ROUTES.INTEGRATIONS)}
            >
              Cancel
            </AppButton>
            <AppButton type="submit" variant="primary" size="md" loading={saving}>
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
            <div className="row">
              <div className="col-md-6 mb-3">
                <label htmlFor="integration-name" className="form-label">
                  Name<span className="text-danger"> *</span>
                </label>
                <input
                  id="integration-name"
                  className="form-control"
                  value={name}
                  onChange={event => setName(event.target.value)}
                />
              </div>
              <div className="col-md-6 mb-3">
                <label htmlFor="integration-description" className="form-label">
                  Description
                </label>
                <input
                  id="integration-description"
                  className="form-control"
                  value={description}
                  onChange={event => setDescription(event.target.value)}
                />
              </div>
              <div className="col-md-6 mb-3">
                <label htmlFor="integration-endpoint" className="form-label">
                  Endpoint<span className="text-danger"> *</span>
                </label>
                <select
                  id="integration-endpoint"
                  className="form-select"
                  value={endpointId}
                  onChange={event => chooseEndpoint(event.target.value)}
                >
                  <option value="">Choose where to deliver</option>
                  {endpoints.map(candidate => (
                    <option key={candidate.id} value={candidate.id}>
                      {`${candidate.name} (${candidate.type}${candidate.status === 'active' ? '' : ', disabled'})`}
                    </option>
                  ))}
                </select>
                <Link to={ROUTES.ENDPOINT_NEW} className="small">
                  Add an endpoint
                </Link>
              </div>
              <div className="col-md-6 mb-3">
                <label htmlFor="integration-event-set" className="form-label">
                  Event set<span className="text-danger"> *</span>
                </label>
                <select
                  id="integration-event-set"
                  className="form-select"
                  value={eventSetId}
                  onChange={event => {
                    setEventSetId(event.target.value);
                    setError(null);
                  }}
                >
                  <option value="">Choose which events to deliver</option>
                  {eventSets.map(candidate => (
                    <option key={candidate.id} value={candidate.id}>
                      {`${candidate.name} (${candidate.events.length} event${candidate.events.length === 1 ? '' : 's'})`}
                    </option>
                  ))}
                </select>
                <Link to={ROUTES.EVENT_SET_NEW} className="small">
                  Add an event set
                </Link>
              </div>
            </div>
            <div className="form-check form-switch">
              <input
                id="integration-active"
                className="form-check-input"
                type="checkbox"
                checked={status === 'active'}
                onChange={event => setStatus(event.target.checked ? 'active' : 'disabled')}
              />
              <label htmlFor="integration-active" className="form-check-label">
                Active
              </label>
              <div className="form-text">A disabled integration delivers nothing.</div>
            </div>
          </div>
        </div>

        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">Template</h6>
          </div>
          <div className="card-body">
            {endpoint ? (
              <TemplateEditor
                type={endpoint.type}
                content={content}
                onChange={next => {
                  setContent(next);
                  setError(null);
                }}
                variables={variables}
                onValidityChange={setTemplateValid}
              />
            ) : (
              <p className="text-muted mb-0">Pick an endpoint to write its template.</p>
            )}
          </div>
        </div>

        {withAudit && (
          <div className="card shadow mb-4">
            <div className="card-header py-3">
              <h6 className="m-0 font-weight-bold text-primary">Governance Audit delivery</h6>
            </div>
            <div className="card-body">
              <p className="text-muted small">
                The event set holds audit events. Their records are journaled and retried until
                delivered, unless these limits skip them.
              </p>
              <AuditDeliveryLimitsSection limits={limits} onChange={setLimits} />
            </div>
          </div>
        )}
      </form>
    </div>
  );
};

export default IntegrationEditorPage;
