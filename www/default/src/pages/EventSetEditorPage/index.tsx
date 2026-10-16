import React, { useEffect, useState } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import GroupedEventPicker, { PickerEntry } from '../../components/integrations/GroupedEventPicker';
import { AppButton } from '../../components/shared/AppButton';
import { usePermissions } from '../../context/PermissionsContext';
import {
  CatalogEvent,
  createEventSet,
  EventSet,
  getCatalog,
  getEventSet,
  listIntegrations,
  updateEventSet,
} from '../../integrationsApi';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';

const EVENT_SETS_TAB = '/integrations?tab=event-sets';
const AUDIT_FAMILY = 'audit';
const AUDIT_VIEW_NEEDED = 'Audit events need the audit.view permission.';

const isAuditEvent = (event: string) => event.startsWith(`${AUDIT_FAMILY}.`);

/**
 * Families as the catalog lists them; audit events split further by their audit group, and
 * shown but not pickable without `audit.view`.
 */
const toEntry = (event: CatalogEvent, canPickAudit: boolean): PickerEntry => ({
  key: event.id,
  label: event.name,
  description: event.description,
  group: event.family === AUDIT_FAMILY ? `audit-${event.group}` : event.family,
  groupLabel:
    event.family === AUDIT_FAMILY
      ? `${event.family_label}: ${event.group_label}`
      : event.family_label,
  disabled: event.family === AUDIT_FAMILY && !canPickAudit,
});

/** Creates an event set, or changes a stored one. */
const EventSetEditorPage: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canPickAudit = hasPermission('audit.view');
  const auditPreset = !id && searchParams.get('preset') === 'audit' && canPickAudit;

  const [catalog, setCatalog] = useState<CatalogEvent[]>([]);
  const [stored, setStored] = useState<EventSet | null>(null);
  const [usedBy, setUsedBy] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [events, setEvents] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const loadedCatalog = await getCatalog();
        setCatalog(loadedCatalog.events);
        if (id) {
          const [eventSet, integrations] = await Promise.all([getEventSet(id), listIntegrations()]);
          setStored(eventSet);
          setName(eventSet.name);
          setDescription(eventSet.description);
          setEvents(eventSet.events);
          setUsedBy(
            integrations
              .filter(integration => integration.event_set_id === eventSet.id)
              .map(integration => integration.name)
          );
        } else if (auditPreset) {
          setName('Governance Audit');
          setEvents(
            loadedCatalog.events
              .filter(event => event.family === AUDIT_FAMILY)
              .map(event => event.id)
          );
        }
      } catch (failure) {
        setLoadError(getErrorMessage(failure, 'Failed to load the event set'));
      } finally {
        setLoading(false);
      }
    };
    load();
  }, [id, auditPreset]);

  const known = new Set(catalog.map(event => event.id));
  const unknown = events.filter(event => !known.has(event));
  const holdsAudit = events.some(isAuditEvent);
  // The gateway refuses to change a set that holds audit events, before or after, without
  // audit.view.
  const auditLocked = !canPickAudit && (holdsAudit || Boolean(stored?.events.some(isAuditEvent)));

  const save = async (event: React.FormEvent) => {
    event.preventDefault();
    const missing = [
      ...(name.trim() ? [] : ['Name']),
      ...(events.length ? [] : ['at least one event']),
    ];
    if (missing.length) {
      setError(`Fill in: ${missing.join(', ')}`);
      return;
    }
    setSaving(true);
    setError(null);
    const request = { name: name.trim(), description: description.trim(), events };
    try {
      const saved = stored
        ? await updateEventSet(stored.id, request)
        : await createEventSet(request);
      showToast('success', `Event set ${saved.name} saved`);
      navigate(EVENT_SETS_TAB);
    } catch (failure) {
      setError(getErrorMessage(failure, 'Failed to save the event set'));
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="d-flex justify-content-center py-5">
        <div className="spinner-border" role="status">
          <span className="visually-hidden">Loading the event set</span>
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
        <Link to={EVENT_SETS_TAB}>Back to event sets</Link>
      </div>
    );
  }

  return (
    <div className="container-fluid" data-testid="page-event-set-editor">
      <form onSubmit={save} noValidate>
        <div className="d-flex justify-content-between align-items-center mb-4">
          <h1 className="h4 mb-0">{stored ? `Event set ${stored.name}` : 'New event set'}</h1>
          <div className="d-flex gap-2">
            <AppButton
              variant="outline-secondary"
              size="md"
              onClick={() => navigate(EVENT_SETS_TAB)}
              data-testid="event-set-cancel-button"
            >
              Cancel
            </AppButton>
            <AppButton
              type="submit"
              variant="primary"
              size="md"
              loading={saving}
              disabled={auditLocked}
              title={auditLocked ? AUDIT_VIEW_NEEDED : undefined}
              data-testid="event-set-save-button"
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
              <label htmlFor="event-set-name" className="form-label">
                Name<span className="text-danger"> *</span>
              </label>
              <input
                id="event-set-name"
                data-testid="event-set-name-input"
                className="form-control"
                value={name}
                onChange={change => setName(change.target.value)}
              />
            </div>
            <div className="mb-3">
              <label htmlFor="event-set-description" className="form-label">
                Description
              </label>
              <input
                id="event-set-description"
                data-testid="event-set-description-input"
                className="form-control"
                value={description}
                onChange={change => setDescription(change.target.value)}
              />
            </div>
            {usedBy.length > 0 && (
              <p className="text-muted small mb-0">
                Used by {usedBy.join(', ')}. A change that leaves one of them without the variables
                its template uses is refused.
              </p>
            )}
          </div>
        </div>

        <div className="card shadow mb-4">
          <div className="card-header py-3">
            <h6 className="m-0 font-weight-bold text-primary">Events</h6>
          </div>
          <div className="card-body">
            <p className="text-muted small">
              An enabled event is delivered for every gateway, user or surface that raises it.
            </p>
            {!canPickAudit && (
              <div className="alert alert-secondary small">
                {AUDIT_VIEW_NEEDED}{' '}
                {auditLocked
                  ? 'This event set holds audit events, so only a user with it can change it.'
                  : 'They are listed but cannot be picked.'}
              </div>
            )}
            {holdsAudit && (
              <div className="alert alert-info small">
                Governance Audit events are delivered through the audit journal: each record is kept
                until delivered, with the drop policy and attempt limit set on the integration.
              </div>
            )}
            {unknown.length > 0 && (
              <div className="alert alert-warning small">
                These events are no longer in the catalog, so the event set cannot be saved with
                them:
                <ul className="mb-0">
                  {unknown.map(event => (
                    <li key={event}>
                      <code>{event}</code>{' '}
                      <AppButton
                        variant="link"
                        size="sm"
                        onClick={() => setEvents(current => current.filter(e => e !== event))}
                        aria-label={`Remove ${event}`}
                        data-testid={`event-set-remove-${event}-button`}
                      >
                        Remove
                      </AppButton>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            <GroupedEventPicker
              entries={catalog.map(event => toEntry(event, canPickAudit))}
              selected={events}
              onChange={setEvents}
              testIdPrefix="event-set"
              searchable
            />
          </div>
        </div>
      </form>
    </div>
  );
};

export default EventSetEditorPage;
