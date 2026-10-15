import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { DeleteButton } from '../../components/shared/DeleteButton';
import { EmptyState } from '../../components/shared/EmptyState';
import { DOCS_URL } from '../../config/docs';
import { usePermissions } from '../../context/PermissionsContext';
import { deleteEventSet, EventSet } from '../../integrationsApi';
import { eventSetPath, ROUTES } from '../../routes';
import { getErrorMessage } from '../../utils/apiError';
import { showToast } from '../../utils/toaster';
import { matches, namesOfIntegrations, STICKY_ERROR, usedByLabel } from './listHelpers';
import { IntegrationDefinitions } from './useIntegrationDefinitions';

interface EventSetsTabProps extends IntegrationDefinitions {
  searchTerm: string;
  onChanged: () => void;
}

const holdsAuditEvents = (eventSet: EventSet) =>
  eventSet.events.some(event => event.startsWith('audit.'));

/** Which events integrations deliver, picked from the catalog. */
const EventSetsTab: React.FC<EventSetsTabProps> = ({
  integrations,
  eventSets,
  searchTerm,
  onChanged,
}) => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const canEdit = hasPermission('integrations.edit');
  const canDelete = hasPermission('integrations.delete');

  const term = searchTerm.trim().toLowerCase();
  const shown = eventSets.filter(
    eventSet => !term || matches(term, eventSet.name, eventSet.description, ...eventSet.events)
  );
  const usersOf = (eventSet: EventSet) =>
    namesOfIntegrations(integrations, integration => integration.event_set_id === eventSet.id);

  const remove = async (eventSet: EventSet) => {
    try {
      await deleteEventSet(eventSet.id);
      onChanged();
    } catch (failure) {
      showToast('error', `Delete failed: ${getErrorMessage(failure)}`, STICKY_ERROR);
    }
  };

  return (
    <div className="card shadow mb-4">
      <div className="card-header py-3 d-flex justify-content-between align-items-center">
        <h6 className="m-0 font-weight-bold text-primary">
          <i className="fas fa-list-check" aria-hidden="true"></i> Event Sets
        </h6>
        {canEdit && (
          <AppButton
            variant="primary"
            size="md"
            className="shadow-sm"
            onClick={() => navigate(ROUTES.EVENT_SET_NEW)}
            iconStart={<i className="fas fa-plus fa-sm me-2" aria-hidden="true" />}
          >
            Add Event Set
          </AppButton>
        )}
      </div>
      <div className="card-body">
        {eventSets.length === 0 ? (
          <EmptyState
            icon="fa-list-check"
            title="Add your first event set"
            body="An event set picks the events an integration delivers, from gateway and user changes to payments and Governance Audit records. One event set can serve several integrations."
            docsHref={DOCS_URL.integrations}
          />
        ) : shown.length === 0 ? (
          <div className="text-center text-muted py-5">
            <i className="fas fa-search fa-3x mb-3" aria-hidden="true" />
            <p className="mb-0">No event sets match your filter.</p>
          </div>
        ) : (
          <div className="table-responsive">
            <table className="table table-hover table-sm">
              <thead>
                <tr>
                  <th style={{ width: '44%' }}>Name</th>
                  <th style={{ width: '18%' }}>Events</th>
                  <th style={{ width: '20%' }}>Used by</th>
                  {(canEdit || canDelete) && <th style={{ width: '18%' }}>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {shown.map(eventSet => {
                  const users = usersOf(eventSet);
                  const count = eventSet.events.length;
                  return (
                    <tr
                      key={eventSet.id}
                      onClick={canEdit ? () => navigate(eventSetPath(eventSet.id)) : undefined}
                      style={canEdit ? { cursor: 'pointer' } : undefined}
                    >
                      <td>
                        <strong>{eventSet.name}</strong>
                        {eventSet.description && (
                          <div className="small text-muted">{eventSet.description}</div>
                        )}
                      </td>
                      <td>
                        {count} event{count === 1 ? '' : 's'}{' '}
                        {holdsAuditEvents(eventSet) && (
                          <span
                            className="badge text-bg-warning"
                            title="Holds Governance Audit events, delivered through the audit journal"
                          >
                            audit
                          </span>
                        )}
                      </td>
                      <td title={users.join(', ') || undefined}>{usedByLabel(users.length)}</td>
                      {(canEdit || canDelete) && (
                        <td onClick={e => e.stopPropagation()}>
                          <div className="d-flex gap-2 align-items-center">
                            {canEdit && (
                              <AppButton
                                variant="outline-primary"
                                size="sm"
                                onClick={() => navigate(eventSetPath(eventSet.id))}
                                title="Edit"
                                aria-label={`Edit event set ${eventSet.name}`}
                              >
                                <i className="fas fa-edit" aria-hidden="true"></i>
                              </AppButton>
                            )}
                            {canDelete && (
                              <DeleteButton
                                onDelete={() => remove(eventSet)}
                                disabled={users.length > 0}
                                title={
                                  users.length > 0
                                    ? `Used by ${users.join(', ')}`
                                    : 'Delete event set'
                                }
                                aria-label={`Delete event set ${eventSet.name}`}
                              />
                            )}
                          </div>
                        </td>
                      )}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};

export default EventSetsTab;
