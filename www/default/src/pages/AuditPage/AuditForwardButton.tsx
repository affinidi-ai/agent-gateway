import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { useApp } from '../../context/AppContext';
import { usePermissions } from '../../context/PermissionsContext';
import { ROUTES } from '../../routes';
import { AUDIT_INTEGRATION_CATEGORY } from '../../utils/auditIntegrations';
import { useAuditForwarding } from './useAuditForwarding';

const NEW_AUDIT_STREAM = `${ROUTES.INTEGRATION_WIZARD}?category=${AUDIT_INTEGRATION_CATEGORY}&type=stream`;

const AUDITING_OFF_NOTE =
  'VP Auditing is off in Settings › Security, so the VP Audit Log keeps nothing; ' +
  'Governance Audit integrations still receive the events selected for them.';

function noEventsNote(count: number): string {
  return count === 1
    ? '1 Governance Audit integration selects no events and receives nothing.'
    : `${count} Governance Audit integrations select no events and receive nothing.`;
}

/**
 * Shows how many Governance Audit integrations receive audit records and opens
 * them, or starts a new Governance Audit stream when none do. Hidden when the
 * gateway does not offer the Governance Audit category. Warns when active
 * integrations select no events, and says when VP Auditing is off that only the
 * VP Audit Log keeps nothing, since integrations receive their own events.
 */
const AuditForwardButton: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const { state } = useApp();
  const canEditIntegrations = hasPermission('integrations.edit');
  const forwarding = useAuditForwarding(hasPermission('integrations.view'));
  const auditingOff = state.settings?.audit_enabled === false;

  if (
    forwarding === null ||
    !forwarding.categoryConfigured ||
    (forwarding.integrations === 0 && !canEditIntegrations)
  ) {
    return null;
  }

  const { integrations, integrationsWithoutEvents } = forwarding;
  const label =
    integrations > 0
      ? `Forwarding to ${integrations} integration${integrations === 1 ? '' : 's'}`
      : 'Forward records';
  const notes = [
    integrationsWithoutEvents > 0 ? noEventsNote(integrationsWithoutEvents) : null,
    auditingOff ? AUDITING_OFF_NOTE : null,
  ].filter((note): note is string => note !== null);

  return (
    <AppButton
      variant="outline-primary"
      size="md"
      onClick={() => navigate(integrations > 0 ? ROUTES.INTEGRATIONS : NEW_AUDIT_STREAM)}
      data-testid="audit-forward-button"
      title={notes.length > 0 ? notes.join(' ') : undefined}
      iconStart={<i className="fas fa-share-square me-1" aria-hidden="true" />}
      iconEnd={
        integrationsWithoutEvents > 0 ? (
          <i
            className="fas fa-exclamation-triangle text-warning ms-1"
            aria-hidden="true"
            data-testid="audit-forward-no-events-warning"
          />
        ) : undefined
      }
    >
      {label}
    </AppButton>
  );
};

export default AuditForwardButton;
