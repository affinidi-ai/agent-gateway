import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { useApp } from '../../context/AppContext';
import { usePermissions } from '../../context/PermissionsContext';
import { ROUTES } from '../../routes';
import { useAuditForwarding } from './useAuditForwarding';

/** An event set of every audit event, the first step towards forwarding records. */
const NEW_AUDIT_EVENT_SET = `${ROUTES.EVENT_SET_NEW}?preset=audit`;

const AUDITING_OFF_NOTE =
  'VP Auditing is off in Settings › Security, so the VP Audit Log keeps nothing; ' +
  'Governance Audit integrations still receive the audit events of their event sets.';

function pausedNote(count: number): string {
  return count === 1
    ? '1 Governance Audit integration is disabled, or its endpoint is, and receives nothing.'
    : `${count} Governance Audit integrations are disabled, or their endpoint is, and receive nothing.`;
}

/**
 * Shows how many integrations receive audit records and opens them, or starts an event set of
 * the audit events when none do. Warns when integrations with audit events are disabled, and
 * says when VP Auditing is off that only the VP Audit Log keeps nothing, since integrations
 * receive the audit events of their own event sets.
 */
const AuditForwardButton: React.FC = () => {
  const navigate = useNavigate();
  const { hasPermission } = usePermissions();
  const { state } = useApp();
  const canEditIntegrations = hasPermission('integrations.edit');
  const forwarding = useAuditForwarding(hasPermission('integrations.view'));
  const auditingOff = state.settings?.audit_enabled === false;

  if (forwarding === null || (forwarding.integrations === 0 && !canEditIntegrations)) {
    return null;
  }

  const { integrations, pausedIntegrations } = forwarding;
  const label =
    integrations > 0
      ? `Forwarding to ${integrations} integration${integrations === 1 ? '' : 's'}`
      : 'Forward records';
  const notes = [
    pausedIntegrations > 0 ? pausedNote(pausedIntegrations) : null,
    auditingOff ? AUDITING_OFF_NOTE : null,
  ].filter((note): note is string => note !== null);

  return (
    <AppButton
      variant="outline-primary"
      size="md"
      onClick={() => navigate(integrations > 0 ? ROUTES.INTEGRATIONS : NEW_AUDIT_EVENT_SET)}
      data-testid="audit-forward-button"
      title={notes.length > 0 ? notes.join(' ') : undefined}
      iconStart={<i className="fas fa-share-square me-1" aria-hidden="true" />}
      iconEnd={
        pausedIntegrations > 0 ? (
          <i
            className="fas fa-exclamation-triangle text-warning ms-1"
            aria-hidden="true"
            data-testid="audit-forward-paused-warning"
          />
        ) : undefined
      }
    >
      {label}
    </AppButton>
  );
};

export default AuditForwardButton;
