import React from 'react';
import { useNavigate } from 'react-router-dom';
import { AppButton } from '../../components/shared/AppButton';
import { useApp } from '../../context/AppContext';
import { usePermissions } from '../../context/PermissionsContext';
import { ROUTES } from '../../routes';
import { AUDIT_INTEGRATION_CATEGORY } from '../../utils/auditIntegrations';
import { useAuditForwarding } from './useAuditForwarding';

const NEW_AUDIT_STREAM = `${ROUTES.INTEGRATION_WIZARD}?category=${AUDIT_INTEGRATION_CATEGORY}&type=stream`;

/**
 * Shows how many integrations receive the audit records and opens them, or
 * starts a new Governance Audit stream when none do. Hidden when the gateway
 * does not offer the Governance Audit category; says so when VP Auditing is
 * off, because nothing is then written or forwarded.
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

  const { integrations } = forwarding;
  const label =
    integrations > 0
      ? `Forwarding to ${integrations} integration${integrations === 1 ? '' : 's'}`
      : 'Forward records';

  return (
    <AppButton
      variant="outline-primary"
      size="md"
      onClick={() => navigate(integrations > 0 ? ROUTES.INTEGRATIONS : NEW_AUDIT_STREAM)}
      data-testid="audit-forward-button"
      title={
        auditingOff
          ? 'VP Auditing is off in Settings › Security, so no records are written or forwarded'
          : undefined
      }
      iconStart={<i className="fas fa-share-square me-1" aria-hidden="true" />}
    >
      {auditingOff && integrations > 0 ? `${label} (VP Auditing off)` : label}
    </AppButton>
  );
};

export default AuditForwardButton;
