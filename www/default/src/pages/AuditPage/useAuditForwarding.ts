import { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { AUDIT_INTEGRATION_CATEGORY } from '../../utils/auditIntegrations';

interface IntegrationSummary {
  category?: string;
  status?: string;
  tenant_id?: string | null;
  audit_events?: string[];
}

export interface AuditForwarding {
  /** Active, appliance-wide Governance Audit integrations that select at least one event. */
  integrations: number;
  /** Active, appliance-wide Governance Audit integrations that select no events and receive nothing. */
  integrationsWithoutEvents: number;
  /** Whether `/integrations/config` offers the Governance Audit category at all. */
  categoryConfigured: boolean;
}

function isForwardedTo(integration: IntegrationSummary): boolean {
  return (
    integration.category === AUDIT_INTEGRATION_CATEGORY &&
    integration.status === 'active' &&
    !integration.tenant_id
  );
}

function selectsEvents(integration: IntegrationSummary): boolean {
  return Array.isArray(integration.audit_events) && integration.audit_events.length > 0;
}

/** Where audit records are forwarded, or `null` when it cannot be shown. */
export function useAuditForwarding(canViewIntegrations: boolean): AuditForwarding | null {
  const [forwarding, setForwarding] = useState<AuditForwarding | null>(null);

  useEffect(() => {
    if (!canViewIntegrations) {
      setForwarding(null);
      return;
    }
    let cancelled = false;
    Promise.all([apiClient.get('/integrations'), apiClient.get('/integrations/config')])
      .then(([integrationsResponse, configResponse]) => {
        if (cancelled) {
          return;
        }
        const integrations: IntegrationSummary[] = Array.isArray(integrationsResponse.data)
          ? integrationsResponse.data
          : [];
        const categories: { enum_value?: string }[] = configResponse.data?.categories ?? [];
        const forwardedTo = integrations.filter(isForwardedTo);
        const receiving = forwardedTo.filter(selectsEvents).length;
        setForwarding({
          integrations: receiving,
          integrationsWithoutEvents: forwardedTo.length - receiving,
          categoryConfigured: categories.some(
            category => category.enum_value === AUDIT_INTEGRATION_CATEGORY
          ),
        });
      })
      .catch(() => {
        if (!cancelled) {
          setForwarding(null);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [canViewIntegrations]);

  return forwarding;
}
