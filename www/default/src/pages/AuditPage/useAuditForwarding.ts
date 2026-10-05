import { useEffect, useState } from 'react';
import { apiClient } from '../../api';
import { AUDIT_INTEGRATION_CATEGORY } from '../../utils/auditIntegrations';

interface IntegrationSummary {
  category?: string;
  status?: string;
  tenant_id?: string | null;
}

export interface AuditForwarding {
  /** Active, appliance-wide Governance Audit integrations: the ones the gateway forwards to. */
  integrations: number;
  /** Whether `/integrations/config` offers the Governance Audit category at all. */
  categoryConfigured: boolean;
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
        setForwarding({
          integrations: integrations.filter(
            integration =>
              integration.category === AUDIT_INTEGRATION_CATEGORY &&
              integration.status === 'active' &&
              !integration.tenant_id
          ).length,
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
