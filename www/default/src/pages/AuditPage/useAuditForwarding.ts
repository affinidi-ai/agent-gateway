import { useEffect, useState } from 'react';
import { listEndpoints, listEventSets, listIntegrations } from '../../integrationsApi';

export interface AuditForwarding {
  /** Active integrations, with an active endpoint, whose event set holds audit events. */
  integrations: number;
  /** Integrations whose event set holds audit events but that, or whose endpoint, is disabled. */
  pausedIntegrations: number;
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
    Promise.all([listIntegrations(), listEndpoints(), listEventSets()])
      .then(([integrations, endpoints, eventSets]) => {
        if (cancelled) {
          return;
        }
        const auditSets = new Set(
          eventSets
            .filter(eventSet => eventSet.events.some(event => event.startsWith('audit.')))
            .map(eventSet => eventSet.id)
        );
        const activeEndpoints = new Set(
          endpoints.filter(endpoint => endpoint.status === 'active').map(endpoint => endpoint.id)
        );
        const withAudit = integrations.filter(integration =>
          auditSets.has(integration.event_set_id)
        );
        const receiving = withAudit.filter(
          integration =>
            integration.status === 'active' && activeEndpoints.has(integration.endpoint_id)
        ).length;
        setForwarding({
          integrations: receiving,
          pausedIntegrations: withAudit.length - receiving,
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
