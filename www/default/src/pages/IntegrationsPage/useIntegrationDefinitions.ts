import { useCallback, useEffect, useState } from 'react';
import {
  Endpoint,
  EventSet,
  Integration,
  listEndpoints,
  listEventSets,
  listIntegrations,
} from '../../integrationsApi';
import { getErrorMessage } from '../../utils/apiError';

export interface IntegrationDefinitions {
  integrations: Integration[];
  endpoints: Endpoint[];
  eventSets: EventSet[];
}

/** The integrations, endpoints and event sets, loaded together so each tab can name the others. */
export function useIntegrationDefinitions() {
  const [definitions, setDefinitions] = useState<IntegrationDefinitions>({
    integrations: [],
    endpoints: [],
    eventSets: [],
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async () => {
    try {
      const [integrations, endpoints, eventSets] = await Promise.all([
        listIntegrations(),
        listEndpoints(),
        listEventSets(),
      ]);
      setDefinitions({ integrations, endpoints, eventSets });
      setError(null);
    } catch (failure) {
      setError(getErrorMessage(failure, 'Failed to load integrations'));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    reload();
  }, [reload]);

  return { ...definitions, loading, error, reload };
}
