import { renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../../api';
import { useAuditForwarding } from '../useAuditForwarding';

jest.mock('../../../api', () => ({
  apiClient: {
    get: jest.fn(),
  },
}));

const mockGet = apiClient.get as jest.Mock;

interface Definitions {
  integrations: { status: string; endpoint_id: string; event_set_id: string }[];
  endpoints?: { id: string; status: string }[];
  eventSets?: { id: string; events: string[] }[];
}

const AUDIT_SET = { id: 'audit-set', events: ['gateway.created', 'audit.policy_decision'] };
const GATEWAY_SET = { id: 'gateway-set', events: ['gateway.created'] };

function withDefinitions({
  integrations,
  endpoints = [{ id: 'on', status: 'active' }],
  eventSets = [AUDIT_SET, GATEWAY_SET],
}: Definitions) {
  const byPath: Record<string, unknown> = {
    '/integrations': integrations,
    '/integrations/endpoints': endpoints,
    '/integrations/event-sets': eventSets,
  };
  mockGet.mockImplementation((path: string) => Promise.resolve({ data: byPath[path] }));
}

const integration = (status: string, endpointId: string, eventSetId: string) => ({
  status,
  endpoint_id: endpointId,
  event_set_id: eventSetId,
});

describe('useAuditForwarding', () => {
  beforeEach(() => {
    mockGet.mockReset();
  });

  it('counts active integrations with an active endpoint whose event set holds audit events', async () => {
    withDefinitions({
      integrations: [
        integration('active', 'on', 'audit-set'),
        integration('active', 'on', 'audit-set'),
        integration('active', 'on', 'gateway-set'),
      ],
    });

    const { result } = renderHook(() => useAuditForwarding(true));

    await waitFor(() => expect(result.current).not.toBeNull());
    expect(result.current).toEqual({ integrations: 2, pausedIntegrations: 0 });
  });

  it('reports integrations with audit events that are disabled or whose endpoint is', async () => {
    withDefinitions({
      integrations: [
        integration('active', 'on', 'audit-set'),
        integration('disabled', 'on', 'audit-set'),
        integration('active', 'off', 'audit-set'),
        integration('disabled', 'on', 'gateway-set'),
      ],
      endpoints: [
        { id: 'on', status: 'active' },
        { id: 'off', status: 'disabled' },
      ],
    });

    const { result } = renderHook(() => useAuditForwarding(true));

    await waitFor(() => expect(result.current).not.toBeNull());
    expect(result.current).toEqual({ integrations: 1, pausedIntegrations: 2 });
  });

  it('shows nothing when the definitions cannot be loaded', async () => {
    mockGet.mockRejectedValue(new Error('Forbidden (403)'));

    const { result } = renderHook(() => useAuditForwarding(true));

    await waitFor(() => expect(mockGet).toHaveBeenCalled());
    expect(result.current).toBeNull();
  });

  it('looks nothing up without permission to view integrations', () => {
    withDefinitions({ integrations: [integration('active', 'on', 'audit-set')] });

    const { result } = renderHook(() => useAuditForwarding(false));

    expect(result.current).toBeNull();
    expect(mockGet).not.toHaveBeenCalled();
  });
});
