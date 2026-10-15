import { renderHook, waitFor } from '@testing-library/react';
import { apiClient } from '../../../api';
import { useAuditForwarding } from '../useAuditForwarding';

jest.mock('../../../api', () => ({
  apiClient: {
    get: jest.fn(),
  },
}));

const mockGet = apiClient.get as jest.Mock;

interface IntegrationFixture {
  category?: string;
  status: string;
  tenant_id?: string;
  audit_events?: string[];
}

function withIntegrations(integrations: IntegrationFixture[], categories = ['general', 'audit']) {
  mockGet.mockImplementation((url: string) =>
    Promise.resolve({
      data:
        url === '/integrations'
          ? integrations
          : { categories: categories.map(enum_value => ({ enum_value })) },
    })
  );
}

describe('useAuditForwarding', () => {
  beforeEach(() => {
    mockGet.mockReset();
  });

  it('counts only active appliance-wide Governance Audit integrations that select events', async () => {
    withIntegrations([
      { category: 'audit', status: 'active', audit_events: ['policy_decision'] },
      { category: 'audit', status: 'active', audit_events: ['trust_check', 'vp_injected'] },
      { category: 'audit', status: 'disabled', audit_events: ['policy_decision'] },
      {
        category: 'audit',
        status: 'active',
        tenant_id: 'tenant-a',
        audit_events: ['policy_decision'],
      },
      { category: 'gateway', status: 'active', audit_events: ['policy_decision'] },
    ]);

    const { result } = renderHook(() => useAuditForwarding(true));

    await waitFor(() => expect(result.current).not.toBeNull());
    expect(result.current).toEqual({
      integrations: 2,
      integrationsWithoutEvents: 0,
      categoryConfigured: true,
    });
  });

  it('reports active appliance-wide Governance Audit integrations that select no events', async () => {
    withIntegrations([
      { category: 'audit', status: 'active', audit_events: ['policy_decision'] },
      { category: 'audit', status: 'active', audit_events: [] },
      { category: 'audit', status: 'active' },
      { category: 'audit', status: 'disabled' },
      { category: 'audit', status: 'active', tenant_id: 'tenant-a' },
    ]);

    const { result } = renderHook(() => useAuditForwarding(true));

    await waitFor(() => expect(result.current).not.toBeNull());
    expect(result.current?.integrations).toBe(1);
    expect(result.current?.integrationsWithoutEvents).toBe(2);
  });

  it('reports whether the gateway offers the Governance Audit category', async () => {
    withIntegrations([], ['general', 'gateway']);

    const { result } = renderHook(() => useAuditForwarding(true));

    await waitFor(() => expect(result.current).not.toBeNull());
    expect(result.current?.categoryConfigured).toBe(false);
  });

  it('looks nothing up without permission to view integrations', () => {
    withIntegrations([{ category: 'audit', status: 'active', audit_events: ['policy_decision'] }]);

    const { result } = renderHook(() => useAuditForwarding(false));

    expect(result.current).toBeNull();
    expect(mockGet).not.toHaveBeenCalled();
  });
});
