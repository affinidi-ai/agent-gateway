import {
  DIRECT_LINE_DEFAULT_BASE_URL,
  defaultA2aProxyFormData,
  formDataFromProxy,
  payloadFromFormData,
  validateA2aProxyForm,
} from './formHelpers';
import type { A2aProxy } from './types';

function proxy(agentIdentity: A2aProxy['agent_identity']): A2aProxy {
  return {
    id: 'proxy-1',
    name: 'Copilot proxy',
    description: 'A proxy',
    status: 'active',
    backend: {
      kind: 'copilot_direct_line',
      secret_id: 'direct-line-secret',
      credential_mode: 'secret',
      base_url: DIRECT_LINE_DEFAULT_BASE_URL,
      timeout_secs: 30,
      poll_interval_ms: 500,
      max_poll_attempts: 60,
    },
    agent_card: null,
    agent_identity: agentIdentity,
    created_at: '2026-07-16T00:00:00Z',
    updated_at: '2026-07-16T00:00:00Z',
  };
}

describe('A2A Proxy form helpers', () => {
  it('hydrates legacy subject identity as proxy-managed subject', () => {
    const formData = formDataFromProxy(proxy({ subject: 'support-copilot-prod' }));

    expect(formData.agent_identity_type).toBe('proxy_subject');
    expect(formData.agent_identity_subject).toBe('support-copilot-prod');
    expect(formData.entra_agent_id).toBe('');
    expect(formData.client_tenant_id).toBe('');
  });

  it('emits Entra identity payload', () => {
    const formData = {
      ...defaultA2aProxyFormData(),
      name: 'Copilot proxy',
      backend: {
        ...defaultA2aProxyFormData().backend,
        secret_id: 'direct-line-secret',
      },
      agent_identity_type: 'entra_agent' as const,
      entra_agent_id: ' agent-123 ',
      client_tenant_id: ' tenant-456 ',
    };

    expect(payloadFromFormData(formData, true)).toMatchObject({
      agent_identity: {
        type: 'entra_agent',
        entra_agent_id: 'agent-123',
        client_tenant_id: 'tenant-456',
      },
    });
  });

  it('requires both Entra fields in Entra identity mode', () => {
    const formData = {
      ...defaultA2aProxyFormData(),
      name: 'Copilot proxy',
      backend: {
        ...defaultA2aProxyFormData().backend,
        secret_id: 'direct-line-secret',
      },
      agent_identity_type: 'entra_agent' as const,
      entra_agent_id: 'agent-123',
      client_tenant_id: '',
    };

    expect(validateA2aProxyForm(formData)).toBe('Client Tenant ID is required');
  });
});
