import type { A2aProxy, A2aProxyAgentIdentity, A2aProxyFormData } from './types';

export const DIRECT_LINE_DEFAULT_BASE_URL = 'https://directline.botframework.com/v3/directline';

export const defaultA2aProxyFormData = (): A2aProxyFormData => ({
  name: '',
  description: '',
  status: 'active',
  backend: {
    kind: 'copilot_direct_line',
    secret_id: '',
    credential_mode: 'secret',
    base_url: DIRECT_LINE_DEFAULT_BASE_URL,
    timeout_secs: 30,
    poll_interval_ms: 500,
    max_poll_attempts: 60,
  },
  agent_card_name: '',
  agent_card_description: '',
  agent_identity_type: 'entra_agent',
  agent_identity_subject: '',
  entra_agent_id: '',
  client_tenant_id: '',
});

export function formDataFromProxy(proxy: A2aProxy): A2aProxyFormData {
  const identity = hydrateAgentIdentity(proxy.agent_identity);
  return {
    name: proxy.name || '',
    description: proxy.description || '',
    status: proxy.status || 'active',
    backend: {
      kind: 'copilot_direct_line',
      secret_id: proxy.backend?.secret_id || '',
      credential_mode: proxy.backend?.credential_mode || 'secret',
      base_url: proxy.backend?.base_url || DIRECT_LINE_DEFAULT_BASE_URL,
      timeout_secs: proxy.backend?.timeout_secs ?? 30,
      poll_interval_ms: proxy.backend?.poll_interval_ms ?? 500,
      max_poll_attempts: proxy.backend?.max_poll_attempts ?? 60,
    },
    agent_card_name: proxy.agent_card?.name || '',
    agent_card_description: proxy.agent_card?.description || '',
    ...identity,
  };
}

export function payloadFromFormData(formData: A2aProxyFormData, isEditMode: boolean) {
  const agentCardName = formData.agent_card_name.trim();
  const agentCardDescription = formData.agent_card_description.trim();
  const agent_card =
    agentCardName || agentCardDescription
      ? {
          ...(agentCardName ? { name: agentCardName } : {}),
          ...(agentCardDescription ? { description: agentCardDescription } : {}),
        }
      : null;

  const payload = {
    name: formData.name.trim(),
    description: formData.description.trim(),
    backend: formData.backend,
    agent_card,
    agent_identity: agentIdentityPayload(formData),
  };

  return isEditMode ? { ...payload, status: formData.status } : payload;
}

export function validateA2aProxyForm(formData: A2aProxyFormData): string | null {
  if (!formData.name.trim()) return 'Name is required';
  if (!formData.backend.secret_id.trim()) return 'Direct Line secret is required';
  if (!formData.backend.base_url.trim()) return 'Direct Line base URL is required';
  if (formData.agent_identity_type === 'entra_agent') {
    if (!formData.entra_agent_id.trim()) return 'Entra Agent ID is required';
    if (!formData.client_tenant_id.trim()) return 'Client Tenant ID is required';
  }

  try {
    new URL(formData.backend.base_url);
  } catch {
    return 'Direct Line base URL must be an absolute URL';
  }

  if (formData.backend.timeout_secs < 1 || formData.backend.timeout_secs > 120) {
    return 'Timeout seconds must be between 1 and 120';
  }
  if (formData.backend.poll_interval_ms < 100 || formData.backend.poll_interval_ms > 5000) {
    return 'Poll interval must be between 100 and 5000 milliseconds';
  }
  if (formData.backend.max_poll_attempts < 1 || formData.backend.max_poll_attempts > 240) {
    return 'Max poll attempts must be between 1 and 240';
  }

  return null;
}

function hydrateAgentIdentity(identity: A2aProxyAgentIdentity | null | undefined) {
  if (identity?.type === 'entra_agent') {
    return {
      agent_identity_type: 'entra_agent' as const,
      agent_identity_subject: '',
      entra_agent_id: identity.entra_agent_id || '',
      client_tenant_id: identity.client_tenant_id || '',
    };
  }

  return {
    agent_identity_type: 'proxy_subject' as const,
    agent_identity_subject: identity?.subject || '',
    entra_agent_id: '',
    client_tenant_id: '',
  };
}

function agentIdentityPayload(formData: A2aProxyFormData): A2aProxyAgentIdentity | null {
  if (formData.agent_identity_type === 'entra_agent') {
    return {
      type: 'entra_agent',
      entra_agent_id: formData.entra_agent_id.trim(),
      client_tenant_id: formData.client_tenant_id.trim(),
    };
  }

  const subject = formData.agent_identity_subject.trim();
  return subject
    ? {
        type: 'proxy_subject',
        subject,
      }
    : null;
}
