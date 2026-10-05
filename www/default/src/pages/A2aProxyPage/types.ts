export type A2aProxyStatus = 'active' | 'disabled';
export type DirectLineCredentialMode = 'secret' | 'generate_token';

export interface CopilotDirectLineBackend {
  kind: 'copilot_direct_line';
  secret_id: string;
  credential_mode: DirectLineCredentialMode;
  base_url: string;
  timeout_secs: number;
  poll_interval_ms: number;
  max_poll_attempts: number;
}

export interface A2aProxyAgentCardProfile {
  name?: string;
  description?: string;
}

export type A2aProxyAgentIdentity =
  | {
      type?: 'proxy_subject';
      subject?: string;
    }
  | {
      type: 'entra_agent';
      entra_agent_id?: string;
      client_tenant_id?: string;
    };

export type A2aProxyAgentIdentityType = 'entra_agent' | 'proxy_subject';

export interface A2aProxy {
  id: string;
  name: string;
  description: string;
  status: A2aProxyStatus;
  backend: CopilotDirectLineBackend;
  agent_card?: A2aProxyAgentCardProfile | null;
  agent_identity?: A2aProxyAgentIdentity | null;
  created_at: string;
  updated_at: string;
}

export interface A2aProxyFormData {
  name: string;
  description: string;
  status: A2aProxyStatus;
  backend: CopilotDirectLineBackend;
  agent_card_name: string;
  agent_card_description: string;
  agent_identity_type: A2aProxyAgentIdentityType;
  agent_identity_subject: string;
  entra_agent_id: string;
  client_tenant_id: string;
}

export interface SecretOption {
  id: string;
  name: string;
  secret_id?: string;
  secret_type?: string;
}
