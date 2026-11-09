/**
 * VTA connection types, mirroring `src/vta/connections.rs` and
 * `src/vta/pairing.rs`.
 */

export type VtaTransport = 'https' | 'unix' | 'didcomm';

export type VtaConnectionStatus = 'unpaired' | 'connected' | 'error';

export type PairingState = 'draft' | 'awaiting_grant' | 'connected' | 'degraded' | 'revoked';

export interface PairingRecord {
  state: PairingState;
  control_did?: string | null;
  pinned_vta_did?: string | null;
  granted_role?: string | null;
  granted_contexts?: string[];
  payload_expires_at?: string | null;
  last_verified_at?: string | null;
  last_error?: string | null;
}

/** A published signing key on a connection, mirroring `SigningKey`. */
export interface SigningKey {
  key_id: string;
  public_key?: string | null;
}

/**
 * Mirrors `SigningKeys`. `retiring` keys no longer sign but stay published, so
 * artifacts they signed keep verifying.
 */
export interface SigningKeys {
  active?: SigningKey | null;
  retiring?: SigningKey[];
}

export interface VtaConnection {
  id: string;
  tenant_id?: string | null;
  name: string;
  description?: string | null;
  enabled: boolean;
  transport: VtaTransport;
  endpoint: string;
  vta_did: string;
  default_context_id?: string | null;
  /** A reference into the secrets store — never key material. */
  control_key_ref?: string | null;
  status: VtaConnectionStatus;
  pairing: PairingRecord;
  /** Absent until a key is provisioned on this connection. */
  keys?: SigningKeys;
  created_at: string;
  updated_at: string;
}

/** What the operator supplies to create a connection, before pairing. */
export interface NewVtaConnection {
  name: string;
  endpoint: string;
  vta_did: string;
  /** Required before pairing, so the grant can be scoped to one context. */
  default_context_id: string;
}

/** The artifact the customer acts on, from `POST …/pair`. */
export interface PairingPayload {
  connection_id: string;
  control_did: string;
  vta_did: string;
  endpoint: string;
  context_id?: string | null;
  requested_role: string;
  expires_at: string;
  grant_command: string;
}

/** `GET /v1/vta/status` — the appliance's signing-deployment tier. */
export interface VtaDeploymentStatus {
  enabled: boolean;
  tier: string;
  /**
   * Whether this deployment supports a key-custody claim. False for both
   * bundled and local signing — the UI must never imply custody when this is
   * false.
   */
  custody_claim: boolean;
  self_administered: boolean;
  auto_provision_contexts: boolean;
  reserved_origins: string[];
  /** The DID method the gateway authenticates to the agent as. */
  control_did_method?: 'did_key' | 'did_webvh';
  /** How the bundled sidecar's first-start bootstrap went. Absent unless one runs. */
  bootstrap?: VtaBootstrapStatus | null;
}

export type VtaBootstrapState =
  | 'connected'
  | 'waiting_for_vta'
  | 'enrolment_refused'
  | 'vta_replaced'
  | 'vta_lost'
  | 'revoked'
  | 'misconfigured';

/** The bundled trust agent's bootstrap, from `GET /v1/vta/status`. */
export interface VtaBootstrapStatus {
  state: VtaBootstrapState;
  /** What an operator should do about it, written by the backend. */
  advice: string;
  detail?: string;
  vta_did?: string;
  control_did?: string;
  context_id: string;
  bootstrapped_at?: string;
  /** A completed bootstrap was recorded before this start. */
  previously_connected: boolean;
  /** `unclaimed` until a person claims the trust agent. */
  owner: string;
}

export type WizardBackend = 'bundled' | 'own';
