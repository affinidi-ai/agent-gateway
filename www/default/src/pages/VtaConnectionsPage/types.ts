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

export type RotationPhase = 'prepared' | 'introduced' | 'switched';

/** A control-key rotation under way. Holds no secret reference: the API drops them. */
export interface ControlKeyRotation {
  phase: RotationPhase;
  previous_verification_method: string;
  next_verification_method: string;
  started_at: string;
  give_up_at: string;
  attempts: number;
}

/** Which key of the connection's `did:webvh` the gateway signs in with, and a rotation under way. */
export interface ControlKeyState {
  verification_method?: string;
  rotated_at?: string;
  rotation?: ControlKeyRotation;
  last_error?: string;
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
  /** The `did:webvh` the gateway authenticates as, when it has one. */
  control_did?: string | null;
  control_key_state?: ControlKeyState;
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
  /** `local` when signing is in-process, `self-hosted` when a trust agent signs. */
  tier: string;
  /**
   * Whether this deployment supports a key-custody claim. False for local
   * signing — the UI must never imply custody when this is false.
   */
  custody_claim: boolean;
  auto_provision_contexts: boolean;
  reserved_origins: string[];
  /** The DID method the gateway authenticates to the agent as. */
  control_did_method?: 'did_key' | 'did_webvh';
  /** The `did:key` control key the gateway holds and can rotate. Absent or null when it holds none. */
  control_key?: VtaControlKeyStatus | null;
}

/** The control key the gateway signs in to its trust agent with, from `GET /v1/vta/status`. */
export interface VtaControlKeyStatus {
  control_did: string;
  /** When the control key last moved to a new one; absent until it has. */
  rotated_at?: string;
  /** When it is next due; absent when automatic rotation is off. */
  next_rotation_at?: string;
  /** Days between automatic rotations; 0 is off. */
  rotation_days: number;
}
