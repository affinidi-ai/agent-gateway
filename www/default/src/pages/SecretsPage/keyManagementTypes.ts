/** Key inventory types, mirroring `src/vta/inventory.rs`. */

export interface KeyEntry {
  /** Also the published `kid` — how a token correlates to the key that signed it. */
  key_id: string;
  status: 'active' | 'retiring';
  public_key?: string;
  label?: string;
  retired_at?: string;
}

export interface ConnectionInventory {
  connection_id: string;
  name: string;
  enabled: boolean;
  transport: string;
  vta_did: string;
  default_context_id?: string;
  pairing_state: string;
  /** The backend's own rule, so the UI cannot disagree about what may sign. */
  usable: boolean;
  keys: KeyEntry[];
}

export interface SurfaceMapping {
  surface_id: string;
  surface_name: string;
  variant_id?: string;
  variant_alias?: string;
  /** `inherit` when nothing is declared at this level — shown, not resolved. */
  backend: string;
  connection_id?: string;
  context_id?: string;
  key_id?: string;
  inherits: boolean;
  derived_context: string;
}

export interface KeyInventory {
  tier: string;
  /** False for both local signing and a bundled sidecar. Computed server-side. */
  custody_claim: boolean;
  connections: ConnectionInventory[];
  mappings: SurfaceMapping[];
  /** Contexts no live surface claims. Reported for cleanup, never reclaimed. */
  orphaned_contexts: string[];
}
