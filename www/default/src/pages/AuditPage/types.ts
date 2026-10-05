export interface PolicyDecisionData {
  scope: string;
  /** Which request flow produced the decision: access_point | transit_point | fabric */
  flow?: string | null;
  policy_id: string;
  policy_name?: string | null;
  policy_definition_id?: string | null;
  decision: string;
  deny_reason?: string | null;
  surface_id?: string | null;
  caller_did?: string | null;
  http_method?: string | null;
  http_path?: string | null;
  /** Monotonic version of the enforced policy revision, when versioned. */
  policy_version?: number | null;
  /** `sha256:<hex>` content hash of the exact Rego enforced (attestation) — matches the SHA shown on the Policies list. */
  policy_content_hash?: string | null;
}

export interface TrustCheckData {
  leg: string;
  /**
   * Resolved (or, on a pre-dispatch failure, templated) TRQP authority id.
   * Omitted from the JSONL — and therefore `undefined` here — on the
   * target-leg "unavailable" paths (`AGENT_CARD_UNAVAILABLE`,
   * `TRUST_REGISTRY_METADATA_UNAVAILABLE`) where the raw template strings
   * would be noise; renderers must handle the absent case.
   */
  authority_id?: string | null;
  /** Same absence semantics as `authority_id`. */
  entity_id?: string | null;
  ok: boolean;
  error_code?: string | null;
}

export interface TraceTerminatedData {
  /** This gateway's own trace for the request (its audit + caller-facing leg). */
  own_trace_id: string;
  /** The fresh trace forwarded downstream (what the next hop sees). */
  downstream_trace_id: string;
  /** Which request flow terminated the trace: access_point | transit_point | fabric */
  flow: string;
}

export type AuditEventField =
  | string
  | { policy_decision: PolicyDecisionData }
  | { trust_check: TrustCheckData }
  | { trace_terminated: TraceTerminatedData }
  | Record<string, unknown>;

export interface AuditCaller {
  did?: string;
  auth_method?: string;
  email?: string;
  name?: string;
  email_redacted?: string;
  name_redacted?: string;
  [key: string]: unknown;
}

export interface AuditEntry {
  id?: string;
  timestamp: string;
  /** Raw event field — a string for unit variants, object for struct variants */
  event: AuditEventField;
  caller?: AuditCaller;
  surface_id?: string | null;
  /** Human-readable surface/channel name */
  channel_name?: string | null;
  /** Credential provider machine id */
  provider_id?: string | null;
  /** Human-readable credential provider name */
  provider_name?: string | null;
  /** Channel protocol (a2a, mcp, …) */
  protocol?: string | null;
  /** MCP tool name, when the request was an MCP tool call */
  mcp_tool_name?: string | null;
  via_fabric?: boolean;
  vp_jwt?: string;
  /** Actual resolved DID identity of the agent (holder) — populated on vp_injected */
  agent_identity_did?: string | null;
  /** Agent endpoint DID used as vault namespace — populated on vp_injected */
  agent_did?: string | null;
  /** Request trace ID — correlates all audit events for the same request */
  trace_id?: string | null;
  /** SHA-256 fingerprint of the VP JWT — populated on vp_injected */
  vp_fingerprint?: string | null;
  [key: string]: unknown;
}

export interface AuditResponse {
  events: AuditEntry[];
  total: number;
  page: number;
  limit: number;
  category_counts?: Record<string, number>;
}

export interface WorkloadIntent {
  protocol?: string;
  method?: string;
  tool?: string;
  resourceUri?: string;
  promptName?: string;
}

/** A policy decision embedded (and signed) inside a VP's `workloadBinding.policyDecisions`. */
export interface EmbeddedDecision {
  scope: string;
  flow?: string;
  policy: string;
  policy_name?: string;
  policy_id?: string;
  policy_definition_id?: string;
  decision: string;
  deny_reason?: string;
  surface_id?: string;
  caller_did?: string;
  http_method?: string;
  http_path?: string;
}

export type DecisionFilter = '' | 'allow' | 'deny';
export type FlowFilter = '' | 'access_point' | 'transit_point' | 'fabric';
export type ScopeFilter = '' | 'gateway' | 'surface' | 'mcp_tool' | 'response';
