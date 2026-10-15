# Observability Internals

Use the hosted [observability documentation](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/concepts/observability/)
and [reference](https://docs.affinidi.com/products/affinidi-trust-fabric/agent-gateway/reference/observability/)
for monitoring and operator guidance. This page documents internal event and correlation contracts
for the checked-out source revision.

## Dashboard WebSocket

[`WsState`](../src/server/websocket.rs) wraps a Tokio broadcast sender. Each connected dashboard
WebSocket subscribes independently after any configured authentication check; a slow receiver that
lags is disconnected rather than blocking producers. `websocket_broadcast_buffer` controls the
channel capacity and defaults to `500`.

`WsUpdate` currently defines these event shapes:

| Variant | Current behavior |
| --- | --- |
| `IdentityCreated` | Emitted after an identity is created. |
| `IdentityUpdated` | Emitted after persisted identity usage data changes. |
| `MetricsUpdated` | Emitted by metrics update paths. |
| `LogEntry` | Emitted by the tracing WebSocket layer for a new log event. |
| `PayloadCaptured` | Emitted by direct-path payload capture when `extension_inspection.enabled` is set, by every MCP Proxy (`proxy://`) request whether it succeeds or fails, by every forwarded fabric-received request, and by onboarding capture. |
| `ChannelExpired` | Emitted when an in-memory onboarding session expires. `channel_name` is a legacy event field. |
| `OnboardingAttempt` | Defined for wire compatibility but not emitted; onboarding uses `PayloadCaptured`. |
| `RefreshDashboard` | Requests a complete dashboard refetch after settings updates, policy-definition create/update/delete, or Trust Registry connection-state changes. |
| `DashboardDelta` | Carries a pre-serialized periodic dashboard delta in `Arc<String>`. |

Configuration reload does **not** emit `RefreshDashboard`. A dashboard observes reloaded state
through periodic `DashboardDelta` broadcasts or an explicit refetch.

## Payload capture

Normal surface capture can represent four pipeline observations in one `PayloadCaptured` event:

1. `payload`: inbound request;
2. `outbound_request`: request after gateway transformations;
3. `inbound_response`: response received from the Target; and
4. `response_payload`: response after gateway transformations.

```mermaid
flowchart LR
    C([Caller]) -->|"1 payload"| G[Agent Gateway]
    G -->|"2 outbound_request"| T([Target])
    T -->|"3 inbound_response"| G
    G -->|"4 response_payload"| C
```

The event also carries validation status, an optional validation error, derived schema, and an
optional surface-variant alias. Some producers do not have all four observations. Onboarding, for
example, sets both intermediate fields to `None` because it does not forward the request.

## WebSocket flow

For each dashboard connection, the handler subscribes to the broadcast channel and multiplexes
outbound updates with periodic ping frames. An incoming JSON `subscribe` command replaces the set
of dashboard sections included in subsequent `DashboardDelta` events. Any broadcast receive error,
including lag, ends the connection; socket closure does likewise.

`DashboardDelta` is already serialized before broadcast and held in `Arc<String>`, reducing clone
cost across subscribers. Other variants are serialized per connection.

## A2A protocol version metric

`agent_gateway_a2a_protocol_version_total{channel_id,negotiated_version,method_era}` is a Prometheus
counter incremented once for each A2A or AP2 request that reaches
[version negotiation](PROTOCOLS.md#version-negotiation), whether its `A2A-Version` negotiates or is
refused. A request answered before that step is not counted: for example agent-card discovery, and
refusals by source authentication, rate limiting, gateway or appliance-wide policy, or the AP2 gate.
A request later refused by delegated payment, the egress guard or the request-body size limit
(HTTP `413`) is counted. Requests to a `fabric://` target are never negotiated and never counted.

| Label | Value |
| --- | --- |
| `channel_id` | The surface **name** (a legacy label name; it is not the surface ID) |
| `negotiated_version` | `0.3` or `1.0`, as resolved from `A2A-Version` (an absent or empty header counts as `0.3`), or `rejected` when the request is refused with `-32009` |
| `method_era` | The era of the JSON-RPC method name: `0.3` (slash-form), `1.0` (PascalCase), `unknown` (not an A2A method), or `none` (no method) |

The two version labels can differ, because either method era is accepted whatever version was
negotiated; a `negotiated_version="0.3"` series shows callers that would be refused with legacy
compatibility off. After it is switched off, refused callers appear as `negotiated_version="rejected"`,
with `method_era` showing which method names they send. Requests later refused by JSON-RPC or
request-shape validation are counted under their negotiated version. `fabric://` traffic is never counted (see
[Fabric coverage gap](PROTOCOLS.md#fabric-coverage-gap)).

## Logging initialization

Logging is initialized after the encryption service so secret-backed OTLP headers can be resolved.
The tracing subscriber combines:

- the logging level from `config.logging.level`;
- a stderr formatting layer;
- an optional file layer;
- the WebSocket log layer that emits `LogEntry` events; and
- optional OpenTelemetry export according to the observability configuration.

Structured call sites attach searchable fields such as surface identifiers, request method, path,
latency, and trace context. Some older field names still contain `channel`; treat those as legacy
telemetry schema names rather than current domain terminology.

## Request correlation

HTTP tracing and policy auditing attach correlation data to request spans and structured events.
When configured, the root HTTP span can also record `caller.auth_method`, `caller.principal`, and
`caller.did`. Policy decisions are emitted through the policy-audit target with policy scope,
decision, policy identity, deny reason, surface identity, and caller context; denials are WARN and
allows are DEBUG.

The gateway propagates `X-Gateway-Trace-Id` to a Target where the request path creates that trace
identifier, allowing gateway and managed-agent logs to be correlated.

## Access token rotation events

`POST /api/v1/access-tokens/{id}/rotate` emits structured tracing events on the `audit` target.
They are log events only: they are not written to `delegation-audit.jsonl` and are not forwarded
to Governance Audit integrations, so ship the `audit` target off the appliance to keep them. See
[`ACCESS_TOKENS.md`](ACCESS_TOKENS.md#token-contract) for the rotation contract.

| Event | Level | Fields |
| --- | --- | --- |
| `access_token.rotated` | INFO, or WARN when `rotated_for_other_user` is true | `token_id`, `owner_user_id`, `caller_user_id`, `caller_auth_method`, `caller_token_id`, `rotated_for_other_user`, `rotation_generation` |
| `access_token.rotate_denied` | WARN | `token_id`, `caller_user_id`, `caller_auth_method`, `caller_token_id`, `status`, `reason` |

`caller_auth_method` is `access_token` for a PAT caller and `session` otherwise; `caller_token_id`
is the calling PAT's id and empty for a session caller. `access_token.rotate_denied` carries no
owner and covers only refusals made by the handler: `401` for a request with no authenticated
caller, `403` for a non-administrator rotating another user's token, a PAT caller naming a token
id outside its lineage (including an unknown id) or a PAT scoped by `required_headers` alone,
`404` for a session caller naming an unknown token id, and `409` for a revoked, expired,
inactive-lineage or concurrently rotated token. It is also emitted with status `500` when
loading the caller or saving the rotated token fails; the error detail is logged only on the
default target. Requests refused before the handler runs emit neither event: the
`access_tokens.edit` route check and any refusal by the authentication middleware, for example a
missing or invalid credential, the `403` it returns to a PAT with a `resource_pattern` because the
access-token routes are not a resource-scoped path family, a required header that does not
match, or Terms the token owner has not accepted.

## Governance audit forwarding

Governance audit records go to **sinks**: the VP Audit Log (`delegation-audit.jsonl`, read by
`/v1/audit`) and each Governance Audit integration (category `audit`). Every sink selects the
audit events it wants, and the selections are independent: an integration can receive an event
the VP Audit Log does not keep, and the reverse. Nothing is selected on a fresh install, and a
record nobody selects is never built.

**Selection.** The VP Audit Log keeps the events in the settings field `audit_events` while
`audit_enabled` is on (Settings › VP Audit); turning it off pauses the log without losing the
selection. Each Governance Audit integration receives the events in its own `audit_events` list;
an empty list receives nothing. Both take event names from the audit event catalog
(`src/audit/catalog.rs`), for example `policy_decision`, `auth_failed`, `token_injected`; an
unknown name is rejected (400). An integration update that leaves `audit_events` out keeps the
integration's current list. `GET /v1/settings/audit-events` lists the catalog in order, each entry
with its `event` name, `label`, `description`, `group` and `group_label`; the dashboard builds its
event pickers from it. The catalog is also listed in the category's
`metadata.event_types` as `audit.<event>` with the event's `group`.

**Request events.** Raised at the Access Point on the direct, MCP-proxy and fabric paths.
Reasons are fixed codes; no record carries a credential, token or validator message.

- `auth_failed`: the caller failed authentication. `scheme` is `jwt`, `api_key`, `did_auth`,
  `mtls` or `mcp_resource_token`. `reason` is `missing_credential`, `invalid_credential`,
  `insufficient_scope`, `config_not_found`, `internal`, `setup_failed` or `unavailable` (no MCP
  resource authorization context). `blocking` is false when the failure was handed to policy
  (`input.source_auth.method == "failed"`) instead of refusing the request. `client_ip` is the
  resolved client address (forwarded headers only from `client_ip.trusted_proxies`); absent on
  the fabric path, where the caller connected to the sending gateway.
- `rate_limited`: the request was refused with 429. `scope` is `surface` (the Access Point's
  rate limit), `sse_sessions` (the legacy SSE session cap) or `fabric_capacity` (a full Fabric
  stream cap on the way to a fabric target). `retry_after_ms` is the wait the caller is given,
  when there is one; the surface limit also sends it as `Retry-After` in whole seconds.
- `request_rejected`: the Access Point refused the request before or while forwarding it.
  `http_status` is what the caller received and `rpc_error_code` the JSON-RPC error code, when
  the refusal was one; legacy MCP refuses a malformed request with HTTP 200 and a JSON-RPC error,
  so read the two together. `stage` and `reason`:
  - `routing`: `no_route` (no surface matches; recorded against surface `unknown`, with no trace
    id on the direct path), `unknown_variant`, `variant_disabled`.
  - `admission`: `body_too_large`, `protocol_mismatch` (an MCP body on an A2A Access Point or the
    reverse), `invalid_envelope` (not JSON, or not a JSON-RPC request, on every protocol and MCP
    revision), `invalid_request_shape` (A2A fields), `version_unsupported` (A2A or MCP),
    `mcp_admission` (MCP transport rules: Origin, header size, mirrored method or protocol
    headers, HTTP method, per-request capabilities, `_meta`), `extension_rejected` (request
    extension rules, and an inbound identity that is missing or invalid),
    `consent_identity_required` (credential delegation for an anonymous caller).
  - `forward`: `ssrf_blocked` (egress policy refuses the target address).

  Requests answered before any gateway handler runs (a path under no configured route) and
  gateway faults (a misconfigured default variant, a failed egress check task) are not recorded.
- `identity_binding_verified` and `identity_binding_failed`: the outcome of checking the identity
  presentation (identity binding VP) a request carries, recorded wherever the gateway checks one:
  A2A requests on the direct path, MCP requests at admission, Transit Point MCP requests, and, on
  the fabric receive path, when a surface policy relies on the presentation. These record that a
  received presentation was checked; `vp_injected` records the gateway creating one.
  - `identity_binding_verified`: the presentation verified and a trust anchor vouches for its
    issuer. Carries `agent_did`, `issuer_gateway` and the caller-context `assurance`.
  - `identity_binding_failed`: `outcome` is `absent` (no presentation was sent), `invalid` (it
    failed verification, including an issuer the receiving connection does not trust) or
    `untrusted` (it verified, but no trust anchor was available to vouch for its issuer).
    `error_detail` is a short diagnostic and never carries the presentation itself.

**Volume.** Request events are unbounded by design: each is recorded once per request, with no
aggregation or sampling. `auth_failed` and the routing `request_rejected` are recorded before
the surface rate limit is checked, and `rate_limited` once for every request the limit refuses,
so an unauthenticated or unroutable client produces one record per request it sends
(unroutable ones against surface `unknown`). Selecting these events for an Email or Slack
integration sends one message per record. They also count towards the journal size and its
1 GiB backlog cap (see _Backlog_ below), so a flood can make a slow sink skip records.

**Recipients.** Every integration with category `audit`, status `active` and no tenant owner,
whatever its type. Every record is one delivery, so Email and Slack send one message per record;
Stream (Kafka, Kinesis, Pulsar or Redis Streams) and Webhook suit busy appliances. The records
hold administrator-only evidence: the caller's email and name, request details and the signed VP
leave the appliance with each record, so point audit integrations only at destinations cleared
for that data.

**Access.** Integrations are managed through `/v1/integrations` with the `integrations.*`
permissions alone, whatever events they deliver; `audit.view` guards `/v1/audit`, not the
integrations that forward records. Changing integrations is administrator-only by default
(see [`INTEGRATIONS.md`](INTEGRATIONS.md#management-api)).

- They cannot belong to a tenant. `PUT /v1/tenant-ownership/integrations/{id}` with a tenant
  returns 400, and a tenant-owned integration never receives records even if its category is
  edited on disk.
- Only the dispatcher publishes to them. A connection point or gateway cannot link one (400),
  and every event trigger (connection point, gateway, user, identity, surface, x402, MPP)
  refuses one, so values those triggers carry, some of them caller-supplied, never reach the
  audit stream.

**Delivery.** No record is lost by the gateway except in the counted cases below.

- *Producing.* The producer (`src/audit/producer.rs`) is the only place a record is finalised.
  It checks the selections first (one atomic read), gives the record an `event_id` (UUID v4),
  addresses it to the sinks that select its event at that moment, and hands it to the journal
  without waiting. Records a proxied request produces while credential delegation runs are held
  until the request's identity VP is minted, then stamped with it; any still held when the
  request ends, on any path, are submitted without a VP. A selected record produced while the
  pipeline is not running is dropped and counted in
  `agent_gateway_audit_records_lost_total{reason="pipeline_not_running"}`, and one handed to a
  journal writer that has stopped in `reason="journal_closed"`.
- *Journal.* Every record is appended to the journal (`{log_directory}/journal/`, segment
  files named by their first sequence number) by a dedicated thread that writes in batches of up
  to 256 records or 5 ms and syncs each batch to disk before any sink may read it. A crash can
  lose at most the last unsynced batch. If the journal cannot be written the writer retries with
  backoff while holding up to 10,000 records in memory; beyond that the oldest are discarded and
  counted in `agent_gateway_audit_records_lost_total{reason="journal_write"}`. A failed batch
  is cut off again; if that fails too, the segment is re-read before the next batch, as on start.
  When the pipeline stops before the writer has written records it was handed, the writer stops
  between batches or during its backoff and discards them, counted in
  `agent_gateway_audit_records_lost_total{reason="aborted"}`.
  The journal directory is owner-only (`0700`) and its files `0600`.
- *One writer.* Only an Active node runs the pipeline (see
  [Server mode](CONFIGURATION_RELOAD.md#server-mode)); a Standby node keeps no audit records.
  On stepping down a node stops taking records, gives the writer up to 5 s to journal what it
  was handed, then cancels the writer, the dispatcher and every reader: a delivery in flight is
  dropped, no cursor is saved after that, and records still unwritten are counted with
  `reason="aborted"`. The journal lock is released last, once all of them have stopped. On
  becoming Active it re-opens the journal and cursors from disk and continues after
  the last record the previous Active node wrote. Before the pipeline starts, on start-up or on
  becoming Active, the sinks are built from the current settings and integrations, so delivery
  never starts from sinks that were never built or are stale; while the integrations cannot be
  listed the pipeline does not start and is tried again every 5 s. A node becoming Active
  first re-reads the dashboard settings (`settings.json`, which hold the VP Audit Log
  selection) from disk and empties its integration cache, so the sinks it builds and every
  delivery follow the settings and integrations the previous Active node left, not those this
  node loaded before (see [Server mode](CONFIGURATION_RELOAD.md#server-mode)). The node admits
  traffic after one start attempt; a refused start keeps being retried in the background. The
  writer holds an exclusive lock on `journal/journal.lock`, so a second process sharing the
  directory cannot write to it; a node that becomes Active while another still holds the lock
  tries again every 5 s. Stepping down ends these retries, and the sink rebuild retries below,
  along with the pipeline.
- *Dispatch.* Each sink has its own reader and cursor (`journal/cursors.json`). A reader
  delivers the records addressed to its sink in journal order and saves its cursor after each
  batch, so it resumes there after a restart; a slow or unreachable destination only delays
  itself. A failed delivery is retried with backoff (1 s up to 5 min) and holds back the records
  after it, until the integration's drop policy or attempt limit (below) skips it; the
  integration retry policy still applies inside each attempt. Delivery is
  at-least-once: a record may be delivered again after a restart, so receivers should
  deduplicate on `event_id`. The VP Audit Log does this itself for the records at the end of
  its file.
- *Sinks coming and going.* A new sink reads from the start of the journal; no record is
  addressed to a sink before it exists, so it misses nothing. A Governance Audit integration
  that is disabled, given a tenant or moved to another category is paused: it keeps its
  configuration but receives nothing, and records addressed to it while it is paused are not
  kept. Pausing moves its cursor to the end of the journal, letting go of the records it had not
  received; each one addressed to it is counted in
  `agent_gateway_audit_sink_skipped_total{sink, reason="paused"}` (unreadable lines with
  `reason="corrupt"`) and one warning per integration gives the count. An integration paused
  while the gateway was stopped is paused the same way when the pipeline starts. Resuming
  continues from where the pause left it, so it receives only records produced after the pause;
  that position never holds back journal pruning, and once pruning has deleted everything up to
  it the integration resumes from the oldest remaining record, all of them produced after the
  pause. Deleting an integration lets go of its records in the same way and drops its cursor.
  The VP Audit Log is never paused. Until its reader is stopped a paused integration refuses
  records, counted with `result="not_receiving"`, so none is reported as delivered; those
  records are counted as paused. Records produced at the moment of pausing, before the change
  takes effect, may still be delivered after the integration resumes, or be counted as paused.
  The sinks are rebuilt from the settings and integrations one rebuild at a time, so an older
  rebuild never replaces newer sinks. When the integrations cannot be listed, including before
  integration storage is set up, the previous sinks are kept, the failure is counted in
  `agent_gateway_audit_sink_rebuild_failed_total`, and the rebuild is retried every 5 s until it
  succeeds or the node steps down.
- *Backlog.* Journal segments every active cursor has passed are deleted. The journal size is
  reported in `agent_gateway_audit_journal_bytes` and logged as a warning above 256 MiB. Above
  1 GiB, every sink still in the oldest segment is moved past it so the segment can be deleted;
  the records each one skips are counted in
  `agent_gateway_audit_sink_skipped_total{sink, reason="backlog_cap"}`.
- *Drop policy.* A Governance Audit integration may set `audit_drop_after_secs`: records older
  than that are skipped for it, including one still being retried, and counted with
  `reason="expired"`. Without it nothing is skipped.
- *Attempt limit.* A Governance Audit integration may set `audit_max_attempts`: a record that
  fails that many delivery attempts is skipped for it, so a record the destination never
  accepts does not hold back the records after it. Every failed attempt counts, whatever the
  error; one attempt is one hand-over to the integration, including the integration retry
  policy inside it. The skipped record is counted with `reason="rejected"` and one warning gives
  its seq, the attempt count and the last error. Attempts are counted while the reader stays on
  the record, so a restart starts the count again. A changed limit applies to the record being
  retried. Without it a record is retried until it is delivered. The limit does not tell a
  rejected record from an outage: while the destination is down, each record is skipped once it
  reaches the limit. With the retry backoff (1 s, doubling, up to 5 min), 10 attempts span
  about 8.5 minutes and 20 about an hour, plus the time the attempts themselves take.
- *Damage.* A damaged journal or cursors file never stops the pipeline. On start, everything
  after the last readable line of the newest segment is cut off and logged with the number of
  bytes discarded; a segment with no readable line is emptied. Files in `journal/` that are not
  segments are logged and ignored. An unreadable `cursors.json` is renamed to
  `cursors.json.corrupt-<unix seconds>` and every sink starts without a cursor. A reader moves
  past a journal line that does not parse as it would past a delivered record, counts it with
  `reason="corrupt"` and logs one warning per batch naming the segment.

Records produced are counted in `agent_gateway_audit_records_produced_total{event}`;
integration deliveries in
`agent_gateway_audit_forward_total{result="delivered"|"failed"|"not_receiving", integration_id}`;
records a sink skipped in
`agent_gateway_audit_sink_skipped_total{sink, reason="backlog_cap"|"expired"|"corrupt"|"paused"|"rejected"}`.

`agent_gateway_audit_pipeline_started` is 1 while the pipeline runs and 0 when it could not start
(the journal directory cannot be created or written, for example) or the node is in Standby.
While it is 0 on an Active node the gateway keeps serving requests but keeps and forwards no
audit records; alert on that.

*A writer stuck in I/O.* A journal writer blocked inside a write or sync (a failing disk, for
example) cannot see that the pipeline was stopped. It keeps the journal lock, deliberately, so no
other writer interleaves with it; ten seconds after the stop the node logs an error saying the
writer is stuck in I/O and keeps the journal lock. The node taking over then cannot open the
journal and keeps retrying every 5 s. Alert when `agent_gateway_audit_pipeline_started` is 0 on
the Active node, or `agent_gateway_audit_records_lost_total{reason="pipeline_not_running"}`
increases; if the stuck-writer error was logged on the node that stepped down, reboot that node to
release the lock.

**Payload.** Audit templates may use `EVENT_TYPE`, `TIMESTAMP` (the record's own timestamp),
`AUDIT_RECORD`, `AUDIT_CATEGORY`, `AUDIT_TRACE_ID`, `AUDIT_SURFACE_ID`, `AUDIT_SURFACE_NAME`,
`AUDIT_PROTOCOL`, `AUDIT_AGENT_DID`, `AUDIT_VIA_FABRIC`, `AUDIT_PRINCIPAL`,
`AUDIT_PRINCIPAL_EMAIL`, `AUDIT_PRINCIPAL_NAME`, `AUDIT_AUTH_METHOD`, `AUDIT_DECISION`,
`AUDIT_DENY_REASON`, `AUDIT_POLICY_NAME`, `AUDIT_POLICY_VERSION`, `AUDIT_POLICY_CONTENT_HASH`,
`AUDIT_VP_JWT` and `AUDIT_VP_FINGERPRINT`. `AUDIT_RECORD` is the full record in the
`/v1/audit` row shape. The principal variables come from the record's `caller` context:
`AUDIT_PRINCIPAL` is the caller's email, else display name, else authenticated subject (JWT
`sub`, API key name, DID, mTLS principal, or on a Transit Point the caller the transit token
carries), and all four are empty when the request had no caller context (no source auth, or a
Transit Point whose token carries no caller). The policy variables describe the policy that made
a `policy_decision` (`AUDIT_POLICY_NAME` falls back to the Rego package when the policy has no
stored definition) and are empty for other records; see
[`POLICY.md`](POLICY.md#versioned-policy-definitions) for which decisions carry a revision. In a JSON template (Stream, Webhook), a string value that is exactly
`${AUDIT_RECORD}` is embedded as a JSON object; inside other text it is inserted as JSON text.
Other state variables such as `OLD_STATE` keep their string form. The dashboard seeds Stream
and Webhook audit integrations with:

```json
{
  "event_type": "${EVENT_TYPE}",
  "category": "${AUDIT_CATEGORY}",
  "timestamp": "${TIMESTAMP}",
  "trace_id": "${AUDIT_TRACE_ID}",
  "surface_id": "${AUDIT_SURFACE_ID}",
  "record": "${AUDIT_RECORD}"
}
```

Kafka producers are reused per integration, rebuilt when its brokers or SASL settings change,
and dropped when the integration is saved or deleted; the Kinesis, Pulsar and Redis Streams
publishers still open a client per record.

**Configuration.** `config/examples/gateway.example.json` carries the canonical `audit`
category entry. A `gateway.json` that lacks it, such as one created before the category
existed, is given the built-in entry at load with a WARN, so an upgrade offers Governance Audit
without an edit; an operator's own `audit` entry is kept. Settings saved with the older
`audit_categories` booleans are read as the events `policy_decision`, `trust_check` and
`vp_injected`; nothing else is selected on upgrade, and existing Governance Audit integrations
start with no events. See `src/audit/` and `src/integrations/audit_integration_triggers.rs`.
