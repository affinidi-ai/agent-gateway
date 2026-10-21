# Integrations

How the gateway tells other systems that something happened: an email when a user
registers, a Slack message when a gateway goes offline, an event on a Kafka topic for every
failed payment. Implemented in [`src/integrations/`](../src/integrations/).

In-dashboard notifications, the bell in the top bar, are a separate feature and are
covered at the end.

## Endpoints, event sets and integrations

An integration is one **endpoint**, one **event set** and a **template**. Each is its own
definition, kept as one JSON file
([`src/integrations/definitions/`](../src/integrations/definitions/)), so one endpoint or event
set can serve several integrations.

| Definition | Holds | Stored in |
| --- | --- | --- |
| Endpoint | `type` (`email`, `slack`, `webhook`, `stream`), `configuration`: the transport, destination and credentials, and `status` | `storage_paths.integration_endpoints` |
| Event set | `events`: event ids from the catalog, such as `gateway.created` or `audit.policy_decision`, audit and other events mixed freely | `storage_paths.integration_event_sets` |
| Integration | `endpoint_id`, `event_set_id`, `content` (the template), `status`, and for audit events `audit_drop_after_secs` and `audit_max_attempts` | `storage_paths.integration_definitions` |

Integrations belong to the whole appliance: none has a tenant owner, and a tenant or
resource-scoped PAT is refused with `403` on every route under `/v1/integrations`.

**Endpoints.** `smtp_password` (email), `webhook_url` (Slack), `signing_secret` and `headers`
(webhook), and `sasl_password`, `redis_url` and `auth_token` (stream) are written but never
read back:
responses leave them out of `configuration` and name the ones set in `secrets`. An update that
leaves a secret out keeps it, and one that sends it as `null` clears it. A secret field may
instead hold `$SECRET:<secret_id>`, a reference to an appliance-wide secret in the secrets
store, resolved at each delivery and shown in responses as written; a reference that does not
resolve fails the delivery. Only a value that is the reference as a whole counts. Deleting a
secret that an endpoint references is refused with `409` naming the endpoints; change or
delete those endpoints first. Changing the secret's value is allowed, and the next delivery
uses it. Only appliance-wide secrets resolve; a tenant-owned one never does. No `secrets.*`
permission is checked when a reference is saved or resolved, so `integrations.edit` can use, and
therefore read, every appliance-wide secret: pointing an endpoint that holds a reference at a
host of the caller's choosing and sending a test delivers the value there. Grant
`integrations.edit` only to roles that may read secrets; by default it and `secrets.*` are
administrator-only (see [`RBAC.md`](RBAC.md#secrets-in-endpoints)). The dashboard's stored
secret picker lists secrets only for callers with `secrets.view`, but a typed reference resolves
regardless. A save checks the configuration with its references resolved; when a referenced
value fails the checks, the `400` names the field and the secret id, for example "The value of
webhook_url from secret slack-hook fails the endpoint checks", and never the value. No error
of a save, a test, the startup check or the migration repeats a secret value or a URL (a
blocked host is named). Webhook `headers` must be an object of header names to strings, and
each header value may be such a reference; the field as a whole cannot be one. It cannot set
`Content-Type`, `X-Webhook-Timestamp` or `X-Webhook-Signature-256`, which the gateway sets on
every delivery; an endpoint stored with one of them still sends each exactly once, the
gateway's value. An endpoint's `type` cannot change. Its configuration is checked by
its publisher when saved, so a webhook or Slack URL that fails the checks under _Outbound
requests_ is refused with `400`.

**Event sets** need at least one event, every one from the catalog; repeats are dropped. A
request listing more events than the catalog holds is refused with `400`.

**Integrations** need an existing endpoint and event set. Their template must be a JSON object
whose variables some event of the event set fills, and the audit delivery limits are accepted
only when the event set holds audit events, and must be at least 1. Changing an event set is
refused with `409` while one of its integrations would no longer fit it, and an endpoint or
event set is not deleted (`409`) while an integration uses it.

## How an event becomes a message

```mermaid
flowchart LR
    E["Event, such as<br/>gateway.status_changed"] --> S["Active integrations whose event set<br/>holds it, with an active endpoint"]
    S --> T["Render the template,<br/>replacing ${VARIABLE}"]
    T --> P{Publisher}
    P --> EM[Email]
    P --> SL[Slack]
    P --> WH[Webhook]
    P --> ST["Stream: Kafka, Kinesis,<br/>Pulsar, Redis"]
```

An enabled event is delivered for every resource that raises it; there is no filter by
gateway, user or surface. Delivery reads a snapshot of the definitions
([`delivery/dispatch.rs`](../src/integrations/delivery/dispatch.rs)), taken again after any
change through the API and at most 5 seconds old otherwise, so definitions written by another
node are picked up too.

Delivery runs in spawned tasks and never blocks or fails the operation that raised the event.
Each integration of an event is delivered in a task of its own, so a slow or unreachable
endpoint does not hold up the others. At most 100 such tasks run at once; a delivery due while
all are busy is not made, and a warning is logged.

A transient failure (a connection error, timeout, or request error, or an HTTP 429 or 5xx
response) is retried up to five times, after 1, 2, 4, 8, and 16 seconds plus jitter
([`delivery/retry.rs`](../src/integrations/delivery/retry.rs)). Any other failure, such as an
HTTP 4xx, is logged and dropped. A retried delivery can arrive more than once, so a receiver
that is not idempotent should expect duplicates.

Audit events (`audit.*`) take another path: they are journaled and forwarded by the audit
pipeline, with its own retries and drop policy. See
[`OBSERVABILITY.md`](OBSERVABILITY.md#governance-audit-forwarding).

## Events

`GET /v1/integrations/catalog` lists every event the gateway delivers, with its name,
description, family, its audit group for audit events, and the template variables its delivery
fills; every template variable with its description; each endpoint type with its secret
fields; and `variable_pattern`, the placeholder syntax in use (see _Templates_)
([`events.rs`](../src/integrations/events.rs)).

| Family | Events |
| --- | --- |
| Gateway | `gateway.created`, `updated`, `deleted`, `status_changed`, `accessed` |
| User | `user.created`, `approved`, `updated`, `deleted`, `login`, `accessed` |
| Connection point | `connection_point.connected`: someone connected through a connection point with its secret |
| x402 | `x402.verification.failed`, `x402.settlement.failed`, `x402.transaction.completed`, `x402.cleanup.completed` |
| MPP | `mpp.verification.failed`, `mpp.payment.verified`, `mpp.challenge.issued` |
| Audit | `audit.<event>` for every event of the audit catalog ([`src/audit/catalog.rs`](../src/audit/catalog.rs)) |

A passkey registration raises `user.created`, and an administrator's approval `user.approved`. A
SAML sign-in that creates the user raises `user.created`; SAML users are approved on creation,
so no `user.approved` follows. A later SAML sign-in that changes the user's role, status, or
primary flag raises `user.updated`. Every SAML sign-in then raises `user.login`, in that order
([`saml/user_provisioning.rs`](../src/auth/saml/user_provisioning.rs)).

## Templates

An integration's `content` is a JSON object whose string values may hold `${VARIABLE}`
placeholders. Fields the template leaves out take the endpoint type's default, so an empty
template sends a complete message:

| Type | Default |
| --- | --- |
| `email` | `subject` `${EVENT_NAME}`, `body` `${EVENT_SUMMARY}`, `format` `plain` (or `html` when the body is HTML) |
| `slack` | `text` `*${EVENT_NAME}*` and `${EVENT_SUMMARY}` on the next line |
| `webhook`, `stream` | `event_type`, `event_name`, `timestamp`, `appliance_id`, `summary` and `data` (`${EVENT_DATA}`) |

Every event fills these variables, plus its own:

| Variable | Value |
| --- | --- |
| `EVENT_TYPE` | The event id, such as `gateway.created` |
| `EVENT_NAME` | Its name, such as `Gateway Created` |
| `EVENT_SUMMARY` | One line on what happened, such as `Gateway edge was created` |
| `EVENT_DATA` | The event's own variables as a JSON object with lower-case keys; for an audit event, the audit record |
| `TIMESTAMP` | RFC 3339 |
| `APPLIANCE_ID` | The **Appliance ID** set in Settings › System Settings (`appliance_id` in `settings.json`), such as the appliance's id in Agent Watch. It never comes from event values, is never the appliance DID, and is unrelated to any Kafka topic name. Empty while unset. |

The computed variables (`EVENT_TYPE`, `EVENT_NAME`, `EVENT_SUMMARY`, `EVENT_DATA`,
`APPLIANCE_ID`) are always set by the gateway, never by the code that raised the event. Each
event's own variables, such as `GATEWAY_ID`, `GATEWAY_NAME`, `GATEWAY_DID`, and
`GATEWAY_STATUS` for a gateway event, are listed in the catalog. Gateway and user events also
carry `OLD_STATE` and `NEW_STATE`: the resource before and after the change as JSON, empty for a
create or a delete respectively.

A user's `OLD_STATE` and `NEW_STATE` carry only `user_id`, `role`, `status`, `is_primary`,
`created_at`, and `updated_at`
([`user_integration_triggers.rs`](../src/integrations/user_integration_triggers.rs)). Passkeys,
the SAML subject, and profile details (names, department, job title, avatar) never leave the
appliance through an integration. `USERNAME` and `USER_EMAIL` remain available as separate
variables for a template that needs them.

Placeholders are filled in one pass
([`delivery/render.rs`](../src/integrations/delivery/render.rs)): a placeholder with no value
becomes empty, and a substituted value is never scanned for placeholders again, so a username
of `${SECRET}` stays literal. For `webhook` and `stream`, a string that is exactly
`${EVENT_DATA}` or `${AUDIT_RECORD}` is embedded as a JSON value. Everywhere else, including
`slack` and `email`, and inside other text, these JSON-valued variables are inserted as JSON
text and escaped like any other value.

Values, never the template, are escaped for the transport. Slack messages are sent as mrkdwn,
with `&`, `<`, and `>` escaped, so caller-supplied text such as a JWT `name` claim cannot
produce mentions (`<!channel>`) or links. HTML email bodies have `&`, `<`, `>`, `"`, and `'`
escaped.

The placeholder syntax is `integration.variable_pattern` in `gateway.json`, fixed at startup
([`runtime_variables.rs`](../src/integrations/runtime_variables.rs)); a pattern that is not a
valid regular expression stops the gateway from starting.

## Publishers

| Type | Sends to | Configuration |
| --- | --- | --- |
| `email` | An SMTP server | `smtp_host`, `smtp_port`, `smtp_username`, `smtp_password`, `from`, `to`, optional `cc` and `bcc`, `use_tls`, `use_starttls` |
| `slack` | A Slack incoming webhook | `webhook_url` |
| `webhook` | Any HTTPS endpoint | `url`, optional `method` (`POST`, `PUT`, `PATCH`), `signing_secret`, `headers` |
| `stream` | Kafka, Amazon Kinesis, Apache Pulsar, or Redis Streams | `platform`, `topic`, and the platform's connection settings |

All four stream platforms are compiled into the binary; which one is used is a matter of
configuration.

A webhook request carries `X-Webhook-Timestamp`, the Unix time in seconds. With a
`signing_secret` it also carries `X-Webhook-Signature-256`: `sha256=` and the hex
HMAC-SHA256 of `<timestamp>.<body>` keyed with the secret, so a receiver can check the sender
and reject replays.

## Outbound requests

Webhook and Slack URLs are checked with `validate_resolved_webhook_url`
([`src/url_validation.rs`](../src/url_validation.rs)), which resolves the host and rejects
cloud metadata addresses, loopback and unspecified addresses, the RFC 1918 private ranges,
IPv4 and IPv6 link-local, IPv6 unique-local, and IPv4-mapped forms of all of these. This is
stricter than the forward legs, which allow loopback and RFC 1918 for same-host and
same-network targets. A DNS failure is an error. The request is then sent through the shared
external client ([`src/http_client.rs`](../src/http_client.rs)), which has a 30-second
timeout and redirects disabled, so a redirect cannot lead to an internal address.

These sinks do not use the pin-once primitive in [`src/egress.rs`](../src/egress.rs) that
the forward legs use. The client resolves the host again when it connects, so the checked
address and the connected address are not bound together. See
[`POLICY.md`](POLICY.md#egress-and-ssrf-controls) for the sinks that are pinned.

## Dashboard

Settings live on the **Integrations** page, in three tabs: Integrations, Endpoints and Event Sets
([`www/default/src/pages/IntegrationsPage/`](../www/default/src/pages/IntegrationsPage/)). The
sidebar item and the pages need `integrations.view`, the editors and test sends
`integrations.edit`, and deleting `integrations.delete`.

- **Endpoints** show the fields of their type. Secret fields are never shown once stored: they
  can be kept, replaced or cleared, or point to an appliance-wide secret with
  `$SECRET:<secret_id>`. A saved endpoint can send a test message.
- **Event sets** pick events from the catalog, grouped by family and audit events by their
  audit group, with search. Audit events are picked and saved like any other.
- **Integrations** join an endpoint and an event set and hold the template for the endpoint's
  type. The editor lists the variables the event set fills, refuses a template that uses
  others, sets the audit delivery limits when the event set holds audit events, and tests the
  integration as it stands on screen.
- An endpoint or event set in use cannot be deleted; the list names the integrations using it.
- On the Audit page, **Forward records** opens a new event set of every audit event when no
  integration receives audit records yet.

## Management API

| Route | Purpose |
| --- | --- |
| `GET`, `POST /v1/integrations` | List and create integrations |
| `GET`, `PUT`, `DELETE /v1/integrations/{id}` | Read, change, and remove one |
| `POST /v1/integrations/{id}/test` | Send a saved integration's message once |
| `POST /v1/integrations/test` | Send an unsaved integration's message once |
| `GET`, `POST /v1/integrations/endpoints` | List and create endpoints |
| `GET`, `PUT`, `DELETE /v1/integrations/endpoints/{id}` | Read, change, and remove one |
| `POST /v1/integrations/endpoints/{id}/test` | Send the endpoint's default message once |
| `GET`, `POST /v1/integrations/event-sets` | List and create event sets |
| `GET`, `PUT`, `DELETE /v1/integrations/event-sets/{id}` | Read, change, and remove one |
| `GET /v1/integrations/catalog` | Events, template variables and endpoint types |

A test sends one message without retries
([`api/send_test.rs`](../src/integrations/api/send_test.rs)). An integration test renders its
template for one event of its event set (the smallest event id, so repeated tests match),
filled with sample values; an unsaved one is
checked as a save would be first. An endpoint test sends the endpoint type's default message
for the event `integration.test`. A test that reaches the destination returns
`{"delivered": true, "event_type": ...}`; one that fails returns `502` with the reason.

Each route needs `integrations.view`, `integrations.edit` (including the tests), or
`integrations.delete`, checked by the RBAC guard ([`api/mod.rs`](../src/integrations/api/mod.rs)).
Mounted without a guard, every route above refuses the request with `403`. No route checks any
other permission: an event set holding audit events, an integration delivering them and its
endpoint are managed and tested like any other, and every `integrations.view` holder sees every
endpoint's destination, including where Governance Audit records go. `audit.view` guards reading
the audit records, not where they are forwarded; the previous release hid audit integrations
from callers without it and needed it to change them (see
[`RBAC.md`](RBAC.md#governance-audit-integrations)). Each create, change
and delete is logged as `integrations.<endpoint|event_set|integration>.<created|updated|deleted>`
with its id and the caller, and each test as `integrations.test_sent`; secret values are never
logged.

## In-dashboard notifications

Separate from integrations, the gateway keeps notifications for dashboard users, shown in
the top bar.

| Route | Purpose |
| --- | --- |
| `GET`, `POST /v1/notifications` | List and create |
| `GET`, `PUT`, `DELETE /v1/notifications/{id}` | Read, update, or delete one |
| `GET /v1/notifications/unread/count` | The badge count |
| `POST /v1/notifications/send-welcome` | Send the welcome message |
| `GET`, `PUT /v1/notifications/user-welcome-template` | Read or change the welcome template |

Welcome messages for administrators and users start from the templates
[`admin_welcome.json`](../src/integrations/admin_welcome.json) and
[`user_welcome.json`](../src/integrations/user_welcome.json).

## Upgrading from the previous version

The version before endpoints and event sets kept each integration as one record (transport,
credentials, category and template) and attached it to gateways, users and connection points.
On the first start of the Active node, a one-time migration
([`src/integrations/migration/`](../src/integrations/migration/)) turns each one into an
endpoint, an event set and an integration, all three with the old integration's id.

**What it becomes.**
- **Endpoint:** its type and configuration, with credentials kept as written (they become
  write-only).
- **Event set:** the events it actually received. That means:
  - the event types of its gateway and user attachments (an empty list meant all of them);
  - every x402 or MPP event for those categories;
  - `connection_point.connected` when a connection point named it;
  - for an appliance-wide `audit` integration, the audit records the previous version
    forwarded, including the three the VP Audit Log settings gated.
- **Integration:** its name, template and status. An audit integration gets the delivery
  limits of 7 days and 20 attempts, since unset means retried forever.
- **Endpoint only:** an integration that received nothing keeps only its endpoint, so its
  destination is not lost. This covers `surface`, `identity` and unattached
  `general`/`connection_point` integrations, and tenant-owned `audit` ones.

**What changes, for each integration the report names:**
- **Scope:** an integration attached to some gateways or connection points now receives the
  event from all of them, every tenant's included. A tenant-owned integration becomes
  appliance-wide, and its tenant's tokens can no longer reach it.
- **Templates:**
  - `${CHANNEL_*}` becomes `${SURFACE_*}`.
  - Custom `_` variables and variables that no event of its set fills are removed. Attachment
    values for custom variables are not migrated.
  - Placeholders in webhook header values are removed, since header values are sent as
    written.
  - An empty webhook or stream template sends the event envelope.
- **Slack:** `bot_name` and `icon_emoji` move from the template to the endpoint, and
  `channel` is dropped.
- **Dropped:**
  - Kinesis `access_key` and `secret_key`, which nothing read;
  - webhook headers the gateway sets itself, or whose value is not text;
  - `pre_authorize_blocked`, which no longer exists.
- **Disabled:**
  - an endpoint that fails the current checks, such as a URL now refused, is written disabled
    with the reason;
  - a tenant-owned integration is written disabled whatever its status, since enabled it would
    receive every tenant's events instead of only those of the gateways and connection points
    linked to it. The report gives the reason and the node logs
    `integrations.migration.integration_disabled`. Review its destination before enabling it.
    Its endpoint keeps its status, since no integration delivers to it while it is disabled.
- **Audit:** audit records are now journaled and retried. Audit events added since the
  previous version are not selected.

**Where it reads and what it leaves.**
- It reads `_storage/integrations/definitions` and `_storage/integrations/triggers`, or the
  deprecated `storage_paths.integrations` and `storage_paths.integration_triggers` when set.
  Like every other storage path, a relative path, the defaults included, is relative to the
  config file's directory, not the working directory. Those keys are read for this only and
  log a deprecation warning.
- When `storage_paths.integrations` is set, each of `integration_endpoints`,
  `integration_event_sets` and `integration_definitions` that the config leaves unset goes
  beside it: with the old example config, `../_storage/integrations/endpoints`,
  `…/event_sets` and `…/integrations`. So a config written for the previous version keeps the
  definitions with the rest of its storage, which matters in Docker, where the config
  directory is mounted read-only. A key whose folder there would be one of the old directories
  takes the key's name as its folder instead: with `integrations = "/data/integrations"`, the
  definitions go to `/data/integration_definitions`. Before removing the deprecated keys, set
  those three keys to the directories they use now; otherwise they fall back to
  `_storage/integrations/…` under the config directory.
- The node refuses to start when `integration_endpoints`, `integration_event_sets` or
  `integration_definitions` is one of the old directories, or sits inside one. The new store
  would read the old records, which it cannot parse, and the migration renames the old
  directories with whatever they hold. The error names both keys.
- When the old definitions directory is not there, the node logs
  `integrations.migration.not_found` with the path it looked in: INFO, as on a fresh install
  or once migrated, or WARN when `storage_paths.integrations` names it.
- Each integration logs `integrations.migration.integration`. A disabled endpoint logs
  `integrations.migration.endpoint_disabled`, a tenant's integration written disabled logs
  `integrations.migration.integration_disabled`, an integration that cannot be migrated logs
  `integrations.migration.skipped`, and the end logs `integrations.migration.done`.
- The report is `migration-report-<unix seconds>.json` in the directory holding
  `storage_paths.integration_definitions` (by default `_storage/integrations/` beside the
  config file, or the directory holding the old definitions when only
  `storage_paths.integrations` is set), with no secret, header or attachment value in it.
- The two old directories are renamed to `<dir>.migrated-<unix seconds>`, which also keeps
  the migration from running again. They may hold credentials in plain text, so the Active
  node deletes them 30 days later, without a restart.
- Connection point records keep their old integration fields until they are next saved.

**When something goes wrong.**
- If any old record cannot be read or decrypted, nothing is written or renamed. The node logs
  `integrations.migration.failed` and starts normally, and the next start tries again.
- Restoring a backup that holds the old directories runs the migration again. Definitions
  whose id already exists, migrated or edited since, are left as they are.

**High availability.** Upgrade both nodes before the Active node first starts on the new
version: the rename removes the directories an old-version node still reads. A node started
as Standby migrates when it is promoted, then refreshes delivery and the audit sinks.

After the upgrade, check the startup summary `integrations.definitions.checked` (below) for
migrated definitions that do not pass their checks.

## Troubleshooting

**Definitions checked at startup.** Each node checks the stored definitions when it starts
([`definitions/check.rs`](../src/integrations/definitions/check.rs)), the way saving them
would:

- each endpoint's configuration, with its `$SECRET:` references resolved;
- each event set's events, against the catalog;
- each integration's endpoint and event set, which must exist, and its template, which must
  fit the event set.

Each definition that fails logs a warning, `integrations.definition.invalid`, with its kind,
id, name and the reason, never a secret value. One summary line,
`integrations.definitions.checked`, gives the counts: a warning when anything failed,
otherwise info. Nothing is changed or disabled. A failing definition's deliveries fail and log
`Integration delivery failed` until it is fixed through the API or the dashboard. The usual
cause after a restore or an upgrade is a referenced secret that is missing from the secrets
store, or an endpoint URL that the current _Outbound requests_ checks refuse.

## Related

- [`CAPABILITIES.md`](CAPABILITIES.md#managing-the-gateway): integrations from a user's point of view.
- [`POLICY.md`](POLICY.md#egress-and-ssrf-controls): how outbound requests are controlled.
- [`OBSERVABILITY.md`](OBSERVABILITY.md): metrics and traces, and Governance Audit forwarding.
