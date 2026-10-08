# User integration events: working plan

Branch-only working file. Remove before the merge request (AGENTS.md rule 7); nothing in
source, tests or docs may reference it.

Goal: forward user events (starting with `user.created`) to Agent Watch with minimal data,
make user trigger mappings safe to save, and make the dashboard able to attach them.

## Status

| Phase | Scope | Status |
|---|---|---|
| 1 | Allow-listed user event state (no passkeys, SAML id or profile PII) | Done |
| 2 | Server-side validation of user and identity trigger mappings | Not started |
| 3 | Dashboard: attach on select, no swallowed errors, event types required | Not started |
| 4 | Minimal Agent Watch `user` template | Not started |
| 5 | SAML: `user.created` and role-change `user.updated` | Not started |
| 6 | SAML: keep the primary administrator's role (security fix) | Not started |

Every phase is test-first: write the failing test, run it and see it fail for the expected
reason, write the smallest code that passes, run it green, then refactor.

## Decisions

- The first Agent Watch template carries no email or username; `user_id` correlates.
- A `user` mapping must name its event types: the dashboard requires a choice and the API
  rejects an empty list on create or change. Stored empty lists keep meaning "all events".
- SAML users raise no `user.approved`; `user.created` already shows `status: approved`.

## Phase 1: allow-listed user event state

Findings: every `user.*` event serialises the whole `UserData` into `NEW_STATE`/`OLD_STATE`,
including `webauthn_rs::Passkey` (credential id, COSE public key, counter), `saml_id`, email,
names, department, job title and avatar path. Usernames are logged at info on every event.

Tests first (`src/integrations/user_integration_triggers.rs`):
- The serialised state has exactly `user_id, role, status, is_primary, created_at,
  updated_at`, so a new `UserData` field cannot leak without a test change.
- A user with passkeys and a SAML id yields state with neither.
- Each event fills `OLD_STATE`/`NEW_STATE` as before (create: new only; delete: old only;
  update: both).

Then: a `UserEventState` DTO, one `user_runtime_values` helper replacing the six copies,
`user_id` in logs. Docs: `runtime_variables.rs` descriptions, `docs/INTEGRATIONS.md`.

## Phase 2: validate trigger mappings

Findings: `PUT /v1/users/integrations` saves anything: no existence, audit, tenant or
resource-scope check, no event-type or variable validation. Dispatch does not skip
tenant-owned integrations. Text substitution re-scans substituted values.

Tests first (handler unit tests, mirroring `gateway_integrations_handlers.rs`):
- Unknown integration, `audit` integration, tenant-owned integration, and category other
  than `user`/`general` → 400.
- Tenant- or resource-scoped PAT → 403.
- Unknown event type, empty event types, duplicate integration ids, non-custom or oversized
  variables, unknown fields → 400.
- A valid mapping is saved and returned.
- Dispatch skips tenant-owned and audit integrations.
- A substituted value containing `${_VAR}` is not expanded again.

Then: a shared linkability helper used by the gateway, user and identity handlers; request
DTO with `deny_unknown_fields`; change logged with actor, integration ids and event types.

## Phase 3: dashboard

Findings: the selector never attaches; save/load errors are swallowed into fake success;
custom-variable validation reads stored values, not the template.

Tests first (Jest, `www/default`):
- Selecting an integration attaches it with its template's custom variables and enables Save.
- An attached integration is no longer offered.
- A failed PUT shows an error, not success; a failed GET shows an error, not an empty list.
- In the `user` category Save stays disabled until an event type is ticked.

Then: `IntegrationsStep`, `UserIntegrationsPage`, `IdentityIntegrationsPage`;
`www/default/AGENTS.md` if a UI pattern changes.

## Phase 4: Agent Watch template

Test first: the dashboard sample for the `user` category is exactly the minimal template.

```json
{
  "event_type": "${EVENT_TYPE}",
  "timestamp": "${TIMESTAMP}",
  "user": { "user_id": "${USER_ID}", "user_role": "${USER_ROLE}", "user_status": "${USER_STATUS}" }
}
```

Agent Watch side (separate repo): `docs/INTEGRATION_PAYLOADS.md` `state.old`/`state.new`.

## Phase 5: SAML user events

Finding: SAML sign-in provisions users without `user.created` and changes roles without
`user.updated`; only `user.login` fires.

Tests first:
- First sign-in reports `Created`, the next `Updated { previous }`.
- Created raises `user.created` then `user.login`, in that order.
- A role change raises `user.updated` with old and new role; an unchanged sign-in raises
  only `user.login`.
- A sign-in refused by the user limit raises nothing.

Then: `provision_user_from_saml` returns the outcome; the ACS handler raises events in one
task; SAML logs carry `user_id`, not username or email. Docs: `docs/INTEGRATIONS.md`.

## Phase 6: primary administrator role

Finding: SAML sign-in overwrites the stored role from the IdP even for the primary user,
who must never be demoted.

Tests first: a primary user whose IdP role maps to `user` stays Administrator and a warning
is logged; a non-primary user's role still follows the IdP.

## Follow-ups (not on this branch)

- Agent Stream: same user triggers, selector and (if present) SAML provisioning.
- Allow-list review of other triggers that serialise whole entities: identity first, then
  gateway, connection point, mediator.
- SAML sign-in writes the session token into `sessionStorage` from an inline script.
