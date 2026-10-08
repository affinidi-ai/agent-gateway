# Frontend Agent Instructions

These instructions apply to work under `www/default/`.

For the stack, the directory layout, and how the dashboard talks to the management API,
see [`README.md`](README.md). This file holds the rules a change has to follow.

## Scope

Use this file when building or editing the React dashboard frontend.

**Status:** `www/default/` is the **current** dashboard, the production frontend shipped
to users. It is **not** legacy or obsolete; treat it as the primary surface for UI work.

Applies to:

1. `www/default/src/pages/**`
2. `www/default/src/components/**`
3. `www/default/src/context/**`
4. `www/default/src/utils/**` when changes are frontend-specific
5. frontend config files in `www/default/`

## Working rules

1. Preserve existing dashboard visual language before introducing new UI patterns.
2. Prefer shared dashboard building blocks before creating page-local alternatives.
3. Keep page entry files orchestration-focused; move page-owned logic into sections,
   hooks, helpers, and local types when needed.
4. If logic is only used by one page folder, keep it inside that page folder unless it
   becomes genuinely shared.
5. Prefer configuration-driven rendering over duplicated sibling JSX sections.
6. Avoid introducing `any` in new frontend code.
7. Do not add new design systems, component libraries, or styling approaches unless
   explicitly requested.
8. Header topbar controls must use the shared topbar action button pattern, a single
   reusable component plus shared CSS state rules, rather than ad-hoc per-button markup.

## Test identifiers

Every new interactive element ships with a `data-testid`. Tests under `ui-tests/specs/`
are the consumer; the convention is documented in
[`ui-tests/README.md`](../../ui-tests/README.md).

| Element       | Pattern                                                                              |
| ------------- | ------------------------------------------------------------------------------------ |
| Page root     | `page-<area>`                                                                        |
| Action button | `<area>-<verb>-button`                                                               |
| List item     | `<area>-card-<id>` or `<area>-row-<id>`                                              |
| Wizard        | `wizard-<name>`, `wizard-step-<name>`, `wizard-next`, `wizard-back`, `wizard-submit` |

## CLI consent page

`/cli-consent` (`pages/CliConsentPage/`) asks a signed-in user to approve a `fabric` CLI
login. `App.tsx` renders it in place of `AuthenticatedApp`, so it has no sidebar or topbar.

- Reuse the login card: the `LoginPage.module.css` form panel, logo, heading, and subtext
  classes on a centred full-screen backdrop. Do not build a second card style.
- Show the signed-in username and the `127.0.0.1:<port>` return target in the bordered
  details box, then a warning `Alert` to only allow a login the user just started.
- Actions are shared `AppButton`s side by side: **Cancel** (`secondary`) and **Allow**
  (`primary`), with `cli-consent-cancel-button` and `cli-consent-allow-button`.
- Invalid link, loading, cancelled, not-approved, and redirecting states replace the body in
  the same card. Never show a code or token on the page.
- Cancel, and a `403` from consent (account not approved), send the browser to the CLI's
  loopback callback with `error=access_denied`, built by `loopbackCallbackUrl`, so the CLI
  stops waiting. The not-approved state tells the user to ask an administrator.
- A signed-out user on `/cli-consent` gets the login page, which returns to the CLI authorize
  path built from the consent query (`loginNextTarget`), so a SAML sign-in continues the flow.

## Surface Builder

- Sidebars may include small, legible configuration controls. Move dense editors,
  repeated rows, long lists, JSON and schema editors, and advanced controls into an
  element `FullscreenPanel`. When fullscreen is used, keep the sidebar focused on counts
  and status plus a Configure or Edit button.
- A field's full explanation goes behind `FieldHelp`, a field-level question-mark
  tooltip, or a collapsed section-level `InfoBanner`. Never as permanent text under the
  field. Only a one-line format hint or a hard-consequence warning stays always visible.
  Reuse `HelpBalloon`, `InfoBanner`, and `FieldHelp` for contextual help.
- Partial templates with a recognized protocol tag are shown only when that protocol
  matches the active surface. Partials without a recognized protocol tag remain available
  across protocols.
- Payment setup dependency alerts stay hidden until the first Save attempt. Invalid
  payment configuration remains blocked on Save, while embedded safety warnings stay
  visible.

## Access Tokens page

Management personal access tokens live in the Secrets page's **Access Tokens** tab.

### Routes and layout

- Create and edit use full-page routes with the same visual pattern:
  `/access-tokens/new` and `/access-tokens/:id`.
- A successful create replaces the editor with the one-time secret page.
- The right column always shows **About Access Tokens**. Edit mode also shows **Access
  Token Details**, resolving the bound user UUID to a name and email while keeping the
  UUID as a fallback.

### Scopes

- The form labels selected and addable values as **scopes**.
- Selected scopes are removable primary pills; available scopes are filterable add pills.
- An empty selection inherits the bound user's full role.
- Stored scopes missing from the live catalog render as red removable pills and block
  submission.

### List rows

- Rows are clickable and keyboard-openable, and carry no separate edit icon.
- The danger revoke action is isolated from row navigation, and uses the shared two-step
  revoke confirmation.
- Revoked status is red.

### Expiry

- Creation defaults to **Never expires**, and the disabled expiry input visibly reads
  **Never** with the application-wide dark disabled-control treatment.
- Switching it off requires a validated future local date and time at the bottom of the
  form, and restores the standard enabled control treatment.

### Saving

- Description is single-line.
- Save stays actionable for invalid input, so required markers and inline validation can
  explain the errors.
- `Cmd+S` and `Ctrl+S` follow the same save path as the buttons. A successful edit stays
  on the editor, matching Secrets; creation stays on the one-time-secret view.
- A failed save shows the same `alert-danger` summary with the warning-triangle icon used
  by the Secret editor, while keeping field-level feedback.
- Clear the raw secret on route exit or unmount, and ignore stale saves.

### Advanced resource scoping

- Uses the same collapsed shadow-card, header, and chevron pattern as **About User
  Integrations**.
- Keeps the shared `required_headers` and `resource_pattern` fields, and enforces Agent
  Gateway's canonical values: blank is appliance-wide, and every nonblank pattern is
  `TENANT:${one-header}:<bounded-resource-selector>` with every alternative starting in a
  known resource kind.
- The tester uses the compact sample-header and **Sample entity ID** rows, plus Agent
  Gateway's resource-kind selector and canonical target.
- Static patterns, repeated or multiple placeholders, and tenant-wide catch-alls block
  save.
- Header validation regexes match the entire value: `\d` means one digit and `\d{4}`
  means four. Show this rule in the tester, and render **no match** for a failed sample.
- Warn that non-literal header patterns let the holder choose any matching tenant.
- Do not add a PAT-only tenant field or tenant picker.

Keep labels associated, timestamps exact, and clipboard failures visible.

## MCP Proxy write warnings

MCP Proxy create and update responses can carry `warnings`, for example when only the
modern catalog could be registered. Render them with the shared `WriteWarnings` alert
(`components/mcp-proxy/WriteWarnings.tsx`, `data-testid="mcp-proxy-write-warnings"`):

- The wizard's `CompleteStep` shows them, titles the step **MCP Proxy Created with
  Warnings**, and does not claim the proxy is ready to use.
- The edit page shows the warnings from the latest save above the editor card, and clears
  them when the next save starts or another proxy opens.

## Identities page

`pages/IdentitiesPage.tsx` orchestrates. Its page-only parts live in
`pages/IdentitiesPage/`, with tests in `pages/IdentitiesPage/__tests__/`: search,
unnamed filter, and surface links in the `useIdentityRows` hook, and the row parts
`IdentityNameCell` and `IdentityOriginBadge`.

- Each DID gets its own row, keyed by the DID, with its own actions (Trust Score, Version History, Configure Policy, Copy link).
  Managed identities that share a surface, such as parallel `from_jwt_claim` DIDs, are
  separate rows linked to the same surface. `/identities/<did>` expands that exact
  identity.
- Expansion state is a `Set` of DIDs. Rows expand and collapse independently, and a deep link
  adds to the set rather than replacing it.
- The name cell shows the display name prominently, with the shortened DID in monospace
  beside it and a copy button for the full DID. Without a name, the shortened DID and
  copy button are the primary line, with no placeholder chip. While a caller name
  lookup is pending (`display_name_pending`), a muted "resolving…" line sits above the
  DID. A name conflict shows the DID as primary with a "name conflict" marker beside it.
  A verified agent name renders as `local · host` with a verified marker, and a
  caller's Agent Card name (`agent_card`) and a managed agent's target Agent Card name
  (`target_agent_card`) are both marked unverified. A surface name shows no badge.
- The unnamed filter and its count include only rows with no name and no pending lookup.
- The **Origin** column holds the origin badge (Managed Agent or External Caller), or
  LOCAL/REMOTE for records without an origin, plus a VERIFIED badge where it applies.
- Managed rows show an origin badge, the live surface name linking to
  `/surfaces/<surface_id>`, and the credential principal as a separate field.
- When the backend sends none of the naming fields, the page renders as it did without
  them: no name line, filter, or origin badge.

| Element                                       | Test id                                                                                                                            |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Identity row                                  | `identities-row-<did>`                                                                                                             |
| Name, pending, conflict, verified, unverified | `identities-name`, `identities-name-pending`, `identities-name-conflict`, `identities-name-verified`, `identities-name-unverified` |
| Copy DID                                      | `identities-copy-did-button`                                                                                                       |
| Origin badge                                  | `identities-origin-<origin>`                                                                                                       |
| Surface link, credential principal            | `identities-surface-link`, `identities-credential-principal`                                                                       |
| Unnamed filter                                | `identities-unnamed-filter-button`                                                                                                 |

## Remote gateway Issuer DIDs

The **Remote** tab of a remote gateway starts with the **Issuer DIDs** card
(`EditGatewayPage/IssuerDidsCard.tsx`).

### Established issuer DID

- Shown read-only with a source badge: Pairing handshake or Issuer exchange.
- When absent, shows a warning **Not established** state with a **Request from peer**
  action (`POST /gateways/{id}/issuer`).
- A **Forget** two-step action calls `DELETE /gateways/{id}/issuer`.

### Trusted issuer DIDs for this connection

- Listed below, as removable rows using the two-step `DeleteButton` and
  `DELETE /gateways/{id}/trusted-issuers/{did}`.
- Added through an inline `did:`-validated form (`POST /gateways/{id}/trusted-issuers`).
- Connection-scoped. Never add a surface-level or appliance-wide issuer list.

### Elsewhere

- Mutations are gated by `gateways.edit`. View-only users still see the lists.
- The Gateways list shows a muted **ISSUER NOT ESTABLISHED** badge on active remote rows
  that have neither an established nor a trusted issuer DID.

## Feature flags

Settings → **System** → **Feature Flags** is a table of the shared `FeatureFlagRow`
(`SettingsPage/SystemTab.tsx`).

- A new flag is one row plus an optional field on `FeatureFlags` in `types.ts`.
- Its default-when-unset is expressed in `checked`: `!== false` for default on, `=== true`
  for default off.
- The switch carries `data-testid="settings-flag-<flag>"`, `role="switch"`, and
  `aria-labelledby` pointing at the row's flag-name cell, so its accessible name is the
  flag key.
- `a2a_legacy_compatibility` is default on, and every reader uses
  `isA2aLegacyCompatibilityOn` (`utils/a2aLegacyCompatibility.ts`), where unset counts as
  on, the gateway's rule. On, surfaces accept A2A 1.0 and 0.3 and generated agent cards list
  both. Off, they serve 1.0 only, and a 0.3 or version-less call gets an
  unsupported-version error.

## Schema capture and A2A versions

- Schema capture (`utils/schemaUtils.ts`) detects the protocol when none is given, in this
  order: an `ap2.` method prefix is AP2; `_meta` at the top level or in `params` is MCP; a
  known A2A method in either spelling (v0.3 slash-form or v1.0 PascalCase) or a
  `params.message` envelope is A2A; any other JSON-RPC method is MCP.
- The A2A method table mirrors `src/a2a/methods.rs`. Keep them in step.
- The A2A proxy **Agent Card** tab (`a2a-proxy-agent-card-version`) states that the
  generated card is A2A 1.0 and, following the current `a2a_legacy_compatibility` value,
  that it also carries the 0.3 fields (on) or is 1.0 only (off). It does not follow
  `[a2a] default_version`.

## Governance Audit integrations

### Category and type

- The **Governance Audit** category (`audit`) is offered in the Add and Edit integration
  category selects only to users with `audit.view` (`selectableCategories` in
  `utils/auditIntegrations.ts`), and only for Stream and Webhook
  (`AUDIT_INTEGRATION_TYPES`, which the gateway enforces too).
- In the Add wizard, choosing it narrows the type select to those two (`selectableTypes`)
  and moves Email or Slack onto Stream. The Edit page, whose type is fixed, doesn't offer
  it to Email or Slack integrations.
- Choosing it shows the shared **Governance Audit** card
  (`components/integrations/AuditIntegrationCard.tsx`, `integration-audit-card`) at the
  top of the right column. For Stream and Webhook, the card's **Use audit record
  template** action (`integration-audit-template-button`) replaces the payload with the
  audit template (routing fields plus `record: ${AUDIT_RECORD}`), which is the `audit`
  category's Stream/Webhook sample (see [Starting content](#starting-content)).

### Query parameters

The Add wizard honours `?category=` and `?type=` once permissions have loaded, and never
overrides a category the user already picked. A requested category the user can't choose
shows the `integration-category-unavailable` warning instead of silently falling back.

### Audit Log header

The Audit Log header shows `audit-forward-button` beside Refresh for users with
`integrations.view`, only when `/integrations/config` offers the `audit` category.

- **Forwarding to N integration(s)** counts active integrations without a `tenant_id`,
  the ones the gateway forwards to, and opens the Integrations list. It adds
  "(VP Auditing off)" and a tooltip when VP Auditing is disabled in Settings › Security.
- With none, users with `integrations.edit` get **Forward records**, which opens the wizard
  at `?category=audit&type=stream`.

### Starting content

- Integration starting content comes from `utils/integrationSamples.ts`, never from
  hard-coded samples in the forms.
- `buildIntegrationSamples` builds, for the selected category, the Stream/Webhook JSON
  payload, the Email subject and body, and the Slack message text from the backend
  runtime-variable catalogue (`GET /integrations/runtime-variables`: the general
  variables plus the category's own), so a sample only uses variables that category can
  substitute. `audit` keeps its curated full-record JSON payload, and Email and Slack
  leave out `AUDIT_RECORD` and `AUDIT_VP_JWT`. `user` has a curated minimal JSON payload
  (`event_type`, `timestamp`, and the user's id, role and status) so names, emails and the
  state blocks leave the appliance only when an operator adds them.
- The Add wizard and Edit page apply it through `hooks/useIntegrationSamples.ts`. When the
  category changes, each type's content that is empty or still the previous category's
  sample (compared ignoring key order, since the gateway stores payloads with keys sorted)
  is replaced with the new sample, and edited content is kept.
- The Edit page starts only after the integration has loaded, so stored content is never
  replaced on open.

## Attaching integrations to events

`components/connection-points/IntegrationsStep.tsx` attaches integrations to a resource's
events on the gateway, connection point, user, and identity pages.

- Choosing an integration in the selector (`data-testid="integrations-step-select"`)
  attaches it at once with its template's custom (`_`-prefixed) variables set empty, opens
  its card, and drops it from the selector. Event checkboxes carry
  `data-testid="integration-<index>-event-<event type>"`.
- Missing custom variables are judged against the integration's template, not only the
  stored values.
- `requireEventTypes` (user and identity pages) blocks saving until every attached
  integration names an event, matching the API, which refuses a new mapping without one.
- The user and identity pages show a failed load as an error with no editor, so an empty
  list can never be saved over the stored mappings, and a failed save as an error, never as
  success. Save buttons are `user-integrations-save-button` and
  `identity-integrations-save-button`.

## Validation

After frontend edits, prefer these checks when relevant:

1. `npm run lint`
2. `npm run lint:fix`
3. `npm run format`
4. `npm run test -- --watchAll=false`

When only page architecture is touched, prioritize lint and format first.

## Source of truth

Consult these files before inventing new patterns:

1. `www/default/src/dashboard.css`
2. `www/default/src/pages/AuthenticatedApp.tsx`
3. `www/default/src/components/shared/SearchInput.tsx`
4. `www/default/src/components/shared/UserAvatar.tsx`
5. `www/default/src/context/AppContext.tsx`
6. `www/default/src/context/PermissionsContext.tsx`

If these instructions and live code disagree, follow the live code and update this file
afterward.
