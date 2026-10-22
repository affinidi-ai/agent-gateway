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
9. Mediator lists may contain directory entries (`directory:*` ids), and stored records
   created from them carry `provided: true`. The Create Connection Point wizard pre-selects the
   first `provided` mediator (else the only mediator, else nothing) and marks it in no other way;
   the Mediators page renders every mediator with `provided: true` read-only (no ping, edit or
   delete) and shows no badge or warning for them.

## Toasts

`showToast` and `showUndoToast` (`utils/toaster.ts`) render the message and the action label as
text (`textContent`), never as HTML, so a name or a server error message in a toast cannot run
script. Pass plain text only: markup such as `<b>` shows literally, and callers must not
escape the text themselves.

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
- **Send delegated credentials over Fabric** is one shared section
  (`_shared/FabricDelegatedCredentialsSection.tsx`) used by the Managed Agent and Transit
  Point panels. It writes `fabric_delegated_credentials` and appears only when that route
  is `fabric://` and the surface has credential bindings (a Credential Delegation row, or
  the Transit Point's own `transit_credentials`). It defaults to off. When on, an
  always-visible warning names the receiving gateway. Test ids:
  `<managed-agent|transit-point>-fabric-delegated-credentials-switch` and
  `-warning`. There is no surface-wide switch.
- **Entry point URL** is the label for an Access Point's composed URL, with "The URL used to
  access this gateway" behind its `FieldHelp`. It shows at the top of the Access Point panel
  and as a banner along the top of the canvas, both rendered by `RouteListenerBanner`
  (`_shared/RouteListenerSection.tsx`) with the shared `CopyButton`; a failed copy shows an
  error toast. The canvas banner sits in the `.surface-canvas-topbar` flex row between the
  variants widget and the toolbar, so it shrinks instead of sliding under either; only its
  URL text truncates, and it leaves out the info icon. The Managed Agent panel does not
  repeat the URL. Test ids: `access-point-entry-point-url` and `surface-entry-point-url`,
  each with `-help` and `-copy-button`; the Transit Point's **Listener URL** banner is
  `transit-point-listener-url`.
- A new surface is named `<protocol>_surface_<n>` (`surfaceNaming.ts`), where `n` is one more
  than the existing surfaces of that protocol, skipping names already taken. The name follows
  the protocol until the user types a different name, from the Name field or the Config tab
  JSON; typing the generated name back keeps it generated. It never derives from the route. The
  unsaved-changes check ignores the generated name, so the surface list arriving never marks
  the page dirty and edits made while it loads still do.
- **Networking** retryable status codes: an empty field means the gateway default and
  saves no `retryable_status_codes`, and its placeholder says so. The **Retry on
  connection errors only** switch saves an empty list and disables the field. A field
  that isn't a comma-separated list of HTTP status codes (100 to 599) blocks Save. Test
  ids: `networking-retry-status-codes-input` and
  `networking-retry-connection-errors-only-switch`.

## Trust Recorder

- The sidebar panel and each entry in its fullscreen editor show the shared
  `NoSurfaceIssuerWarning` (`elements/trust-recorder/NoSurfaceIssuerWarning.tsx`, an
  `InfoBanner` warning variant, never the amber `alert-warning`, which fails contrast) while
  `SurfaceMetaContext.issuerId` is empty, or names an Issuer that is not in the Issuer list, and
  an entry's Authority is **Use surface Issuer** (`usesSurfaceIssuer`). The backend skips such an
  entry and writes no records. The title tells the two cases apart: "No Issuer is selected for
  this surface" and "This surface's Issuer no longer exists".
- `useSurfaceIssuerProblem` calls the shared Issuer list (`getIssuers`), and refetches it once
  before reporting an Issuer as deleted. It stays quiet while the list loads and when it cannot
  be loaded.
- It is a warning, not save validation. It stays hidden for entries with an explicit
  Authority, and outside a surface editor, where there is no surface Issuer to check.
- The entry **Issuer** is only the Entity of custom records whose Entity Target is Issuer DID.
  Never describe it as signing records or setting the Authority.
- The fullscreen editor opens with a collapsed `InfoBanner` explaining Authority, Entity, the
  entry Issuer and the surface Issuer, linked to the Trust elements guide.

| Element                            | Test id                                                                                                                           |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Panel warning                      | `trust-recorder-panel-no-surface-issuer-warning`                                                                                  |
| Entry warning                      | `trust-recorder-entry-<index>-no-surface-issuer-warning`                                                                          |
| Explainer toggle, body, guide link | `trust-recorder-fullscreen-context-toggle`, `trust-recorder-fullscreen-context-body`, `trust-recorder-fullscreen-context-doclink` |
| Canvas node, by element type       | `surface-node-<type>`, for example `surface-node-trust-recorder`                                                                  |

## Access Tokens page

Management personal access tokens live in the Secrets page's **Access Tokens** tab.

### Routes and layout

- Create and edit use full-page routes with the same visual pattern:
  `/access-tokens/new` and `/access-tokens/:id`.
- `/access-tokens/new` presets the form from its query string so an external link can
  open a filled-in form: `name`, `description`, `scope` (repeatable) or `scopes`
  (comma-separated), `expires_at` (ISO 8601; clears **Never**), `resource_pattern`, and
  `header=<name>:<pattern>` (repeatable). The link never saves; the operator still clicks
  Create, and preset scopes they cannot grant render as red unavailable pills. The
  resource-scope card opens when a pattern or header is preset. The link survives sign-in:
  a signed-out visitor sees the login page at that URL, and `loginNextTarget` re-encodes the
  query and returns to the form after passkey or SAML login (the gateway's SAML return-target
  allowlist accepts `/access-tokens/new`).
- The form footer always has a **Copy creation link** button
  (`access-token-copy-permalink-button`), in create and edit mode, that copies an absolute
  `/access-tokens/new` URL encoding the current name, description, scopes, expiry, resource
  pattern and headers in the parameters above. It is always enabled, even for an incomplete
  or invalid configuration; the opened form validates on Create. When the settings are
  invalid (a resource pattern or required header the form rejects, or a refused expiry) the
  copy still happens and a `warning` toast says the opened form will not create a token until
  they are fixed; missing fields and scopes the operator cannot grant do not warn. The toast
  text never repeats what was typed. In edit mode it sits beside
  **Revoke token** and the link carries no expiry.
- A successful create replaces the editor with the secret page. The secret isn't rendered:
  the field shows a masked placeholder and **Copy** puts the real value on the clipboard.
  If copying fails (clipboard denied, or no clipboard API on a plain-HTTP origin), the
  field shows the secret, selected on focus, so it can be copied by hand.
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

- Uses the same collapsed shadow-card, header, and chevron pattern as **About the Audit
  Log** (`pages/AuditPage/AuditInfoBanner.tsx`).
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

## Secret editor

- `/secrets/new` and `/secrets/:id` have one save button, at the bottom of the form beside
  **Delete Secret** (`secret-save-button`); `Cmd+S` and `Ctrl+S` follow the same path. In
  edit mode, saving is possible only while **Update Secret Value** is checked or the name,
  description, type or tags differ from the loaded secret, so undoing an edit disables it.
- The API never returns a stored secret value, so the editor never shows one. In edit mode
  the value field is disabled with a **Stored value is hidden** placeholder until **Update
  Secret Value** is checked. Unchecking it, or a successful save, clears the entered value
  and returns the field to that hidden state.
- **Show the value you entered** (`secret-value-reveal-checkbox`) appears only while the
  value field is editable, and reveals only what was typed or generated on this page. The
  value field is `secret-value-input`.

## Policy definition editor

The **Policy Instructions & Examples** panel on the Create Policy Definition page is collapsed
by default. Its title is a heading holding one full-width button (`policy-instructions-toggle`,
with `aria-expanded` and `aria-controls="policyDefInstructions"`), so the whole header row
toggles, Enter and Space work natively, and screen readers still announce the heading. The
title is `policy-instructions-title`, the arrow `policy-instructions-chevron` sits inside the
button and flips with the state, and the body is `policy-instructions-body`. Build collapsible
panels the same way, and do not put `role="button"` on a wrapper around a heading.

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
  A verified agent name renders as `local · host` with a verified marker. A caller's
  Agent Card name (`agent_card`), a managed agent's target Agent Card name
  (`target_agent_card`) and a surface name show no badge.
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
| Name, pending, conflict, verified             | `identities-name`, `identities-name-pending`, `identities-name-conflict`, `identities-name-verified`                               |
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

## Remote gateway exposure

The **Publishing** tab of a remote gateway (`EditGatewayPage/PublishingTab.tsx`) edits the
peer's Fabric exposure through `PUT /gateways/{id}/exposed-surfaces`.

- A radio group picks the mode: **No surfaces** (`none`), **Selected surfaces** (`list`), or
  **All surfaces** (`all`). The surface checklist shows only in **Selected surfaces** mode.
- The page reads the mode with `exposureModeOf` (`utils/gateways.ts`), which keeps the earlier
  meaning for a record without `exposure_mode`. A form without a mode shows **No surfaces**.
- Save sends `exposure_mode` with the list, and an empty list outside `list` mode.

| Element                        | Test id                                                              |
| ------------------------------ | -------------------------------------------------------------------- |
| Mode radio                     | `gateway-exposure-mode-<mode>`                                       |
| Surface checklist, one surface | `gateway-exposure-surfaces`, `gateway-exposure-surface-<surface_id>` |
| Save button, summary           | `gateway-exposure-save-button`, `gateway-exposure-summary`           |

## Feature flags

Settings → **System** → **Feature Flags** is a table of the shared `FeatureFlagRow`
(`SettingsPage/SystemTab.tsx`).

- A new flag is one row plus an optional field on `FeatureFlags` in `types.ts`.
- Its default-when-unset is expressed in `checked`: `!== false` for default on, `=== true`
  for default off.
- The switch carries `data-testid="settings-flag-<flag>"`, `role="switch"`, and
  `aria-labelledby` pointing at the row's flag-name cell, so its accessible name is the
  flag key.
- `mediator_federation` is default off and experimental. On, the Connect via OOB wizard's
  details step (`gateway-add-via-oob/EnterDetailsStep.tsx`) shows a mediator picker
  (`wizard-oob-acceptor-mediator`) that lists only mediators with `status === 'active'` and
  `registered` true, and sends the choice as `acceptor_mediator_id`; the default option
  sends nothing. When the list is empty it shows `wizard-oob-acceptor-mediator-empty`, and
  when `/mediators` fails, `wizard-oob-acceptor-mediator-load-error`.

## Restore from backup

Settings → **System** → **Restore from Backup** (`SettingsPage/SystemTab.tsx`) accepts
`.agbak` and legacy `.tgwbak` files. The legacy support is stated on the page
(`data-testid="restore-legacy-format-note"`), and the wrong-file toast names both extensions.
The hidden file input is `data-testid="restore-file-input"`.

## Schema capture and A2A versions

- Schema capture (`utils/schemaUtils.ts`) detects the protocol when none is given, in this
  order: an `ap2.` method prefix is AP2; `_meta` at the top level or in `params` is MCP; a
  known A2A method in either spelling (v0.3 slash-form or v1.0 PascalCase) or a
  `params.message` envelope is A2A; any other JSON-RPC method is MCP.
- The A2A method table mirrors `src/a2a/methods.rs`. Keep them in step.
- A2A versions and message validation are per surface, not feature flags. The Access Point
  panel of an A2A or AP2 surface has an **A2A Protocol** section (`access-point-a2a-protocol`): a
  checkbox per version (`access-point-a2a-version-0.3`, `-1.0`, both checked by default) and a
  **Message validation** dropdown (`access-point-a2a-validation`) with **Off**, **JSON-RPC
  envelope** (the default) and **Envelope + A2A fields**, each with field help. Keep the option
  labels short: the sidebar is narrow, and the field help explains each level, including that only
  an appliance-wide administrator can choose Off (the API refuses it from tenant-scoped tokens). The node keeps
  them flat as `a2a_accepted_versions` and `a2a_validation`; `access-point/a2aSettings.ts` maps
  them to and from the payload's `access_point.a2a`, which every A2A and AP2 save sends.
- With no version checked, the section shows `access-point-a2a-versions-error` and a
  blocking dependency error stops the save.
- The versions follow the base Target, as the gateway decides them; the validation lock follows
  the Target in view. Panels and the save gate read the base from `base` (`BaseSurfaceView` in
  `elements/types.ts`: the base snapshot's Target endpoint and Access Point canvas config, given
  only while a named variant is active, from `useVariantSnapshots().getBaseSurface()`); without it
  the Target in view is the base. `a2aTargetView` in `access-point/a2aSettings.ts` decides both.
- When the base Target is an `a2a-proxy://` endpoint, the version checkboxes are disabled and show
  the gateway's fixed versions, and `access-point-a2a-proxy-locked` gives the reason when they
  include 0.3: the versions the stored block of a surface loaded with an A2A proxy base Target is
  served with, or both when it has no block (`storedA2aProxyVersions`, kept on the node, and on the
  base view's Access Point config, as `a2a_locked_versions`; never taken from a canvas blob alone;
  `syncAccessPointIdentifiers` keeps a snapshot's versions when the synced block names none),
  and 1.0 only for a new surface or one whose base Target was just moved to a proxy. In a view whose Target is a URL it adds that message validation applies to this
  Target. The payload's `access_point.a2a` then carries only `validation`, so the gateway keeps its
  fixed versions; the page sets it to `envelope` on save when no variant points the Target at a URL
  (`withA2aValidationSettled`). The at-least-one-version save gate does not apply.
- When the Target in view is an `a2a-proxy://` endpoint, **Message validation** is disabled at
  **JSON-RPC envelope**. If the base Target is a URL, the versions stay editable and
  `access-point-a2a-proxy-envelope-only` says that this Target checks only the envelope and takes
  the surface's versions.
- When the Managed Agent element targets an A2A proxy, its panel shows only the A2A Proxy select;
  the version note lives on the A2A proxy's **Agent Card** tab.
- The A2A proxy **Agent Card** tab (`a2a-proxy-agent-card-version`) states that the generated
  card lists the versions the exposing surface accepts, as its Access Point shows them; that a new
  surface whose Target is the proxy accepts only A2A 1.0, so its callers must send the
  `A2A-Version: 1.0` header and should use A2A 1.0 methods such as `SendMessage`; and that requests
  to the proxy are checked only for the JSON-RPC envelope. The header requirement is stated for a
  new surface only, because a variant with a URL base Target, or an older surface, can accept other
  versions. It does not follow `[a2a] default_version`.

## Integrations

An integration joins one **endpoint** (where to deliver) and one **event set** (which events)
with a template. Integrations are not attached to gateways, connection points, users or
identities: an integration receives every event of its event set, from every resource.

### API and permissions

- Every call to `/v1/integrations` goes through `src/integrationsApi.ts`, which types each
  route. Do not call `apiClient` for integrations directly. `getCatalog()` loads the event
  catalog once and adopts the gateway's placeholder syntax (`setVariablePattern` in
  `utils/templateVariables.ts`).
- Routes live in `pages/integrationRoutes.tsx`: `/integrations` needs `integrations.view`;
  `/integrations/new`, `/integrations/:id`, `/integrations/endpoints/new|:id` and
  `/integrations/event-sets/new|:id` need `integrations.edit`. The sidebar item needs
  `integrations.view`.
- In the lists, Add, Test and Edit need `integrations.edit`, and Delete `integrations.delete`.
- Audit events are handled like every other event. No integrations page, editor or list control
  checks `audit.view`, and none is disabled or annotated because an event set, integration or
  endpoint involves audit events; the gateway checks only `integrations.*` there.
  `holdsAuditEvents` (`utils/auditIntegrations.ts`) decides behaviour only: the Event Sets tab's
  `audit` badge, the event set editor's audit journal note, and the integration editor's
  **Delivery limits**. The Audit page's own `audit.view` checks (sidebar, route, Credentials
  page tab) are separate and stay.

### Integrations page

- `pages/IntegrationsPage/` (`page-integrations`) has three tabs: Integrations, Endpoints and
  Event Sets (`integrations-tab-integrations`, `integrations-tab-endpoints`,
  `integrations-tab-event-sets`). The tab is kept in `?tab=` (`integrations`, `endpoints`,
  `event-sets`), and an unknown value opens Integrations. Only the active tab is mounted.
- `useIntegrationDefinitions` loads integrations, endpoints and event sets together, so each
  tab can name the others. One filter box serves all three tabs.
- Rows are `integration-row-<id>`, `endpoint-row-<id>` and `event-set-row-<id>`. Inside a
  row, the buttons are `<area>-test-button`, `<area>-edit-button` and `<area>-delete-button`
  (`integration`, `endpoint`, `event-set`; event sets have no test). The add buttons are
  `integrations-add-button`, `endpoints-add-button` and `event-sets-add-button`.
- An endpoint or event set in use cannot be deleted. Its Delete button is disabled, with the
  integrations using it in the title. A refusal from the gateway shows as an error toast.

### Endpoint editor

- `pages/EndpointEditorPage/` (`page-endpoint-editor`): `/integrations/endpoints/new`
  (`?type=` preselects a type) and `/integrations/endpoints/:id`. The type is chosen once
  (`endpoint-type-select`) and fixed after.
- The fields of each type come from `ENDPOINT_FIELDS` in `endpointFields.ts`, which lists only
  what the gateway's publishers read: email `cc` and `bcc`; Slack `bot_name` and
  `icon_emoji`, no channel; stream SASL only for Kafka, no AWS keys. Each field is
  `endpoint-<field>-input`; the others are `endpoint-name-input`, `endpoint-active-switch`,
  `endpoint-save-button` and `endpoint-cancel-button`.
- **Send test** (`endpoint-test-button`) tests the saved endpoint, so it is disabled while
  there are unsaved changes.
- Secret fields use `components/integrations/SecretInput.tsx`, and a stored value is never
  shown. A stored secret is kept by default and can be replaced or, when optional, cleared:
  `endpoint-<field>-replace-button`, `-clear-button`, `-undo-button`, `-keep-button` and
  `-input`.
- `-stored-secret-select` picks an appliance-wide secret instead (`hooks/useApplianceSecrets.ts`),
  saved as `$SECRET:<secret_id>`. Webhook headers have no picker, because only header values
  resolve references; they are written inside the JSON.
- A stored reference counts as a stored secret (`form.stored`, not the endpoint's `secrets`
  list, which leaves references out), so it also gets Keep and, when optional, Clear.
- `buildConfiguration` leaves kept secrets out, so the gateway keeps them. On an update it sends
  `null` for a stored secret that is cleared or left empty, such as a reference set to "None, type
  a value", since the gateway keeps one that is left out. It also sends `null` for a stored secret
  the form now hides, such as the SASL password once SASL is switched off, so no unseen credential
  stays stored.

### Event set editor

- `pages/EventSetEditorPage/` (`page-event-set-editor`): `/integrations/event-sets/new` and
  `/integrations/event-sets/:id`.
- Events are picked from the whole catalog with `components/integrations/GroupedEventPicker.tsx`,
  using the prefix `event-set`: `event-set-search-input`, `event-set-group-<group>` and
  `event-set-event-<event id>`. Families come from the catalog, and audit events are grouped
  further by their audit group.
- `?preset=audit` starts a new event set named **Governance Audit** with every audit event
  picked.
- Events the catalog no longer lists are shown, each with an `event-set-remove-<event>-button`,
  since the gateway refuses to save them. The other ids are `event-set-name-input`,
  `event-set-save-button` and `event-set-cancel-button`.
- `components/integrations/AuditEventPicker.tsx` is a thin wrapper over the same picker, for
  Settings › Security › VP Audit. There it uses the prefix `vp-audit`, the catalog from
  `GET /v1/settings/audit-events`, `vp-audit-scope-note` and `vp-audit-catalog-error`.

### Integration editor

- `pages/IntegrationEditorPage/` (`page-integration-editor`): `/integrations/new` and
  `/integrations/:id`. Its ids are `integration-name-input`, `integration-endpoint-select`,
  `integration-event-set-select`, `integration-active-switch`, `integration-save-button`,
  `integration-cancel-button` and `integration-test-button`.
- `TemplateEditor.tsx` shows the template fields of the endpoint type, from `templateModel.ts`,
  with the gateway's defaults as placeholders. Each field is `template-<field>-input`.
- The template editor also lists the variables the chosen event set fills. Each one is a
  `template-insert-<NAME>-button` that inserts the variable where the cursor is.
- Choosing an endpoint of another type starts the template over.
- **Delivery limits** (`components/integrations/AuditDeliveryLimitsSection.tsx`,
  `integration-audit-limits`, `integration-audit-max-attempts-input`,
  `integration-audit-drop-after-input`) appear only when the event set holds audit events.
  Their helpers live in `utils/auditIntegrations.ts`.
- Save and **Send test** share one check, `problem()`: missing fields, a payload that is not a
  JSON object, variables no event of the set fills, or invalid limits. Send test is disabled
  with the same reason Save gives, and posts the integration as it stands on screen
  (`testDraftIntegration`).
- `${APPLIANCE_ID}` is filled by the gateway from the **Appliance ID** in Settings › System
  Settings (`settings-appliance-id-input`), and is empty while none is set.

### Audit Log header

- The Audit Log header shows `audit-forward-button` to users with `integrations.view`. It
  counts the active integrations, with an active endpoint, whose event set holds audit
  events (`useAuditForwarding`), and opens `/integrations`.
- Integrations with audit events that are disabled, or whose endpoint is, add a warning icon
  (`audit-forward-paused-warning`) and a tooltip.
- When VP Auditing is off, the tooltip says the VP Audit Log keeps nothing while integrations
  still receive the audit events of their event sets.
- When none receive records, users with `integrations.edit` get **Forward records**, which
  opens `/integrations/event-sets/new?preset=audit`.
- The **About the Audit Log** panel (`AuditInfoBanner.tsx`) says each integration with an
  event set holding audit events receives them independently of the log, at least once, so
  receivers deduplicate on `event_id`.

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
