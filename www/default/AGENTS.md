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
   first `directory:` entry (else the only mediator, else nothing; never a stored provided
   record) and marks it in no other way. The dropdown lists a directory mediator once, as its
   `directory:` entry. The Mediators page renders every mediator with `provided: true` read-only
   (no ping or edit; Delete only when the list marks the record `deletable`: the directory
   stopped offering it, or none is configured), shows no badge or
   warning for them, and shows the stored `provided` record instead of the entry when one exists
   for the DID. An operator-added mediator with the same DID is a separate row and never hides
   the entry. The wizard's mediator step shows a failed load above the empty-list message and
   offers a Refresh button (`wizard-mediator-refresh-button`) in that state and below the list, since
   a directory can take a moment to answer after the gateway starts; a load error shows as
   `wizard-mediator-load-error`.

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
- **Public access** is a switch in the Access Point panel (`access-point-public-switch`, with an
  always-visible `access-point-public-warning` while on). It writes `access_point.public`, which
  is surface-level (an `ACCESS_POINT_IDENTIFIER_FIELDS` entry, never a variant override). A
  surface stored without the field sends none until the operator flips the switch, so saving it
  keeps its rules. The Access Point and Caller Context elements carry `public` and
  `caller_authentication.on_failure` through a load and save unchanged. `validateSurfacePayload`
  owns the save prompts, listed before its other warnings:
  - No Caller Context and Public access off, on a new surface or one stored with
    `public: false`: a blocking error toast, "This Access Point is closed to all callers. Add a
    Caller Context, or turn on Public access.", whose **Show me** selects the Access Point. No API
    call is made.
  - Public access on: a `warning` toast after every successful save, "Warning: This Access Point
    is public. …".
  - Stored without `public` and no Caller Context: the save goes ahead, then a `warning` toast,
    "Warning: This Access Point has no Caller Context. …".
  Post-save warnings go through `showSurfaceSaveWarnings` (`elements/saveWarnings.ts`) as
  `warning` toasts, at most three.
- **Transit Settings** has no listener authentication control: the gateway does not support
  `transit.source_auth` and refuses a save that sets it. The **Transit Token Mode** option
  says the embedded token is signed and readable by the agent, not encrypted.
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
- **Authorization server discovery** (`caller-auth/CallerAuthDiscoverySection.tsx`) edits
  `caller_authentication.protected_resource` in the Caller Context editor of an MCP surface whose
  method is JWT Bearer. Turning it on prefills the resource with the Access Point's https listener
  URL plus its route (left empty otherwise), empties Accepted Audiences, turns token forwarding
  off and sets the `Authorization` header with the `Bearer` scheme; each of those controls stays
  locked while discovery is on, once it holds that value. Authorization servers (1 to 8) and
  scopes are lists checked as each value is added, and `protectedResource.ts` mirrors the
  gateway's save rules, which block Save. Leaving JWT Bearer drops the setting. A variant shows
  the resource it advertises, `<resource>$<alias>`, and keeps its own setting. A failed save whose
  message names the setting shows in the section and in the sidebar, which also shows whether
  discovery is on.
- A PUT that leaves out a stored `protected_resource` keeps it, so Save sends a setting the
  operator switched off as `protected_resource: null` in the same PUT
  (`withDroppedProtectedResourcesRemoved`), for the surface and each variant. A save that fails
  leaves it in place. The default variant's note says it also answers on the surface's route
  with the resource as written.

| Element                                                        | Test id                                                                                                                                                                                            |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Discovery switch, resource, use listener URL                   | `caller-auth-discovery-switch`, `caller-auth-discovery-resource-input`, `caller-auth-discovery-use-listener-url-button`                                                                            |
| List, where `<list>` is `authorization-server` or `scope`      | `caller-auth-discovery-<list>-input`, `caller-auth-discovery-add-<list>-button`, `caller-auth-discovery-<list>-<index>`, `caller-auth-discovery-remove-<list>-<index>-button`                      |
| Variant resource, default variant note, rules explainer toggle | `caller-auth-discovery-variant-resource`, `caller-auth-discovery-default-variant-note`, `caller-auth-discovery-context-toggle`                                                                     |
| Errors                                                         | `caller-auth-discovery-save-error`, `caller-auth-discovery-rules-error`, `caller-auth-discovery-resource-error`, `caller-auth-discovery-<list>s-error`, `caller-auth-discovery-<list>-input-error` |
| Sidebar status and error                                       | `caller-auth-panel-discovery-status`, `caller-auth-panel-discovery-save-error`                                                                                                                     |

## Trust Check

- A Trust Check on a Managed Agent → Transit Point arrow belongs to that Transit Point
  (slot `request:trust-check-transit_points_trust_check_list`, node
  `trust-check-<transit point node id>`, parented on the Transit Point). The Transit Point
  factory writes it to `transit.points[i].trust_check_list`; the trust-check element's own
  `buildPayload` skips Transit-Point-parented nodes. A new one can be dropped only on A2A and AP2
  Transit Points (`makeSurfaceSlotFilter`). A stored list on an MCP or HTTP Transit Point (a
  migrated copy) still hydrates onto that Transit Point's arrow and saves back, so it can be
  kept or removed; once removed it cannot be added there again. Such a copy is read-only
  (`readOnlyTrustCheckProtocol`): the sidebar panel and fullscreen editor say "Trust Checks can't
  be changed on an MCP Transit Point; keep or remove this migrated copy.", the sidebar button
  (`trust-check-panel-configure`) reads "View Queries…" instead of "Configure Queries…", the
  fullscreen query list sits in a disabled `fieldset` (no field edits, add or remove query) and
  has no Save. It keeps the stored wire entries (`STORED_TRUST_CHECK_LIST_KEY`) and saves them
  back exactly as loaded, never rebuilt from the panel's queries. A2A and AP2 copies stay
  editable and are rebuilt from their queries.
- A node parented on a Transit Point is that Transit Point's leg whatever its slot id says
  (`trustCheckLeg(node, allNodes)`); otherwise the slot decides, and a node with no known slot is
  the caller leg. Only a node in the Managed Agent slot is the Managed Agent's own leg. An empty
  blob placeholder with no real arrow (no known slot and parented on neither the Access Point
  nor a Transit Point, such as an old `_edge: 'ma-tp'` placeholder on the Managed Agent) is
  dropped on load.
- The Managed Agent's own target-leg Trust Check sits on the Managed Agent → External Target
  arrow (slot `request:trust-check-target_trust_check_list`, node `trust-check-target`) and is
  offered and saved only for `a2a-proxy://` and `fabric://` targets. On any other target (for
  example after switching the endpoint to a URL) the node is an error-severity feature
  dependency: the canvas rings it, Save and switching variants are blocked with "Remove it or
  switch the target" (`dependencyErrorBlocker`, the same toast and **Show me**), and the panel
  shows `trust-check-panel-managed-agent-target-warning`. When every Transit Point already
  carries the same queries, the message and banner add "The same checks already run on this
  surface's Transit Points, so removing it loses nothing." Loading such a surface, applying a
  template or switching variants (`hydrateSurfaceCanvas`) drops that node automatically when the
  surface has Transit Points and every one carries the same queries (ids and names aside), and
  reattaches anything chained after it; a node whose queries are missing from any Transit Point,
  or on a surface with no Transit Points, stays and blocks Save. Editing the endpoint never drops it. Feature-dependency rules receive the
  node (`getDependencyWarnings(type, config, ctx, node)`) to tell legs apart, and a rule's
  `message` may be a function of the surface.
- Every surface write sends `trust_check_split: true` at the top level, and every Surface
  Template create and update sends it inside `surface` (`withTrustCheckSplit` and
  `templateWithTrustCheckSplit` in `src/api.ts`). The gateway migrates a write without it that
  carries `target.trust_check_list` as the old surface-wide shape. A template import uploads the
  file unchanged, so the gateway converts an old export.
- Trust Check config comes only from the stored payload (`payloadOwnsConfig`); the canvas blob
  supplies position only. A blob `parentId` never moves a Trust Check between the Managed Agent
  and a Transit Point or between Transit Points, and a blob node is matched to a hydrated one
  only when their slot ids agree or either has no slot id, so a stale node from the old shared
  layout does not come back. An empty Trust Check placeholder in the blob (no queries, `isBlobPlaceholder`) is kept, except
  one in the Managed Agent slot when the stored target is not `a2a-proxy://` or `fabric://`, and
  one with no real arrow (see the leg bullet above).
- `hydrateSurfaceCanvas` places a Trust Check the blob has no position for at the middle of
  its arrow, so a migrated per-Transit-Point Trust Check keeps the rest of the saved layout
  instead of triggering auto-layout.
- Trust Check snaps to the Access Point → Managed Agent, Managed Agent → Transit Point and
  Managed Agent → External Target arrows (`registry.snapsToArchetype`). Its `edgeSnap.allows`
  drops Managed Agent → External Target unless the Managed Agent targets `a2a-proxy://` or
  `fabric://`; the canvas passes the target endpoint as the snap context, so on a URL target a
  Trust Check dropped near that arrow snaps to Access Point → Managed Agent or Managed Agent →
  Transit Point. Elements without `edgeSnap.allows` snap exactly as their archetype list says.
- A Transit Point's `trust_check_migrated: true` moves onto its Trust Check node's config at
  hydration. A flagged node shows a canvas badge (`syncTrustCheckReviewBadge`, run by the full
  canvas rebuild and the config update, so it disappears on **Keep** and returns on undo), and
  its sidebar panel and fullscreen editor show the shared `MigratedTrustCheckWarning`
  (`elements/trust-check/MigratedTrustCheckWarning.tsx`, an `InfoBanner` warning) with **Keep**. **Keep**, saving edited queries, or removing the node
  drops the flag from the next save; untouched flagged Transit Points keep it.
- `MigratedTrustChecksSummary` sits under the canvas top bar in `.surface-canvas-notices`:
  "N Transit Points need Trust Check review" ("1 Transit Point needs …" for one), counting each
  Transit Point with a flagged migrated copy, on the canvas and in every other loaded variant
  snapshot (it says how many are in other variants), hidden at zero.

| Element                            | Test id                                                                              |
| ---------------------------------- | ------------------------------------------------------------------------------------ |
| Per-Transit-Point scope line       | `trust-check-panel-transit-point-scope`                                              |
| Fullscreen leg label               | `trust-check-fullscreen-leg`                                                         |
| Managed Agent URL-target warning   | `trust-check-panel-managed-agent-target-warning`                                     |
| Read-only migrated copy line       | `trust-check-panel-read-only`, `trust-check-fullscreen-read-only`                    |
| Fullscreen query list             | `trust-check-fullscreen-queries`                                                     |
| Migrated warning and Keep          | `trust-check-panel-migrated-warning`, `trust-check-fullscreen-migrated-warning`, each with `-keep` |
| Review summary                     | `surface-migrated-trust-checks-summary`                                              |
| Migrated canvas badge              | `surface-node-trust-check-migrated-badge`                                            |

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

### Trust Recorder panel

The Trust Recorder panel (sidebar and fullscreen) shows a **Last outcome** row from
`GET /surfaces/{id}/trust-recorder-status` (`apiClient.getSurfaceTrustRecorderStatus`), rendered
by one shared component, `components/trust-recorder/TrustRecorderLastOutcome.tsx`. It reads the
surface id from `SurfaceMetaContext` and is hidden outside the builder, while a surface is
being created, and without an id. States: a quiet **Loading…**, **No attempt yet** for a
`null` status, the state badge with reason text, relative time (absolute in its `title`) and
the counts summed across entries, and **Status unavailable** when the fetch fails; a failed
fetch never breaks the panel. Test ids: `trust-recorder-last-outcome` with `-state`,
`-reason`, `-time`, `-counts`, `-loading`, `-empty`, and `-unavailable`.

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

## Audit page: policy changes

The seven policy change events (`policy_created`, `policy_updated`, `policy_deleted`,
`policy_attached`, `policy_detached`, `policy_attachment_changed`, `policy_change_refused`) are
read with `policyChange` (`pages/AuditPage/auditHelpers.ts`), never by indexing `entry.event`
in components. It fills `surface_variant` from `variant` on records written before the rename.

- The list row and the panel title use `describeEntry`: one sentence saying which policy changed
  where, and a detail line naming the actor and why (`definition_deleted`, `ownership`). Refused
  changes are red, deletions and detachments amber, the rest neutral.
- The footnote shows the actor instead of the caller. Records hold ids only; `useUserNames`
  resolves user ids to usernames from `/users` and keeps the id when the list is not readable.
  It is called once, in `AuditPage`, and asks for the list only when the page shows a policy
  change and the viewer has `users.view`; the resolver is passed down as the `userName` prop.
  Don't call it per row. The names are cached per session token, so signing out and in (as
  anyone) loads them again and never shows the previous session's. Within a session a 403 is
  kept until the page reloads; any other failure is retried on the next visit. The status comes
  from `ApiError` (`api.ts`): read `error.status`, not the message text. Only `apiClient`
  requests the server answers with an error status other than 401 throw it; a 401 (session
  expired), a timeout and the export and download helpers throw a plain `Error`.
- The evidence pane shows only **Details** for a change (no request journey or signed
  presentation), grouped as Change, Policy, Where and Refusal. The policy links to the Policies
  tab of its type, the target to its surface or gateway page.
- Every value is rendered as React text; record fields come from the gateway and are untrusted.

## Audit page: surface variants and refusals

Records of a surface request carry `surface_variant`: a configured alias, `_base_` (the base
surface served it) or `_unknown_` (the URL named a variant the surface doesn't have). Read and
word it only through `utils/surfaceVariant.ts`, which the Metrics page uses too.

- The Details list shows it as **Variant** under Surface & routing ("Base surface", "Unknown
  variant" or the alias), and under Where for a policy change.
- The narratives say "on variant beta", "on the base surface" or "on an unknown variant (“typo”
  was asked for)", naming the refusal's `requested_variant`. A base slot change reads "on the base
  surface and the variants that inherit it". A gateway-scope decision reads "Gateway-wide policy
  “X”, applied to Orders, variant beta", and its Scope row is **Gateway (all surfaces)**.
- `request_rejected` is read with `requestRejected` (`auditHelpers.ts`), titled **Request
  refused** in the deny tone, with a Refusal group of Stage, Reason, HTTP status, JSON-RPC error
  and Requested variant. `http_status` is absent on a Fabric refusal and `rpc_error_code` present
  only when the caller got a JSON-RPC error; a row shows only when the value is recorded.
- `requested_variant` is caller-chosen text: render it as React text only.
- The Metrics page shows the `$alias` badge for a configured alias only, never for `_base_`.

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
unnamed filter, recorder filter, and surface links in the `useIdentityRows` hook, and the row
parts `IdentityNameCell`, `IdentityOriginBadge`, and `IdentityRecorderChip`.

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
- **Recorder** status comes from the optional `trust_recorder` field on an identity (types in
  `types.ts`), present only when the identity's surface has a Trust Recorder. It is the
  gateway recorder's last known outcome, not a live registry check. When any identity has it,
  the table gains a **Recorder** column and the filter row gains a **Recorder** select; with
  none, neither appears and the page looks as before.
  - The column holds `IdentityRecorderChip`, a shared `Badge` (never colour-only: the text is
    always shown) in a focusable button, so the tooltip opens on hover and keyboard focus and a
    click does not expand the row. Labels and tones come from `utils/trustRecorderStatus.ts`:
    Recorded (success), Partly recorded (warning), Failed (danger), Skipped (secondary), Not
    attempted yet (light). The tooltip gives the last attempt (relative plus absolute) or
    "No attempt yet", the overall reason text, and one row per entry with the registry id, its
    state, its reason, and "created N, already existed N, failed N". Reason codes map to fixed
    text; no registry error text is ever shown.
  - The **Recorder** select (`recorderFilter.ts`, a pure predicate) offers All, Recorded,
    Partly recorded, Failed, Skipped, Not attempted yet, and No recorder (identities without
    the field). It is page state like the unnamed filter, and combines with the search and the
    unnamed filter (AND).
  - A websocket identity update replaces the whole identity, so a changed `trust_recorder`
    outcome shows without a reload. The backend includes an identity in the delta when its
    recorder outcome changes; adding or removing a Trust Recorder shows on the next update or
    reload.

| Element                                       | Test id                                                                                                                            |
| --------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Identity row                                  | `identities-row-<did>`                                                                                                             |
| Name, pending, conflict, verified             | `identities-name`, `identities-name-pending`, `identities-name-conflict`, `identities-name-verified`                               |
| Copy DID                                      | `identities-copy-did-button`                                                                                                       |
| Origin badge                                  | `identities-origin-<origin>`                                                                                                       |
| Surface link, credential principal            | `identities-surface-link`, `identities-credential-principal`                                                                       |
| Unnamed filter                                | `identities-unnamed-filter-button`                                                                                                 |
| Recorder filter                               | `identities-recorder-filter`                                                                                                       |
| Recorder chip                                 | `identities-recorder-chip-<state>`                                                                                                 |
| Recorder tooltip                              | `identities-recorder-tooltip`                                                                                                      |
| Tooltip last attempt, reason                  | `identities-recorder-last-attempt`, `identities-recorder-reason`                                                                   |
| Tooltip registry entry                        | `identities-recorder-entry-<registry id>`                                                                                          |

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

## Laptop layouts

Pages must stay usable at the common laptop viewports, 1280x720 to 1920x1080 with the
sidebar expanded; `ui-tests/specs/laptop-layout.spec.ts` checks each page at five of them.

### Audit Log

The Audit Log is a list of entries and a detail panel (`pages/AuditPage/`, rules under
_Viewport-filling master/detail_ in `dashboard.css`).

- **Side by side** from 1440px wide: the page fills the viewport between the topbar and
  the footer, so the document does not scroll, and the list and the evidence body scroll
  inside their panels. The card body is a two-column grid (`.audit-shell` is
  `display: contents`): the "About the Audit Log" banner sits above the list in the left
  column and the detail panel takes the full height of the right one, so at 1536x864 the
  list and the evidence body are each still at least 300px tall.
- **Stacked** below 1440px wide (`@media (max-width: 1439.98px)`): there the two panels
  are too narrow to read (about 510px each at 1366px, each entry over 230px tall). The
  list sits above the detail and the page scrolls as one: no scroll box inside the page
  and no overlay drawer.
- **Pinned filters** while stacked: `.audit-filters` (search and filters) and
  `.audit-card-header` (title, Forward records, Refresh) are `position: sticky` under the
  70px topbar. `AuditPage` publishes their heights as `--audit-filters-height` and
  `--audit-header-height` with a `ResizeObserver`, since the filters wrap; the header's
  `top` and the scroll margins below use them. Sticky needs every ancestor up to the
  document to leave overflow visible or `clip`: `#content-wrapper` hides its sideways
  overflow on every page, so the stacked rule switches it to `overflow-x: clip` on the
  Audit Log, and `.audit-card` clips instead of hiding.
- **Scroll on select**: while stacked, selecting an entry smooth-scrolls the page so the
  detail panel starts just below the pinned filters and header (`scroll-margin-top`). `AuditPage`
  decides "stacked" from the computed `flex-direction` of `.audit-shell` at click time,
  so the breakpoint lives only in CSS. The default selection on load, a page change and a
  filter change do not scroll, and side by side selecting never scrolls. Clicking the
  detail title scrolls back to the entry, which lands fully below the pinned area.

### List tables

List pages show their rows in a `.table-responsive` table (Surfaces, MCP Proxies, Secrets,
Certificates). No list table scrolls sideways at a laptop viewport, so every column keeps
room for its text.

- Badges in table cells wrap. Bootstrap sets `white-space: nowrap` on `.badge`, so one long
  tag or owner name fixes a column at its full length and squeezes or pushes out the
  others. Add `text-wrap text-break` to a badge that shows a user-supplied value (tags,
  owner names) so it wraps inside its cell and the full value stays readable. Short badges
  still sit on one line.
- Do not truncate such a value to make it fit; wrap it.

### Page headers and charts

- **Tasks header**: the shared `.card-header.py-3` is a centred flex row, which would put the
  tag filter row beside the title. The Tasks header adds `flex-column align-items-stretch`,
  so the filter row sits under the title row and Refresh stays at the header's right end.
  The shared rule is unchanged.
- **Metrics flow chart labels**: node labels are at most 25 characters. A source, identity
  or target label longer than that is cut to 22 characters plus `...` by `cutLabel` in
  `MetricsFlowVisualization.tsx`, so a long DID cannot run across its neighbours or past the
  chart edge; `Anonymous` is unchanged and the hover tooltip shows the full value.
- **Identities table**: ten columns, so `.identities-table` (`dashboard.css`) keeps
  Bootstrap's `table-sm` horizontal cell padding (0.25rem) instead of the 0.75rem of the
  shared `.table-sm` rules. The table fits its box at 1280px wide with every row action
  inside it; the DID keeps its title and copy button.
- **Connection Points actions**: the row actions sit in a 6rem wide wrapping block (two
  buttons per line) with no left margins, so the Actions column stays near 120px and the
  Name and Mediator columns keep their room. Add a new row action inside that block.
- **Credential Audit columns**: only Time, Event and the chevron column keep a fixed width.
  Intent takes what its content needs, and its badge wraps (`text-wrap text-break`), so
  Downstream Provider and Agent Surface keep room for their linked names.

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
