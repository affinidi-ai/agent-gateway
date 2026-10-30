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

| Element                 | Pattern                                                                                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Page root               | `page-<area>`                                                                                                                                             |
| Action button           | `<area>-<verb>-button`                                                                                                                                    |
| List item               | `<area>-card-<id>` or `<area>-row-<id>`                                                                                                                   |
| Wizard                  | `wizard-<name>`, `wizard-step-<name>`, `wizard-next`, `wizard-back`, `wizard-submit`                                                                      |
| Form field              | `<form>-<field>`, for example `strategy-issuer`, `provider-token-endpoint`                                                                                |
| Canvas                  | `surface-node-<type>`, `surface-canvas` (the canvas svg), `canvas-link` (each pipeline link)                                                              |
| Element palette         | `palette-section-<category>` (section header), `palette-item-<type>`                                                                                      |
| Surface Builder actions | `surface-starter-use-<templateId>`, `surface-create-button` and `surface-welcome-dismiss` (Add Surface page), `surface-save-button` (surface detail page) |
| Caller Context editor   | `caller-auth-configure` (panel button), `caller-auth-jwt-strategy` (strategy select), `caller-auth-close-button`                                          |

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
- **Target Authentication** on the Managed Agent has None plus six types. Four are header presets
  backed by a secret (`static_secret`). **Credential Provider** writes `{ credential_provider:
{ credential_provider_id, scopes, inject_as } }` (field types in `utils/targetAuth.ts`,
  config mapping in `managed-agent/targetAuthConfig.ts`). The provider picker
  (`_shared/CredentialProviderPicker.tsx`, test id `target-auth-credential-provider-select`)
  lists only providers whose type `permits` Target Authentication, so Authorization Code
  providers are absent. A saved provider that is missing or not allowed shows a warning and is
  kept until the operator picks another; the client cannot see the type at validation, so
  the gateway rejects that combination on save and stays the authoritative check.
  Scopes (`target-auth-scopes`, empty means the provider's default scopes) and the header shape (`target-auth-inject-as`: Authorization
  Bearer, or a custom header with `target-auth-inject-name` and `-format`, which must
  contain `{value}`, and a name other than `Host`, `Content-Length`, `Transfer-Encoding` or
  `Connection`) sit beside it. The option is offered only for a direct URL, in both the
  sidebar and the fullscreen editor: a `fabric://` target cannot use a provider on the sending
  gateway. Save is blocked (`managedAgentDefinition.validate`) while the type is Credential
  Provider and no provider is picked, the custom header name or `{value}` format is wrong, the
  URL is not `https://`, or the endpoint is not a direct URL. The fullscreen editor ties that
  reason (`target-auth-error`, from `credentialProviderAuthProblem`) and the picker's
  `-unusable` and `-error` messages to the field they concern with `aria-describedby` and
  `aria-invalid`, and marks the starred fields `aria-required`. The sixth type, **Unsupported method
  (kept as saved)**, is never chosen by hand. Any `target.auth` variant the dashboard cannot
  edit (an unknown method, `credential_lookup`, a `credential_provider` with an `inject_as`
  type other than `bearer_header` or `custom_header`, or with fields the form does not model)
  is hydrated into `target_auth_raw` and written
  back byte for byte on save, unless the operator picks another type or None. A Transit Point
  keeps its `target_auth` unchanged on save for every method while no `auth_type` is picked
  (`hasUnpickedTargetAuth`, so a surface never opened in the panel loses nothing; the panel's
  own notice uses `hasPreservedTargetAuth` and covers only the variants it cannot edit), and has no credential provider option because the backend rejects
  one there.
- The route controls of the Access Point panel have test ids: `route-listener-listen-address`,
  `route-listener-surface-prefix` and `route-listener-custom-path`.
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
- **Transit Settings** has no listener authentication control: the gateway does not support
  `transit.source_auth` and refuses a save that sets it. The **Transit Token Mode** option
  says the embedded token is signed and readable by the agent, not encrypted.
- A new surface is named `<protocol>_surface_<n>` (`surfaceNaming.ts`), where `n` is one more
  than the existing surfaces of that protocol, skipping names already taken. The name follows
  the protocol until the user types a different name, from the Name field or the Config tab
  JSON; typing the generated name back keeps it generated. It never derives from the route. The
  unsaved-changes check ignores the generated name, so the surface list arriving never marks
  the page dirty and edits made while it loads still do.
- The canvas redraws when it is shown again after a structure change made while another view was
  open (`resizeNeedsRebuild` in `canvasResize.ts`), and a redraw keeps the selected node marked
  `node-single-selected`.
- **Networking** retryable status codes: an empty field means the gateway default and
  saves no `retryable_status_codes`, and its placeholder says so. The **Retry on
  connection errors only** switch saves an empty list and disables the field. A field
  that isn't a comma-separated list of HTTP status codes (100 to 599) blocks Save. Test
  ids: `networking-retry-status-codes-input` and
  `networking-retry-connection-errors-only-switch`.
- **Caller Context** (JWT bearer) on an A2A, AP2 or MCP surface carries the authorization server discovery controls in
  one section, `caller-auth/CallerAuthDiscoverySection.tsx` (`caller-auth-discovery`), for all three
  protocols; DIDComm has none of them. It mounts `ScopesInput.tsx`, the **Required Scopes** chip
  input (test ids `caller-auth-scopes`, `caller-auth-scope-input`, `caller-auth-scope-add` and
  `caller-auth-scope-error`). Each entry must be an RFC 6749 scope token (no spaces, double quotes or
  backslashes), 1 to 128 characters, at most 32, no duplicates (`scopes.ts`); a bad entry shows an
  inline error tied to the input with `aria-invalid` and `aria-describedby` and is not added, and
  each chip's remove button is named `Remove scope <scope>`; removing a chip moves focus to the
  scope input. The field round-trips through
  `definition.ts` as `required_scopes` on the `jwt_bearer` method, is left out when empty, and
  `validate` reports scopes the gateway would refuse.
- **Authorization server discovery** is the one switch of that section
  (`caller-auth-discovery-explicit`, switch `caller-auth-discovery-switch`, described by
  `caller-auth-discovery-switch-help`, with `field-help-caller-auth-discovery`). It is the single
  opt-in by which an A2A, AP2 or MCP Access Point with a JWT Bearer method declares, and it edits
  `caller_authentication.protected_resource`. Required scopes alone never declare. While it is off,
  `caller-auth-discovery-off-summary` (plain text; only the cleared message and the off warning sit in
  the live region) says that no protected resource metadata is published (on A2A and AP2 the card keeps the managed agent's own security) and that a caller whose
  token is missing, invalid or short of a scope reaches policy as `source_auth.method == "failed"`,
  so a policy has to deny it. Turning it off on a saved surface whose saved record stores the setting on the route edited (read
  from the saved surface, not from what the editor opened with) shows
  `caller-auth-discovery-off-warning`, because the gateway then stops refusing failed callers itself.
- Turning discovery on prefills the resource with the Access Point's https listener URL plus its
  route (left empty otherwise, and then `caller-auth-discovery-resource-hint` says there is nothing
  to suggest), moves focus to the resource input, empties Accepted Audiences, turns token
  forwarding off and sets the `Authorization` header with the `Bearer` scheme; each of those
  controls stays locked while discovery is on, once it holds that value, and
  `caller-auth-discovery-cleared` says what was removed. The resource input
  (`caller-auth-discovery-resource-input`) is `aria-invalid` and described by its hint and error
  while it has a problem. The banner says what changes: protected resource metadata is published on
  the Access Point's listener, a caller without a valid token gets `401` with a challenge and a token
  short of a required scope gets `403` `insufficient_scope`, both before rate limiting, any policy,
  the AP2 gate and payment, a token is accepted when the resource URL is one of its audiences, and
  the token is never forwarded to the managed agent.
- Below the resource, a read-only definition list (`caller-auth-discovery-derived`, headed "What
  callers are told") shows what the gateway publishes, never a token or a secret. The authorization
  server is the selected strategy's `expected_issuer` (`-derived-authorization-server`, with its
  source line `-derived-authorization-server-source`, "From the JWT verification strategy <name>";
  "Select a JWT verification strategy." when none is selected). The scopes are the Required Scopes
  plus any stored extra scopes (`-derived-scopes`, `-derived-scopes-source`; "None required" when
  empty, and callers without a valid token are still refused). The audience is the resource, or
  `<resource>$<alias>` on a variant (`-derived-audience`, `-derived-audience-source`). On A2A and
  AP2, `-card-pin` shows the strategy's pinned authorization server that the card's security scheme
  names (a static key set counts as pinned when its pinned issuer is the expected issuer, as in the
  gateway); when the strategy is not pinned or its pin no longer matches, `-strategy-link` opens
  `/jwt-verification-strategies/<id>` to run Discover.
- A surface that stores more than a resource shows `caller-auth-discovery-stored-overrides`: a stored
  `authorization_servers` list with **Use the strategy's issuer**
  (`-clear-authorization-servers-button`) and stored extra `scopes` with **Advertise required
  scopes only** (`-clear-scopes-button`; the "does not enforce" sentence lists only the stored scopes
  that Required Scopes does not already hold). The gateway advertises the strategy's issuer, so a stored
  list that is not exactly `[expected_issuer]` shows
  `caller-auth-discovery-authorization-servers-error` after a save attempt, for cleanup; the gateway
  keeps an unchanged stored list and reports `authorization_servers_stale`. The editor has no input to add an
  authorization server or an advertised scope.
- The Caller Context editor's intro (`caller-auth-jwt-intro`) says that while Authorization server
  discovery is on, a missing or invalid token gets `401` with a challenge and a token short of a
  required scope gets `403` `insufficient_scope` before rate limiting, any policy, the AP2 gate and
  payment; otherwise a failed caller reaches policy as `source_auth.method == "failed"`. While
  discovery is on, `caller-auth-audiences-discovery-note` says Accepted Audiences stay empty because
  the resource URL is the audience. The strategy select is `caller-auth-jwt-strategy` and the
  audience input `caller-auth-audience-input`, each with a `htmlFor` label; audience chips are
  named `Remove audience <audience>`.
- The **declaration outcome chip** (`DeclarationOutcomeChip.tsx`, `caller-auth-outcome`,
  `caller-auth-outcome-chip`, `caller-auth-outcome-icon`, `caller-auth-outcome-detail`) shows the
  outcome for the variant being edited (`activeVariantAlias`, the base when none) from
  `GET /api/v1/surfaces/{id}/declarations`, labelled **Agent card:** on A2A and AP2 and **Protected
  resource metadata:** on MCP. The outcomes are **Declares OAuth** (on A2A and AP2 the detail says that only the protected resource metadata names
  the authorization server when the save report carries `card_scheme_unavailable` for that variant),
  **Not declared** (on every
  protocol, with the reason text from `STRIP_REASON_TEXT`: `not_declared` reads "Authorization
  server discovery is off for this route."; on A2A and AP2 the detail adds that the card keeps the
  managed agent's own security), **Upstream card unchanged** (**No metadata published** on MCP)
  and **Cannot be served** (`unservable`, with the action for the reason code from
  `UNSERVABLE_REASON_TEXT`, which has exactly the gateway's nine codes, or a general sentence when
  the reason is missing or unknown). The chip is the shared
  `Badge` (tinted `app-badge`, tones success, warning, danger and secondary, with the class
  `caller-auth-outcome-chip`; `SurfaceBuilder.css` darkens the light warning text of this chip and
  of the Agent Cards badges to `#92400e` to keep 4.5:1 contrast), never a solid `badge text-bg-*`. Each badge carries an icon and a text label, never
  colour alone. It reflects the saved surface, so a new
  surface shows "Outcome shown after the first save", and a failed read, or a gateway without that
  endpoint, shows "<noun> outcome unavailable" without breaking the page. It appears in the Caller
  Context sidebar (`caller-auth-panel-outcome`, beside the discovery status line) and in the
  editor under the intro, with a **See the card** link button (`caller-auth-outcome-card-link`)
  that opens the Agent Cards view, shown only on A2A and AP2 for a saved surface. A view switch
  started from content (**See the card**, **View agent cards**, **Open the Surface view**) goes
  through `openViewFromContent` in `SurfaceFormShell`, which then moves focus to the destination's
  sidebar view button (or the Agent Cards heading when the sidebar is collapsed); a click on a
  sidebar view button leaves focus where it is.
- **Surface warnings** are the `warnings` array of a surface save response (`code`, `message`,
  `path`, `variant`). `SurfaceWarningsAlert` keeps an empty polite live container
  (`surface-warnings-live`) always mounted on Surface Detail, so warnings that arrive after a save
  are announced, and shows them inside it as a labelled region (`surface-warnings-alert`,
  `surface-warning-<code>`). For the fail-open codes (`fail_open_policy`, `fail_open_undetermined`)
  it offers **Copy deny rule** (`surface-warnings-copy-rule`), which copies
  `DENY_FAILED_CALLERS_REGO` (`utils/denyRule.ts`), a whole surface policy denying failed callers,
  with a hint (`surface-warnings-copy-rule-hint`) to attach it to the Managed Agent
  (`target.policy`) when that has no policy, so callers arriving over Fabric are denied too, and
  otherwise to add `not input.source_auth.method == "failed"` to each existing allow rule rather
  than paste the whole policy. For `payment_before_policy` it offers **Copy gateway deny rule**
  (`surface-warnings-copy-gateway-rule`), which copies `GATEWAY_DENY_FAILED_CALLERS_REGO`, the
  same rule under `package gateway.policy`, with the matching hint
  (`surface-warnings-copy-gateway-rule-hint`) for the gateway policy; a surface policy cannot fix
  that warning because payment runs before it. When the surface has a JWT Bearer first method on
  a protocol that can declare and no `protected_resource`, the fail-open block also shows
  `surface-warnings-discovery-hint` (the `offersDiscovery` prop, set by Surface Detail), pointing
  at the **Authorization server discovery** switch as the other way to refuse failed callers. The
  dashboard never creates or attaches either policy itself. Surface Detail reads `GET /api/v1/surfaces/{id}/declarations` (the
  `useSurfaceDeclarations` hook, refreshed after each save), so it shows the current result, not
  the snapshot from the last save, and falls back to the save response when that read is
  unavailable. After creating a surface whose response carries warnings, the dashboard opens
  Surface Detail instead of the list so they stay visible (`surfacePathAfterCreate`).
  `toBackendSurface` never sends `warnings` or `declarations` back.
- `protectedResource.ts` mirrors the gateway's save rules. The editor blocks Save on the resource
  rules (a public https URL of the Access Point's listener followed by its route exactly) and the
  JWT Bearer settings the gateway constrains. A variant of an Access Point on `/` has no resource of
  its own (`rootVariantProblem`) and a stored authorization server list must be the strategy's
  issuer: the section shows both. The gateway refuses a root variant, and keeps an unchanged stored
  list with an `authorization_servers_stale` warning; the editor does not block either.
  Stored authorization server entries must be https URLs, except a single entry that is the
  strategy's http issuer (or any single http entry while the strategy issuer is unknown); the
  gateway accepts that only for a strategy no tenant owns, and otherwise refuses a list the
  save sends or changes (an unchanged stored list is kept, as above).
  Leaving JWT Bearer drops the setting.
  A variant shows the resource it advertises, `<resource>$<alias>`, and keeps its own setting. A
  failed save whose message names the setting of the route edited (a `variant '<alias>': ` message
  belongs to that variant only) shows in the section (the resource message under the
  resource input, the issuer messages under the stored overrides, others in
  `caller-auth-discovery-save-error`) and in the sidebar, which also shows whether Authorization
  server discovery is on or off.
- A PUT that leaves out a stored `protected_resource` keeps it, so Save sends a setting the
  operator switched off as `protected_resource: null` in the same PUT
  (`withDroppedProtectedResourcesRemoved`), for the surface and each variant. A save that fails
  leaves it in place. The default variant's note says it also answers on the surface's route
  with the resource as written.

| Element                                                        | Test id                                                                                                                                                                                                                                                                                                                                                                                                       |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Discovery switch, its help and the off summary                 | `caller-auth-discovery-switch`, `caller-auth-discovery-switch-help`, `caller-auth-discovery-off-summary`, `caller-auth-discovery-off-warning`, `caller-auth-discovery-cleared`                                                                                                                                                                                                                                |
| Resource, hint, use listener URL                               | `caller-auth-discovery-resource-input`, `caller-auth-discovery-resource-hint`, `caller-auth-discovery-use-listener-url-button`                                                                                                                                                                                                                                                                                |
| What callers are told                                          | `caller-auth-discovery-derived`, `caller-auth-discovery-derived-authorization-server`, `caller-auth-discovery-derived-authorization-server-source`, `caller-auth-discovery-derived-scopes`, `caller-auth-discovery-derived-scopes-source`, `caller-auth-discovery-derived-audience`, `caller-auth-discovery-derived-audience-source`, `caller-auth-discovery-card-pin`, `caller-auth-discovery-strategy-link` |
| Stored overrides                                               | `caller-auth-discovery-stored-overrides`, `caller-auth-discovery-clear-authorization-servers-button`, `caller-auth-discovery-clear-scopes-button`                                                                                                                                                                                                                                                             |
| Variant resource, default variant note, rules explainer toggle | `caller-auth-discovery-variant-resource`, `caller-auth-discovery-default-variant-note`, `caller-auth-discovery-context-toggle`                                                                                                                                                                                                                                                                                |
| Errors                                                         | `caller-auth-discovery-save-error`, `caller-auth-discovery-rules-error`, `caller-auth-discovery-resource-error`, `caller-auth-discovery-authorization-servers-error`, `caller-auth-discovery-scopes-error`                                                                                                                                                                                                    |
| Sidebar status and error                                       | `caller-auth-panel-discovery-status`, `caller-auth-panel-discovery-save-error`                                                                                                                                                                                                                                                                                                                                |
| Surface Detail hint                                            | `surface-warnings-discovery-hint`                                                                                                                                                                                                                                                                                                                                                                             |

## Agent Cards tab

The **Agent Cards** view (`components/surface-builder/agent-card/`, view key `agent-card`, button
`surface-view-agent-card`) is a first-class Surface Builder view placed directly after **Elements**
and before **Monitoring** in `SIDEBAR_VIEWS` of `SurfaceFormShell.tsx` (Surface, Templates,
Elements, Agent Cards, Monitoring, Config). `visibleSidebarViews(mode, protocol)` offers it for
A2A and AP2 surfaces (`AGENT_CARD_PROTOCOLS`) and never for MCP or DIDComm; when the protocol
changes away while it is open, the shell returns to the Surface view. Every view button has the
test id `surface-view-<key>` and `aria-current="page"` while active. The view shows the saved
surface, never the unsaved form.

- `AgentCardTab` orchestrates and calls `useAgentCardPreview` (`GET /api/v1/surfaces/{id}/agent-card`;
  Refresh is `POST .../agent-card/refresh`). A Refresh answer that arrives after the surface, the
  refresh key or the tab changed comes back as `{ kind: 'stale' }` and changes nothing, with no
  toast. The parts are `AgentCardHeader` (facts),
  `AgentCardCompare` (summary, legend, side by side cards) and `AgentCardRawJson`. The wire types,
  `parseAgentCardPreview` (rejects unknown enum values), the cause and sign-in copy,
  `describeFetchFailure` and `safeHttpUrl` live in `utils/agentCardPreview.ts`; the pure comparison
  lives in `utils/agentCardDiff.ts` (`diffAgentCards` with `addedCount`, `modifiedCount` and
  `removedCount`, and `cardEra`). Tests build bodies with `utils/agentCardTestFixtures.ts`. A
  gateway without these endpoints, a thrown request or a body that does not parse shows the
  read-failed state, and the rest of the page keeps working.
- The **Managed Agent Card** (the agent's own card, `agent-card-before`) and the **Gateway-Served
  Agent Card** (what callers see, `agent-card-after`) sit side by side. Rows are
  `agent-card-row-signin|scope|signature|endpoint|other`, each with
  `data-status="same|changed|removed|absent"`. Each item carries a tag with a distinct colour and
  always an icon with a text label, never colour alone: **Added** on the served side
  (`agent-card-item-added`), **Modified** on both sides (`agent-card-item-changed`), **Removed** on
  the managed side (`agent-card-item-removed`) and **Unchanged**. The summary strip
  (`agent-card-summary`, `agent-card-change-count`) reads "N added, N modified, N removed", and the
  legend is a list named **Legend** (`agent-card-legend`, `agent-card-legend-added|changed|removed|same`).
  **Show raw JSON** (`agent-card-raw-toggle`) shows the full content of each card side by side, each
  in a focusable `pre` region named by its heading (`agent-card-raw-before|after`, sections
  `agent-card-raw-<side>-section`), with copy buttons named "Copy the <card title> JSON"
  (`agent-card-copy-before-button`, `agent-card-copy-after-button`). The colours are local tokens on
  `.agent-card-tab` in `SurfaceBuilder.css`, redefined under `body.dark-theme`; the light tokens
  (added `#065f46`, modified `#92400e`, removed `#b91c1c`) keep the tag text at 4.5:1 or more on
  its 8% tint. The tab sizes itself
  with a container query (`container-type: inline-size` on `.agent-card-tab`), not a viewport query,
  because the app nav and the Surface sidebar take part of the width: below 640px of tab width the
  cards and raw panels stack and the facts become one column.
- The Surface Entry point URL stays in the Surface view. The Agent Cards view links back to it:
  "The Entry point URL and the rest of the surface settings are in the Surface view." with an
  **Open the Surface view** button (`agent-card-surface-link`, `agent-card-open-surface-button`),
  through `SurfaceMetaContext.onOpenSurfaceView`; outside a surface editor the link is absent.
- The header is a definition list: **Served card discovery URL** (the gateway-served card
  discovery URL, `agent-card-served-url`, **Copy** named "Copy the served card discovery URL"
  `agent-card-url-copy-button`, **Open** `agent-card-open-button`, **Refresh**
  `agent-card-refresh-button`), **Fetched from** (`agent-card-source-url`, with "(query hidden)"),
  **Fetch** (`agent-card-fetch`, holding the `agent-card-fetch-status` badge and
  `agent-card-fetch-cause` with `data-cause`, not a live region), **Target Authentication** (`agent-card-auth`: the provider and token expiry, **Static
  secret**, **Looked-up credential**, **No Target Authentication**, **The remote gateway signs in**,
  **Credential not obtained** or **No credential sent**), **Last fetched** (`agent-card-fetched-at`,
  a `time` element with the absolute time as its title), **Outcome** (`agent-card-outcome`, `agent-card-outcome-reason`, from
  `describeDeclaration`; for a declaring route the reason says the agent card names the
  authorization server only when the served card carries the `agent_gateway` scheme
  (`cardNamesGatewayScheme`), says only the protected resource metadata names it when the served
  card lacks that scheme, and makes no claim about the card when no served card is shown) and **Last caller fetch** (`agent-card-last-caller-fetch`, per gateway
  replica). A failed fetch names the cause with the HTTP status (`describeFetchFailure`), for
  example "Sign-in failed — HTTP 401". The longer cause text (`CARD_FETCH_CAUSE_TEXT`) says what
  happened and what to do, for example "Check that the agent is running, then Refresh."
  **Refresh** needs `surfaces.edit`; without it the button is disabled with the reason as its title
  and description. A successful Refresh replaces the failed state with the new cards and puts
  "Card refreshed." with the fetch result (OK, failing or not served, never the cause, which the
  alert gives) in a visually hidden status region (`agent-card-refresh-status`), cleared when the
  next Refresh starts; a 429 shows a warning toast and keeps the cards on screen; a refused or
  failed Refresh shows an error toast. The tab heading (`agent-card-heading`, `tabIndex=-1`) takes
  focus when **Retry** replaces itself with the loading status.
- A failed or not-served fetch shows a danger alert with the cause text (`agent-card-failed`,
  `agent-card-failed-cause`) and opens both raw panels. The managed panel reads "Not available:
  <cause — HTTP n>." (`agent-card-raw-before-missing`), or shows the managed card when the gateway
  fetched it but will not serve it. The served panel shows, in this order: the card the gateway
  returns in `after` whatever the fetch status, with "The card the gateway last served for this
  surface, before the latest fetch failed. Callers do not get it until this is fixed." (or "before
  the gateway refused to serve the card it fetched.") as `agent-card-raw-after-note`, never in the
  present tense, because the card route keeps no stale card for callers; when `after` is
  `null` because the card is over the display limit, "The card the gateway last served is N KB, more
  than the N KB the dashboard shows. Open the card URL to read it."; on a gateway that returns no
  served card, the last Gateway-Served Agent Card the dashboard saw for this surface
  (`useAgentCardPreview` `lastServed`, never carried to another surface) with "The last card the
  gateway served, fetched <time>."; otherwise "The gateway serves no card while the fetch fails."
  (`agent-card-raw-after-missing`). A failed or not-served fetch shows no comparison, summary or
  **Added** marks, because there is no managed card from the same fetch to compare against.
- Other states, each with its own test id and fixed copy: create mode or no id
  (`agent-card-unsaved`, "Save the surface to see its agent cards."), unsaved edits
  (`agent-card-unsaved-changes`, a banner above the content; moving or zooming the canvas does not
  count, see `utils/surfaceDirtySignature.ts`), loading (`agent-card-loading`), read failed with
  **Retry** (`agent-card-error`, `agent-card-retry-button`), `not_a2a` ("Only A2A and AP2 surfaces
  have agent cards.") and `not_running` (`agent-card-unsupported`; `operator_only` reads "Only an
  appliance operator can preview the card of an appliance-wide surface."; an `auth_failed` cause on
  a `remote_gateway` sign-in reads "The remote gateway refused this gateway's authorization (HTTP
  {status}). Check the sign-in settings of the remote surface."), a card over the display limit
  (`agent-card-too-large`), a gateway-generated A2A proxy card (`agent-card-generated`, served column
  only), callers paying first (`agent-card-payment`) and Surface Variants existing
  (`agent-card-variant-note`, because the view shows the base route). `hasVariants` comes from the
  saved surface's enabled variants.
- The required scopes and the Authorization server discovery resource are set in the A2A surface's
  Caller Context editor (see _Surface Builder_ above); the authorization server comes from the
  strategy and appears with the scopes in the served card. Card content comes from the agent, so it
  is untrusted: every value renders as React text, there is no `dangerouslySetInnerHTML`, and no
  card URL (`iconUrl`, `documentationUrl`, `provider.url`) becomes a link or an image. The only link
  is the served card URL, and only when `safeHttpUrl` passes (http or https, no user info), opened
  with `rel="noopener noreferrer"`. The parser keeps no token, secret, secret id or upstream error
  body, so the view has nothing of that kind to show.
- The Managed Agent panel shows one line, **Card fetch: OK**, **Card fetch: failing (<cause — HTTP
  n>)** or **Card: generated by the gateway**, with an icon, and a **View agent cards** link button
  (`managed-agent-card-fetch`, `managed-agent-card-fetch-status`, `managed-agent-card-fetch-icon`,
  `managed-agent-card-fetch-link`), through `agent-card/AgentCardFetchLine.tsx`. The status text
  uses `agent-card-fetch-ok` and `agent-card-fetch-failing` (AA colours in both themes, scoped to
  `.agent-card-fetch-line`), not `text-success` or `text-danger`. `AgentCardFetchLine` reads the
  preview with its own `useAgentCardPreview` call and never calls Refresh; it reads again when
  `SurfaceMetaContext.agentCardFetchRevision` changes, which the shell bumps on a save and on each
  successful Refresh in the Agent Cards view (`AgentCardTab` `onRefreshed`), so the line does not
  keep a stale status. It shows `Card fetch: checking…` while loading and `Card fetch: status
unavailable` when the read fails. Like the chip's
  link, it reaches the view through `SurfaceMetaContext.onOpenAgentCard`, which `SurfaceFormShell`
  sets only while the view is offered, and it shows only for a saved surface. `SurfaceDetailPage`
  passes `isDirty`, the declarations revision as `agentCardRefreshKey` (so a save reads the cards
  again; the shell also exposes it as `SurfaceMetaContext.agentCardRevision`) and `hasVariants`.

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

| Element                          | Test id                                                                                            |
| -------------------------------- | -------------------------------------------------------------------------------------------------- |
| Per-Transit-Point scope line     | `trust-check-panel-transit-point-scope`                                                            |
| Fullscreen leg label             | `trust-check-fullscreen-leg`                                                                       |
| Managed Agent URL-target warning | `trust-check-panel-managed-agent-target-warning`                                                   |
| Read-only migrated copy line     | `trust-check-panel-read-only`, `trust-check-fullscreen-read-only`                                  |
| Fullscreen query list            | `trust-check-fullscreen-queries`                                                                   |
| Migrated warning and Keep        | `trust-check-panel-migrated-warning`, `trust-check-fullscreen-migrated-warning`, each with `-keep` |
| Review summary                   | `surface-migrated-trust-checks-summary`                                                            |
| Migrated canvas badge            | `surface-node-trust-check-migrated-badge`                                                          |

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

## JWT verification strategies

- A failed save shows the gateway's message in `strategy-error` (role `alert`).
- The editor (`EditJwtVerificationStrategyPage.tsx`) sends `discover_metadata` explicitly:
  `true` after **Discover** (`strategy-discover-button`), `false` after **Clear pinned
  metadata** (`strategy-pinned-clear`) or when the keys become static while a server is pinned,
  and omitted otherwise, which keeps the pin. Discover posts `{ issuer }` to
  `/api/v1/jwt-verification-strategies/discover`, needs Remote URL keys and an `https` issuer
  (the editor refuses any other issuer in `strategy-discover-error` without calling the gateway,
  which itself requires `https` only when the caller uses a tenant-scoped token, the strict
  posture), and shows the result in the pinned card (`strategy-pinned-server`: issuer, metadata URL, token
  endpoint, JWKS URI). A discovered JWKS URI replaces the typed one. Editing the issuer or JWKS
  URI after Discover drops the result; a pin that no longer matches the issuer or JWKS URI shows
  `strategy-pinned-stale`, which says that surfaces using the strategy stop advertising an
  authorization server, that saving a changed issuer or JWKS URI tries discovery
  again and, when that fails, still saves and clears the pin when the issuer changed (it keeps
  the pin when only the JWKS URI changed), and that Discover pins matching metadata. Without a
  pin, `strategy-no-pin` says surfaces using the strategy advertise no authorization server in
  their agent card or protected resource metadata.
  A failed discovery shows one generic `strategy-discover-error` alert, never the gateway's
  detail.
- The **Check URI** save gate applies only to a JWKS URI the operator typed or changed, not to a
  discovered or unchanged one.
- **Scope claims** (`strategy-scope-claims`, described by its help text `scope_claims-help`
  through `aria-describedby`) is a comma separated list sent as `scope_claims`. A new
  strategy leaves it out when empty. Saving an existing strategy with the field cleared sends
  `["scope", "scp"]`, because the gateway keeps the stored list when the field is omitted and
  rejects an empty list; the default list is stored as absent.
- The authorization server fields (`authorization_server`) follow the gateway's discovery
  response, which returns the pinned metadata at the top level of the body.
- The list marks a strategy with a pinned server with a **Discovered** badge
  (`strategy-discovered-badge`). Deleting asks in the page (`strategy-delete-confirm`, role
  `alertdialog`, confirm and cancel buttons). It lists the credential providers that use the
  strategy for consent identity (read from `/api/v1/credential-providers`; "Could not check which
  credential providers use it." when that read fails, and Delete stays available) and the surfaces
  whose Access Point or variants use the strategy, or whose Transit Points or outbound credential
  bindings (base or variant) use one of those providers (read from `/api/v1/surfaces`; "Could not
  check" when that fails). It states that, without authorization server discovery, a caller
  presenting a token is refused with `500` and a caller without one is left to the surface's
  policy; that a surface that advertises an authorization server can no longer be served and
  refuses every caller until the strategy is restored; and that a credential provider using it for
  consent identity can no longer obtain credentials that need the user's consent (see
  `docs/SOURCE_AUTH.md#source-authentication`). A refused delete shows
  inline in `strategy-delete-error`. Opening the confirmation moves focus into it and scrolls it
  into view; Escape or Cancel closes it and returns focus to the row's Delete button, and a
  confirmed delete moves focus to the list heading (`hooks/useInPageConfirm.ts`). Only the
  surfaces of the strategy asked about last are shown.
- A Discover that answers after the Expected Issuer was edited is ignored, so the page never
  shows or saves metadata for an issuer it no longer names.
- Provider-neutral trust is configured through JWT verification strategies and credential
  providers; the dashboard has no OIDC Providers page.

## Credential providers

- One descriptor, `PROVIDER_TYPE_CAPABILITIES` in `utils/credentialProviders.ts`, is a
  `Record<CredentialProviderType, ...>` so TypeScript rejects a type with no entry. The form
  (`EditCredentialProviderPage`), the list (`CredentialProvidersTab`) and the pickers read it
  for labels, badge colors, which fields apply, and which uses a type permits
  (`providerPermits`, `filterProvidersForUse`). Never compare `provider_type` to a string
  elsewhere. Request building and validation live in the same module
  (`validateProviderForm`, `buildProviderBody`, `providerFormFromWire`). Updating a provider sends
  `null` for an emptied description or authorization endpoint, `{}` for emptied or unsupported
  additional parameters, and `null` for the client and API key secret references the provider's
  type does not use; creating a provider sends none of these.
- **JWT Bearer** (`oauth2_jwt_bearer`) shows `jwt-bearer-section`: Signing Key Secret
  (required), Algorithm (RS256 or ES256), Key ID, Assertion Issuer (required), Subject (the
  `sub` claim, sent only when set) and Audience (`provider-audience`, optional, described by
  `audience-help`, its placeholder the current token endpoint; sent trimmed as `audience`, left
  out when blank, refused before saving when it holds whitespace or control characters or
  exceeds 512 bytes, and the assertion audience is the token endpoint when unset).
  The client ID and client secret references are optional and sent only as a pair. The section carries an
  always-visible `jwt-bearer-encryption-banner` because encryption at rest is off by default.
  The signing key is an ordinary secret (type Certificate or General); the dashboard has no
  separate private-key secret type. The assertion settings travel in a nested `jwt_bearer`
  object (`signing_key_secret_ref`, `signing_algorithm`, `assertion_issuer`,
  `assertion_subject`, `key_id`, `audience`), which a save replaces as a whole. Clearing the optional
  client references on an existing provider sends them as `null`; the gateway removes both
  stored references (an omitted field keeps them), and the next grant sends no client
  authentication.
- Choosing JWT Bearer for a new provider whose Token Endpoint is empty prefills Google's
  endpoint (`GOOGLE_TOKEN_ENDPOINT`, `tokenEndpointForType`) with the hint
  `provider-token-endpoint-google-hint`, shown only on a new provider; the field stays editable, choosing another type removes
  the untouched prefill, and nothing is prefilled once the operator has edited the endpoint or on
  an existing provider.
- Create and update both send `provider_type`, so changing the Provider Type of an existing
  provider saves the new type; the gateway answers 409 while a surface uses the provider in a way
  the new type cannot serve: Target Authentication with Authorization Code, or a delegation
  binding that breaks the JWT Bearer binding rule (an https leg and caller authentication), or a
  surface of another tenant uses the provider and the new type sends the gateway's own
  credential (see `docs/CREDENTIAL_DELEGATION.md#binding-a-provider-to-a-surface`). A provider
  whose `provider_type` the dashboard does not know opens read-only with `provider-unknown-type` (disabled form, no save button, no
  `Cmd+S` save), so it can never be saved with a guessed type.
- A form error (`provider-error`, role `alert`) is announced. The Provider ID is derived from the
  Name for every type except Authorization Code, so a Name with no ASCII letter or digit is
  refused with "Name must contain at least one letter or number."; for Authorization Code the
  error names the **Callback URL Route** field.
- The delegation pickers (the surface-level outbound bindings and the Transit Point
  credential binding) list only providers whose type permits `legacy_delegation`, and keep a
  saved provider that is no longer allowed selectable with a `not usable here` label
  (`keptProviderLabel`). They do not check the JWT Bearer binding rule; the gateway refuses such
  a surface on save with 400. The Credential Delegation sidebar panel only looks up the bound
  providers' callback URLs and does not filter.
- The list deletes with the two-step `DeleteButton`. A refused delete (`409` while a surface
  still uses the provider) shows the gateway's reason and status inline in
  `credential-provider-delete-error` (role `alert`), never a native alert.
- The strategy editor's **Discover** button calls `/discover`; see _JWT verification
  strategies_.
- Permissions: the list, add, delete, and the provider picker use `credential_providers.view`,
  `.edit` and `.delete` (administrator by default, matching `src/rbac/mod.rs`), not
  `settings.edit`. `/credential-providers/new` needs `.edit`, `/credential-providers/:id` needs
  `.view` and shows the form read-only without `.edit`, with a `provider-read-only` notice
  saying the role can view but not change it. Each list row's name is a link to the provider,
  so every role that can list providers can open one from the keyboard. Without `.view` the list shows a
  notice and the Target Authentication picker keeps the saved provider id read-only, because a
  role that can edit surfaces cannot list providers.

## Secret editor

- `/secrets/new` and `/secrets/:id` have one save button, at the bottom of the form beside
  **Delete Secret** (`secret-save-button`); `Cmd+S` and `Ctrl+S` follow the same path. In
  edit mode, saving is possible only while **Update Secret Value** is checked or the name,
  description, type or tags differ from the loaded secret, so undoing an edit disables it.
- The API never returns a stored secret value, so the editor never shows one. In edit mode
  the value field is disabled with a **Stored value is hidden** placeholder until **Update
  Secret Value** is checked. Unchecking it, or a successful save, clears the entered value
  and returns the field to that hidden state.
- Deleting a secret warns first when credential providers reference it, in the Secrets list and
  in the editor (`hooks/useSecretDeleteGuard.tsx`; the guard is rendered once per page as
  `warningNode`). The two-step delete button still comes first. The hook then reads the providers
  (`providersUsingSecret` in `utils/credentialProviders.ts`: the list, then each provider, because
  the list omits secret references) and, when any reference the secret's Secret ID, shows
  `secret-delete-warning` (role `alertdialog`) naming them (`secret-delete-warning-provider`), with
  `secret-delete-warning-confirm-button` (**Delete secret anyway**) and
  `secret-delete-warning-cancel-button`. The gateway does not block the delete, so confirming
  deletes. A secret nothing references deletes at once; a failed read shows
  `secret-delete-warning-unknown` and still allows the delete; without `credential_providers.view`
  there is no check. The warning takes focus when it opens; Escape or Cancel returns focus to
  the Delete button, and a confirmed delete in the Secrets list moves focus to the list heading
  (`hooks/useInPageConfirm.ts`).
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

| Element                            | Test id                                                                                              |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------- |
| Identity row                       | `identities-row-<did>`                                                                               |
| Name, pending, conflict, verified  | `identities-name`, `identities-name-pending`, `identities-name-conflict`, `identities-name-verified` |
| Copy DID                           | `identities-copy-did-button`                                                                         |
| Origin badge                       | `identities-origin-<origin>`                                                                         |
| Surface link, credential principal | `identities-surface-link`, `identities-credential-principal`                                         |
| Unnamed filter                     | `identities-unnamed-filter-button`                                                                   |
| Recorder filter                    | `identities-recorder-filter`                                                                         |
| Recorder chip                      | `identities-recorder-chip-<state>`                                                                   |
| Recorder tooltip                   | `identities-recorder-tooltip`                                                                        |
| Tooltip last attempt, reason       | `identities-recorder-last-attempt`, `identities-recorder-reason`                                     |
| Tooltip registry entry             | `identities-recorder-entry-<registry id>`                                                            |

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
