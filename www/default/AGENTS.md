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
| Canvas node   | `surface-node-<type>`, for example `surface-node-payment`                            |

An indexed or per-row button keeps the `-button` suffix before the index or id, for example
`payments-details-button-<id>`. On `/surfaces/<id>` the save button is `surface-save-button`
and the banner for a refused save is `surface-error-alert`.

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
  visible. The one exception is a local x402/MPP policy, which is always flagged.
- **Payment** (`elements/payment/`) charges through a connected agent-pay payment gateway
  only. The sidebar picks the gateway and payment surface with the shared **Gateway picker**.
  It lists only the gateways `GET /gateways/payment-providers` returns: active payment
  gateways (Connections → **Payment Gateways**) exposing at least one payment surface. A Fabric
  peer is never one. There is no switch to show other gateways, and a failed load lists none.
  Its Add link reads **Add Payment Gateway** and opens the payment gateway wizard
  (`deepLinks.paymentGateway`, `/payment-gateways/connect`). Surfaces come from
  `GET /payment-gateways/{id}/surfaces` (`surfacesBasePath: '/payment-gateways'`) and the
  manifest from `GET /payment-gateways/{id}/surfaces/{surface}/payment-manifest`
  (`apiClient.getPaymentManifest`). It offers only payment surfaces (a payment flag, a manifest or a
  `payment` tag); a peer that sends none of these markers is refreshed once and then
  lists every surface. A surface id cannot be typed in, so a variant (`id$alias`) cannot be
  newly chosen; a saved one stays selected as `<id>$<alias> (variant)`. The sidebar
  previews the agent-pay manifest (the saved `manifest_snapshot` until the selection
  changes or Refresh is pressed, then the live one with a drift notice; Refresh bypasses
  the gateway's manifest cache, and the route's error codes map to readable messages; each
  payment method shows its logo, `/api/v1/gateways/payment-logos/<sha256>` from the point's
  `logo`, built only from a lowercase hex hash by `paymentLogoUrl` and shown with an `<img>`,
  never inlined, with empty alt text since the label follows, or a generic `fa-coins` (x402) or
  `fa-credit-card` (MPP) icon when there is none or it fails to load, test ids
  `payment-manifest-point-logo-<id>` / `payment-manifest-point-icon-<id>`), and holds
  the timeout. It has no **Charge every request** switch (the triggers editor has none either)
  and no switch to share the payer's email; a stored
  `require_all` or `share_payer_email` is kept as saved.
  The timeout is a whole number of milliseconds from 1000 to 120000, the range the gateway
  accepts; an empty field means the default, and anything else shows
  `payment-timeout-error` and blocks Save.
  MCP/A2A triggers live in the `PaymentTriggersEditor` fullscreen. Opening it never changes
  the config. A policy with no trigger set charges the protocol's default operations, the
  gateway's rule: every `tools/call` for MCP, `message/send` and `message/stream` for A2A.
  The editor says so (`payment-triggers-mcp-scope`, `payment-triggers-a2a-defaults-note`), and
  the A2A **Add default filters** button (`payment-triggers-a2a-add-defaults-button`) writes the
  two default filters; editing while none are set starts from them, so an edit never un-charges
  them. Blank patterns count as unset, and the only blocking trigger error is an MCP charged
  selection with no non-blank pattern (a Match with no pattern), which the gateway refuses with
  400 `invalid_payment_policy`; the editor warns about it at once
  (`payment-triggers-mcp-none-charged`) and shows it as `payment-triggers-mcp-error` after a
  save attempt. The
  browser's check of an MCP regex (`triggerPatternAdvice`) is advisory: the gateway's regex
  engine differs from the browser's (inline flags such as `(?i)` and `(?P<name>...)` are valid
  there), so a doubted pattern shows a warning under it and a warning-level dependency, and
  never blocks Save. The gateway's 400 on save is final, and its `details` reach the page error.
  The MCP editor (`McpTriggerEditor`) has no mode dropdown. Its **Patterns** list is the
  selection and is always shown with every stored row: selecting a tool adds the exact pattern
  `^<escaped name>$` at the end, clearing it removes that row, and removing or editing a row
  updates the tool's box; other rows keep their place. **Selected tools and patterns are
  Charged | Free** (`-mcp-selection-charged-button`, `-mcp-selection-free-button`) sets only
  what the list means and never rewrites it: Charged saves `match`, or `all` while the list is
  empty, and Free saves `exclude`. A surface with no trigger, or `all`, shows Charged with nothing
  selected and every tool charged, so the first tool selected is charged and every other tool
  becomes free; clearing the last one charges every tool again. The line under the switch
  (`-mcp-others`) says that every other tool, including tools the Target adds later, gets the
  opposite, or that nothing is selected yet. The **Tools** card lists the selected tools and, with
  **Discover tools**, the Target's tools, fetched on demand, never on open, through
  `POST /mcp-proxies/discover-tools` (`_shared/mcpToolDiscovery.ts`): an MCP Proxy Target by id;
  a Direct URL Target of a saved surface (`/surfaces/:surfaceId`) by `surface_id` with the draft
  endpoint, so the gateway dials the saved Target and auth under the forward step's egress
  policy (local and private Targets work, and an unsaved endpoint change answers `409`); on an
  unsaved surface, the URL with its auth secret reference (never a secret value), which the
  strict policy refuses for local and private hosts, so the error then adds a save hint
  (`-mcp-discover-save-hint`). A gateway (`fabric://`) or A2A proxy Target offers no discovery
  and says why; tools can still be added by name. Each row shows the tool's effective
  charge. A tool a non-exact pattern matches shows as ticked and locked and names that pattern.
  The select-all box (checked, indeterminate or clear), **Select all** and **Clear** act on the
  tools the filter shows (**Select shown** / **Clear shown** while filtering); selecting skips
  tools a pattern already matches. **Add tool** adds a tool by name to the list, and **Add
  Pattern** adds a blank regex row; the last row can be removed. A selected tool the Target no
  longer lists is badged. A pattern the browser cannot read the gateway's way (inline flags,
  lookaround) is ignored by the list and counted in a warning. The gateway's discovery error,
  such as a missing permission, is shown as is.
  A2A message patterns are plain, case-sensitive "message contains" text, never checked as a
  regex. While a message method has no text, the editor says every message of that method
  is charged (`payment-triggers-a2a-<method>-scope`). A loaded enabled local x402/MPP policy
  is kept as-is and shown with a banner whose **Start migration** keeps only its triggers; the
  policy is never silently dropped. A disabled legacy policy (`enabled: false`) charges
  nothing, does not block Save, and is saved back unchanged until an agent-pay surface is
  chosen. `manifest_snapshot` and the save response's `warnings` (objects `{code, message}`,
  shown as toasts by `showSaveWarnings`, used by the Add and Edit surface pages) are
  server-written and never sent. Choosing another gateway drops `manifest_snapshot` and the
  surface id (a surface id only exists on its own gateway); choosing
  another surface drops `manifest_snapshot`. The API client reads and writes through one scrub:
  `stripServerWrittenFields` removes the snapshot from the policies and from every canvas blob
  it sends, both a Payment node's config and the Managed Agent node's copy of the policy, and
  `fromBackendSurface` removes it from the canvas blobs of every surface it reads (get, list,
  and the create/update responses), so an earlier surface's price never comes back as the new
  surface's saved price. Test ids:
  the shared picker's `payment-*` ids (see **Gateway picker**), `payment-manifest-preview`,
  `payment-manifest-refresh-button`,
  `payment-manifest-drift`, `payment-legacy-unsupported-banner`,
  `payment-legacy-migrate-button`, `payment-disabled-legacy-note`,
  `payment-timeout-input`, `payment-timeout-error`, `payment-configure-triggers-button`, and
  `payment-triggers-*` in the fullscreen (`-mcp-scope`,
  `-mcp-error`, `-a2a-defaults-note`, `-a2a-add-defaults-button`,
  `-a2a-command-toggle-button`, `-a2a-control-toggle-button`, `-a2a-<method>-scope`,
  `-a2a-method-<method>` for a control method, `-pattern-<n>`, `-pattern-warning-<n>`,
  `-add-pattern-button`, `-remove-pattern-button-<n>`, and for MCP
  `-mcp-selection-charged-button`, `-mcp-selection-free-button`, `-mcp-others`, `-mcp-none-charged`,
  `-mcp-tools`, `-mcp-discover-button`, `-mcp-discover-unavailable`, `-mcp-discover-error`,
  `-mcp-discover-save-hint`, `-mcp-no-tools`, `-mcp-tool-count`, `-mcp-select-all`,
  `-mcp-tool-filter`, `-mcp-select-all-button`, `-mcp-clear-button`, `-mcp-tool-<name>`,
  `-mcp-tool-row-<name>`, `-mcp-tool-missing-<name>`, `-mcp-add-tool-input`,
  `-mcp-add-tool-button`, `-mcp-patterns`, `-mcp-unchecked`). Transit Points take no Payment node.
- `/surfaces/<id>` shows no payment activity for a surface charging through agent-pay; its
  payments are on the Payments page.
- **Send delegated credentials over Fabric** is one shared section
  (`_shared/FabricDelegatedCredentialsSection.tsx`) used by the Managed Agent and Transit
  Point panels. It writes `fabric_delegated_credentials` and appears only when that route
  is `fabric://` and the surface has credential bindings (a Credential Delegation row, or
  the Transit Point's own `transit_credentials`). It defaults to off. When on, an
  always-visible warning names the receiving gateway. Test ids:
  `<managed-agent|transit-point>-fabric-delegated-credentials-switch` and
  `-warning`. There is no surface-wide switch.
- **Gateway picker** is one shared gateway-then-surface picker
  (`_shared/GatewaySurfacePicker.tsx`, data from `_shared/useGatewaySurfaces.ts`) used by the
  Managed Agent and Transit Point **via Gateway Connection** routes and by Payment. Every user
  gets the same states:
  - Placeholders read `Select a gateway…` / `Select an Agent Surface…` (Payment: `Select a
    payment gateway…` / `Select a payment surface…`) and `Loading…` while a list loads.
  - With no gateway to offer, a warning panel replaces the dropdown with the Add link, which
    opens in a new tab so the canvas is kept. Otherwise a muted "Don't see the one you need?"
    line with the same link sits under it. The link is the picker's `addGatewayLink` and
    `addGatewayLabel`: **Add Gateway** to `/gateways/connect` by default (Managed Agent,
    Transit Point), **Add Payment Gateway** to `/payment-gateways/connect` for Payment.
  - A failed gateway load lists none and shows the error with **Retry**; it never reads as
    "no gateway". Retry reloads the gateways bypassing any cache.
  - `useGatewaySurfaces` lists surfaces from `{surfacesBasePath}/{id}/surfaces`: `/gateways`
    by default, `/payment-gateways` for Payment.
  - A failed surface load says why (not connected, not found, or a generic retry message,
    never the raw error). A gateway with no surfaces, or none passing the panel's filter, gets
    a muted line naming the next step.
  - **Refresh** reloads the surface list from the gateway (`force_refresh=true`). A response
    for an earlier gateway is dropped, so it never lists under a later one.
  - A saved gateway or surface missing from the list stays selected, as
    `<id> (not currently connected)` / `<id> (not currently exposed)`.
  - Surfaces read `name (first 8 id characters…)`.
  - The full explanation of each field sits behind its `FieldHelp`.

  Managed Agent and Transit Point list active remote peers (`filterSelectableGateways`, never a
  payment gateway)
  and read the route from config, falling back to the saved `fabric://` URL, so undo, redo
  and an API-authored surface restore it. They keep surfaces of the route's protocol plus
  surfaces with no protocol; an HTTP Transit Point keeps every surface. Choosing another
  gateway clears the surface, the endpoint and the synthesized gateway and channel names.
  Choosing a surface writes `fabric://<gateway>/<surface>` and names the channel after it. The
  node's incomplete reason names the missing step: `Select a gateway`, then `Select an Agent
  Surface on the gateway`. Test ids, with `<prefix>` one of `managed-agent`, `transit-point`
  or `payment`: `<prefix>-gateway-select`, `-gateway-error`, `-gateway-retry-button`,
  `-no-gateway`, `-add-gateway-link`, `-surface-select`, `-surface-refresh-button`,
  `-surface-error`, `-surface-empty`, and `field-help-<prefix>-gateway` / `-surface`. The
  route type selects are `<managed-agent|transit-point>-endpoint-type-select`, and the URL
  inputs are `managed-agent-endpoint-input` and `transit-point-target-endpoint-input`.
- **Release per-user grants to Fabric callers** is the Managed Agent panel's
  `managed-agent/PartnerGrantReleaseSection.tsx`, under a **Fabric Callers** label. It writes
  `target.delegated_credentials_for_fabric_callers` and appears only when the Target is an HTTP
  or HTTPS URL and the surface has a Credential Delegation row; a save drops the field for any
  other Target. It defaults to off, its explanation sits behind `FieldHelp`, and while on an
  always-visible warning says a paired gateway that sends a person's own token gets that
  person's grant. A variant carries it in `overrides.target`. Test ids:
  `managed-agent-partner-grants-switch` and `managed-agent-partner-grants-warning`.
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
  always-visible `access-point-public-warning` while on), directly under the Entry point URL
  (`RouteListenerBanner`'s `footer`), with no section heading above it. Its label is styled
  like the other section labels, such as Routing. It
  writes `access_point.public`, which
  is surface-level (an `ACCESS_POINT_IDENTIFIER_FIELDS` entry, never a variant override). The
  Access Point and Caller Context elements carry `public` and `caller_authentication.on_failure`
  through a load and rebuild unchanged; `withCallerAccessSettled`
  (`access-point/publicAccess.ts`) settles the write. On a surface stored without `public`
  (`legacyAccessPoint` in `SurfaceMetaContext`, set by the edit page), the panel shows the
  legacy state, "Not enforced (legacy)", under the switch with a **Close Access Point** button
  (`access-point-close-button`, hidden when read-only) that sets `public: false`. Turning the
  switch off there clears `public`, so turning it on and off again keeps the stored rules. A
  `public: false` the operator sets, in the panel or the JSON editor, is sent. Once `public` is
  sent, `on_failure` is left out of the surface and its variants, because the gateway derives it.
- **Access Point readiness.** A closed Access Point (`public: false`, which the gateway stamps on
  a new surface) with no caller authentication method and no `mcp_http.authorization` is not
  ready: it saves (unless it sends a Target credential, or has an `a2a-proxy://` Target, while
  `credential_policy.target_source_auth` is `enforce`, which refuses the save with 400), and callers get 503 until a save adds a Caller
  Context or turns Public access on. A public one, and one stored without `public`, are always ready. `accessPointStatus`
  (`access-point/readiness.ts`) is the one copy of that rule, and the notice uses it. Every
  surface response carries a read-only `access_point_status`, which `toBackendSurface`
  (`src/api.ts`) leaves out of writes.
  - The notice sits under the canvas Entry point URL, which keeps its copy button
    (`surface-access-point-readiness`), rendered by `AccessPointReadinessNotice` through
    `RouteListenerBanner`'s `footer`, in the warning yellow. The Access Point panel doesn't
    repeat it. The page
    decides it (`chooseAccessPointNotice`) and passes it through `SurfaceFormShell` to
    `SurfaceMetaContext`. The create page uses the draft. The edit page uses the saved state:
    `access_point_status` for the base, the stored variant resolved over the surface for a
    variant; it refreshes from the save response, so it clears without a reload. Nothing shows
    while ready.
  - Not ready: "Not ready for external access" with a **Configure Authentication** button
    (`<notice>-configure-authentication-button`, hidden when read-only). It selects the Access
    Point, expands the sidebar and highlights the Caller Context element in the palette
    (`palette-item-caller-auth`). The builder has no way to select or open an empty slot, so it
    can't open the Caller Context slot itself.
  - Saved not ready but the unsaved canvas would be ready: "Not ready for external access. Save
    to activate.", with no button.
  The save prompts come from the gateway, as `Warning` headers on the save response, so API
  clients get them too; the dashboard adds no caller access warning of its own:
  - Not ready: "This Access Point is not ready for external access. …", and one per enabled
    variant that is not ready, prefixed `variant '<alias>': `.
  - Public access on: "This Access Point is public. …", on every successful save.
  - Stored without `public` and no Caller Context: "This Access Point is neither closed nor
    public, and it admits callers without credentials. …".
  The dashboard shows none of these after a save (`shownSaveWarnings` in
  `elements/saveWarnings.ts` drops them, a variant's prefix ignored): the canvas notice and the
  Access Point panel already show the Access Point's state, and turning Public access on is the
  operator's own choice. Every other `Warning` header is shown.
  `showSurfaceSaveToast` (`elements/saveWarnings.ts`) shows a save in one toast, since a later
  toast replaces an earlier one: "<saved>" alone as `success`, or "<saved>, with warnings:"
  and one line per warning as a `warning` toast, the shown `Warning` headers first, then the
  dashboard's own non-blocking issues (`validateSurfacePayload`), each message once. The same
  headers fill `SaveWarningsBanner` on the edit page, and a create that drew any opens the new
  surface's page so the banner lists them.
- **Transit Settings** has no listener authentication control: the gateway does not support
  `transit.source_auth` and refuses a save that sets it. **Transit Token Mode** is shown, not
  chosen: only the embedded token exists, signed and readable by the agent, not encrypted, so
  the panel offers no `reference` option and every save sends `transit_token_mode: embedded`.
  Neither the panel, its canvas summary, the
  Transit Point factory nor a variant's overrides set `sign_requests`, which the gateway
  ignores.
- The Transit Point panel's **Agent Card** section (**Override Agent Card Location**) is shown
  for an A2A or AP2 Transit Point with a URL destination only. A gateway destination
  (`fabric://`) reads the card at the remote gateway's discovery paths, so the section is
  hidden there; a stored `agent_card_path` is kept and ignored.
- The Transit Point panel's **Who can call this Transit Point** section
  (`TransitCallerSection.tsx`, rules in `callerAuth.ts`) holds the transit token switch
  (`transit-point-require-transit-token-switch`), the **Caller authentication** select
  (`transit-point-caller-auth-method`: None, API key from the secret store, API key from the
  provider, JWT bearer; mTLS only shows, and keeps, one set through the API) with its fields
  (`transit-point-caller-auth-header`, `-secret`, `-strategy`, `-audience-input`,
  `-token-header`, `-token-scheme`), and the **Open to any caller** switch
  (`transit-point-allow-unauthenticated-callers-switch`), shown only while the Transit Point
  has no transit token, `source_auth` or `mcp_http.authorization`, and set only through a
  confirmation (`transit-point-open-confirm`). The node config holds `source_auth` in its wire
  shape, so a stored one round-trips; the factory writes it with `callerAuthToWire`. Turning
  caller authentication off sends `"source_auth": null`, which a `PUT` honours as removal (an
  omitted `source_auth` keeps the stored one). The open marking is sent only while nothing
  else authenticates the Transit Point, and as an explicit `false` after the operator turned
  it off. The save rules the API enforces apply before the save, through the element's
  `validate`, which faults the node and blocks Save: no way to authenticate and not open,
  open beside the token or a method, `source_auth` beside `mcp_http.authorization`, and an API
  key with no secret or header, a JWT with no strategy, token header or audience (or one that
  forwards the token); an empty token scheme is allowed, as the gateway reads the raw header
  value then. Each shows as `transit-point-caller-auth-problem`. Choosing the API Key Provider
  shows `transit-point-caller-auth-provider-scope`: its keys are the surface's own, the same an
  Access Point using the provider accepts. Its `agent_id` is written from the surface being
  saved (`callerAuthToWire(config, surfaceId)`), as the Access Point's is, so a Transit Point
  copied from a template or another surface does not keep that surface's. The strategy and API key secret lists load through
  `useJwtStrategies` and `useApiKeySecrets` (`elements/caller-auth/useCallerAuthOptions.ts`),
  shared with the Access Point's caller authentication editor.
- The exposure warning: when a save answers with `Warning: 299` headers, `apiClient.createSurface`
  and `updateSurface` pass their messages to an `onWarnings` option, the pages toast them and
  `SurfaceMetaContext.saveWarnings` hands them to the Transit Point whose alias they name, in
  the base view, or in the variant view a warning's `in variant '<alias>'` names
  (`transit-point-save-warning`), where each stays until that Transit Point's token, caller
  authentication, open marking or listener changes. Before the save, the panel predicts the
  exposure from the Transit Point's listener URL (`transit-point-exposure-warning`) with the
  gateway's own rule; the gateway also counts bind addresses and shared-domain inbound
  listeners, which the dashboard does not see, so only the header is complete. A create that
  drew warnings opens the new surface's page with them in the route state, which that page
  reads once and then clears, keeping the query string and hash, so a refresh or a Back return
  does not show them again. The page keeps save warnings with the surface they came from, so
  they do not show on another surface the page moves to. A refused
  save shows the API's reason in plain words on the Transit Point it names, in the base view
  for `transit.points[i]: ...` and in that variant's view for `variant '<alias>' transit.points[i]: ...`
  (`transit-point-save-error`). A write never carries `transit_point_source_auth`: the gateway
  derives it from the stored Transit Points.
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
- **Identity → From API Key** on the inbound Identity has no key field: in place of the picker
  the panel shows the one line "Each caller is identified by the API key it presents."
  (`identity-panel-inbound-api-key-note`);
  `buildPayload` never sends an inbound `api_key_id`. The protected and external Identities keep
  the picker (`identity-panel-api-key-select`) and need a key. An error-level dependency blocks
  Save unless every Caller Context method is API Key or API Key Provider, with the gateway's
  own message. `incompleteReason(config, node?)` receives the node so a rule can tell the slots
  apart. Rules only the gateway enforces (an MCP `proxy://` target, `mcp_http.authorization`)
  and rules on inactive variants show as the save-error banner.
- **Caller Context methods**: the caller-auth element's config holds `methods`, saved as
  `caller_authentication.methods`, the first being the primary method, and `protected_resource`,
  which belongs to the primary;
  `readMethods` in `caller-auth/methods.ts` also reads an older canvas that kept the first method
  on the element and the rest as `additional_methods`. The sidebar and the fullscreen editor show
  the same list (`CallerAuthMethodList.tsx`): one row per method with a ready or problem icon, its
  short name, what it reads (or its problem), and a **Configure ↗** button, then **Add method**,
  a menu of method types that adds one and opens it. Configure in the sidebar opens the
  fullscreen editor on that method (`selectedMethod.ts`, never saved); the editor's list adds
  **Make primary** (which moves a method first and keeps the rest in order) and remove buttons
  (a sole method cannot be removed) and shows the selected method's
  settings below it (`CallerAuthMethodFields.tsx`, one method at a time, so its ids stay
  `caller-auth-*`). With several methods the first carries a Primary badge. While authorization
  server discovery is on, the primary stays primary and carries a discovery badge. `methods.ts`
  mirrors the gateway's save rules (each method reads its own credential location, only a sole
  method reads the request body, at most one DID Auth, and, while authorization server discovery
  is on, JWT Bearer only as the first method), shown on each row and on the canvas. Removing the
  primary method also turns discovery off, since discovery belongs to it. With several methods an incomplete one marks the element
  unconfigured as `Method <n>: <reason>`. Loading a surface always replaces `methods`, so a stale
  canvas copy never brings back a removed method.
- **Authorization server discovery** (`caller-auth/CallerAuthDiscoverySection.tsx`) edits
  `caller_authentication.protected_resource` in the Caller Context editor of an MCP surface whose
  first method is JWT Bearer; additional methods never show it. Turning it on prefills the
  resource with the Access Point's https listener URL plus its route (left empty otherwise),
  empties Accepted Audiences, turns token forwarding off and sets the `Authorization` header with the `Bearer` scheme; each of those controls stays
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

- A Transit Point's Rate Limit panel (`rate-limit/RateLimitPanel.tsx`) adds a **Per caller
  (optional)** section (`per-caller-rate-limit`) below the shared limit, with its explanation
  behind `field-help-rate-limit-per-caller`. It writes `transit.points[].per_caller_rate_limit`
  beside `rate_limit` (`rate-limit/wire.ts`), and either can be set alone. The inbound Rate Limit
  panel does not show it. Inputs: `rate-limit-caller-requests-input`,
  `rate-limit-caller-window-secs-input` and `rate-limit-caller-burst-input`; like the gateway,
  `validate` refuses a per-caller requests, window or burst below 1. A per-caller limit set
  through the API is kept by a dashboard save, and a limit removed through the API is not
  restored: a Transit Point's rate-limit node takes its limits only from the stored surface,
  never from the canvas blob. On a named variant the per-caller inputs are read-only, with the
  hint `rate-limit-caller-base-only`, and show the base point's limit (`resolveVariant`);
  `computeOverridesFromPayload` leaves `per_caller_rate_limit` out of a variant's points, since
  the gateway enforces the base point's.
- A Transit Point's **Inject outbound credential** binding (`_shared/TransitCredentialBindingSection.tsx`)
  keeps what its controls do not set: `elicit_timeout_secs`, `elicit_fallback` and an external
  consent binding's `subject` round-trip through the form, and the consent select
  (`transit-point-consent-mode-select`) shows a stored `elicit` or `external` mode as a disabled
  option. An `external` binding is read-only: its provider, scopes, consent mode and injection
  inputs are disabled, and only the switch that removes it stays enabled, with a line saying
  whose grant it uses and that changing or removing it revokes its grants
  (`transit-point-binding-subject`): such a binding is changed through the API. The Credential
  Delegation element (`_shared/OutboundCredentialsListSection.tsx`) does the same for the Access
  Point Target's binding with external consent in `outbound_credentials`
  (`credential-delegation-consent-mode-select`, `credential-delegation-binding-subject`), and asks
  for an agent identity only beside a binding without external consent, since the gateway
  refuses a presentation of the agent beside one. Beside such a binding it disables **Add
  credential** (`credential-delegation-add`), with a line saying it is the Target's only binding
  (`credential-delegation-add-blocked`), and shows no gateway callback URL for it, since its
  grant arrives through the connect API's own redirect. Its rows come only from the stored
  `outbound_credentials` (`payloadOwnsConfig`), so a binding moved to a variant or removed through
  the API never comes back from the canvas blob; an element in the blob whose rows name no
  provider yet, which no save stored (`isBlobPlaceholder`), is kept. A variant save sends
  `outbound_credentials`, `[]` when the variant has no binding, since the gateway reads a missing
  list as keeping the surface's. A stored variant without its own list still has none sent while
  it shows no binding and the surface has none, so it keeps inheriting the surface's.
- **Target authentication** on the Managed Agent (fullscreen editor) and on a Transit Point
  takes its credential from a static secret or from a credential provider. The Managed Agent
  editor has a **Credential Source** select (`managed-agent-target-auth-source`: Static secret,
  Credential provider); the Transit Point's auth type select (`transit-point-target-auth-type`)
  has a **Credential Provider** option with header name and format inputs defaulting to
  `Authorization` and `Bearer {value}`. Both use the shared `TargetAuthProviderSelect`
  (`_shared/TargetAuthProviderSelect.tsx`), which lists only Client Credentials, JWT Bearer,
  Client Credentials JWT and API Key providers, since the gateway refuses an Authorization Code
  provider here. `_shared/providerTargetAuth.ts` maps the form to and from the wire
  `method.credential_provider`, and a Transit Point with the option but no provider blocks Save.
  Test ids: `managed-agent-target-auth-provider`, `transit-point-target-auth-provider`, each with
  `-add-link`, and `transit-point-target-auth-provider-header-name` / `-header-format`.
- **Tenant-aware pickers.** A surface's tenant (`tenantId` in `SurfaceMetaContext`, from the stored
  surface's `tenant_id`; `null` is appliance-wide, absent while creating) decides what the credential
  provider pickers (`TargetAuthProviderSelect`, `TransitCredentialBindingSection`,
  `OutboundCredentialsListSection`) and the Custom Metadata secret menu offer: only items with the
  same `tenant_id` (`utils/tenantScope.ts`, `splitByTenant`). The delegation pickers
  (`TransitCredentialBindingSection`, `OutboundCredentialsListSection`) also offer a tenant surface
  appliance-wide authorization code providers, which send the user's own token and which the gateway
  keeps accepting (`sendsGatewayCredential`), except a provider with an `issuer` (external consent),
  which the gateway refuses outside its own tenant and the pickers leave out of that allowance. A
  provider or secret already stored on the surface that lies outside its tenant stays selectable and
  is labelled by what the gateway does with it (`outOfTenantLabel`): "appliance-wide, stops working
  when enforced" for an appliance-wide one, so it can be replaced before the gateway enforces tenant
  isolation, "appliance-wide, refused by the gateway" for an appliance-wide provider with an
  `issuer`, and "another tenant, refused by the gateway" for one of another tenant, which the
  gateway already refuses. While creating, every visible item is offered
  and the gateway refuses a cross-tenant reference on save.

| Element                                                        | Test id                                                                                                                                                                                            |
| -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Discovery switch, resource, use listener URL                   | `caller-auth-discovery-switch`, `caller-auth-discovery-resource-input`, `caller-auth-discovery-use-listener-url-button`                                                                            |
| List, where `<list>` is `authorization-server` or `scope`      | `caller-auth-discovery-<list>-input`, `caller-auth-discovery-add-<list>-button`, `caller-auth-discovery-<list>-<index>`, `caller-auth-discovery-remove-<list>-<index>-button`                      |
| Variant resource, default variant note, rules explainer toggle | `caller-auth-discovery-variant-resource`, `caller-auth-discovery-default-variant-note`, `caller-auth-discovery-context-toggle`                                                                     |
| Errors                                                         | `caller-auth-discovery-save-error`, `caller-auth-discovery-rules-error`, `caller-auth-discovery-resource-error`, `caller-auth-discovery-<list>s-error`, `caller-auth-discovery-<list>-input-error` |
| Sidebar status and error                                       | `caller-auth-panel-discovery-status`, `caller-auth-panel-discovery-save-error`                                                                                                                     |

- **Switching views from content.** The Surface Builder views are Surface, Templates, Elements,
  Agent Cards, Monitoring and Config (see _Agent Cards tab_). A switch started from content (**View
  agent cards**, **Open the Surface view**) goes through `openViewFromContent` in
  `SurfaceFormShell`, which then moves focus to the destination's sidebar view button (or the Agent
  Cards heading when the sidebar is collapsed); a click on a sidebar view button leaves focus where
  it is.

Caller Context method lists use `<area>` `caller-auth-panel` (sidebar) or `caller-auth-editor`
(fullscreen editor):

| Caller Context methods element      | Test id                                                                                 |
| ----------------------------------- | --------------------------------------------------------------------------------------- |
| Method list, one method row         | `<area>-methods`, `<area>-method-<index>`                                               |
| A row's status icon and Configure   | `<area>-method-<index>-status`, `<area>-method-<index>-configure-button`                |
| A row's Make primary and remove     | `<area>-method-<index>-make-primary-button`, `-remove-button` (editor)                  |
| Add method button, menu, menu entry | `<area>-add-method-button`, `<area>-add-method-menu`, `<area>-add-method-<method type>` |
| Selected method's settings (editor) | `caller-auth-editor-method-settings`                                                    |

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

## Payments page

`/payments` (`pages/PaymentsPage.tsx`, sections in `pages/PaymentsPage/`), shown on
`payments.view` whether or not `agent_pay_delegation` is on (see _Feature flags_), is one list of payments, with no tabs, chart or audit trail view, and reads the
append-only ledger from `GET /api/admin/payments` (`surface_id` from the URL query,
`outcome` from the filter) and shows one row per payment check with an outcome badge; a
held row shows its case id. The Surface cell says `via <payment surface> on <payment
gateway>` (`payments-gateway-<id>`, the id as its tooltip) and the details show the
**Payment gateway** by name (`payments-detail-gateway`). `usePaymentGatewayNames` reads
`GET /payment-gateways` once per page and falls back to the id for an unlisted gateway or a
failed read; the ledger is never filtered by it. `usePaymentLedger` only lets the latest request write rows,
the error and the Refresh state, so a slow answer to an earlier filter never overwrites a
later one. When a refresh fails, the rows of the same filter stay under
`payments-stale-note` ("may be out of date"), and the rows of an earlier filter are dropped.
An outcome or surface filter with no rows shows "No payments match this filter" rather than
"No payments yet". The outcomes are `paid`, `challenge`, `held`, `rejected`, `unavailable`, `unconfirmed` (the
charge outcome is unknown), `authorized` (funds held until the Target delivers), `voided` (held funds released) and
`capture_failed` (the Target delivered but the capture failed), each with its note in `OUTCOME_META`; an unconfirmed row's details show `payments-detail-outcome-note`
("Payment taken or unconfirmed - retry the same request with the same credential within 2
minutes"). **Details** opens `GET /api/admin/payments/{id}`; for a
held row the response may carry `case_status` (`{status, checked_at}` from agent-pay), shown
as **Case status** in plain words, and **Refresh status** reads the row again while the
shown row stays. It is absent whenever agent-pay could not be asked, and the modal says "Not available" with the
possible reasons (not connected or no answer in time, the case no longer known, or no status
requested for the row).
The details also show, only when the row has them (`settlementFields` in
`pages/PaymentsPage/settlementFields.tsx`): **Authorization id**, **Capture deadline**, **Intent**
(capture or void, with the attempt count), **Settlement status** (awaiting delivery, capture or
void pending, unconfirmed, settled, superseded, or reconciliation gave up), **Charged vs quoted**
with a "Price mismatch" badge, **Superseded by** and a "Reconcile failed" badge.
The details also show **Reason** (why a refused, failed or released payment ended so),
**Updated at**, **Idempotency key**, **Settle timeout** and **Caller (hashed)** (the peppered hash
the ledger records, never the caller) when the row has them.
A row with a reason shows it, truncated with the full text as its tooltip, under the outcome badge.
`capture_failed` reads "Payment capture failed or is unconfirmed - reconcile before asking
the payer to pay again". `listPayments` and `getPayment` go through the shared request path,
so a 401 expires the session. A
read-only **Legacy x402/MPP** list appears below the payments only while the old
x402/MPP endpoints still return rows: one row per transaction (the verification and
settlement summaries merged, the settlement giving the status) with the x402 amount scaled
by the token's decimals and shown in dollars. `/x402payments` redirects here and keeps its query string and hash. Test ids:
`page-payments`, `payments-outcome-filter`, `payments-filter-input`, `payments-refresh-button`,
`payments-row-<id>`, `payments-surface-link-<id>`, `payments-held-case-<id>`,
`payments-details-button-<id>`, `payments-detail-modal`, `payments-detail-dismiss-button`,
`payments-detail-close-button`, `payments-detail-error`, `payments-detail-case-status`,
`payments-detail-case-status-text`, `payments-detail-refresh-button`,
`payments-detail-authorization-id`, `payments-detail-capture-deadline`, `payments-detail-settle-intent`,
`payments-detail-settlement-status`, `payments-detail-price-mismatch`, `payments-detail-superseded-by`,
`payments-detail-reconcile-failed`, `payments-detail-reason`, `payments-detail-updated-at`,
`payments-detail-idempotency-key`, `payments-detail-settle-timeout`,
`payments-detail-caller-principal`, `payments-reason-<id>`,
`payments-legacy-panel`, `payments-legacy-row-<key>`,
`payments-error-alert`, `payments-error-dismiss-button`, `payments-stale-note`,
`payments-surface-filter`, `payments-gateway-<id>`, `payments-detail-gateway`.

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
  a `time` element with the absolute time as its title). A failed fetch names the cause with the HTTP status (`describeFetchFailure`), for
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
  only) and Surface Variants existing
  (`agent-card-variant-note`, because the view shows the base route). `hasVariants` comes from the
  saved surface's enabled variants.
- Card content comes from the agent, so it
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
  passes `isDirty` (ignoring canvas layout), its save counter as `agentCardRefreshKey` (so a save reads
  the cards again) and `hasVariants`.

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
  known resource kind. The known kinds (`ACCESS_TOKEN_RESOURCE_KINDS` in
  `accessTokenHelpers.ts`) list every backend `ResourceKind`; a Rust test in `src/tenancy`
  fails while one is missing.
- The tester uses the compact sample-header and **Sample entity ID** rows, plus Agent
  Gateway's resource-kind selector and canonical target.
- Static patterns, repeated or multiple placeholders, and tenant-wide catch-alls block
  save.
- Header validation regexes match the entire value: `\d` means one digit and `\d{4}`
  means four. Show this rule in the tester, and render **no match** for a failed sample.
- Warn that non-literal header patterns let the holder choose any matching tenant.
- Do not add a PAT-only tenant field or tenant picker.

Keep labels associated, timestamps exact, and clipboard failures visible.

## JWT verification strategy editor

`/jwt-verification-strategies/new` and `/jwt-verification-strategies/:id`
(`EditJwtVerificationStrategyPage.tsx`) have a **Caller identity claim** field
(`jwt-strategy-editor-principal-claim-input`), the strategy's `principal_claim`. A new strategy
sends the trimmed value only when it is not blank, so a blank field means `sub`. On an existing
strategy the field shows the stored claim, is disabled, and is left out of the update, since the
gateway refuses a change to it. A save's `Warning` headers, such as another strategy naming the
same issuer's callers by a different claim, are shown in a warning toast that stays until closed.

## Credentials audit tab

`pages/CredentialsPage/CredentialAuditTab.tsx` shows an expanded event's caller. **Subject** is
the token's own `sub`; a **Principal** row (`credential-audit-caller-principal`) shows the value
the caller's grants are keyed by, `caller.principal`, only when the JWT strategy names a claim
other than `sub`.

## Credential provider editor

`/credential-providers/new` and `/credential-providers/:id` (`EditCredentialProviderPage.tsx`)
show the inputs of the chosen Provider Type (`credential-provider-type-select`).
`EditCredentialProviderPage/credentialProviderForm.ts` decides which inputs a type uses
(`providerTypeFields`), the first missing required field, and the request fields.

- **JWT Bearer** asks for Token Endpoint, Issuer, Subject, Signing Key, and optionally Key ID and
  Audience, with no client ID or secret. **Client Credentials JWT** asks for Token Endpoint,
  Client ID and Signing Key, and optionally Certificate (Entra) and Key ID, with no client
  secret. Both share the **Signed JWT** section (`JwtAssertionSection.tsx`,
  `credential-provider-jwt-section`): Key ID sits under Certificate, a warning
  (`credential-provider-jwt-key-unidentified-warning`, from `jwtKeyUnidentified`) shows when
  neither names the key, and the algorithm select lists the type's algorithms, default first.
- Key material is never typed into this form. Signing key and certificate are secret pickers
  (`SecretSelect.tsx`, `credential-provider-<field>-select`); the operator creates the secret on
  the Secrets page and pastes the PEM, or a whole Google service account JSON key file (16 KiB
  at most), there. Key ID may stay empty for a JSON key, whose `private_key_id` is then sent as
  `kid`; a Key ID overrides it. The gateway checks the key on save.
- Save sends a field the type does not use as empty, which the gateway reads as cleared, so
  switching a provider to Client Credentials JWT drops its client secret.
- `resource` has no input (it is set through the API or YAML) and is never sent on save. When
  `entraRejectsResource` finds it set on a Microsoft identity platform v2.0 token endpoint, which
  rejects it (AADSTS901002), the form warns under Token Endpoint
  (`credential-provider-entra-resource-warning`) and the list row shows a warning icon
  (`credential-provider-entra-resource-badge`).
- The secret pickers offer only secrets of the provider's own tenant (`SecretOptions` in
  `SecretSelect.tsx`; the tenant is the loaded provider's `tenant_id`, unknown while creating). A
  stored secret outside that tenant stays selectable with the same labels: "appliance-wide, stops
  working when enforced" or "another tenant, refused by the gateway". The gateway keeps such a
  secret on save only in the field that holds it and while the provider's type and destination
  are unchanged.
- A Token Endpoint starting with `http://` shows a warning
  (`credential-provider-token-endpoint-https-warning`, warning styling, field not marked invalid)
  saying new or changed http endpoints are refused unless listed by exact URL in the bootstrap
  `credential_policy.insecure_token_endpoints`, and that an unchanged stored one is still accepted
  while `token_endpoint_https` is `warn`. It does not block Save; the gateway decides on save.
- A provider with an `issuer` (external consent) shows a notice naming the issuer
  (`credential-provider-external-notice`) in place of the type, endpoint, client, callback and
  additional parameter inputs, which the gateway keeps fixed; Save sends only its name,
  description, default scopes and token refresh (`externalProviderUpdate`).
- The Credential Providers tab labels the types from `PROVIDER_TYPE_LABELS` in the same module. A
  refused delete shows the API's reason and, for a `409`, the surface that binds the provider
  (`providerDeleteError`).

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
`pages/IdentitiesPage/`, with tests in `pages/IdentitiesPage/__tests__/`: search, recorder
filter, and surface links in the `useIdentityRows` hook, the shared managed DID check in
`sharedManagedDid.ts`, and the row parts `IdentityNameCell`, `IdentitySurfaceCell`,
`IdentityOriginBadge`, and `IdentityRecorderChip`.

- Each DID gets its own row, keyed by the DID, with its own actions (Trust Score, Version History, Configure Policy, Copy link).
  Managed identities that share a surface, such as parallel `from_jwt_claim` DIDs, are
  separate rows linked to the same surface. `/identities/<did>` expands that exact
  identity.
- Expansion state is a `Set` of DIDs. Rows expand and collapse independently, and a deep link
  adds to the set rather than replacing it.
- The **Name** column (`IdentityNameCell` with `showDid={false}`) shows the display name
  prominently. The header is "Name", not "Agent Name": the column holds display names, and
  _agent name_ is the verified `host/@local` handle only. While a caller name lookup is
  pending (`display_name_pending`), it shows a muted "resolving…" line. A verified agent
  name renders as `local · host` with a verified marker. A caller's Agent Card name
  (`agent_card`), a managed agent's target Agent Card name (`target_agent_card`) and a
  surface name show no badge. Without a display name, it shows `metadata.agent_name` when that
  is a non-empty string, else a muted, italic "Unnamed Agent".
- The **DID** column (`IdentityNameCell` with `showName={false}`) shows the shortened DID in
  monospace with a copy button for the full DID, then the version badge and SCID when set.
- The table has no Usage Count column; the usage count is still in the expanded details and
  the API.
- A **shared managed DID** is the managed agent on more than one live surface: its
  `managed_surfaces` (every live surface where the DID is the managed agent, sorted by name;
  omitted when empty) has two or more entries. It is one row. Its Name cell shows a muted,
  italic "Unnamed Agent" (so it is not mistaken for an Agent Card named that), then "N
  surfaces". This applies even if a `display_name` arrives.
- The **Agent Surface** cell lists every surface in `managed_surfaces` for a shared managed
  DID, each linking to `/surfaces/<surface_id>` (live name preferred), not the last-used
  `channel_*` surface. Other rows show their single surface link as before. The credential
  principal sits beneath the surfaces.
- The expanded details of a shared managed DID leave out the Agent Surface entry, so the
  surface names appear only in the Agent Surface cell. Single-surface rows keep it.
- The **Origin** column holds the origin badge (Managed Agent or External Caller), or
  LOCAL/REMOTE for records without an origin, plus a VERIFIED badge where it applies.
- Managed rows show an origin badge, the live surface name linking to
  `/surfaces/<surface_id>`, and the credential principal as a separate field.
- Search also matches the surface names in `managed_surfaces`. It does not match the
  last-used `channel_name` of a managed row, which may be a surface where the DID was only a
  caller.
- When the backend sends none of the naming fields, the Name column still shows, with
  `metadata.agent_name` or "Unnamed Agent", and there is no origin badge.
- **Recorder** status comes from the optional `trust_recorder` field on an identity (types in
  `types.ts`), present only when one of the identity's managed surfaces has a Trust Recorder.
  A shared managed DID carries the worst outcome across those surfaces, ranked Failed >
  Partly recorded > Skipped > Not attempted yet > Recorded. "Not attempted yet" outranks
  "Recorded", so a DID recorded on one surface whose other surface's recorder has not run
  shows "Not attempted yet". Such a DID also carries `trust_recorder_surface` (a
  `ManagedSurfaceRef`, sent only for a shared managed DID), the surface whose outcome
  `trust_recorder` holds; the chip's accessible name reads "Trust Recorder status on
  <surface>: <state>" and its tooltip opens with "Recorder on <surface>". It is the gateway
  recorder's last known outcome, not a live registry check. When any identity has it,
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
    the field). It is page state and combines with the search (AND).
  - A websocket identity update replaces the whole identity, so a changed `trust_recorder`
    outcome shows without a reload. The backend includes an identity in the delta when its
    recorder outcome changes; adding or removing a Trust Recorder shows on the next update or
    reload.

| Element                        | Test id                                                                  |
| ------------------------------ | ------------------------------------------------------------------------ |
| Identity row                   | `identities-row-<did>`                                                   |
| Name, pending, verified        | `identities-name`, `identities-name-pending`, `identities-name-verified` |
| No name                        | `identities-name-empty`                                                  |
| Shared managed DID name, count | `identities-unnamed-agent`, `identities-shared-surface-count`            |
| Copy DID                       | `identities-copy-did-button`                                             |
| Origin badge                   | `identities-origin-<origin>`                                             |
| Surface list, surface link     | `identities-surface-list`, `identities-surface-link`                     |
| Credential principal           | `identities-credential-principal`                                        |
| Recorder filter                | `identities-recorder-filter`                                             |
| Recorder chip                  | `identities-recorder-chip-<state>`                                       |
| Recorder tooltip               | `identities-recorder-tooltip`                                            |
| Tooltip recorder surface       | `identities-recorder-surface`                                            |
| Tooltip last attempt, reason   | `identities-recorder-last-attempt`, `identities-recorder-reason`         |
| Tooltip registry entry         | `identities-recorder-entry-<registry id>`                                |

## Trust Agent page

`/trust-agent` lists the Verifiable Trust Agent connections and states which signing tier the
gateway is on. The tier banner (`VtaTierBanner`) reads `GET /v1/vta/status` and never derives
anything itself:

- `custody_claim` is computed by the backend. It is false for the bundled sidecar and for
  local signing, and the banner then says the deployment is **not** a key custody tier. Never
  write copy that implies custody while it is false.
- For a bundled sidecar that bootstraps itself (`bootstrap` present), the banner adds one line
  (`data-testid="vta-bootstrap-status"`): the state, from the fixed set `connected`,
  `waiting_for_vta`, `enrolment_refused`, `vta_replaced`, `vta_lost`, `revoked` and
  `misconfigured`. A healthy state shows the owner (`vta-bootstrap-owner`, `unclaimed` until a
  person claims the trust agent). Any other state shows the backend's `advice`
  (`vta-bootstrap-advice`) and `detail` (`vta-bootstrap-detail`) in danger text, and says signing
  is refused when `previously_connected` is true. The advice text is the backend's, so a new
  state needs a label here and advice there.
- The connections table below it reads `GET /v1/vta/connections`. The `vta-bootstrap` record is
  the bundled sidecar's; the backend reports its pairing state from the bootstrap (so it reads
  Connected while the sidecar is, never "Not paired"), and the page offers no Revoke on it
  (`canRevoke`) or Verify (`canVerify`), since the server refuses both.
- The Surface Builder's **Signing key** select (`SurfaceSigningSection`) offers the `[vta]` block's
  own record (`vta-bootstrap`) as **Bundled trust agent** once it is connected and shows its
  signing key (`keys.active`, filled in by the API from the bootstrap), so a surface can be pinned
  to the sidecar while the appliance default is another agent. While it is not connected it is
  left out rather than shown as "not ready", unless the surface already saved it, so the select
  is never blank. Other connections without an active key stay listed as "not ready".
- While the gateway signs locally because a bundled trust agent never came up (`enabled` is
  false), the banner still shows the bootstrap line, so the operator is told why.
- **Settings → Key management** (`KeyManagementSettingsSection`, with `DefaultSigningPicker`)
  reports what is in force: a default chosen in the picker (stored in `default_signing`) wins over
  what the configuration resolves to (`default_resolution` of `GET /v1/vta/status`). The picker's
  first option clears the stored choice, which hands signing back to the configuration, so it is
  named for what that resolves to: "The bundled trust agent (default)", "The configured agent",
  or "This gateway's own key (local)". The bundled connection is not listed again, and the
  confirmation stays visible after a save because the picker stays mounted.
- The connect wizard's last step offers **Use this agent for all signing**, pre-checked only
  when the appliance has no default yet. A default is either a stored one
  (`default_signing.connection_id` in `GET /v1/settings`) or the bundled trust agent
  (`default_resolution.backend` of `GET /v1/vta/status` is `bundled`): connecting a second agent
  must never silently repoint signing away from either.

## Connections page

`/connections` (`pages/ConnectionsPage.tsx`) has the tabs **Gateways**, **Payment Gateways**,
**Mediators** and **Registries**, kept in `?tab=` (`gateways`, `payment-gateways`,
`mediators`, `trust-registries`). The active tab follows the URL, so a link to another tab of
the page switches it; an unknown or hidden value opens the first tab shown. The page (route and
sidebar entry) opens with `gateways.view`, or also with `payment_gateways.view` while
`agent_pay_delegation` is on (`ProtectedRoute` accepts a list, any one of which is enough; the
route waits for the settings before deciding). **Gateways** shows only with `gateways.view` and
**Payment Gateways** (`connections-tab-payment-gateways`) only with `payment_gateways.view` and
`agent_pay_delegation` on (see _Feature flags_). One filter box serves every tab; each tab reports its
filtered and total counts (`onCountChange`) for the badge, and a tab given `actionsContainer`
portals its add button into the tab banner.

### Payment Gateways tab

`pages/PaymentGatewaysPage.tsx` (`page-payment-gateways`, sections in
`pages/PaymentGatewaysPage/`) lists `GET /payment-gateways` (`apiClient.listPaymentGateways`);
its Connect button is limit-guarded on `connections.paymentgateways` like the Gateways tab's on
`connections.gateways`. It lists:
remote gateways with `role: 'payment'`, which `GET /gateways` never returns. The filter matches
name, description, id and DID.

- Columns: name with its description, status (`GatewayStatusCell` in
  `components/gateways/`, shared with the Gateways tab: badge, failure reason, peer last seen),
  and **Offers**. An active row reads `GET /payment-gateways/{id}/info`
  (`usePaymentGatewayInfo` in `components/payment-gateways/`) and shows
  `PaymentGatewayOfferSummary`: protocol badges, one chip per distinct payment method (network
  or provider, `via <settles_via>`) and the payment surface count. A row exposing no payment
  surface adds a warning line. A failed read shows a short warning with the reason as its
  tooltip (503 not reachable, 502 not a payment gateway) and never blocks the list.
- A row opens the detail page. Actions: **Verify** (`payment_gateways.edit`, a pending or
  awaiting-approval row) resumes the wizard at `/payment-gateways/connect?id=<id>`; Open; Ping
  (`payment_gateways.edit`, `POST /payment-gateways/{id}/ping`, not for a pending row); Delete
  (`payment_gateways.delete`, the two-step `DeleteButton`). A refused delete (409 while surfaces
  take payments through it or it holds unsettled payments) shows the gateway's message.
- **Connect Payment Gateway** (`payment_gateways.edit`) opens the wizard. With no payment
  gateway an `EmptyState` explains agent-pay and has the same action.

### Connect Payment Gateway wizard

`/payment-gateways/connect` (`pages/AddPaymentGatewayWizardPage.tsx`, `payment_gateways.edit`,
root `wizard-add-payment-gateway`) reuses the Connect via OOB step components in
`components/gateway-add-via-oob/` with payment wording (`AddPaymentGatewayWizardPage/wording.ts`);
their `wording` props (and ConnectStep's `endpoint` and `title`) default to the gateway
wizard's, so `/gateways/connect` is unchanged. Steps:

1. **Enter Details**, then **Connection Point Link**, then **Connect**, which posts to
   `POST /payment-gateways/connect-via-oob` (a 409 says the connection point is already a
   Fabric peer) and puts `?id=<new id>` in the URL.
2. **Awaiting Approval** (`AwaitApprovalStep`) reads `GET /payment-gateways/{id}` every 3
   seconds until the status is `active`, says agent-pay's administrator must approve, and lets
   the user leave; Verify on the list returns here. A 404 stops with an error.
3. **Verify** (`VerifyPaymentGatewayStep`) reads `/payment-gateways/{id}/info`. It passes when
   the gateway answers with role `payment`; `payable_count` 0 passes with a warning to expose a
   payment surface on the shared connection point. 502 fails (not a payment gateway, or
   agent-pay too old) and 503 retries by itself every 5 seconds. **Re-check** asks again.
4. **Complete** links to the detail page and back to the tab.

`?id=` opens the wizard at Awaiting Approval, which moves on to Verify at once for an active
gateway. Every wizard's step bar is the shared `components/shared/WizardProgress.tsx`.

### Payment gateway detail page

`/payment-gateways/:id` (`pages/PaymentGatewayDetailPage.tsx`, `payment_gateways.view`,
sections in `pages/PaymentGatewayDetailPage/`) has four tabs, mounted when opened, and no
Publishing or Global Policy tab:

- **Overview**: name and description saved with `PUT /payment-gateways/{id}`, DID, id,
  status, offer, dates, and **Disable**/**Enable** (`PUT` with `status`). A 409 refusal shows
  the gateway's message. A pending gateway links to Verify. Editing needs
  `payment_gateways.edit`; Delete in the header needs `payment_gateways.delete` and shows a 409
  message the same way.
- **Payment Surfaces**: `GET /payment-gateways/{id}/surfaces`, each surface with its manifest
  through `PaymentManifestPreview` (a `testIdPrefix` per surface and no Refresh); **Refresh**
  adds `force_refresh=true`.
- **Used by**: the surfaces from `GET /surfaces` whose `target.payment_policy`, or a variant's
  `overrides.target.payment_policy`, is `agent_pay` naming this gateway (`usedBy.ts`), linked
  to `/surfaces/<id>`.
- **Health**: runtime status, last contact, and **Ping** (`payment_gateways.edit`).

### Use as payment gateway

The Gateways tab (icon button per row) and the gateway edit page (header) offer **Use as
payment gateway** (`components/gateways/UseAsPaymentGatewayButton.tsx`) for an active remote
peer, only with both `gateways.edit` and `payment_gateways.edit`. A confirm says it moves to
Payment Gateways and stops reaching this gateway's surfaces; then
`POST /gateways/{id}/payment-role` and the Payment Gateways tab opens. A 409 (a surface routes
to it over `fabric://`) shows the gateway's message.

| Element                                  | Test id                                                                                                                                                       |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Tab, list, rows                          | `connections-tab-payment-gateways`, `page-payment-gateways`, `payment-gateways-table`, `payment-gateways-row-<id>`, `gateway-status-<id>`                       |
| List actions                             | `payment-gateways-connect-button`, `-open-button-<id>`, `-verify-button-<id>`, `-ping-button-<id>`, `-delete-button-<id>` (all `payment-gateways-`)              |
| List offer                               | `payment-gateways-offer-<id>` (and `-payable-count`), `-offer-loading-<id>`, `-offer-error-<id>`, `-offer-empty-<id>`                                           |
| List states                              | `payment-gateways-empty-state`, `payment-gateways-empty-connect-button`, `payment-gateways-no-match`, `payment-gateways-error-alert`, `payment-gateways-success-alert`, each alert with `-dismiss-button` |
| Wizard steps                             | `wizard-progress`, `wizard-progress-step-<key>`, `wizard-step-details`, `wizard-step-link`, `wizard-step-connect`, `wizard-step-approval`, `wizard-step-verify`, `wizard-step-complete` |
| Wizard navigation (both OOB wizards)     | `wizard-next`, `wizard-back`, `wizard-cancel`, `wizard-submit`, `wizard-oob-view-button`, `wizard-oob-connect-retry-button`                                     |
| Wizard fields (both OOB wizards)         | `wizard-oob-name-input`, `wizard-oob-description-input`, `wizard-oob-did-method-select`, `wizard-oob-link-input`, `wizard-oob-secret-input`, `wizard-oob-details-error`, `wizard-oob-link-error`, `wizard-oob-connect-error` |
| Approval and verify                      | `payment-gateway-approval-status`, `payment-gateway-approval-error`, `payment-gateway-verify-loading`, `-verify-ok`, `-verify-no-surface`, `-verify-error`, `-verify-offer`, `-verify-recheck-button` |
| Detail page                              | `page-payment-gateway`, `payment-gateway-back-button`, `-delete-button`, `-error-alert`, `-tab-<overview\|surfaces\|used-by\|health>`                          |
| Detail overview                          | `payment-gateway-name-input`, `-description-input`, `-did`, `-status`, `-offer`, `-offer-error`, `-save-button`, `-toggle-status-button`, `-pending-note`, `-verify-button` |
| Detail surfaces, used by, health         | `payment-gateway-surfaces-refresh-button`, `-surfaces-error`, `-surfaces-empty`, `-surface-<id>`, `payment-gateway-surface-manifest-<id>-*`, `-used-by-<id>`, `-used-by-link-<id>`, `-used-by-empty`, `-used-by-error`, `-ping-button`, `-ping-result` |
| Use as payment gateway                   | `gateways-use-as-payment-button-<id>` (Gateways tab), `gateway-use-as-payment-button` (edit page)                                                             |

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
- Under the status of an active, pending or failed remote row it shows when the peer
  gateway was last heard from (`PeerLastSeen` in `utils/connectionHealth.tsx`, from the list's
  `peer_last_seen_at`, rendered by the shared `GatewayStatusCell` that the Payment Gateways
  list uses too): "Peer seen <relative time>" with the absolute time as the tooltip, or
  "Peer not heard from since this gateway started" (testid `gateway-peer-last-seen-<id>`). It
  is separate from the row's own status, which reflects this gateway's mediator link.

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

Settings → **Admin** → **Feature Flags** is a table of the shared `FeatureFlagRow`
(`SettingsPage/SystemTab.tsx`).

- A new flag is one row plus an optional field on `FeatureFlags` in `types.ts`.
- Its default-when-unset is expressed in `checked`: `!== false` for default on, `=== true`
  for default off.
- The switch carries `data-testid="settings-flag-<flag>"`, `role="switch"`, and
  `aria-labelledby` pointing at the row's flag-name cell, so its accessible name is the
  flag key.
- `agent_pay_delegation` (`settings-flag-agent_pay_delegation`) is default off and shows the
  agent-pay UI. Read it through `utils/featureFlags.ts` (`agentPayEnabled`, `useAgentPayFlag`),
  never inline. While off: Connections has no **Payment Gateways** tab and a payment-gateways-only
  caller no longer reaches Connections; `/payment-gateways`, `/payment-gateways/connect` and
  `/payment-gateways/:id` go to `/connections` (`components/AgentPayRoute.tsx`, which renders
  nothing until the settings have loaded, so a deep link is not redirected early); **Use as
  payment gateway** is not shown; the palette does not offer the **Payment** element
  (`registry.paletteItems(protocol, hidden)`) and the templates panel hides templates that add
  one (`templateTakesPayments`); the Payment element's gateway picker shows no Add link
  (`addGatewayLink={null}`). A surface that already has a Payment element keeps it, rendered and
  editable, so opening and saving it never drops its `payment_policy`. The Payments page is not
  gated: its sidebar entry and `/payments` (and `/x402payments`, which redirects to it) need only
  `payments.view`, so the ledger and the legacy x402/MPP list stay readable with the flag off;
  only its empty state changes, naming the flag instead of the Payment element.
  Like `mediator_federation`, it is
  system-only: a user's own flag overrides never change it, so the UI always matches the gateway,
  which refuses to add a payment gateway while it is off. The gateway turns it on at startup when a
  payment gateway already exists and no operator has set it either way. The Connections permission
  list (`connectionsPermissions`) is shared by the route and the sidebar. When the settings cannot
  be loaded, `FALLBACK_SETTINGS` (every flag off) is used so the pages waiting for them render.
- `mediator_federation` is default off and experimental. On, the Connect via OOB wizard's
  details step (`gateway-add-via-oob/EnterDetailsStep.tsx`) shows a mediator picker
  (`wizard-oob-acceptor-mediator`) that lists only mediators with `status === 'active'` and
  `registered` true, and sends the choice as `acceptor_mediator_id`; the default option
  sends nothing. When the list is empty it shows `wizard-oob-acceptor-mediator-empty`, and
  when `/mediators` fails, `wizard-oob-acceptor-mediator-load-error`.

## Restore from backup

Settings → **Admin** → **Restore from Backup** (`SettingsPage/SystemTab.tsx`) accepts
`.agbak` and legacy `.tgwbak` files. The legacy support is stated on the page
(`data-testid="restore-legacy-format-note"`), and the wrong-file toast names both extensions.
The hidden file input is `data-testid="restore-file-input"`.

## Maintenance actions

The Dashboard's Gateway Configuration card shows the metrics **Delete** button
(`dashboard-metrics-delete-button`) only when `hasPermission('settings.edit')`, the permission
`POST /v1/metrics/truncate` needs; the **Logs** button is shown to everyone. Settings → **Admin**
(`SettingsPage/SystemTab.tsx`), shown with `settings.view`, holds **Truncate Old Metrics Now**
(`settings-admin-truncate-metrics-button`) and **Truncate Old Logs**
(`settings-admin-truncate-logs-button`), whose routes also need `settings.edit`. The backend
check is authoritative; see [`docs/RBAC.md`](../../docs/RBAC.md#maintenance-and-welcome-routes).

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
