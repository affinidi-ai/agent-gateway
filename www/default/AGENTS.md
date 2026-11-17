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
9. Theme-dependent styles hang off `body.dark-theme`, never `@media (prefers-color-scheme)`:
   the dashboard theme is the operator's choice and need not match the operating system, so a
   media query paints light text on a light surface (or the reverse). `themeSelectors.test.ts`
   fails on any stylesheet that uses it.
10. Text and icons on a light surface use the text-safe tokens in `dashboard.css`
   (`--warning-text`, `--success-text`, `--danger-text`, `--accent-blue-text`,
   `--accent-teal-text`, `--accent-purple-text`, `--muted-text`), which `body.dark-theme` swaps for
   lighter values; solid buttons and badges under white text use `--primary-solid`,
   `--success-solid`, `--warning-solid` and `--danger-solid`. The brand colours `--warning`,
   `--success`, `--danger` and `--accent-blue` stay for borders, tints and text on dark
   surfaces. Normal text needs 4.5:1 and informational icons 3:1 in both themes; do not use
   `#9ca3af`, `--gray-400`, `--gray-500` on a dark surface, or an `opacity` below 1 for text.
   Purely decorative icons, such as the large stat card and empty state icons, are exempt.
11. Mediator lists may contain directory entries (`directory:*` ids), and stored records
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
10. Dashboard routes are served from the gateway root, so a top-level route must not share a
    prefix with a gateway channel (`/agents`, `/payments`, `/routes`, ... in
    `config/examples/gateway.example.json`). In-app navigation still works, but refresh, deep links
    and new tabs reach the proxy and return 404. Agent endpoints default to `/agents/<surface-name>`,
    so `/agents` in particular is never a dashboard route. Add every new top-level route to
    `SPA_RESERVED_TOP_LEVEL` in `src/proxy/paths.rs`.

## Toasts

`showToast` and `showUndoToast` (`utils/toaster.ts`) render the message and the action label as
text (`textContent`), never as HTML, so a name or a server error message in a toast cannot run
script. Pass plain text only: markup such as `<b>` shows literally, and callers must not
escape the text themselves. `showUndoToast` returns a function that dismisses that toast
without Undo, as its close button does. A new toast replaces the one on screen and stops it:
the replaced toast's timer and `u` key no longer act, and an Undo toast counts as dismissed
without Undo (its `onExpire` runs). `removeToast` does the same. This holds on every page.

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
`payments-details-button-<id>`. On `/surfaces/<id>` the save button is `surface-save-button`,
the banner for a refused save is `surface-error-alert`, and the delete button is
`surface-delete-button`, which opens `surface-delete-confirm` with `surface-delete-confirm-name`,
`surface-delete-confirm-confirm` and `surface-delete-confirm-cancel` (see _Surface delete_).

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

- The palette offers the A2A Transit Point only on A2A and AP2 surfaces and the MCP Transit
  Point only on MCP surfaces (`protocols` on the node definition); a DIDComm surface, or one
  with no protocol yet, is offered neither. Transit Points already on a surface keep
  rendering and editing.
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
- **Response Authentication** is the Managed Agent panel's
  `managed-agent/ResponseAuthSection.tsx` (rules and wording in `managed-agent/responseAuth.ts`),
  shown only for an HTTP or HTTPS Target. It edits `target.response_auth` in its wire shape:
  **Off**, **API key** (response header, default `X-Agent-Key`, and a secret from
  `useApiKeySecrets`) or **mTLS** (trust by pinned certificate or Certificate Authority, with
  checkboxes listing the active `client_leaf` or `ca` certificates of `GET /certificates`, and an
  optional client certificate from the `client_leaf` ones; the list does not say which have a
  private key, so `FieldHelp` says one is needed and the gateway refuses the save otherwise).
  mTLS is a disabled option on an `http://` Target, and its `FieldHelp` says why. An API key on
  an `http://` Target shows an always-visible warning. A stored id the lists do not have stays
  shown, so it can be cleared, and a shape the panel cannot read is kept as "Set through the API".
  The Target's config takes `response_auth` only from the stored surface, never from the canvas
  blob, so one removed through the API stays removed. The gateway keeps a stored one a `PUT`
  leaves out, so Save sends the value unchanged when the operator did not edit it, `null` once
  switched off or when the Target is no longer HTTP or HTTPS, and nothing when there is none. A
  variant carries it in `overrides.target`, with `null` to clear its stored override. `validate`
  blocks Save for an API key without a header or secret, and for mTLS without a trusted
  certificate or on an `http://` Target. The gateway's refusal (`target.response_auth…`, or
  `variants['<alias>'].target.response_auth…` in that variant's view) and its `Warning` headers
  show in the section with the field name in plain words; a warning stays until the endpoint or
  the setting changes. A save sends every variant as a complete override, which replaces the
  base's setting with the variant's own, so while the base view has a setting, an
  `InfoBanner` warning (`-variants-warning`) names the variants whose snapshot has an HTTP or
  HTTPS Target and no setting (`variantsWithoutResponseAuth`; a variant never opened has no
  snapshot and is saved from the base, so it is not named). Its **Copy to variants** button
  (`-copy-to-variants`, disabled while the base setting is incomplete or the surface is
  read-only) writes the base value, in its wire shape, into those snapshots only, so the next
  Save sends it in each one's `overrides.target`; it never saves by itself, and the warning
  disappears once no variant is left without it. Test ids, with prefix
  `managed-agent-response-auth`: `-section`,
  `-method`, `-header`, `-secret`, `-add-secret-link`, `-http-warning`, `-trust-mode`,
  `-trust-certificates`, `-trust-cert-<id>`, `-add-certificate-link`, `-client-cert`,
  `-certificates-error`, `-unsupported`, `-variants-warning`, `-copy-to-variants`, `-problem`,
  `-save-warning`, `-save-error`, and
  `field-help-managed-agent-response-auth` / `-client-cert`.
- The Agent Identity panel (`identity/IdentityPanel.tsx`) disables **From API Key** on the
  Managed Agent response identity (`response:identity-protected`), since the key picker lists
  API keys issued to callers, and none of them identifies the Managed Agent; the inbound and
  external slots still offer it. A protected
  identity already set to From API Key keeps showing its key selector. Transit Point
  identities offer only From Payload.
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
  (`legacyAccessPoint` in `SurfaceMetaContext`, set by the edit page), turning the switch off
  clears `public`, so turning it on and off again keeps `public` unset. A `public: false`
  set in the JSON editor shows `access-point-closing-notice` under the switch until the save,
  and is sent, like one set with the switch on a surface that has `public`. Once `public` is
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
  `elements/saveWarnings.ts` drops them, a variant's prefix ignored). Every other `Warning` header is shown.
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
  the picker (`identity-panel-api-key-select`) and need a key. The picker lists only the active
  keys of the surface being edited (`GET /api-keys/{surface_id}`, from `SurfaceMetaContext`), as
  the gateway refuses another surface's key; a stored id that is not among them stays selected
  as a disabled option, so it cannot be picked again once changed, labelled by its status
  (below), or "<id> (not an active key of this surface)" when that status is not `revoked`,
  `missing` or `unavailable`. **Unconfigured Identity**: the surface read and save
  responses carry `api_key_references` (`key_id`, `status` and `blocking`), passed to the panels and the
  canvas as `apiKeyStatuses` in `SurfaceMetaContext` (`elements/identity/apiKeyStatus.ts`). The
  gateway sets `blocking` on `revoked` and `missing`, and on `unavailable` (another surface's
  key) when that key is revoked or while `tenant_credential_isolation` is `enforce`, exactly as
  the gateway refuses the surface; the dashboard follows `blocking`
  and does not work it out itself. A
  protected, external or Transit Point From API Key Identity whose current `api_key_id` is
  `blocking` gets the canvas's red `unconfigured-ring` (red, dashed
  and animated by the `.surface-builder-canvas .unconfigured-ring` rule, like every other ring)
  with "API key revoked", "API key deleted" or "API key of another surface" under its label, and
  the panel shows the full warning in red under the picker (`identity-api-key-revoked-warning`,
  `role="alert"`) and
  labels the stored key "<client id> (revoked)" (the revoked key's name from the surface's key
  list, or its id when that list does not have it), "<id> (deleted)" or "<id> (belongs to
  another surface)". The
  warnings are "The API key this Identity uses was revoked. Select an active API key of this
  surface.", "… was deleted. Select an active API key of this surface." and "The API key this
  Identity uses belongs to another surface. Select an active API key of this surface." An
  `unavailable` key that is not `blocking` (`warn`) keeps the "(belongs to another surface)"
  label and shows the same text in the warning yellow (`text-warning`, `role="status"`,
  `identity-api-key-other-surface-notice`), with no ring, no canvas reason and no Save block. An
  `active` or `unknown` status, a key id not in the
  list, and the inbound Identity show nothing. The lookup is by key id, so variant canvases use
  the same list, and picking an active key clears the ring before Save. It blocks Save on the
  surface page, in the base and every variant, with "Identity: " and the full warning
  (`firstUnusableApiKeyIdentity` in `computeBlockingReason`), and the toast's "Show me" selects
  the Identity. It is not part of `configured` or `getIncompleteReason`, since the statuses come
  from the stored surface, not the node. On the create page (`isCreate`, which already has a
  client-made `surfaceId`) it fetches nothing and shows "A new surface has no API keys yet. Remove
  this Identity or choose another type, save the surface, add an API key, then come back and
  select it." (`identity-panel-api-key-unsaved`); the rule is behind
  `field-help-identity-api-key`. A protected or external From API Key Identity without a key is
  incomplete and blocks Save with "Select an API key of this surface. A new surface has no API keys
  yet: remove this Identity or choose another type, save the surface, add an API key, then come
  back and select it." (`SELECT_OWN_API_KEY`). A template capture or apply
  (`scrubVolatileTemplateFields`) drops every `api_key_id` of the identity slots, target identity
  injection, Transit Point `managed_identity` and `identity_injection`, variant overrides and
  canvas Identity nodes (top-level and in variant overrides), every `atgk_` Caller Context
  `secret_id` of the base and the variant overrides, and the read-only `access_point_status`,
  `api_key_references` and `serving_status`, so the new surface's Identity asks for its own key. A
  surface write never sends `access_point_status`, `api_key_references` or `serving_status`
  (`toBackendSurface`). **Refusing requests**: while the surface response's `serving_status`
  (present only beside `api_key_references`) is `not_serving`, the surface page's top banner shows
  "This surface is refusing requests" (`surface-refusing-requests`, `alert-warning`,
  `role="status"`); `serving` and `not_judged` show nothing. The gateway gives no reason, so the
  notice names none. An error-level dependency blocks
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
  unconfigured as `Method <n>: <reason>`.
- **JWT Bearer audiences**: Accepted Audiences is required; with none listed, discovery off and
  Audience Claim `aud`, the method shows `caller-auth-audiences-missing-warning`. Save is not
  blocked for it, since the gateway keeps a method stored without audiences unchanged and refuses
  a new or changed one with a message the page shows. **Audience Claim**
  (`caller-auth-jwt-audience-claim`) writes `audience_claim` (`aud`, `client_id` or `azp`, saved
  only when not `aud`); a value other than `aud` shows `caller-auth-jwt-audience-claim-warning`
  (its callers get no per-user delegated credentials; the gateway refuses it beside an
  `on_demand`, `pre_authorize` or `elicit` binding) and blocks Save until a value is listed. Transit Points have no Audience Claim control: they match `aud`. Loading a surface always replaces `methods`, so a stale
  canvas copy never brings back a removed method.
- **Authorization server discovery** (`caller-auth/CallerAuthDiscoverySection.tsx`) edits
  `caller_authentication.protected_resource` in the Caller Context editor of an MCP surface whose
  first method is JWT Bearer; additional methods never show it. Turning it on prefills the
  resource with the Access Point's https listener URL plus its route (left empty otherwise),
  empties Accepted Audiences, sets Audience Claim to `aud`, turns token forwarding off and sets the `Authorization` header with the `Bearer` scheme; each of those controls stays
  locked while discovery is on, once it holds that value. Authorization servers (1 to 8) and
  scopes are lists checked as each value is added, and `protectedResource.ts` mirrors the
  gateway's save rules, which block Save. Leaving JWT Bearer drops the setting. A variant shows
  the resource it advertises, `<resource>$<alias>`, and keeps its own setting. A failed save whose
  message names the setting shows in the section and in the sidebar, which also shows whether
  discovery is on.
- **Accepted Audiences** adds a value left in the field when the field loses focus or on
  Cmd/Ctrl+S, so a typed audience is saved without pressing Enter, comma, or Add. It adds
  nothing while discovery is on, and skips empty and duplicate values.
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
  (`transit-point-binding-subject`): such a binding is changed through the API. A binding's
  own consent time limit (`max_consent_age_secs`) has no control either: it round-trips through
  the form (`consentLimitFieldOf`) and is shown as a line under the consent select
  (`_shared/BindingConsentLimitNote.tsx`), in words from `describeConsentLimit`
  (`transit-point-binding-consent-limit`, and `credential-delegation-binding-consent-limit` in the
  Credential Delegation element), so a dashboard save never drops a limit set through the API. The Credential
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
  `method.credential_provider`, and a Managed Agent or Transit Point with the option but no
  provider blocks Save.
  Test ids: `managed-agent-target-auth-provider`, `transit-point-target-auth-provider`, each with
  `-add-link`, and `transit-point-target-auth-provider-header-name` / `-header-format`.
  - **Scopes.** The credential provider method has an optional space-separated **Scopes** input
    (`managed-agent-target-auth-scopes`, `transit-point-target-auth-provider-scopes`) wired to the
    wire `scopes`; empty uses the provider's default scopes.
  - **Rules that block Save**, which the gateway refuses in every mode: a header name that is not
    an HTTP token or is reserved (Host, Content-Length, Transfer-Encoding, Connection, Keep-Alive,
    Proxy-Connection, TE, Upgrade, Trailer, and the gateway's own transit, caller, identity, trace and
    MCP session headers: 23 names in all); a format without exactly one `{value}` or with CR, LF
    or NUL; a provider method with no provider picked; on the Managed Agent, a secret method
    with no secret picked, which would send no `target.auth` and so remove a stored credential
    (the Transit Point secret picker has the same rule). Header names are compared as the gateway
    compares them, in any letter case and with `_` read as `-` (`sameHeaderName`), so
    `X_Transit_Token` is reserved too. In the Managed Agent's full-screen editor the header,
    format, provider and secret (`managed-agent-target-auth-secret-error`) messages show next to
    their inputs, each in a `role="alert"` region and
    tied to its input with `aria-invalid` and `aria-describedby`; the Managed Agent and Transit
    Point panels show every message in a notice (`*-target-auth-errors`), and the Transit
    Point's header inputs point at that notice the same way. Rules that need the whole surface
    live in `elements/targetAuthRules.ts`, run by `validateSurfacePayload` when the page passes
    the stored surface (`stored`, `null` for a new one): a header another credential on the same
    leg already sends (a binding, header metadata mapping, the token header of any JWT Bearer
    caller method that forwards it) blocks Save, on the Managed Agent or on the Transit Point it
    belongs to. The surface page runs the clash check on the view being saved and on every other
    variant, whose error names the variant. The toast's **Show me** selects the canvas node that
    has the problem: a Transit Point's node is the one at its position among the Transit Point
    nodes of the payload's `canvas.nodes`, never an id built from its index, and a payload whose
    canvas data lists a different number of Transit Points names no node.
  - **A stored problem blocks too.** The gateway refuses a header name, format or clash problem
    on every save, one in a stored setting the operator did not edit included, so the dashboard
    shows it as an error next to its field and blocks Save until it is fixed. The editors drop
    only the spaces and tabs around a header name or format (`trimSpaces`), never a line break or
    NUL, so a stored value that ends in one is reported whether or not its panel was opened. A
    blank field sends the default, except a blank the stored setting already had
    (`blankHeaderValue`), which stays blank and is reported; the forms load a stored blank as
    blank (`storedHeaderValue`). The Managed Agent's full-screen editor shows the Header Format
    input for the Custom type, and for any other type while its format has an error and until the
    type is chosen again, so the message always has its input.
  - **Advisories that allow Save.** A Target that is not `https://` (`http://`, `fabric://` and
    `a2a-proxy://` are not) and a leg that authenticates no caller (an Access Point with no source
    authentication, a Transit Point that authenticates no caller) are shown as an advisory
    (`*-target-auth-advisories`, warning styling) and never block Save: the gateway refuses them
    on save only while its `target_https` or `target_source_auth` rule is `enforce`, and in
    `warn` saves with a `Warning: 299` header. The dashboard does not read the rule mode. The
    Managed Agent's `proxy://` Target gets no https advisory, since the gateway decides it from
    the MCP proxy's `base_url`, which the editor does not see; a Transit Point's `proxy://`
    target endpoint does, since the gateway checks it as written. The Managed Agent editors learn whether the
    Access Point checks its callers from `accessPointChecksCallers` in `SurfaceMetaContext`,
    which the surface pages set from the draft payload (`hasCallerAuthentication`). After a
    save in `warn` the header's message shows in the save toast and the surface page's save
    warnings banner; in `enforce` the gateway's 400 shows in the page's error alert. The
    whole-surface caller check is a `warning` issue in `validateSurfacePayload`, left out when
    the stored surface already had it on the same leg with the same setting and endpoint.
  - **Advice with no gateway rule.** The same box also shows a passthrough fallback (the
    request goes on without the credential when the credential cannot be resolved) and a stored
    method the editor cannot show, each ending "Save is allowed".
  - **Messages name their kind.** `TargetAuthProblemNotice` opens every message with **Error:**
    or **Advisory:**, so colour is not the only difference, and keeps its
    `role="alert"` and `role="status"` regions mounted while empty, so a message that appears is
    announced.
  - **Lossless save.** Each Managed Agent and Transit Point keeps the stored `target_auth` in
    the node config (`_stored_target_auth`); the edited fields are merged onto it
    (`mergeTargetAuth`), so a field the editor does not show survives. That holds while the edit
    keeps the stored credential: another method kind, secret or provider replaces the stored
    setting, so nothing unseen follows a credential it was not set for. A Transit Point whose
    auth form was never opened sends the stored `target_auth` unchanged, and so does a Managed
    Agent or Transit Point whose stored method the editor cannot show, until the operator
    chooses a secret or a provider.
  - **Never in the canvas data.** The Target authentication form fields, the stored copy and a
    Transit Point's `target_auth` are left out of the canvas blob on save and ignored when one
    is read (`withoutTargetAuth` in `elements/registry.ts`; the key lists are
    `MANAGED_AGENT_TARGET_AUTH_FORM_KEYS` and `TRANSIT_POINT_TARGET_AUTH_FORM_KEYS`), so a node
    the stored surface no longer has comes back without a Target authentication. A new form
    field must be added to its key list.
- **Transit Point secret picker.** For Bearer Token, API Key Header and Custom Header, the Transit
  Point panel picks the secret from the secrets store (`transit-point/TargetAuthSecretField.tsx`,
  labelled **Secret Reference**) and saves its `secret_id` as `method.static_secret.secret_id`. Options come
  from the shared `components/shared/SecretOptions.tsx` (`Name (secret_id)`, tenant-aware, all
  secret types). A refresh icon button beside the select reloads only the list
  (`useTargetAuthSecrets`); it uses the Managed Agent panel's sync icon and spin but sits beside
  the field, not on the label line, so it isn't missed. **Add secret** below opens `/secrets/new`
  in a new tab, and the help text never changes. A stored secret that no longer exists stays
  selected as `<secret_id> (not found)` with a warning; an out-of-tenant one keeps its
  `outOfTenantLabel` and is explained in full below the field. A list that can't load says
  "Couldn't load secrets." with **Try again**, or, when the request is refused (403), "You don't
  have access to secrets. Ask an administrator."; both keep the stored value and show no refresh
  button. The element's `validate` blocks Save while no secret is picked
  (`targetAuthSecretProblem`, field `auth_secret`), since an empty secret would otherwise drop
  target authentication. Test ids: `transit-point-target-auth-secret`, with `-refresh`,
  `-add-link`, `-error`, `-missing`, `-outside-tenant`, `-load-error`, `-retry` and `-denied`.
- **Tenant-aware pickers.** A surface's tenant (`tenantId` in `SurfaceMetaContext`, from the stored
  surface's `tenant_id`; `null` is appliance-wide, absent while creating) decides what the credential
  provider pickers (`TargetAuthProviderSelect`, `TransitCredentialBindingSection`,
  `OutboundCredentialsListSection`), the Transit Point secret picker (`TargetAuthSecretField`) and
  the Custom Metadata secret menu offer: only items with the
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
| JWT audience claim and its warnings | `caller-auth-jwt-audience-claim`, `-audience-claim-warning`, `caller-auth-audiences-missing-warning` |

### Policy input capture

- The surface's Capture view (`monitoring/capture/SurfaceCapturePanel.tsx`) has a **Policy Input**
  card (`monitoring/capture/PolicyInputCaptureCard.tsx`) between the latest payload and the
  payload history. Its header holds the **Listen to policy input** button
  (`monitoring/PolicyInputCaptureControl.tsx`), shown only on a saved surface (never while
  creating). The Monitoring view itself has only the Capture button.
- The Capture view's toolbar holds **Pause**/**Resume** (payload capture only), **Clear**
  (`btn-outline-danger`; it clears captured payloads and policy inputs) and **Copy All Stages**.
  Every card title in the view is a `font-weight-bold text-primary` `h6`, and the Surface Route
  line copies with the shared `CopyButton`.
- The button is shown only while the `policy_input_capture` feature flag is on (see _Feature
  flags_). While it is off, the card shows no button, no empty-state hint and no no-policy note;
  an `alert alert-info` (`policy-input-capture-off`) says "Policy input capture is turned off on
  this gateway. An administrator can turn it on under Settings › Admin › Feature Flags
  (`policy_input_capture`)." Evaluations already in the list stay. Until the settings have loaded
  the card shows neither the button nor that notice. When the settings could not be read
  (`state.settingsLoadFailed` in `AppContext`, set while `settings` holds `FALLBACK_SETTINGS`;
  `usePolicyInputCaptureFlag` returns it as `loadFailed` and is its only reader), the card shows
  an `alert alert-danger` (`policy-input-capture-settings-error`) saying "Could not read the
  gateway settings" with an `outline-danger` **Retry** (`policy-input-capture-settings-retry`)
  that calls `actions.loadSettings`, in place of the turned-off notice. When the gateway's flag is turned off while
  the page still reads it on, the gateway's refusal (`policy input capture is turned off`) ends
  listening and shows as the inline error, like any other refusal.
- Capture is live and lasts only while the view is open: the button turns into **Stop
  listening**, and an effect keyed on the surface and the listening state sends
  `capture_policy_input` (and its cleanup `stop_capturing_policy_input`) on the dashboard
  WebSocket through `actions.listenToPolicyInput` in `AppContext`. Clicking again, leaving the
  Capture view (unmount) or reloading the page stops it; a new surface id moves listening to that
  surface. Nothing is stored, so a reload starts with listening off. `AppContext` keeps the open
  listens in a `PolicyInputListens` (`context/policyInputListens.ts`) and sends them again after a
  socket reconnect. There is no duration and no admin API call.
- While listening, a green "Listening" indicator shows when the dashboard socket is connected
  (`state.wsStatus === 'CONNECTED'`), and a warning "Waiting for the dashboard connection" in its
  place otherwise. While the Capture view's Pause holds the payload stream during a listen, a
  muted line (`policy-input-capture-paused-note`) says "Pause holds payload capture only; policy
  input keeps arriving. Use Stop listening to stop it." (`SurfaceCapturePanel` passes
  `stream.isPaused` to the card as `payloadPaused`, and the card to the control.)
- The button needs both `surfaces.edit` and `policies.edit`; without either it is disabled with
  "Needs permission to edit surfaces and policies" beside it. When the gateway ends listening
  (`listening: false` with an `error`, such as a refusal, an ended session or a permission lost at
  a keep-alive ping), the button
  goes back to **Listen to policy input** without sending a stop of its own
  (`listenToPolicyInput(id, false, false)`), and an `error` shows inline beside it until the user
  clicks again or a later answer starts listening. A `listening: false` answer without an `error`
  answers this page's own stop and changes nothing, so a stop answered after the user listened
  again doesn't turn the button off.
- The card follows the Capture view's existing cards, Payload History in particular: a
  `card shadow mb-4` whose `text-primary` `h6` header holds the icon, the title and a `count/max`
  `text-bg-primary` badge, with the warning and muted hint lines beneath it (see below) and the
  listen control on the right; a
  `table table-hover table-sm` with a **Timestamp** column rendered by `formatDateTime(…, true)`
  (`timestamp-cell`) and the policy slot as a `text-bg-secondary` badge, like a payload's Channel;
  the no-policy note as an `alert alert-info` with an icon, like the route and Target lines. The
  input's copy button is the shared `CopyButton`, which shows a check when it copied; a failed
  copy shows an error toast. The rest of the Capture view keeps its own markup.
- The card lists the last 50 `policy_input_captured` WebSocket updates of the surface (see
  `monitoring/capture/usePolicyInputCaptureStream.ts`), newest first: time, policy slot with a
  variant badge and, under it, the name and version of each policy the slot ran (`policies`; the
  name, else the id, else "inline policy"; the member that denied a gateway or appliance-wide set
  in red with "(denied)"), a decision badge (Allow green, Deny red, Error yellow) with the reason, a
  **Show input** toggle that opens the input JSON, and a copy button for the input. Above the
  list an "All policy slots" select shows one slot's rows (the header's hint says the last 50
  evaluations are kept and that one request can add several rows); a chosen slot that has
  left the list (cleared or rolled off) falls back to all slots. With none it says to
  listen and send a request, and that on an appliance with several nodes only requests served by
  this dashboard's node show. Clear applies to it too; Pause holds only the payload
  stream, so the card keeps every evaluation of a listen while payloads are paused, and says so
  while a listen is on. Each row's input is formatted as JSON only when its row is opened or
  its copy button is clicked (`CopyButton` takes `text` as a string or a function that builds
  it). When the gateway reports
  captures it dropped for this dashboard (`policy_input_skipped`), a warning alert
  (`policy-input-capture-skipped`) above the list says how many evaluations were not shown;
  Clear resets it. The header stacks
  the title and count badge, then a warning line (`text-warning` with a triangle icon,
  `policy-input-capture-warning`): "For developing and testing policies only", then the muted
  hint line; the Listen control sits on the right.
- While the surface has no policy the gateway captures (`surfaceHasPolicy`: an Access Point,
  Target or Target response policy, the shared Transit Point policy
  `transit.opa_policy_definition_id`, a Transit Point policy or response policy, or a variant's
  Access Point, Target or Target response policy), the card shows an info note above the list: the surface has nothing of
  its own to capture, only a gateway or appliance-wide policy shows, and a request policy (an
  allow-all one is enough) should be added first. The button's `FieldHelp` says the same.
- The note that captures show each request and response policy evaluation (not MCP tool
  policies), only those of this dashboard's node on a multi-node appliance, hold request data with
  credentials masked, reach only the listening user, are neither logged nor stored, are for
  developing and testing policies only, and stop when listening stops sits behind the button's
  `FieldHelp`.
- The Audit Log's Category filter offers `policy_input_capture_started` and
  `policy_input_capture_stopped` ("Policy Input Capture Started" / "Stopped", in the overflow
  menu like the other low-frequency categories).

| Policy input capture element                    | Test id                                                                |
| ----------------------------------------------- | ---------------------------------------------------------------------- |
| Control, button, listening, missing permission  | `policy-input-capture`, `policy-input-capture-listen`, `policy-input-capture-listening`, `policy-input-capture-not-allowed` |
| Waiting for the connection                      | `policy-input-capture-waiting`                                         |
| Pause note while listening                      | `policy-input-capture-paused-note`                                     |
| Hint line (kept count), slot filter             | `policy-input-capture-kept`, `policy-input-capture-slot-filter`        |
| Warning line, skipped notice                    | `policy-input-capture-warning`, `policy-input-capture-skipped`         |
| Help and error                                  | `field-help-policy-input-capture`, `policy-input-capture-error`        |
| Card, empty state, no-policy note, row          | `policy-input-capture-card`, `policy-input-capture-empty`, `policy-input-capture-no-policy`, `policy-input-capture-row` |
| Turned-off notice                               | `policy-input-capture-off`                                             |
| Settings read error, its Retry                  | `policy-input-capture-settings-error`, `policy-input-capture-settings-retry` |
| Reason, input toggle, input, copy               | `policy-input-capture-reason`, `policy-input-capture-toggle`, `policy-input-capture-input`, `policy-input-capture-copy` |
| Policy the slot ran                             | `policy-input-capture-policy`                                          |

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
- **Authority source.** A Trust Check query and a Trust Recorder entry carry `authority_source`
  (`AuthoritySource` in `types.ts`: `authority` or `issuer`) beside a literal anchor DID found in
  that register, and none beside a template or a DID in neither. `queriesFromWire`, `readQueries`
  and `buildEntry` (Trust Check) and `readEntries` (Trust Recorder) keep it through every load and
  save, on the caller, Managed Agent and Transit Point lists and in variants. The gateway
  recomputes it on every save from the registers and never drops `authority`, so a link to a
  deleted Authority stays one;
  `authoritySourceFor` (`_shared/authorityReference.ts`) drops it beside an empty value or a
  template. The Authority picker writes `issuer` for an Issuer and `authority` for an Authority,
  and removes it for a caller-leg template; a preset (`applyPresetToQuery`) removes it; a stored
  custom DID or legacy template left untouched keeps what is stored.
- **Authority lists.** A query stored with `query.authority_ids` (several authorities) keeps that
  list and its `authority_sources` map through every load and save (`listedAuthorities`,
  `queryFromElement`, `buildEntry`), on every leg and in variants; the save never adds
  `authority_id` or `authority_source` beside it. In the fullscreen editor a query's **Authority
  ID** is one multi-select (`IssuerAuthorityPicker` on the shared `FormMultiSelect`, which shares
  its keyboard handling and option markup with `FormSelect` through `shared/listbox.tsx`): a picked Issuer
  or Authority shows a check on the right, as in `FormSelect`; a click toggles it and keeps the menu open, and the toggle lists
  the picked names in order. One pick is the single `authority_id` with `authority_source`,
  exactly as before; two or more are `authority_ids` in the order picked, each DID recorded in
  `authority_sources` as `issuer` or `authority` by the register it was picked from
  (`authorityRows`, `pickAuthorities`). Unchecking down to one makes the query single again, and
  unchecking all leaves an empty `authority_id` (the caller leg's default). The caller-leg
  templates (the verified-issuer default and the sending-gateway DID) combine with each other and
  with literal DIDs like any pick, with no source recorded; while nothing is stored the default
  shows checked and the first pick replaces it, and it stays only when ticked beside other
  picks. There is no limit on how many Authorities a query
  or a Trust Check names, in the editor or at the gateway. A picked Authority that
  was deleted shows as a checked "Deleted Authority" option with the warning, and like a deleted
  single Authority it is listed in the panel's "Configuration required" warning, draws the node
  unconfigured and blocks Save (`missingTrustCheckAuthorities` walks `authorityRows`). A stored
  list is incomplete, is marked invalid, and blocks the editor's Save when it has an empty entry
  or a template its leg refuses: any template on the target leg ("Select an Issuer or Authority
  for every Authority row"), or on the caller leg a template other than the verified-issuer
  default and the sending-gateway DID ("Replace the caller-leg Authority template …"); an empty
  entry gives the first message on either leg. The side panel lists each query as "Query N" and its record type
  only, with no Authorities or name; the fullscreen card header adds "N authorities". A node with one such
  query has the canvas summary `<type> · N authorities`; a node with several queries keeps "N
  queries".
- **Deleted Authority.** A query whose `authority_source` is `authority` and whose DID the loaded
  Authorities register no longer has is `missing-authority` (`classifyTargetAuthoritySelection`,
  checked against the Authorities only, even when an Issuer has the DID); the gateway fails it
  with `AUTHORITY_NOT_FOUND`. The register is `authorityDids` in `SurfaceMetaContext`, from
  `useAuthorityDids` (`hooks/useAuthorityDids.ts`), which both surface pages call: read when the
  page opens and when the tab becomes visible again, and updated by every
  `getAuthorities({ refresh: true })` through `subscribeAuthorities`, so an Authority added in
  another tab clears the problem. Nothing is flagged while it loads or after it failed; the
  fullscreen editors flag only once their own read loaded (`authoritiesLoaded`). It follows the
  blocking API key pattern: the node gets the red `unconfigured-ring` with "Authority deleted"
  under its label; the sidebar panel, and the picker in the fullscreen editor, show the shared
  `MissingAuthorityWarning` (`_shared/MissingAuthorityWarning.tsx`, a non-collapsible `danger`
  `InfoBanner` titled "Configuration required", `role="alert"`) saying the check fails with
  `AUTHORITY_NOT_FOUND` until it is fixed, the fixes (pick another Authority, add an Authority
  with the same DID through `deepLinks.authority`, or remove the Trust Check) and the stored DID
  ("Query <n>: <did>" when the node has several queries); the picker shows the DID as a checked
  "Deleted Authority" option marked invalid, which unchecking removes. Save is blocked on both surface pages, in the base
  and every variant, with the full warning and **Show me** (`firstMissingAuthorityNode` in
  `elements/missingAuthority.ts`). It is not part of `configured` or `getIncompleteReason`. The
  panel copy says the DID is stored directly and that, for an Authority, the gateway fails the
  check once that Authority is deleted. The Audit Log words `AUTHORITY_NOT_FOUND` as "the
  Authority this Trust Check uses no longer exists" (`TRUST_ERROR_LABEL`).

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
| Deleted Authority warning        | `trust-check-panel-authority-missing`, `trust-check-query-<n>-authority-missing`, each with `-dids` and `-add-authority-link` |
| Authority multi-select           | `trust-check-query-<n>-authority`; options `-authority-option-<did>`; `-authority-count` (two or more) |
| Sidebar query row                | `trust-check-panel-query-<n>` (query number and record type only)                                 |

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
- The entry's explicit Authority select writes `authority_source: 'authority'` for a DID of the
  Authorities register and `'issuer'` for an Issuer; **Use surface Issuer** and **Explicit DID**
  remove it (see _Authority source_ under Trust Check). An entry whose Authority was deleted gets
  the same ring, "Authority deleted" reason, `MissingAuthorityWarning` (the entry writes no records
  until it is fixed; "Entry <n>: <did>" in the sidebar when there are several), locked "Deleted
  Authority" option and Save block as a Trust Check. The recorder then reports `skipped` with
  reason `authority_not_found`, worded "Authority not found" by `utils/trustRecorderStatus.ts` in
  the Last outcome row and the Identities page chip.

| Element                            | Test id                                                                                                                           |
| ---------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Panel warning                      | `trust-recorder-panel-no-surface-issuer-warning`                                                                                  |
| Entry warning                      | `trust-recorder-entry-<index>-no-surface-issuer-warning`                                                                          |
| Deleted Authority warning          | `trust-recorder-panel-authority-missing`, `trust-recorder-entry-<index>-authority-missing`, each with `-dids` and `-add-authority-link` |
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

`/x402payments` (`pages/PaymentsPage.tsx`, sections in `pages/PaymentsPage/`), shown on
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
by the token's decimals and shown in dollars. `/payments` is left free for gateway channels, which older configs put there. Test ids:
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
  "Card refreshed." with the fetch result (OK, served without a managed identity, failing or not
  served, never the cause, which the alert gives) in a visually hidden status region (`agent-card-refresh-status`), cleared when the
  next Refresh starts; a 429 shows a warning toast and keeps the cards on screen; a refused or
  failed Refresh shows an error toast. The tab heading (`agent-card-heading`, `tabIndex=-1`) takes
  focus when **Retry** replaces itself with the loading status.
- A card served without a managed identity (`served_without_identity`, cause `identity_missing`)
  is a served card: the badge reads **Served – No managed identity** in the warning tone with no
  `agent-card-fetch-cause` beside it (a served card names no cause in the header), a warning
  alert (`agent-card-served-without-identity`, never danger) reads "The managed agent's card has no
  identity extension, so the gateway serves it without an identity credential.", and the comparison
  and raw panels show as for an OK fetch. `isCardServed` in `utils/agentCardPreview.ts` is the one
  check for "the card is served"; the Managed Agent panel's fetch line reads "Card fetch: Served –
  No managed identity" in the warning tone (`agent-card-fetch-warning`, icon
  `fa-circle-exclamation`), and the card counts as the last served card (`lastServed`).
- A failed or not-served fetch shows a danger alert with the cause text (`agent-card-failed`,
  `agent-card-failed-cause`) and opens both raw panels. For `identity_failed` the alert names
  `fetch.identity_error` with its own text (`CARD_IDENTITY_ERROR_TEXT`: an identity extension the
  gateway can use is missing, the extension is invalid, the card could not be read for its
  identity, a DID could not be issued, or the gateway could not attach its credential), and keeps
  the generic "Check the gateway logs, then Refresh." only when the gateway names none. When
  `fetch.identity_slot` is `external_identity` the alert uses `CARD_EXTERNAL_IDENTITY_ERROR_TEXT`
  instead, which points at the external Identity element rather than the managed agent's card. The
  parser rejects an `identity_error` or `identity_slot` beside any other cause. The managed panel
  reads "Not available:
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
- The Managed Agent panel shows one line, **Card fetch: OK**, **Card fetch: Served – No managed
  identity**, **Card fetch: failing (<cause — HTTP n>)** or **Card: generated by the gateway**, with
  an icon, and a **View agent cards** link button
  (`managed-agent-card-fetch`, `managed-agent-card-fetch-status`, `managed-agent-card-fetch-icon`,
  `managed-agent-card-fetch-link`), through `agent-card/AgentCardFetchLine.tsx`. The status text
  uses `agent-card-fetch-ok`, `agent-card-fetch-warning` and `agent-card-fetch-failing` (AA colours
  in both themes, scoped to `.agent-card-fetch-line`), not `text-success`, `text-warning` or
  `text-danger`. `AgentCardFetchLine` reads the
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

The Settings page's strategies tab (`SettingsPage/StrategiesTab.tsx`) shows a refused delete in
its alert with the gateway's message, the credential providers a `409` lists as still using the
strategy by name (else id), "and N you can't view" for its `hidden_references`, that a
provider's consent confirmation is changed in its editor and its `consent_identity_strategy_id`
through the API, and the status (`strategyDeleteError`). The delete's confirm dialog says
credential providers that use the strategy block the delete. The strategy editor shows a `409`
on save (an issuer change a provider using the strategy would refuse) with the same
`strategyDeleteError` text, so it names those providers and where to change them.

## Credential Tokens and Delegated Access tabs

The Credentials page keeps its **Credential Tokens** tab (`pages/CredentialsPage/CredentialTokensTab.tsx`,
tab key `credential-tokens`) and has a **Delegated Access** tab beside it
(`pages/CredentialsPage/DelegatedAccessTab.tsx`, tab key `delegated-access`, trigger
`credentials-delegated-access-tab-trigger`). The page calls `useDelegationVault()` once and
hands its `vault` to both tabs, so a revoke or a limit made on one is what the other shows. The
hook reads `GET /api/v1/delegation-vault` and `GET /api/v1/credential-providers` and owns the
three changes to the tokens (`revoke`, `revokeUser`, `limitConsent`); a tab keeps only its
toasts. `vault.refresh()` reads both lists again while they stay on screen, with no spinner. It
runs when the gateway answers a change with `404` or `409`, since the list is then out of date
(an entry the hourly removal or another operator already took, a consent given again), when a
limit is saved without its new end in the answer, and when the Credential Providers tab reports
a deactivate, an activate or a delete (`onProvidersChange`), so Delegated Access marks a
deactivated provider without a reload. `vault.reload()`, behind the spinner, is the Retry of a
failed read. The tabs still list the tokens when the providers cannot be read. A vault read the
gateway refuses, or that gets no answer, shows `VaultReadError.tsx` in place of the list: the
reason and **Retry** (`credential-tokens-read-error`, `delegated-access-read-error`, each with
`-retry`), never the empty state, since a failed read says nothing about what the vault holds;
Delegated Access then shows no count in its header.
The shared rules live in `pages/CredentialsPage/delegatedAccess.ts` (`consentState`, `timeLeft`,
`isActiveDelegation`, `isPersonsDelegation`, `consentLimitSecs`, `limitOutcome`,
`limitOutcomeText`, `canLimitConsent`, `renewsAutomatically`, `agentName`, `providerName`,
`matchesSearch`, `tokenStatus`, `consentEndSentence`, `consentEndValue`, `revokeAllLabel`,
`shownTime`) and the page links in the shared `components/shared/PaginationControls.tsx`, which
the Secrets page uses too: Previous page and Next page are named and disabled at the ends, and
the page shown is `aria-current`. Its `clampPage` keeps the page shown inside the list, so
revoking the last entry of the last page shows the page before it. The page search finds a
token by its provider's name or id, its agent's DID or the name the agent is shown under, its
user identity hash or a scope (`matchesSearch`). A scope badge wraps (`text-wrap text-break`),
since a scope can be a long URL. A new view of the vault is a new tab, and both of these tabs
stay.

Both tabs name an agent with `AgentName.tsx`, which shows `agentName`: a `did:web` DID as its
whole web address, the host and any path with each `:` as `/` and its port's `%3A` as `:`
("pr-reviewer.example.com"), never cut; any other DID, and a `did:web` one with another percent
escape or an unprintable character, shortened in the middle. The name is one chip that wraps
after a dot or a slash, and inside a part (`text-break`) only when that part is wider than the
cell. The full DID is the chip's tooltip.

Both revoke one entry with the same text **Revoke** button, and show it, like every other
control that changes a delegation, only to a user with `delegation_vault.delete`, the
permission the routes ask for; without it the Actions column is not shown. A refused revoke
toasts "Not revoked: " and the gateway's words, or its status where it gave none, and the entry
stays. Escape cancels a two-step confirm, as a click elsewhere does (`useTwoStepDelete`).

Credential Tokens lists every agent-keyed token, service tokens included.

- The **Provider** column shows the provider's name, else its `provider_id` (`providerName`,
  shared with Delegated Access's System column), and the search matches the name too; the
  expanded row keeps **Provider ID**.
- The **Consented** cell shows the consent time and, under it, the consent's end
  (`credential-token-consent-end-<id>`): "Ends <date> (in 3 hours)", "Ended <date>", or "No time
  limit" when the vault reports no `consent_expires_at`. The expanded row shows it as **Consent
  Ends**, the date first.
- The **Access Token** column (`credential-token-access-token-<id>`) is the access token's own
  expiry, with "Renews automatically" under it while the gateway renews the token by itself
  (`renewsAutomatically`: the provider's `token_refresh_enabled` is on, a refresh token is
  stored, and the consent has not ended). An ended consent, a provider that does not refresh and
  one that cannot be read show no such line. The expanded row keeps **Token Expires**.
- The status badge reads "Consent ended" once the end has passed and "Ending soon" within 24 hours
  of it; otherwise it is the access token's status (Active, Expired (refreshable), Expired)
  (`tokenStatus`). The card header shows the title alone: no count of tokens and no count per
  status.
- A row opens its detail (`CredentialTokenDetail.tsx`, id and test id
  `credential-token-detail-<id>`) on a
  click anywhere in it, and from the chevron button in its first cell
  (`credential-token-expand-button-<id>`, `aria-expanded`, `aria-controls` the detail), which
  is how a keyboard reaches it.
- **Limit duration** (`credential-token-limit-button-<id>`, `aria-expanded`, `aria-controls`
  the panel, tooltip "Set how long after its consent this delegation ends") sits over
  **Revoke** in the Actions cell, the two stacked at one width (`d-grid gap-1`), on a consent
  an operator can limit (`canLimitConsent`: an Authorization Code provider's token whose
  delegation is still active). It opens `ConsentLimitPanel.tsx` in a row of its own under the
  token's row (`credential-token-limit-panel-<id>`, a `role="group"` named by its title), never
  a modal or a browser dialog. The number takes the focus when the panel opens, and a second
  click or **Cancel** (`credential-token-limit-cancel-<id>`) closes it; Cancel and a save put
  the focus back on **Limit duration**. A search or a page change that hides the row closes the
  panel, and it stays closed when the row is shown again. The panel is titled "Limit duration ·
  <provider name>"
  and reads "The agent may act for this person for at most [number] [minutes | hours | days]
  after consent." (`credential-token-limit-input-<id>`, `credential-token-limit-unit-<id>`),
  starting from the limit that applies now, or empty and in hours for a consent without one;
  the unit select also offers seconds while the limit that applies is not a whole number of
  minutes (`consentLimitUnitsFor`). A
  line under it (`credential-token-limit-preview-<id>`, `aria-live`) says what the limit would
  do, by `limitOutcome` in the words of `limitOutcomeText`: "Consent given <date>. With this limit it ends <date> (in 59
  minutes).", "It already ends <date>. A limit only brings the end forward.", "This consent is
  already older than that. Use Revoke to end it now.", or "Enter a whole number from 1 minute
  to 365 days." **Save limit** (`credential-token-limit-save-<id>`, the shared `AppButton`,
  `loading` while it saves, so it sends once) is enabled only for the first, sends
  `PUT /api/v1/delegation-vault/{id}/consent-limit` with `max_consent_age_secs`
  (`vault.limitConsent`), puts the answered `consent_expires_at` in the row, closes the panel
  and toasts "Limit saved. <provider> access ends <date>." A refusal is shown under the field
  (`credential-token-limit-error-<id>`, the input `is-invalid`, `aria-invalid` and described by
  it) in the gateway's words, or as "The gateway could not be reached." when there was no
  answer, and the panel stays open. A limit refused because the consent changed meanwhile
  (`409`) also reads the vault again, so the row and the panel's preview show the consent as it
  is now. A save that finishes after another row's panel was opened
  updates its own row and leaves that panel open.
- No modal and no browser dialog confirms a revoke. The row's **Revoke**
  (`credential-token-revoke-button-<id>`) works as on Delegated Access: its first click asks with
  a danger button that names the provider, beside **Cancel**
  (`credential-token-revoke-cancel-button-<id>`). **Revoke all for this user**
  (`credential-token-revoke-user-button-<id>`) is the shared `components/shared/TwoStepButton`,
  for a two-step action that is not a delete: the first
  click turns it into a danger button (`confirmAs="danger"`, never small or amber text) that says
  how many of the user's listed delegations it ends, "Revoke all 2 for this user?" or "Revoke
  this user's only delegation?" (`revokeAllLabel`), the second sends the `DELETE`, and a click
  elsewhere or Escape cancels.
- The expanded row links to the user's delegation records in the Audit Log
  (`credential-token-view-activity-button-<id>`): the Audit Log opens with the user identity hash
  as its text filter and the delegation categories selected. The link is shown only to a user
  with `audit.view`.

Delegated Access lists only active access: a token of an Authorization Code provider
(`isPersonsDelegation`) whose consent has not ended and whose access token is valid or
refreshable. It has no history of its own. Its header says "Active access only.", and "Ended and
revoked access is in the history." after it only beside the History button; the empty state
points at the history under the same condition.

- Columns: User, System (the provider's name, else its `provider_id`), Agent, Access (scopes),
  Status (Active, or Ending soon within 24 hours of the end), Ends (`delegated-access-ends-<id>`:
  the time left, then the limit that applies to the consent, "6-hour limit" or "30-day limit"
  (`consentLimitSecs`, from its consent time to the end the vault reports, so the sooner one
  when the limit was shortened since; worded by `consentLimitLabel` in
  `utils/consentLimit.ts`), then the date; or "No time limit"), Last Used and, with
  `delegation_vault.delete`, a text
  **Revoke** button (`delegated-access-revoke-button-<id>`, the shared `TwoStepButton` with
  `confirmAs="danger"` and a `cancelTestId`). Its first click turns it into a danger button that
  names what it ends, "Revoke GitHub access?" with the provider's name as System shows it, and
  offers **Cancel** beside or under it (`delegated-access-revoke-cancel-button-<id>`, focus back
  on Revoke); the second click sends the `DELETE`, and Cancel or a click elsewhere cancels. No
  modal and no browser dialog. Rows are `delegated-access-row-<id>`; the header counts those
  ending soon (`delegated-access-ending-soon-count`).
- **History** (`delegated-access-history-button`) opens the Audit Log on the records of access
  that ended: `consent_expired`, `token_revoked` and `user_tokens_revoked`. It is shown only to a
  user with `audit.view`.
- The list still loads when the providers cannot be read: every token then counts as a person's.

## Credential delegation audit

The credential delegation records are read in the Audit Log (`pages/AuditPage`), not on the
Credentials page, and the Credentials tab row has no audit tab and no link in its place: a
stored `/credentials?tab=credential-audit` opens the first tab, as any unknown tab does. The
two ways from the Credentials page into the audit are **History** on Delegated Access and the
link in a token's expanded row on Credential Tokens, both shown with `audit.view` and built by
`auditLogPath` from `DELEGATION_ENDED_CATEGORIES` or `DELEGATION_CATEGORIES`
(`pages/AuditPage/auditHelpers.ts`).

The delegation categories are the ones the gateway audits: `consent_granted`, `consent_expired`,
`consent_limited`, `token_revoked` and `user_tokens_revoked`. What the gateway does with a credential on each call
(`token_injected`, `token_refreshed`, `refresh_failed`, `consent_required`, `token_not_found`
and the elicitation events) is written to its log, or nowhere while `[logging] delegation_events`
is `false`, and is no audit event, so the Audit Log offers no category for it and no link selects it. A record of one that an older gateway
audited is still shown, with its label (`categoryLabel`). A category `categoryLabel` has no label
for is named in title case from its event name (`auth_failed` as "Auth Failed"), with `API`, `DID`,
`JWT`, `MCP` and `VP` in capitals, never as the raw lowercase name.

- The Audit Log offers each delegation category in its Category filter, labels and narrates
  `consent_expired` ("Consent expired", a warning, apart from a revocation) and
  `consent_limited` ("Consent limited", a warning: an operator made one consent end sooner,
  with its new end and the one before it from the record's `detail`, and it was not revoked),
  and shows them with the other delegation events. The narrative of a `consent_granted` record
  given under a time limit adds "It ends <date>.", from the `consent_expires_at` in its `detail`.
- Its Identity group shows **Subject**, the token's own `sub`, and a **Principal** row with the
  value the caller's grants are keyed by, `caller.principal`, only when the JWT strategy names a
  claim other than `sub`.

## Target authentication fallback

The Target authentication fallback select on the Managed Agent and on a Transit Point offers
**Reject request** and a pass-through option. The reject label names no status: the gateway
answers `500 target_auth_misconfigured` or `503 target_auth_unavailable` depending on the cause.

## Credential provider editor

`/credential-providers/new` and `/credential-providers/:id` (`EditCredentialProviderPage.tsx`)
show the inputs of the chosen Provider Type (`credential-provider-type-select`).
`EditCredentialProviderPage/credentialProviderForm.ts` decides which inputs a type uses
(`providerTypeFields`), the first missing required field, and the request fields.

- **JWT Bearer** asks for Token Endpoint, Issuer, Subject, Signing Key, and optionally Key ID and
  Audience, plus a **Client authentication** select
  (`credential-provider-client-authentication-select`, `ClientAuthenticationSelect.tsx`) that says
  how the provider's OAuth client identifies itself with the grant: "Not sent (default)" (no client
  identity, as Google expects), "Client ID only (public client)", "HTTP Basic", or "Form body". Its
  explanation sits behind its `FieldHelp` (`field-help-client-authentication`), with no permanent
  text under the select. Any choice but Not sent shows the Client ID Secret picker, and HTTP Basic
  and Form body also show the Client Secret picker, both required (the messages name the client
  authentication, not "OAuth providers"); the pickers are the ones Client Credentials uses, under
  the heading "Client identity (secret references)" (`credential-provider-client-heading`). Save sends
  `client_authentication` (empty for Not sent), the client ID reference only while its picker
  shows (empty while it is hidden), and the client secret reference as chosen while its picker
  shows and empty otherwise.
  **Client Credentials JWT** asks for Token Endpoint,
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
- Save sends most fields the type does not use as empty, which the gateway reads as cleared, so
  switching a provider to Client Credentials JWT drops its client secret. The exceptions are the
  client ID reference, which is omitted for every type but JWT Bearer while its picker is hidden
  (JWT Bearer sends it empty then, so a stored one is cleared and no longer blocks deleting its
  secret), and `client_authentication`, which is always sent, empty for every type but JWT Bearer.
- `resource` has no input (it is set through the API or YAML) and is never sent on save. When
  `entraRejectsResource` finds the provider's token requests send it to a Microsoft identity
  platform v2.0 token endpoint, which rejects it (AADSTS901002), the form warns
  (`credential-provider-entra-resource-warning`: under Token Endpoint, or under the external
  consent notice for a provider with an `issuer`) and the list row shows a warning icon
  (`credential-provider-entra-resource-badge`). An external consent provider with
  `send_resource: false` sends no `resource` and is not warned; one that sends it is told to be
  re-created with `send_resource: false` (`entraResourceMessage`), since its resource is required
  and fixed. `send_resource` is never sent on save.
- The secret pickers offer only secrets of the provider's own tenant (`SecretOptions` in
  `SecretSelect.tsx`; the tenant is the loaded provider's `tenant_id`, unknown while creating). A
  stored secret outside that tenant stays selectable with the same labels: "appliance-wide, stops
  working when enforced" or "another tenant, refused by the gateway". The gateway keeps such a
  secret on save only in the field that holds it and while the provider's type and destination
  are unchanged.
- A Token Endpoint starting with `http://` shows a warning
  (`credential-provider-token-endpoint-https-warning`, warning styling, field not marked invalid)
  saying new or changed http endpoints are refused unless listed by exact URL in the bootstrap
  `credential_policy.insecure_token_endpoints`, and that an unchanged stored one, on a provider
  whose type is unchanged, is still accepted while `token_endpoint_https` is `warn`, unless the
  save starts sending a client secret (a client authentication that sends one, or a client
  secret the provider did not have). It does not block Save; the gateway decides on save.
- The Callback URL of an authorization code provider is, when editing, the stored `callback_url`
  unchanged (a reverse proxy prefix included) while the chosen listen address is still its origin
  and the stored URL is `https` and its path ends in the stored `callback_path`
  (`callbackUrlToSave`). Otherwise it is the chosen listen address followed by the provider's
  stored `callback_path` (`callbackUrlFor`). The preview, the copy button and Save all use it,
  because the gateway refuses a `callback_url` whose path does not end in the stored
  `callback_path`, or that is not `https`. A stored provider with no listen address chosen shows,
  in the same preview (`credential-provider-callback-url`), the redirect URI it keeps: its stored
  `callback_url`, or without one `gateway_base_url` from `GET /config/surface-routing` (the base
  the gateway started with) followed by its `callback_path`; Save then sends no `callback_url`.
- A new authorization code provider has no Callback URL until it is created: the gateway builds
  its `callback_path` from the id it generates for the provider (not the Provider ID slug) and
  refuses a `callback_url` on create. The editor shows a notice in its place
  (`credential-provider-callback-url-after-create`), which says to register a placeholder redirect
  URI with an OAuth provider that asks for one before it issues the client ID and secret, and to
  replace it after create; the editor creates the provider without a `callback_url`. With a
  listen address chosen, it then saves that address followed by the returned `callback_path` with
  a PUT. Create refuses an http listen address before sending anything (`isHttpsAddress`), since
  the gateway refuses an http `callback_url`; the message says to choose an https address or
  leave the host unselected. After a create the editor opens the created provider, so its
  Callback URL is in front of the operator. If the PUT fails, an error toast says the provider
  was created and gives the gateway's reason, and the editor still opens the created provider, so
  saving again updates it instead of creating it a second time. The Provider ID input has no
  route prefix, since a new provider's callback path does not contain it.
- An authorization code provider without an `issuer` (legacy consent) shows a **Consent
  confirmation** section after the Callback URL (`ConsentConfirmationSection.tsx`,
  `credential-provider-consent-confirmation-section`), with a switch
  (`credential-provider-consent-confirmation-switch`) that is off by default and on when the
  stored provider has `consent_confirmation`. While on it asks for Login Client ID and Login
  Client Secret (each a `SecretSelect`, `credential-provider-cc_client_id_secret_ref-select` and
  `credential-provider-cc_client_secret_secret_ref-select`), Login Authorization
  Endpoint and Login Token Endpoint (`…-authorization-endpoint-input`, `…-token-endpoint-input`),
  a JWT verification strategy from `GET /jwt-verification-strategies`
  (`credential-provider-consent-confirmation-strategy-select`, loaded by `useJwtStrategyList`),
  offering only strategies of the provider's tenant and appliance-wide ones, as the gateway's
  reference rule allows; a new provider, which the dashboard creates appliance-wide, is offered
  appliance-wide ones only. A stored strategy is listed by its id while the list loads, as
  "(not found)" only once the list loaded without it, and with the other-tenant label when it is
  another tenant's; a list that cannot be read shows "Strategies could not be loaded"
  (`credential-provider-consent-confirmation-strategies-failed`). Then an optional ID-token principal claim
  (`…-principal-claim-input`) and a **Refuse callers that can't be confirmed** switch
(`credential-provider-consent-confirmation-require-switch`, writes `require`, off by default,
sent only while on; its `FieldHelp` says it acts on new links only, so a stored grant is still
used, and that JWT callers get no link while the setting confirms nobody, whether it is on or not).
The Login Client ID and Login Client Secret pickers offer the same tenant's secrets as the
strategy picker: on a new provider, appliance-wide ones only. The labels say "Login" so they never share a name with the
  provider's own client and endpoints. Explanations sit behind each field's `FieldHelp`. A
  read-only **Confirmation redirect URI**
  (`credential-provider-consent-confirmation-redirect-uri`, copy button
  `credential-provider-consent-confirmation-redirect-uri-copy`) is the Callback URL the editor
  shows followed by `/confirm`, which is what the gateway registers. Under it a line
  (`credential-provider-consent-confirmation-redirect-uri-where`) says to add it to the allowed
  redirect URIs of the login client, naming the secret that holds its ID once one is picked, at the
  identity provider, and not at the vendor, whose OAuth app keeps the Callback URL. The line and
  the field's `FieldHelp` both say the URI follows the Callback URL and cannot be edited on its
  own, so it is registered again whenever the Callback URL changes. Without a Callback URL to
  show, new or stored, a notice stands in its place
  (`credential-provider-consent-confirmation-redirect-uri-pending`) saying the URI is shown
  once the provider has a Callback URL. The Login Client Secret's `FieldHelp` says to register
  the login client with `client_secret_post`. Save
  refuses a blank required field first (`missingConsentConfirmationField`) and sends
  `consentConfirmationField`: the setting while on (a blank principal claim left out), `null`
  when a stored setting is switched off or the provider is no longer legacy consent, and no field
  otherwise, so the gateway keeps what it has. The gateway's `400` reason shows like any other
  save error.
- A provider with an `issuer` (external consent) shows a notice naming the issuer
  (`credential-provider-external-notice`) in place of the type, endpoint, client, callback and
  additional parameter inputs, which the gateway keeps fixed; Save sends only its name,
  description, default scopes and token refresh (`externalProviderUpdate`).
- An Authorization Code provider, external consent or not, has a **Consent time limit**
  (`EditCredentialProviderPage/ConsentLimitSection.tsx`, rendered only for such a type): a whole
  number (`credential-provider-consent-limit-input`, placeholder "Not set") and a unit select
  (`credential-provider-consent-limit-unit-select`: minutes, hours or days, hours by default;
  seconds only while the stored limit is not a whole number of minutes, `consentLimitUnitsFor`,
  so such a limit loads and saves unchanged), with its explanation behind `FieldHelp`
  (`field-help-consent-limit`). The line under
  it says an empty field sets no limit on the provider and that the gateway's own default and
  ceiling still apply, never that an empty field means no limit; the field is described by that
  line (`aria-describedby`), and by the error before it while refused. A stored
  `max_consent_age_secs` loads in its largest whole unit (`consentLimitOf`). Save always sends
  `max_consent_age_secs` (`consentLimitSeconds`): the limit in seconds, or `0`, which removes it,
  for an empty field and for every other provider type, where the field is not shown. A limit
  outside one minute to 365 days, or not a whole number, is refused before anything is sent: the
  banner at the top of the form summarises it (`CONSENT_LIMIT_RANGE_MESSAGE`), and the field is
  marked invalid (`is-invalid`, `aria-invalid`, described by the message), says "Enter a limit
  from 1 minute to 365 days, or leave it empty." under itself
  (`credential-provider-consent-limit-error`, `invalid-feedback`) and takes the focus. Changing
  the number or the unit clears the field's error. On a stored provider, a limit shorter than the
  stored one, one set where none was, or an emptied field where a limit was stored (sent as `0`,
  since the gateway's default or ceiling may then be the shorter) is sent to
  `GET /credential-providers/{id}/consent-impact?max_consent_age_secs=<seconds>` once the field
  has stayed unchanged for 400 ms (`EditCredentialProviderPage/useConsentImpact.ts`). While its
  `ending_consents` is above 0, a warning under the field
  (`credential-provider-consent-limit-impact`, the editor's `alert alert-warning`, inside the
  `role="status"` region `credential-provider-consent-limit-impact-region`, which is there
  before the warning is so that it is announced) says how many active consents saving ends now and that those people approve
  again, with the provider's name (`consentImpactMessage`, singular for one). There is no warning
  and no request for a new provider, for a limit that is longer, equal or refused, for an
  empty field where no limit was stored, or once the type is changed to one nobody consents to,
  and no warning for 0 or a failed request. The unit arithmetic and wording live in
  `utils/consentLimit.ts`, with the range's wording (`CONSENT_LIMIT_RANGE`), which the line
  under the field states only while the field is not refused, since the error then states it.
  On such a provider the help under **Enable automatic token refresh** says tokens are
  refreshed for as long as the consent lasts, pointing at the Consent time limit below, and
  that the person approves again when it ends, whether or not a limit is set; every other type
  keeps saying the connection works without reauthorizing.
- A provider a person consents to (`takesConsent`: Authorization Code, external consent or not)
  is deactivated, never deleted, from the dashboard. Its row on the Credential Providers tab has
  **Deactivate** (`credential-provider-deactivate-button-<id>`, the shared two-step
  `TwoStepButton`: the first click shows "Click again to deactivate", the second sends
  `POST /credential-providers/{id}/deactivate`) in place of the delete button, which only the
  other provider types keep. A deactivated row shows **Activate**
  (`credential-provider-activate-button-<id>`, one click). Deactivate and Activate share one
  outline style (`btn-outline-secondary`, text only), since the colour belongs to the **Status**
  column (`credential-provider-status-<id>`, after Type, for every provider): an "Active" badge
  (`text-bg-success`), or a "Deactivated" badge (`credential-provider-deactivated-badge-<id>`,
  `text-bg-secondary`) with "No new consent" under it. The Type column shows only the type. The
  row stays in the list either way. Deactivate and Activate are shown with
  `credential_providers.edit`, the permission their routes ask for, as **Add Provider** is; the
  row delete button is shown with `credential_providers.delete`.
  The editor shows a warning (`credential-provider-deactivated-notice`) that nobody can consent
  again while access already given keeps working, and never sends `deactivated_at` on save. The
  Delegated Access tab marks the access of a deactivated provider "No new consent"
  (`delegated-access-provider-deactivated-<id>`), also right after a Deactivate on the same
  page, since the tab tells the page (`onProvidersChange`). Success and failure are toasts.
- The Credential Providers tab labels the types from `PROVIDER_TYPE_LABELS` in the same module, and
  shows a secondary badge after the type of a JWT Bearer provider that has a
  `client_authentication` (`credential-provider-client-authentication-badge`: Client ID only,
  HTTP Basic or Form body, from `CLIENT_AUTHENTICATION_LABELS`); no badge without one. A
  refused delete shows the API's reason and, for a `409`, the surface that binds the provider
  (`providerDeleteError`).
- Credential provider pages follow their own permissions, not `settings.*`.
  `/credential-providers/new` needs `credential_providers.edit`; `/credential-providers/:id`
  needs `credential_providers.view`. A user with view but not edit gets the editor read-only: the
  form is a disabled `fieldset`, there is no Save (`Cmd+S` and Enter do nothing), and
  `credential-provider-editor-read-only-notice`, the first thing in the card, explains why.
  The Callback URL notice (`credential-provider-callback-url`) then shows above the form
  instead of inside it, since a disabled `fieldset` would disable its copy button. A
  save error shows in an alert (`credential-provider-editor-error`), and Back and Cancel (which
  reads **Back** while read-only) return to `/credentials?tab=credential-providers`. The tab
  shows **Add Provider** with `.edit` and the row delete button with `.delete`.
- The Credentials page and its sidebar entry open for `settings.view`,
  `credential_providers.view` or `delegation_vault.view` (`ProtectedRoute`'s `permission` takes
  one permission or a list of which any one is enough). The JWT Verification tab needs
  `settings.view`, the Credential Providers tab `credential_providers.view`, and the Credential
  Tokens and Delegated Access tabs `delegation_vault.view`, the permission the vault API asks
  for. The page opens on the first of JWT Verification, Credential Providers and Credential
  Tokens the user may see.
- The credential provider routes live in `src/pages/credentialProviderRoutes.tsx`. The retired
  OIDC Providers pages are gone; `/oidc-providers` and every path under it redirect to
  `/credentials?tab=credential-providers`.

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
- Deleting a secret from the Secrets page asks the gateway first. A 409 with `references` (a
  surface, credential provider, A2A proxy or STS client that uses the secret) opens
  `ConfirmDeleteSecretModal` (`confirm-delete-secret-modal`), built on the shared
  `components/shared/WarningDialog.tsx`: it names each reference by kind and
  name (`ReferenceList`), adds "and N more you cannot view" for `hidden_references`, and offers
  Cancel (focused first, sends nothing) and **Delete secret anyway** (`confirm-delete-secret-confirm`, repeats
  the delete with `?force=true`). While the forced delete runs both buttons stay focusable with
  `aria-disabled` and ignore clicks, so focus stays in the dialog. A 409 without `references` (an integration endpoint uses the
  secret) and every other failure show inline (`secrets-delete-error`), with no override and no
  toast.
- A refused credential provider delete shows the `providerDeleteError` message inline on the
  Credential Providers tab (`credential-providers-delete-error`), with no override. The
  provider editor lists the references of a refused retype under its error
  (`credential-provider-editor-references`).

## API key delete

The API Keys tab of `/secrets` (`api-keys-delete-button-<key id>`) and `/api-keys/:agentId/:keyId`
(**Delete**) share `useApiKeyAction('delete', …)` (`src/components/api-keys/ApiKeyActionDialog.tsx`). The
delete button sends nothing: it opens the confirmation dialog `api-key-delete-dialog`, built on
the shared `components/shared/WarningDialog.tsx` (`modal fade show` with `display: block`,
`modal-dialog-centered`, a `modal-backdrop fade show` sibling; `role="dialog"`, `aria-modal`, named
by its title). Its title "Delete API key"
carries a red warning icon (`fa-triangle-exclamation text-danger`); the body names the key's
client id and key id and says, in plain words, that callers using the key will be refused,
surfaces that use it will stop working until another key is picked, and the delete can't be
undone. **Delete API key** (`api-key-delete-dialog-confirm`, `btn-danger`) sends the `DELETE`;
it is enabled on open and disabled, with a spinner, only while the delete runs. **Cancel** and the
close button delete nothing. The confirmation is the dashboard's; the API takes none. A delete succeeds
with the toast "API key deleted", then the tab reloads its keys and the detail page returns to
`/secrets`. A failed delete shows an error toast that stays until dismissed: "Delete failed:
<gateway message> (<status>)", and the detail page stays open.

**Revoke** works the same way through `useApiKeyAction('revoke', …)`: the API Keys tab's revoke
button (`api-keys-revoke-button-<key id>`) and the detail page's **Revoke** send nothing and open
`api-key-revoke-dialog`, the same dialog component with the title "Revoke API key" and the same
red warning icon. Its body names the key's client id and key id and says that surfaces using the
key will stop serving until another key is selected, that a revoked key can't be restored, and
that selecting a new key gives the surface a new DID. **Revoke API key**
(`api-key-revoke-dialog-confirm`, `btn-warning`) sends `POST /api-keys/{agent_id}/{key_id}/revoke`;
**Cancel** and the close button send nothing. A revoke succeeds with the toast "API key revoked",
then the tab reloads its keys and the detail page reloads the key. A failed revoke shows an error
toast that stays until dismissed: "Revoke failed: <gateway message>".

When the key's surface was deleted (`surface_deleted: true` on `GET /api-keys/{agent_id}/{key_id}`),
the detail page shows the info alert "This API key is no longer in use because the associated
surface has been deleted." (`api-key-surface-deleted-info`) at the top of Key Information.

## Surface delete

The surface page's delete button (`surface-delete-button`, `btn-danger` with a trash icon, shown
only with `surfaces.delete`, which the gateway requires for the `DELETE`; `surfaces.edit` alone
shows Save but no delete button) sends nothing: it opens `surface-delete-confirm`, a
[confirm popover](#confirm-popover) beside the button (on its right when the builder sidebar is
at the window's left edge), and clicking the button again
closes it. Its title "Delete Surface?" carries a red `fa-triangle-exclamation` icon. Its body
first names the surface, "Delete `<name>`?" in bold (`surface-delete-confirm-name`, the surface
id when it has no name), then reads "You are about to permanently delete this surface and all
associated configuration. This action cannot be undone." then "Are you sure you want to
continue?". **Delete** (`surface-delete-confirm-confirm`, `btn-danger`) sends the `DELETE`;
**Cancel** (`surface-delete-confirm-cancel`), the close button, Escape and a click outside send
nothing. While the delete runs, Delete shows `…`, Delete, Cancel and the close button are
disabled, Escape and a click outside do nothing, and the page's delete button shows a spinner.
Delete is also disabled while a save runs, and Cmd/Ctrl+S does not save while the popover is
open. A delete succeeds with the toast `Surface "<name>" deleted` and returns to `/surfaces`; a
failed one closes the popover, returns focus to the delete button and shows the gateway's message
in `surface-error-alert`. The popover closes if the page moves to another surface.

## Confirm popover

`components/shared/ConfirmPopover.tsx` is the shared inline confirmation: a speech bubble beside
the button that opened it (`role="dialog"` named by its title), portalled to `<body>`. It opens
to the left of the button (`confirm-popover--left`) and flips to its right
(`confirm-popover--right`) when the left has no room, as for the surface page's trash button in
the builder sidebar with the navigation collapsed; it stays at least 8px inside the window on
both axes, and its tail points at the button's middle. Cancel takes focus when it opens and focus returns to that button when it closes, and while it
is open no key reaches a `window` listener, so the page's shortcuts (Cmd/Ctrl+S, the Surface
Builder's canvas keys) never act behind it. Its `icon` is `fa-info-circle` (default) or
`fa-triangle-exclamation`, shown red when `confirmVariant` is `danger`. Each use passes its own
`testId`; the confirm and Cancel buttons are `<testId>-confirm` and `<testId>-cancel`. Its
styles are the `.confirm-popover*` classes in `dashboard.css`.

Two pages use it:

- **Surface delete** (`surface-delete-confirm`), above.
- **Policies list** (`policy-confirm-popover`), from a row's delete and Enforce globally
  actions: "Delete policy" with a red **Delete**, naming the policy and how many surfaces or
  gateways reference it, and "Enforce globally" with **Continue**, naming how many will enforce
  it. Confirm is disabled while that count loads.

Use the popover to confirm one action on the button that triggers it. Use
`components/shared/WarningDialog.tsx`, a centred modal, when the confirmation needs more room or
blocks a flow, as API key delete and revoke, the secret delete confirmation
(`ConfirmDeleteSecretModal`) and the Authority-in-use dialog do.

## Authority delete

The Authorities list (`pages/AuthoritiesPage.tsx`, `authorities-delete-button-<id>`) and the
Authority editor (`pages/EditAuthorityPage.tsx`, `authority-editor-delete-button`) delete through
`apiClient.deleteAuthority` after the two-step `DeleteButton`. While Trust Checks or Trust Recorder
entries use the Authority, the gateway answers `409` with `references` and `hidden_references`;
`authorityInUse` (`components/authorities/authorityInUse.ts`) reads them from `ApiError.body`, the
raw error body the API client keeps, and `AuthorityInUseDialog` (`authority-in-use-dialog`, a
`WarningDialog` titled "Authority in use") opens in place of the error. It says the Authority is
used by Trust Checks or Trust Recorder entries and to point them at another Authority or remove
them, then delete it, and lists each surface, linked to `/surfaces/<id>` in a new tab
(`authority-in-use-dialog-surface-<id>`, `-surface-link-<id>`), and STS client, not linked
(`authority-in-use-dialog-sts-client-<id>`), each with one line per use from
`describeAuthorityUse`: "Trust Check “<name>” on the Access Point", "… on the Managed Agent's
target", "… on Transit Point <alias>", "Trust Recorder entry for <trust registry name or id>",
with "in variant <alias>" for a variant. "N more you can't view." (`authority-in-use-dialog-hidden`)
follows while `hidden_references` is above zero. Its only action is **Close**
(`authority-in-use-dialog-close`): the dashboard never sends `force=true`. Any other failure keeps
the list page's error alert and the editor's error toast. Every value is rendered as React text.

## Policy definition editor

The create and edit pages share one editor card in three sections, each titled by
`PolicySectionTitle` (unnumbered, like the other edit forms; the dashboard numbers steps only in
`WizardProgress` wizards), separated by a rule. The page follows the credential provider editor
(`/credential-providers/new`): section titles are `font-weight-bold text-primary` `h6`s with a
Font Awesome icon (Start from `fa-layer-group`, Details `fa-info-circle`, Policy `fa-code`);
each field label is a plain `<label className="mb-0">` in a `field-label-with-help` row with its
`FieldHelp` beside it, never inside the label; inputs and selects are full-size `form-control`
(never `form-control-sm`); and Name, which is required, carries a red `*`.

- **Start from** (create only): `TemplateGallery` (`policy-template-gallery`), described under
  _Policy templates_. For users with `policies.edit` the create form shows only this section
  until a template is used or a custom policy created; Details and Policy then appear. Until
  then the header has no **Create** button (`policy-definition-editor-save-button`) and
  Cmd/Ctrl+S saves nothing.
- **Details** (`PolicyDetailsSection`, `policy-details-section`): Name full width, then
  Description full width as a two-row textarea, then Type (when shown, see below) and Status
  (an **Enabled** switch, `policy-definition-enabled-switch`) side by side, so the two controls
  line up (the Status label is a `span`, as the switch has its own label), with the Status
  explanation in a `FieldHelp`. The Rego, template setting and sample input labels follow the
  same label rule. On a saved policy the Policy ID and SHA follow on one
  line of monospace values, each with a copy button (`policy-definition-id`,
  `policy-definition-sha`, `-copy-button`), never as disabled inputs.
- **Policy** (`PolicyEditorSection`, `policy-editor-section`): a **Rules | Rego** switch, one
  joined `btn-group btn-group-sm policy-view-switch` (`role="group"`, `aria-label="Policy view"`)
  of two `AppButton`s with icons, the active one `primary` and the other `secondary` (white, light
  grey border; the shared dark-theme rules apply), both the same width (`min-width: 5.5rem`) and
  with no shadow so the halves sit flush (`policy-view-rules`, `policy-view-rego`,
  `aria-pressed`), a status row with the rule count, default decision,
  compile status (`policy-compile-status`) and **Add rules from a template**. Both views stay
  mounted and the hidden one gets `d-none` (`policy-view-rules-panel`, `policy-view-rego-panel`).
  Both a new and a saved policy open on Rules; only Write Rego, Open Rego and a rule's line
  numbers switch to the Rego view. The Rego view has the **Rego reference** panel, then the textarea
  (`policy-rego-textarea`, `wrap="off"`) with a line-number gutter (`.policy-rego-gutter`)
  that follows its scroll, so the line numbers in the Rules view match, then compile errors and
  the package mismatch with **Fix it**.

The editor and its templates use the shared dashboard components, not local copies: every
action button the templates add is an `AppButton` (size `sm`; link-style actions use
`variant="link"`), while the editor's own Save/Create and **Fix it** stay the plain Bootstrap
`btn btn-sm` buttons they always were; a policy's or template's default decision is
`DecisionBadge` (`TemplateBadges.tsx`, `.policy-default-decision`, always "Default DENY" or
"Default ALLOW"): a quiet outline in `--muted-text` with an `fa-shield-alt` icon for DENY, and
amber (`--warning-text` on a light amber tint) with an `fa-exclamation-triangle` icon for ALLOW,
because allowing by default is the less safe choice; the icons are `aria-hidden`, the tokens
switch with `body.dark-theme`, and the Audit Log's `.audit-decision` pill is left as it is (the
Rules view's decision summary reuses its `audit-decision--deny` pill, unchanged, for
"Otherwise: DENY"); the `DecisionBadge` tooltip says "Denies requests that no rule allows" for DENY and "Allows
requests that no allow rule decides" for ALLOW; an
example's expected and actual decision
and the gallery's MCP tool policy tag (`secondary`) are `Badge`s (a template's `reads` paths
are matched by the Add rules search, never shown), an alert the templates add that carries an action is a non-collapsible
`InfoBanner` with the button as its child and the test id on a wrapping `div`, the template
search and category filter is the shared `SearchInput` and `FilterChipGroup`
(`TemplateFilterBar.tsx`), code blocks use `.policy-preview-block`, and the templates column's
panels are a `card shadow mb-4` with the standard `card-header py-3` title (`h6 m-0
font-weight-bold text-primary`) and their description in the body. A policy Type's name comes
from the one `POLICY_TYPE_NAMES` map in `policyTemplates/types.ts`, and the editor sets no
inline `style` except `SearchInput`'s `wrapperStyle` for the full-width column search, as
`LogsFilterBar` does, and the Test (dry-run) panel's run button and sample input; error text in
its alerts and the Rego view's uses `.policy-error-text`. `PolicyTemplates.css` uses the
`dashboard.css` tokens, never an undefined token, and no literal colour but `rgba` tints of
the brand blue and amber, as `dashboard.css` uses, and white on `--primary-solid`: a dark surface is
`--dark-card` with `--dark-border`, borders take the brand colours (`--accent-blue`,
`--danger`) and text the text-safe ones, and a rule summary, Policy ID and SHA are plain
`<code>` in the dashboard's code colours. Text in the Rego reference takes the heading, body and
`alert-warning` colours, never `text-dark`, which `body.dark-theme` does not swap outside a card
header. The exceptions are the selectable `.policy-template-row` cards and rows (`--gray-0`, or
`--dark-card` under `body.dark-theme`, selected with the Audit Log's `.audit-item--selected`
`--accent-blue` border and tint),
the Rego reference heading toggle, the examples card's `btn-close`, Back, the Rego view's package-mismatch
alert with **Fix it** (Bootstrap `alert-danger`), the Rules view's
rule-kind badges (`.policy-rules__kind`, a neutral `--muted-text` outline for every kind, so a
rule's kind never reads as an allow or deny decision), the Add rules template badge
(`AddsRulesBadge` in `TemplateBadges.tsx`, the same outline), and the Rules view's amber group lines
(`.policy-rules__misfit`, `--warning-text` on a light amber tint, with a `body.dark-theme`
border).

A definition that fails to
load shows only Back and the error (`policy-definition-load-error`), never an editable form.
Without `policies.edit` the page is read-only, since the gateway refuses a create or save
without it: a muted line with a lock icon under the intro says "You can view this policy but not
change it." (`policy-definition-read-only-note`), the Rego textarea is `readOnly`, Name and
Description are `readOnly`, Type and Enabled are disabled, there is no Create or Save button
(`policy-definition-editor-save-button`), Ctrl+S does nothing, a package mismatch offers no
**Fix it**. There is no Test (dry-run) panel
(`policy-simulate-panel`), since the gateway's simulate endpoint also needs `policies.edit`,
and no gallery, templates column, Add rules or Remove (below).

The **Rego reference** panel in the Rego view is collapsed by default. It lists the two inputs a
policy can get, each with a link to its section of the OPA policies reference page: the
request's caller context that gateway and surface policies read (`PolicyInput` in
`src/surface_context/mod.rs`: `input.source_auth`, `input.http`, `input.gateway`,
`input.transit`, `input.mcp`, `input.trust_check_results`, `input.extension_identity`;
`policy-instructions-input-fields`),
which the Test (dry-run) default sample input follows, and the tool call that a policy bound to
MCP tools reads (`McpPolicyContext` in `src/mcp/policy.rs`: `input.jwt`, the claims of the
request's `Authorization` bearer token, `input.mcp.method`, always `tools/call`,
`input.mcp.params.name` as the tool name, `input.channel`, `input.request`;
`policy-instructions-tool-input-fields`). Its title is a heading holding one full-width button (`policy-instructions-toggle`,
with `aria-expanded` and `aria-controls="policyDefInstructions"`), so the whole header row
toggles, Enter and Space work natively, and screen readers still announce the heading. The
title is `policy-instructions-title`, the arrow `policy-instructions-chevron` sits inside the
button and flips with the state, and the body is `policy-instructions-body`. Build collapsible
panels the same way, and do not put `role="button"` on a wrapper around a heading.

### Policy templates

Policy templates live in `pages/SettingsPage/policyTemplates/`. The editor never calls a
template API. The only templates are the built-in catalogue that ships with the dashboard in
`builtinPolicyTemplates.json`; nothing saves, stores or shares a template, and there is no
Save as template. No template is marked Recommended. The page's template state and
the actions that change the Rego, each with Undo, live in `usePolicyTemplateActions`, and the
Start from gallery's state (open, selected card, focus, what the policy started from, Use and
Create custom policy) in `useTemplateGallery`.

- **Layers.** The folder is kept reusable in three layers, and an import only points down:
  - *Logic* (plain `.ts`, no React): `types.ts` (with `FieldText`, `UsedTemplate`,
    `AddedRules`), `policyDefaults.ts`, `regoRules.ts` (parsing, rule use),
    `regoTemplate.ts` (rendering, `insertTemplateRules`, `defaultDecision` for a catalogue
    template and `policyDefaultDecision` for the editor's policy, which reads only its
    top-level `default allow`), `templateSettings.ts` (setting
    text to Rego), `policyStart.ts` (`policyStart`, `replaceText`, `groupsForOtherType`) and
    `policyTemplateLibrary.ts` (`groupTemplateEntries`, `galleryTemplates`, `surfaceOnlyKeys`
    and `buildTemplateLibrary`). Functions take `readonly` template lists.
  - *Hooks*: `useTemplateSettings`, `useTemplateFilter`, `usePolicyTemplateActions`,
    `useTemplateGallery`.
  - *Components* (`.tsx`), which export components only, so no logic lives in a component
    file.
- **App seams.** The feature calls the dashboard's `showUndoToast` (the undo toast) and
  `simulatePolicy` (the dry-run endpoint) directly. After a save the page reads the definition
  back and merges only its `content_hash` and `updated_at` into the form, so the SHA shown is
  the saved revision's; when that read fails the SHA is hidden. The page takes the
  templates from `POLICY_TEMPLATE_LIBRARY` (`builtinPolicyTemplates.ts`, `{entries, templates}`,
  built once from the catalogue by `buildTemplateLibrary`, Agent Surface variants first;
  `templates` feeds `groupsForOtherType`), and hands them to
  `useTemplateGallery` (`entries`, which returns the gallery's `cards` and `surfaceOnly`) and to
  `PolicyTemplatesPanel` (`library`), so `TemplateGallery` and the panel never list templates
  themselves. The catalogue (`builtinPolicyTemplates.*`, with its `DOCS_URL` links and
  `POLICY_TEMPLATE_LIBRARY`) and `RegoReference` are dashboard content, not part of the
  reusable layers.

- **Catalogue.** A JSON entry holds its rules without a `package` line and lists the
  `policy_types` it serves; `builtinPolicyTemplates.ts` adds the package per type. Every entry
  must compile on the gateway's Regorus and give each example's `expected` decision (checked
  by the gateway's tests, below), and may
  read only fields of the gateway's `PolicyInput` (`src/surface_context/mod.rs`). Caller
  identity is `input.source_auth` (`method`, and for `jwt_bearer` its `subject` and `claims`);
  gateway and surface policies get no `input.jwt`. Templates that read `source_auth`,
  `trust_check_results` or `agent` list only `agent_surface`. Entries follow the Apply Policies
  guides and the OPA policies concept and reference pages on docs.affinidi.com; each has `docs`
  (`page`, a `DOCS_URL` key of a direct doc-site URL, since the catalog redirect may drop a
  `#section`; `anchor`; `label`), which becomes the template's `docs_href` and link text. Entries
  with `"input": "mcp_tool"` (category **MCP tool policies**, `agent_surface` only) are for
  policies bound to MCP tools, which decide each `tools/call` to an MCP Target: they read
  `McpPolicyContext` (`src/mcp/policy.rs`: `input.jwt`, the claims of the request's
  `Authorization` bearer token, which their descriptions say needs JWT Bearer caller
  authentication on that header; `input.mcp.method`, always `tools/call`; the tool name in
  `input.mcp.params.name`), carry an "MCP tool policy" badge in the gallery, and are whole
  policies (below). Trust check templates group `input.trust_check_results.target` by `id`, so
  a check that queries several authorities counts once and passes when any of its results is
  `ok`. Allow listed surfaces matches `input.channel.config_id`, the surface id, not its name. A setting is a `{{key}}` placeholder with `kind` `integer` (`min`, `max`),
  `string`, `string_list`, `choice` or `time_of_day`. A string's `format: "time_zone"` accepts
  IANA names only (written in their canonical spelling); a list's `allowed` names the only values
  accepted, matched without regard to case and written in the listed spelling, and an `optional`
  list may be left empty, written as `set()`; a `choice` (a select) writes the `rego` text of the
  picked option, which may be empty; a `time_of_day` (a time input) takes `HH:MM` and writes the
  minutes since midnight, and its `differs_from` names a time it must not equal. Business-hours
  access window uses them all: its **Inside the window** choice writes `in_access_window`
  (Allow requests) or `not in_access_window` (Deny requests) into an `allow` rule that first
  requires `access_minute`, so a time zone the clock can't read denies in both modes; its
  **From** and **Until** times make a window that crosses midnight when Until is earlier, its
  **Days** may be empty for every day (a day is the request's date in the time zone, also for
  the hours after midnight: Monday to Friday 22:00–06:00 covers 00:00–06:00 and 22:00–24:00 on
  Monday to Friday, which the Until help says with that example), and it is a
  whole policy, since added to another policy its allow rule would let requests through
  whatever that policy's other rules say. A template that reads the clock (`time.now_ns()`) has no examples.
  An entry is `standalone` when it is meant to be the whole policy: its rules only set the
  default decision (Deny by default, Monitor-only baseline) or allow requests outside what they
  restrict (Restrict MCP tools by role, Allowlist outbound destinations).
  `templateRole` (`regoTemplate.ts`) gives every template one role: `policy` (a **Whole
  policy**) for a standalone template, an MCP tool template, or one with no rules left once its
  `default allow` line is dropped; `rules` (**Adds rules**) otherwise. A whole policy is used
  only from Start from; only templates that add rules are listed under Add rules. Each column
  row and preview under Add rules shows the `AddsRulesBadge`
  (`policy-template-role-badge`: "Adds rules" with `fa-list-check`); Start from cards and their detail show no role or default decision badge.
  A custom policy is a whole policy. Allow listed
  paths denies a path that contains `..`, `%2e`, `%25`, a backslash or `%5c`, with those checks
  inside its one `allow` rule rather than in a helper rule.
- **Settings defaults.** A deployment-specific setting (issuers, audiences, DIDs, outbound
  destinations, path prefixes, surface IDs, subjects, role and claim values, safe tool names)
  has an empty `default` and a `sample`. Behaviour switches (business-hours mode), counts (N),
  universal values (time zone `UTC`, method `GET`, the business-hours days and times) and
  well-known claim names (`role`) keep a prefilled `default` and no `sample`. A setting with a
  `sample` starts empty with `e.g. <sample>` as its placeholder and `aria-required`; while it is
  empty (`missingSettings` in `templateSettings.ts`) it shows "Required before the template
  can be used." under the field (`<field test id>-required`, `small text-muted`, linked by
  `aria-describedby`, never `is-invalid`), and Use this template and Add to policy stay
  disabled, since an empty list renders no Rego. Show Rego and the lines Add to policy adds
  preview the Rego with each empty setting's sample (`renderPreview`), with "Shown with sample
  values for the empty settings." above it (`SampleValuesNote`, `<prefix>-sample-note`); Use
  and Add to policy write only what was typed. How it decides says "Examples use the default
  settings and the sample values shown in empty fields." on a template with a sample.
  `builtinPolicyTemplates.test.ts` checks every entry renders under its package with its
  samples, lists the settings that have one, and checks each of them blocks rendering while empty.
  `__fixtures__/renderedTemplates.json` holds the modules `regoTemplate.ts` renders: every
  entry under each of its types with its defaults and samples (`sampleParameterValues`,
  `<id>:<type>`), and the Business-hours
  access window with the settings `renderedTemplates.test.ts` names (`<id>:<variant>:<type>`).
  That test writes it and fails while it differs, has a missing or an extra key; never edit
  it by hand, regenerate it with `UPDATE_RENDERED_TEMPLATES=1 CI=true npm test --prefix
  www/default -- --watchAll=false renderedTemplates` and commit it with the catalogue or
  renderer change. The gateway's `src/policies/builtin_templates_tests.rs` compiles every
  module with Regorus, decides each catalogue example, requires a module for every entry and
  type, and evaluates the business-hours variants at fixed instants. The catalogue
  holds the starter templates of the template library except rate controls, which are set on
  the surface's Rate Limit panel.
- **Rendering.** `regoTemplate.ts` fills settings as Rego literals: integers checked against
  their range, list values as JSON string literals in a set, so a value cannot end its string.
  A setting that fails its check shows its error under the field and blocks Use and Add to
  policy. A `time_zone` setting refuses a UTC offset such as `+01:00`, which browsers accept
  and the gateway's Regorus does not; a name must start with a letter and hold no `:`.
- **Start from gallery** (create only, `policies.edit`): `TemplateGallery` is the only place a
  policy starts from a template. A new policy has no card selected and shows only Start from:
  Details and Policy appear once a template is used or a custom policy created (`templatePicked` in
  `usePolicyTemplateActions`, `true` on a saved policy and a restored draft; the Undo of the
  first Use sets it back, which hides them and reopens the gallery). Until then the form's Rego is `DEFAULT_POLICY` (`policyDefaults.ts`,
  `default allow := false`). The
  grid of cards in the `.policy-template-row` style (`policy-template-card-<key>`, with
  `is-selected` and `aria-pressed`) holds one card per template with a variant for the
  policy's Type (`buildTemplateLibrary` groups a template's variants under its catalogue id;
  `galleryTemplates` keeps only the policy's Type), so **Define Gateway Policy** (`?type=gateway`) lists only templates for
  gateways and **Define Agent Surface Policy** (`?type=agent_surface`) only templates for
  surfaces. Each card shows its summary and category, **MCP tool policy** where it applies,
  and no role or default decision badge. On an Agent Surface policy
  a template with no Gateway variant (`surfaceOnlyKeys`) has a muted "Agent surface only" note
  at the card's end (`policy-template-card-scope`, `.policy-template-card__scope`, `0.75rem`
  in `--muted-text`), never a `Badge`. The gallery has no search or category filters. Six
  templates show until **Show all (N)** (`policy-template-gallery-show-all`, an
  `outline-secondary` button), which moves focus to the first card it brings into view. Under the list, after a top border, "None of these fit?" and
  **Create custom policy** (`policy-template-gallery-create-custom-button`, `outline-primary`
  with `fa-plus`, `aria-pressed` while its detail is shown; `.policy-template-gallery__custom`)
  follow the Trust Registry pattern: pick a template, or create a custom one. It calls
  `pickBlank` (Rego `ALLOW_ALL_POLICY`, used template `blank`, its start named "Custom policy";
  the Name and Description are emptied, typed or filled, and its Undo restores them) at once,
  unless a template was used and the Rego is no longer an untouched start (`replaceText` in
  `policyStart.ts` is not null): then it selects `blank`, and the templates column
  shows the Custom policy detail, whose **Create custom policy** asks in place before it
  replaces anything, its question ending "and empties the Name and Description." The help text above the grid points to
  **Add rules from a template** by name, not by where the column sits, since the column stacks
  under the editor below `xl`. The page holds the gallery's open state and selected card, and
  while the gallery is open the templates column shows `TemplateGalleryDetail`
  (`policy-template-gallery-detail-panel`, a `card shadow mb-4` titled "Template details") in
  place of Add rules. With no card selected it says "Pick a template under Start from to see
  what it does, then use it." (`policy-template-gallery-detail-empty`, the
  `.policy-templates-panel__placeholder` style). Choosing a card selects it, shows its detail
  there (`policy-template-gallery-detail`) and moves focus to the detail's heading
  (`policy-template-gallery-detail-heading`, `tabIndex={-1}`); Change with no card selected
  focuses the first card. The Custom policy detail has its description,
  **Show Rego** with `ALLOW_ALL_POLICY` and **Create custom policy** in place of Use. A template's detail is built from
  `TemplatePreview.tsx` and `useTemplateSettings` like the column's preview: description, setting fields (`policy-template-gallery-param-<key>`), **Show Rego**
  (`policy-template-gallery-show-rego`, collapsed by default), which shows the Rego the current
  settings render to in a `policy-preview-block` (`policy-template-gallery-rego`), or "Fix the
  settings above to see the Rego." while a setting is invalid, **How it
  decides** with each example's sample input behind **Show input**
  (`policy-template-gallery-example-input-<i>`, `-json`, at most `16rem` tall and scrolling,
  `.policy-template-example-input`), the docs link
  (`policy-template-gallery-docs-link`) and **Use this template**
  (`policy-template-gallery-use-button`), disabled while a setting is invalid or a required
  one is empty (_Settings defaults_ above). Nothing fills
  the form until Use, which fills Description and Rego with the settings shown, never the
  Name, and offers Undo, which restores those fields and the used template. The page keeps
  the used template, `usedTemplate: {id, fieldText} | null` in `usePolicyTemplateActions`, which
  only Use and Create custom policy set (`blank` for a custom policy); everything else is derived from it and the
  Rego. Use fills the Description only while it is empty or still as the last Use filled it
  (the template's own description); a typed one is kept, for every card. The gallery then collapses to one line
  (`policy-template-gallery-summary`) and the templates column goes back to Add rules. `policyStart` (`policyStart.ts`), computed once by the
  page and passed to the gallery, decides what it says. The Rego still follows its start while
  each template group in it holds exactly the lines Add to policy wrote (`addedRules` in
  `usePolicyTemplateActions`, `{name, body}` per Add, restored by Undo with the rest) and the
  Rego with those groups taken out equals what the start renders to: the used template with
  its settings, `ALLOW_ALL_POLICY` for a custom policy, or `DEFAULT_POLICY` (Deny by default) when no
  template was used. While it does it says
  "Started from <name> · Pre-filled from the template. Edit freely."
  (`policy-definition-prefilled-hint`, not for a custom policy) or, once rules were added, "Started
  from <name> · N templates added" (`policy-template-gallery-added-count`, N counting the
  template groups in the Rego). It says "Custom Rego" once the Rego no longer follows the
  start: a hand edit anywhere, inside an added group too, or a rule of the start removed. A template
  whose `package` line or imports `insertTemplateRules` adds to the start's own lines also
  counts as a change; no default template has either.
  Undo of Use, Create custom policy, Add rules, Remove, Remove rule and Deny by default restores the Rego
  and the used template together. Only the latest action can be undone, and its Undo drops
  edits made since, so each toast ends "Undo restores the Rego from before this change." (Use
  and Create custom policy: "the form", since their Undo also restores the Description, and
  for Create custom policy the Name; Use never changes the Name). A new toast replaces the one
  on screen (see _Toasts_). Save leaves the Undo toast on screen: a successful save merges only
  the stored `content_hash` and `updated_at` into the form, so an Undo or edit made while the
  save runs stays unsaved and the form stays dirty, and a failed save keeps the change and its
  Undo. Use of a template, or Create custom policy, moves focus to **Change**
  (`policy-template-gallery-change-button`), which reopens
  it with the used card selected and its settings as they were used, also after a hand edit,
  and moves focus to the selected card, or to the first card when none is selected. Use
  there replaces the Rego, and **Cancel** beside the title
  (`policy-template-gallery-cancel-button`, shown only once a template was used) collapses the
  gallery without using another, which brings back Add rules. Use (of a template or a custom policy)
  replaces at once before any template was used (`templatePicked` false) and while the Rego is an untouched start (`policyStart` is not
  null and counts no added templates); otherwise its
  first click asks in place under the button, never in a modal
  (`policy-template-gallery-replace-confirm`): "This replaces the N rules in the Policy
  section.", or "This replaces your edits in the Policy section." when there are no rules to
  count or the Rego can't be read, with **Replace** (`danger`,
  `policy-template-gallery-replace-button`) and **Cancel**
  (`policy-template-gallery-replace-cancel-button`). Opening it moves focus to Cancel, so a
  second Enter can't replace; Cancel and Escape close it and return focus to Use; picking
  another card closes it. Replace applies the template with the usual Undo. After a discard and
  Undo the page keeps only the form, with the gallery collapsed and Details and Policy shown.
  The editor restores a left draft only when the discard toast's Undo reopens it
  (`restoreOnlyOnUndo` on the `useDiscardWithUndo` snapshot, which Undo marks with
  `{ discardUndo: true }` navigation state, which the hook clears from the history entry once
  read, so browser Back to that entry is not another Undo); opened any other way it drops the draft, dismisses
  that draft's discard toast if it is still showing (`showUndoToast` returns a dismiss function,
  kept per snapshot key), and starts fresh, with no template selected. Without
  `restoreOnlyOnUndo`, as in the Surface Builder, any visit restores the draft and the toast
  stays. A second discard of the same editor replaces that toast; the replaced toast expires
  without clearing the stored draft, which belongs to the newer toast, so its Undo restores the
  second draft.
  The Type is set by the Define button that opened the page (`?type=`) and can't be changed.
  While `?type=` names a Type, Details has no Type field and the card header says
  "Create <Type> Policy". Opened without it, the page is a Gateway policy titled "Create Policy",
  and `policy-definition-type-select` shows disabled with "Set by the Define button that opens
  this page. It can't be changed here." A saved policy always shows its Type, disabled.
- **Templates column** (`PolicyTemplatesPanel`, `policy-templates-panel`): for users with
  `policies.edit` the page always has two columns, the editor card (`col-xl-8`) and a templates
  column (`col-xl-4`, `policy-templates-column`, sticky from `xl` below the top bar), so the
  editor's width never changes. Template examples, Test (dry-run) and Version history sit in
  the editor column under the editor card, so a taller templates column never pushes them down;
  without `policies.edit` the editor is full width and there is no column. The column only adds
  rules ("Add rules from a template", no close button); only the template details, on the
  create form while Start from is open, swap in their own panel, and closing Start from
  returns to Add rules. **Add rules from a template**
  (`policy-templates-insert-button`, in the Policy section and the empty rules list) brings back
  the Add rules panel, closing Start from when Change reopened it, scrolls to the column and
  focuses its search, and Change doesn't take that focus. It lists only templates
  that add rules of the policy's Type, in one list with no tabs, and says under the list
  how many it leaves out (`policy-templates-left-out-note`: "17 templates
  left out: 3 are whole policies, 14 are for Agent Surface policies.", then "Pick a whole
  policy under Start from." on the create form or "Whole policies are offered only when
  creating a policy." on a saved one while any whole policy is left out), and
  its body opens with "Adds rules to the
  end of this policy." It has a search
  (`policy-templates-search-input`), category chips shown when the list holds more than one
  category (`filter-chip-<key>` inside `policy-templates-categories`), rows
  (`policy-templates-row-<id>`) with a DENY or ALLOW decision pill in a list at most `300px`
  tall that scrolls (`.policy-templates-panel__list`), so the preview under it stays in sight,
  and a preview (heading `policy-templates-preview-heading`). Picking a row scrolls the column
  only as far as needed to show the preview (`block: 'nearest'`, nothing moves when it is
  already in view) and leaves focus on the row; with nothing
  selected, or while the search or a category hides the selected row, it says "Pick a template
  to preview the rules it adds.", `policy-templates-preview-empty`, and the preview comes back
  when the row is listed again. The preview shows the description, default
  decision, setting fields (`policy-templates-param-<key>`), the lines it adds, How it decides
  with each example's input (`policy-templates-example-input-<i>`), the docs link
  (`policy-templates-docs-link`) and **Add to policy**
  (`policy-templates-insert-rules-button`), disabled while a setting is invalid or a required
  one is empty. While the policy allows by default the preview
  warns "This policy allows every request by default, so these rules change nothing until you
  choose Deny by default." (`policy-templates-allow-default-note`, a warning `InfoBanner`). On an
  empty policy it warns instead "This policy is empty, so it allows every request. These rules
  make it deny every request they don't allow." (`policy-templates-empty-policy-note`).
- **Add to policy** shows the lines it adds (`policy-templates-insert-preview`) with a note,
  "Allow rules combine with OR: a request passes when any allow rule matches. Its `default
  allow` line is not copied." (`policy-templates-or-note`), and appends
  them to the end of the Rego between `# Inserted from template: <name>` and
  `# End of template: <name>` comments, offers Undo, and keeps the panel open so several
  templates can be combined, on the create form and on a saved policy. The template's `default
  allow` line is never copied, its `package` line only when the Rego has none, and its imports
  go after the policy's `package` line. When the Rego allows by default, the Rules view warns
  that the allow rules change nothing (below). A template's helper rules that depend on its settings are Rego functions taking the
  setting as an argument, so adding the same template twice with different settings keeps both
  checks apart. Add to policy moves the Policy section to the Rules view.
- **Rules view** (`PolicyRulesList`, `policy-rules-list`) of the Policy section lists the rules
  `regoRules.ts` reads from the Rego as it changes: the rule count (`policy-rules-count`) and
  default decision sit in the section's status row, then come the rules written
  in the editor and one group per added template (`policy-rules-group-<n>`), each a `card mb-2`
  whose `card-header py-2` names the source, gives the group's rule count ("2 rules",
  `policy-rules-group-<n>-count`), the **Just added** mark and, for a template group, **Remove
  group** on the right; the group's in-use reason and amber lines sit in a `card-body` under the
  header. The rules are rows of a `table table-sm align-middle mb-0` with a `thead-light` header
  (Kind, Rule, Line, and a visually hidden Actions column only with `policies.edit`), fixed
  layout so the Rule column truncates instead of scrolling sideways. Each rule
  (`policy-rules-group-<n>-rule-<m>`, the row) has a neutral outline role badge
  (`policy-rules-group-<n>-rule-<m>-kind`, from `ruleRoles` in `regoRules.ts`, shown with or
  without `policies.edit`): Allows (a plain allow rule, as `isPlainAllow` reads it), Sets
  allow (any other rule whose read name is `allow`, such as `allow := false if …` or a dotted
  `allow.x`; title "Sets allow in a way the Rules view can't read; read the Rego"), Deny
  reason (only a rule named `deny_reason`), or, for every
  other name, `deny` included, "Used by allow" when `allow` reads it, directly or through other
  rules, or while the Rego reads its package as a whole document (title "allow reads this rule,
  directly or through other rules") and "Not used by
  allow" otherwise (title "allow doesn't read this rule, so it doesn't change whether a request
  is allowed"); the walk starts from every rule whose read name is `allow`. Then the
  rule on one line (`; ` where a newline separates expressions inside brackets, a space
  otherwise, so `h if { a; b }` and `allow { a; b }` for a brace on the next line; whitespace
  only collapsed when the text can't be tokenized) with its full text in `title`, except that a plain allow rule which
  `splitConditions` in `regoRules.ts` splits into two or more conditions shows them as a
  `ul.list-unstyled` (`policy-rules-group-<n>-rule-<m>-conditions`), one truncated `<code>`
  line per condition (`-condition-<k>`, the condition in `title`), every line after the first
  starting with a muted `small` "and"; a condition over several lines is flattened to one
  (whitespace collapsed outside strings, `; ` where a newline separates expressions inside a
  block). A rule that is not a plain allow, has `else`, one condition, no conditions, a raw
  string over lines, a line that starts or ends mid-expression (such as `with` on the next
  line), a condition that starts with `[` or `(`, or a character the splitter doesn't know
  keeps the one-line view. Then its line numbers, which switch to the Rego
  view and select the rule (`-show-button`): a small `outline-secondary` `AppButton` with a
  `fa-code` icon and only the numbers in monospace (`5`, `5–8`), since the column is headed
  Line; its title is "Show in the Rego" and its accessible name "Show <rule> in the Rego, line 5". The rules outside any template group are titled
  **Your rules** (pen icon), and "Your rules · started from <template>" on the create form while
  `policyStart` says the Rego still follows the template Use filled it from. A template group is
  titled "From template: <name>" (layer icon), the last added one is marked **Just added**
  (`policy-rules-just-added`), and **Remove group** (`policy-rules-group-<n>-remove-button`,
  `outline-danger`, `policies.edit`) deletes the group's lines with Undo. Removing the last rule
  of a template group removes the whole group, its `# Inserted from template` line included, with
  one Undo that brings both back ("Removed the rule <rule>, the last from the template <name>.");
  a template group left with no rules by a hand edit in the Rego still says "No rules left from
  this template." and shows no table. Each rule has its
  own remove button (`policy-rules-group-<n>-rule-<m>-remove-button`, the list tables'
  `outline-danger` trash icon button, named "Remove the rule <head>", `policies.edit`), which
  deletes the rule's lines and the comment lines directly above it, with Undo. `regoRules.ts` decides which Remove is refused, and why (`ruleUse` and `groupUse` return
  the reader, the whole-document read, a reason with no reader, or null): a rule is
  in use when an `allow` rule, a dotted one such as `allow.x` included, reads its name, directly
  or through other rules, from outside that rule, such as `count(deny) == 0`, `not deny_x`, `not deny_reason`, a function call `h(x)` or
  `data.<package>.<name>`, and a dotted rule such as `blocked.ip` is read by its first segment;
  a template group is in use when `allow` reads a name the group defines through rules outside
  the group. A read from `deny_reason` alone doesn't count, since the gateway decides on `allow`
  and reads `deny_reason` only as text, so `deny` rules that only `deny_reason` reads are free;
  names inside strings are not reads. A rule head and the lines under it that start with `if`,
  `contains`, `else`, `:=`, `=` or `{` are one rule, as is a line that ends mid-expression (its
  last token `if`, `not`, `in`, `with`, `as`, `some`, `every`, `contains`, `else`, `,` or an
  infix operator, a keyword after a dot excepted), so `allow` with `if { count(deny) == 0 }`
  on the next line reads `deny` and `allow if not` reads the `blocked` on the next line; an
  `import` or `package` line never continues onto the next. While the Rego imports a `data` path, or reads `data`, its
  package or a parent as a whole document (`data.<package>["name"]`, `doc := data.<package>`),
  every rule but `allow` counts as in use. A rule whose read name is `allow` but that is not a
  plain allow is in use (`sets-allow`), and so is a group that holds one, unless it has an
  identical copy elsewhere: the reasons are "This rule sets allow in a way the Rules view can't
  read; remove it in the Rego view." and "A rule in this template sets allow in a way the Rules
  view can't read; remove it in the Rego view." A plain `allow` rule, a rule with an identical definition
  left (the same template added twice), and a group whose used rules all have identical copies
  outside it can always be removed; one of several different definitions of a used name stays
  in use. Rules are compared by their
  code with comments removed and strings kept, so a `#` inside a string is code. A refused
  Remove is disabled and says why in muted text under the rule
  (`policy-rules-group-<n>-rule-<m>-in-use`: "Another rule uses this (allow, line 10); remove
  that rule first.", naming the first rule by line that reads it, never another definition of
  the same name) or under the group header (`policy-rules-group-<n>-in-use`: "A rule outside
  this template uses its rules (allow, line 10); remove that rule first."), linked to the button
  by `aria-describedby` and repeated in the rule button's `title`; when no reading rule can be
  named the reason leaves out the parentheses, and Remove stays refused. While the Rego reads the
  policy as a whole document both say "The Rego reads the policy as a whole document; remove
  rules in the Rego view." After the banners and before the groups a muted `small` line with
  `fa-info-circle` (`policy-rules-summary`, from `summarizeDecision`) states what this policy
  decides, always starting "This policy" since gateway policy runs first: with any allow
  definition that is not plain (a value other than true, arguments, a dot, `[ ]`, `contains`,
  `else`, or a `default allow` other than true or false) "The Rules view can't summarise how
  this policy sets allow. Read the Rego.", which wins over every other case; with `default
  allow := true` "This policy allows every request: the default is ALLOW."; with an allow rule
  that has no conditions "This policy allows every request: an allow rule has no conditions.";
  with plain allow rules "This policy allows a request when its allow rule matches." (one) or
  "… when any allow rule matches." (several), then "Otherwise:" and the Audit Log's
  `audit-decision audit-decision--deny` DENY pill (`policy-rules-summary-otherwise`), followed
  by "(no default is set)" when there is no `default allow`; and with no allow rule "This
  policy denies every request: no rule allows one." or "… no rule allows one and no default is
  set.". It is hidden while the Rego doesn't parse or compile, has a mismatched package, is
  empty, or has no rules; while a compile is pending it shows from the parse. A policy that allows
  by default and has allow rules, all of them plain, shows a warning `InfoBanner` (`policy-rules-allow-default-warning`) with
  **Deny by default** (`policy-rules-set-default-deny-button`), which sets `default allow` to
  false and drops a `# Allow all traffic by default` comment directly above it, the one a custom
  policy and policies created before templates carry. Under that banner each group with allow
  rules, Your rules included, carries an amber line "No effect while the default is ALLOW."
  (`policy-rules-group-<n>-no-effect`), which doesn't block saving. On the create form a
  template group whose template has no variant for the current Type (`groupsForOtherType` in
  `policyStart.ts`, matched by name against the default templates) carries an amber line under
  its header (`policy-rules-group-<n>-other-type`: "Written for Agent Surface policies. It
  reads input Gateway policies don't get. Remove it to create this policy."), keeps its
  Remove group, and a warning banner (`policy-rules-other-type-banner`) says "Remove the rules
  written for Agent Surface policies to create this policy."; Create is disabled, and Ctrl+S
  refuses, until those groups are removed. An empty Rego shows Default
  ALLOW and "An empty policy allows every request.", as the gateway treats it; Rego with no rules
  and no `default allow` says "No default is set, so every request is denied.", and with a
  default "The default decision (deny) applies to every request." or "(allow)". Removing a group
  keeps the Just added mark and examples card while another group of that template remains. With no rules, an empty state
  (`policy-rules-empty`) offers **Add rules from a template** (`policy-rules-add-button`) and
  **Write Rego** (`policy-rules-write-rego-button`). While the Rego doesn't compile a danger `InfoBanner`
  (`policy-rules-invalid-banner`) offers **Open Rego**
  (`policy-rules-invalid-open-rego-button`) and names a package mismatch when that is the
  cause, and while a bracket is open, or a top-level statement has no rule name or is named
  after a Rego keyword (such as an `if { … }` body a template line separates from its head), the
  view says so (`policy-rules-unparsed`, with `policy-rules-open-rego-button`) instead of
  listing rules.
- **Adding to a saved policy** also shows the **Template examples**
  card (`policy-template-examples-card`) above Test (dry-run): each example runs through
  `POST /policy-definitions/{id}/simulate` with the draft Rego. Its columns are Example,
  Expected, This policy, Result (**Matches** or **Differs** `Badge`) and **Load in Test**
  (`policy-template-example-row-<i>-load-button`), which writes that example's input into
  Test (dry-run)'s sample input, scrolls to it and focuses it, with an Undo toast ("Loaded
  <example> into Test (dry-run). Undo restores the sample input from before.") that puts the
  earlier sample input back; the sample input is part of the policy form, so this makes the
  form dirty. A row that
  differs is highlighted and says why under its name (`policy-template-example-row-<i>-why`):
  for an expected DENY that this policy allows, that the policy allows every request by default
  when its `default allow` is true, and otherwise that another allow rule lets the request
  through and allow rules combine with OR; for an expected ALLOW it denies, to load it in Test,
  with the simulate `reason` when there is one. The simulate response doesn't say which rule
  decided, so the reason never names one. Examples are written for the default settings and
  the samples (`usesDefaultSettings` compares with `sampleParameterValues`), so
  when a setting was changed before inserting, the card says so
  (`policy-template-examples-changed-settings`), shows no Result and highlights no row. Every
  template that adds rules has examples (`builtinPolicyTemplates.test.ts` checks it), so the
  card always has rows; a clock-dependent template without examples is a whole policy. The
  panel scrolls into view when it opens.

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
- A `target_auth_failed` record carries `target_auth` (`outcome` and, when the token endpoint
  sent one, `oauth_error`), shown as **Credential outcome** and **OAuth error** in the Refusal
  group. With outcome `passthrough` the request was forwarded without the Target credential: it is
  titled **Forwarded without Target credential** in the warn tone, not as a refusal. With outcome
  `refused_by_target` the Target refused the gateway's credential: it is titled **Target refused
  the credential** in the deny tone, and `upstream_status` shows as **Target status**. When the
  failing credential is a Transit Point's, `target_auth.transit_point` carries its alias: both
  summaries name that Transit Point in place of the Target, and it shows as **Transit Point**
  in the Refusal group.
- `requested_variant` is caller-chosen text: render it as React text only.
- The Metrics page shows the `$alias` badge for a configured alias only, never for `_base_`.

## Audit page: partial reads and log size

An audit read walks the stored history and may not return all of it. The response says so in two
separate fields: `truncated` (the read stopped before the end — its scan limit, or a rotated file
missing or unreadable) and `dropped_records` (records in the history it could not read — a line
too long to assemble, or one an interrupted append left half-written). **Either one makes the
counts lower bounds**; `useAuditLog` folds them into one `countsAreLowerBounds`, and the UI knows
only that.

- When the counts are lower bounds every number that came from that walk renders with a trailing
  `+` and nothing else changes: the record badge (`audit-total-badge`) reads `1243+`, the pager
  reads `Page 5 of 687+`, and a category count reads `24643+` (`0+` for the zero marker).
  Otherwise the numbers render exactly as before. No banner, notice, colour or tooltip.
- The badge shows while `total > 0` **or** the counts are lower bounds, so `0+` is never hidden,
  and such an empty page reads **"No governance events found in the records searched."**
  (`audit-empty-truncated`) instead of "No governance events yet" and its advice to enable VP
  Auditing: the log is not known to be empty, so that advice would be wrong.
- The flag reaches them through `useAuditLog` (`countsAreLowerBounds`), `AuditList` and
  `AuditFilters` (the same prop name), and the shared `FilterChipGroup` / `FilterOverflowMenu`.
  The Category facet renders its counts, so a category with records reads `24643` (or `24643+`
  when the counts are lower bounds) and one with none keeps the `(0)` / `(0+)` zero marker. The
  Decision, Flow and Scope facets pass `showBadge={false}`: their chips carry no count, so a
  badge there would have nothing to show.
- A **read that failed** is not an empty log. The gateway answers a read it could not make with
  `500`, so `useAuditLog` keeps the message in `error`, and `AuditList` renders the
  `alert alert-danger` panel (`audit-error`) with a Retry (`audit-error-retry`) **instead of** the
  empty state, saying no records could be read and that this is not the log holding none. The
  toast stays, for the moment the read fails; the panel is what is still there after it fades.
  Refresh stays enabled while `error` is set, since a failed read leaves `total` at `0` and
  Refresh is the way back.
- `AuditLogSize.tsx` shows one line above the list, `Audit log: 312 MiB of 1 GiB`, with a thin
  bar: neutral under the configured size, amber over it, and over it a line naming the two
  things an operator can do. It is **usage against a mark, never a quota**: nothing is enforced
  at `[audit] vp_audit_log_soft_cap_bytes`, no record is deleted and the log keeps growing. With
  `soft_cap_bytes` of `0` the size shows alone, with no bar, and with no `history_bytes` the
  line is not shown at all rather than claiming an empty history. The values come from
  `history_bytes` and `soft_cap_bytes` on the audit response.
- Sizes in bytes are formatted by `utils/formatBytes.ts` — one implementation for the whole
  dashboard, in binary units (`312 MiB`, `1.5 GiB`). The Metrics and Tasks pages use it too;
  do not add a page-local copy.

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
`pages/IdentitiesPage/`, with tests in `pages/IdentitiesPage/__tests__/`: grouping, search,
recorder filter, and surface links in the `useIdentityRows` hook, the grouping and change log
in `identityVersions.ts`, the shared managed DID check in `sharedManagedDid.ts`, and the row
parts `IdentityNameCell`, `IdentitySurfaceCell`, `IdentityOriginBadge`,
`IdentityRecorderChip`, and `IdentityVersionHistory`.

- One row per surface Managed Agent: managed rows with the same `surface_id` are versions of
  one entry (`groupIdentityVersions`), whatever their source
  (`agent_identity.credential_type`) or `slot`, so the Managed Agent's response and Transit
  Point DIDs share it. The row shows the most recently used DID, a summed usage count, and the
  latest last use; its actions (Trust Score, Configure Policy, Copy link) belong to that DID.
  `from_jwt_claim` DIDs (one per claim value), external callers and identities without a
  surface keep one row per DID.
- The expanded row's **Version History** section lists the entry's DIDs and the credential
  rotations inside them as one timeline, newest first, numbered from the oldest. Each version
  shows its time ("Time unknown" for a rotation found when tracking began), its DID, a
  Current badge on the primary DID's latest version, and its field changes against the version
  before it (a new DID against the previous DID, a rotation against its DID's earlier
  fields); the first version lists its values. A rotation with field changes (a certificate)
  is labelled "Credential rotated"; one without (an API key, whose update may only have
  edited its details) is labelled "Credential updated". A version that introduces a DID other
  than the row's offers that DID's actions (`identities-version-<n>-<action>-button`). A
  certificate or API key identity with no versions yet still shows the section, saying none
  are recorded. Rows carry only `rotation_count`. Opening Version History fetches every page
  of each member DID's rotations with a count above 0 (`getIdentityRotations` in `api.ts`,
  through the `useEntryVersions` hook), showing `identities-version-history-loading` while it
  loads and `identities-version-history-error` with `identities-version-history-retry-button`
  when it fails. It refetches only when a member's `rotation_count` changes, showing the
  loading state until the new list arrives, and closing Version History aborts the fetch. An
  entry with no rotations builds its DID versions without a request; see
  `docs/SOURCE_AUTH.md#identity-versions`.
- `/identities/<did>` expands the entry holding that DID once the dashboard identities have
  loaded; an earlier DID also opens Version History and marks its versions, including when
  the entry is already expanded.
- Expansion state is a `Set` of primary DIDs. Rows expand and collapse independently, and a
  deep link adds to the set rather than replacing it.
- Identities page tests prefer the backend-generated rows in `src/__fixtures__/backend/` (a
  managed row, a managed mTLS row with a rotation, and an external caller row) over
  hand-written ones. Rust tests fail when the backend no longer sends that shape, and
  `UPDATE_WEB_FIXTURES=1` regenerates them; do not hand-edit them.
- The **Name** column (`IdentityNameCell` with `showDid={false}`) shows the display name
  prominently. The header is "Name", not "Agent Name": the column holds display names, and
  _agent name_ is the verified `host/@local` handle only. While a caller name lookup is
  pending (`display_name_pending`), it shows a muted "resolving…" line. A verified agent
  name renders as `local · host` with a verified marker. A caller's Agent Card name
  (`agent_card`), a managed agent's target Agent Card name (`target_agent_card`) and a
  surface name show no badge. Without a display name, it shows `metadata.agent_name` when that
  is a non-empty string, else a muted, italic "Unnamed Agent".
- The **DID** column (`IdentityNameCell` with `showName={false}`) shows the shortened DID in
  monospace with a copy button for the full DID, then the version badge and SCID when set,
  on a second line.
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
- A **revoked** identity (`revoked` on the identity: the API key its DID comes from is revoked
  or deleted, or every surface it is linked to was deleted) gets a "Revoked" badge beside its
  name cell (`components/IdentityRevoked.tsx`): a plain Bootstrap `badge text-bg-danger`, solid
  red with white text like the Revoked status on the API key table, not the shared `Badge`.
  Expanding the row, or opening it in the
  Dashboard's `IdentityDetailsModal`, shows the `alert-danger` "This identity is no longer in
  use: its API key was revoked or deleted, or its surface was deleted." The page has no
  Revoked filter.
- A surface of an identity marked `surface_deleted` (every surface it is linked to was
  deleted) is shown by `SurfaceLinkButton` (in `IdentitySurfaceCell.tsx`), in the **Agent
  Surface** list and the expanded Summary, as muted plain text, the surface name when the
  identity carries one and otherwise the surface id, with a solid grey "Deleted" badge
  (`badge text-bg-secondary`, white text), and never links. A live surface keeps its link and
  shows no badge.
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
| Identity row (the entry's primary DID) | `identities-row-<did>`                                           |
| History toggle, version                | `identities-version-history-toggle`, `identities-version-<number>` (with `-changes`), `identities-version-history-empty` |
| Name, pending, verified        | `identities-name`, `identities-name-pending`, `identities-name-verified` |
| No name                        | `identities-name-empty`                                                  |
| Shared managed DID name, count | `identities-unnamed-agent`, `identities-shared-surface-count`            |
| Copy DID                       | `identities-copy-did-button`                                             |
| Origin badge                   | `identities-origin-<origin>`                                             |
| Surface list, surface link     | `identities-surface-list`, `identities-surface-link`                     |
| Credential principal           | `identities-credential-principal`                                        |
| Revoked badge, message         | `identities-revoked-badge`, `identity-revoked-info`                      |
| Deleted surface, its badge     | `identities-surface-deleted`, `identities-surface-deleted-badge`         |
| Recorder filter                | `identities-recorder-filter`                                             |
| Recorder chip                  | `identities-recorder-chip-<state>`                                       |
| Recorder tooltip               | `identities-recorder-tooltip`                                            |
| Tooltip recorder surface       | `identities-recorder-surface`                                            |
| Tooltip last attempt, reason   | `identities-recorder-last-attempt`, `identities-recorder-reason`         |
| Tooltip registry entry         | `identities-recorder-entry-<registry id>`                                |

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

### Mediator access step

A mediator in `explicit_allow` mode refuses DIDs its administrator has not added, so both peer
pairing wizards stop after the gateway mints its DIDs, on one shared step
(`components/shared/MediatorAccessStep.tsx`, helpers in `utils/mediatorAccess.ts`). The gateway
cannot tell the mediator's mode, so each wizard tries to continue at once and shows the step only
when the mediator refuses a DID. On a mediator that admits them, **mediator-access** is left out
of the step bar too.

| Wizard | Steps | DIDs shown |
| --- | --- | --- |
| Create Connection Point (`/gateways/publish`) | select-mediator, enter-details, **mediator-access**, complete | Connection Point DID, Permanent DID for the paired gateway |
| Add Gateway (`/gateways/connect`) | enter-details, enter-link, **mediator-access**, connect, complete | Temporary DID for the handshake, Permanent DID for this pairing |

- Leaving enter-details (Create Connection Point) or enter-link (Add Gateway) posts with
  `await_mediator_access: true`; the response's `mediator_access` fills the step. Create
  Connection Point then calls `POST /connection-points/{id}/continue` behind its saving
  spinner; Add Gateway moves to the connect step, which calls `POST /gateways/{id}/continue`.
  Success goes on as before; a `409 mediator_access_refused` opens the step without a
  refusal message. Any other failure of that first try in Create Connection Point shows
  "Connection Point Saved, Not Connected Yet" with the error, **Continue Later** and
  **Try Again** (`first-try-retry-button`), not the step: nothing says the DIDs were refused.
- The card header is "Add These DIDs to the DIDComm Mediator's Allow List" (`fa-user-shield`).
  The text opens with "This {name} Mediator most probably uses Explicit Allow, …" ("Mediator"
  is left out when the name already ends in it), then says what to do when the mediator is
  hosted by Affinidi or self-hosted. **Copy All DIDs as a Bundle** copies every DID, one per
  line; below it, one row per DID with its label, `topAndTail(did, 16, 16)` and a
  `CopyButton`, and a note to use one or the other. Both wizards show the step the same way,
  with no warning banner: the dashboard cannot tell whose mediator it is, since both gateways
  may use the same one.
- **Continue Later** (left) returns to Connections and changes nothing. **Test Connection**
  (right) calls the same Continue again. A `409 mediator_access_refused` then keeps the step
  and shows "DIDComm Mediator {name} still refuses the {label} ({short DID}). Make sure it is
  allowed, then select Test Connection again."
- `?resume=<id>` opens either wizard at the step with the same DIDs, from
  `GET /connection-points/{id}/mediator-access` or `GET /gateways/{id}/mediator-access`,
  without calling Continue first.
- On Connections, a gateway with status `awaiting-mediator-access` and a Connection Point with
  `awaiting_mediator_access` show the warning badge "Waiting for mediator access" and a
  **Continue** button that opens its wizard with `?resume=`. Both **Continue** buttons are
  `outline-primary`, `sm`, like the per-row **Edit** button. Such a Connection Point has no
  copy-link or copy-secret button until it has an invitation; such a gateway is treated as
  pending (`isGatewayPending`): no ping, edit or row link.
- A `pending` gateway (the connection-setup was sent, the inviter has not accepted it) has no
  ping or edit button, but its row opens `/gateways/{id}`, the page the Add Gateway wizard's
  **View Connection** opens (`opensGatewayDetails` in `utils/gateways.ts`; rows waiting for
  approval or mediator access do not open it). There the Overview shows an info notice
  (`gateway-editor-pending-notice`), **Gateway Enabled** is disabled and Save leaves the status
  alone, and the Remote tab says the issuer DIDs and surfaces appear once the inviter accepts
  (`gateway-editor-remote-pending`). An inviter that refuses the setup turns it `failed`, with
  its reason in the description; see
  [`docs/FABRIC.md`](../../docs/FABRIC.md#connection-establishment-invariants).
- The payment gateway wizard does not pause.

| Element | Test id |
| --- | --- |
| Step and DIDs | `wizard-step-mediator-access`, `mediator-access-did-<role>` (`connection_point`, `temporary`, `permanent`), `mediator-access-copy-button-<role>` |
| Actions | `mediator-access-copy-all`, `mediator-access-later-button`, `mediator-access-continue-button` |
| Errors | `mediator-access-refused`, `mediator-access-error` |
| Connections | `gateways-continue-button-<id>`, `connection-points-continue-button-<id>`, `connection-points-status-<id>`, `gateway-status-<id>` |
| Pending gateway page | `gateway-editor-pending-notice`, `gateway-editor-remote-pending` |

## Agents page

`/agent-registry` (`pages/AgentsPage.tsx`, table in `pages/AgentsPage/AgentsTable.tsx`) and
`/agent-registry/:agentId` (`pages/AgentDetailPage.tsx`, header and tabs in `pages/AgentDetailPage/`)
are read-only and need `surfaces.view`. They call only `apiClient.listAgents`, `getAgent` and
`getAgentCard` (`/v1/agents`), never `/v1/dashboard/stats`. There is no create, edit, duplicate,
disable or rotate action: the API has no write endpoints for agents. Styles are in
`pages/AgentsPage/AgentRegistry.css`, built on the theme variables with `body.dark-theme` overrides.

- One record per managed agent: the gateway groups the surfaces that target the same agent and
  returns them in display-name order (case-insensitive, then id); the page does not re-sort.
  MCP surfaces front tool servers, not agents, so `/v1/agents` leaves them out (`is_listed` in
  `src/identity/handlers/agents.rs`) and their details and card return 404. The page adds no
  protocol filter of its own.
- The Agents page shows no status anywhere: no list column, filter or dimmed rows, no
  details header badge.
- Each list row is a link (`role="link"`, named by the agent name and endpoint host) and ends with a
  chevron cell (`agents-row-chevron`); Enter or Space on the row opens the details. The chevron is
  `--muted-text`, and `--accent-blue-text` while the row is hovered or focused, in both themes.
- The details page has three tabs, **Agent Card** (opened first), **Connection** and **Traffic**.
  Surfaces are shown only in the list, never repeated on the details page. The list only counts
  identities; the **Connection** tab lists each DID with a copy button.
- An agent without a name, or with an empty one, shows **Unnamed agent** everywhere
  (`displayName`).
- The details page sets the top-bar title to the agent name (**Unnamed agent** without one) with
  `usePageTitle`; while loading, or when the agent is missing, the route default stays. The
  back button is `btn-outline-secondary`.
- Opening another agent's details clears the shown record and loads again; only the answer for
  the current `agentId` (and its latest load) updates the page, so a late answer for the previous
  agent never replaces it.
- The list filters client-side by text only: the display name (**Unnamed agent** included), every
  surface name in the record, and the route label (`agentMatchesFilter`).
- With no agents and no load error, the list shows the "No managed agents yet" `EmptyState`. For a
  user with `surfaces.edit` it has a **Create a surface** in-app link (`agents-add-surface-link`,
  `ctaTo`) that opens `/surfaces/new`, followed by a **What’s a surface?** docs link
  (`DOCS_URL.surfaces`, `docsPlacement="actions"`); without `surfaces.edit` only the docs link
  shows, since the page needs only `surfaces.view` and `/surfaces/new` needs `surfaces.edit`.
- Columns: Agent, Route, Protocol, Identities, Used by surfaces, Trust registry, Last activity.
  The protocol badge (`agents-protocol-badge`) is the shared `ProtocolBadge`
  (`components/shared/ProtocolBadge.tsx`), the one the Surfaces page uses: A2A
  `text-bg-primary`, AP2 `text-bg-warning`, MCP `text-bg-info`, DIDComm `text-bg-success`, any
  other protocol upper-cased in `text-bg-secondary`. Never restyle it per page. The template
  picker's protocol badge (`getTemplateProtocolBadge`) reads the same list.
  The count badges of **Used by surfaces** and **Identities** match the Surfaces page's Transit
  Points count: a square `badge text-bg-primary`, not a pill, at the same size, so never inside a
  `small` element (a badge's size is relative to its parent).
  Font sizes: every value in a row is the table's 12px body text, never `small`; only the endpoint
  host under the name is `small`. Every badge in a row is 9px (0.75em of the cell text):
  `.agents-table .app-badge` in `AgentRegistry.css` sizes the shared `Badge` (rem-based) the same
  as the Bootstrap badges (em-based) beside it.
  **Used by surfaces** shows a count badge and the surface names joined with commas on one
  truncated line, with the full list in the tooltip. The surface names and the endpoint host are
  cut only at their column's edge (the cell has `max-width: 0`), never at a fixed width, so wide
  screens show them in full. It has no links. **Identities** shows no DID,
  only the count, in the same square count badge as **Used by surfaces**
  (`agents-identities-count`), followed by "identity" or "identities" (`identityNoun`), with every
  DID in `identities` in the tooltip. Without any it shows **No identity** in
  `text-muted` text, like an empty **Used by surfaces** cell: the badge is only for a count, and
  never a warning, since a surface without a DID is a valid setup. While surfaces use the agent its tooltip says none of them has a DID (the API does not
  say which surface holds which DID). The **Trust registry** header stays on one line (`text-nowrap`).
- The agent name matches the A2A Proxies list on the Proxies page: a plain `<strong>` at the
  table's font size, with the endpoint host under it in `small text-muted`. An agent without a
  name shows "Unnamed agent" the same way (`agents-unnamed`), never italic or muted. The name
  (`agents-name`) is the strongest text in a row: bold, in the table's text colour like a surface
  name on the Surfaces page. The global `.table td:first-child` rule would grey it, so
  `AgentRegistry.css` gives the first cell `var(--bs-table-color)`. The host under it stays
  `small text-muted`. The table's
  column headers (`agents-table`) keep the uppercase `.table-sm` default, like the Surfaces page.
- **Agent** shows the endpoint host under the name (`endpointHost`: the URL origin with its
  scheme, such as `https://agent.example`, the A2A proxy, or `gateway/channel`), so rows with the
  same name can be told apart. A proxy or gateway shows
  `target_name` from `GET /v1/agents`, or its id when the name is `null` or blank; the
  `a2a-proxy://` and `fabric://` schemes are never shown. An endpoint `connectionTarget` cannot
  show gets no line.
- Raw API values are never shown. `pages/AgentsPage/agentLabels.ts` maps them: runtime `url`,
  `a2a-proxy`, `gateway` to the route Direct, Proxied, Fabric; the protocol badge shows the
  protocol only (`A2A`), never the route. Shared badges are in `pages/AgentsPage/AgentBadges.tsx`.
- The route is called **Route** everywhere (list column, Connection heading). The list renders it
  with `AgentRoute`: plain text at the normal text size and colour, never a badge (the row's
  badges are for counts, the protocol and the trust registry state), with the route icon and
  label, its meaning (`routeDescription`) as the tooltip and as visually hidden text
  (`agents-runtime`). The details page shows no route:
  not in the header, not on the Connection tab, whose description says the route.
- An agent with a `null` name shows **Unnamed agent** styled like a name, never italic or muted,
  in the list, the details header and the Agent Card preview, with the endpoint host beside it in
  the header (`agent-details-endpoint-host`). The API
  names Direct, Proxied and Fabric agents from their Agent Card; a Proxied or Fabric name comes
  from the card the gateway serves and can take a refresh of the list to appear after the
  background lookup. A canvas target name that only names a surface (a surface's own name, or a
  generated `<kind>_surface_<n>`) is never the agent's name.
- **Trust registry** shows **Recorded** with the Agent Identities page's badge
  (`TrustRecorderStateBadge`, state `recorded`: success tone, no icon), with a tooltip saying
  recording is not trust, when `trust_registry.recorded` is true, else **Not recorded** in the
  same shared `Badge` (`size="sm"`) in the `secondary` tone, so both states share one shape and
  size, with no tooltip.
- Agent `id` is opaque and never read as a surface id; surface links come from `surfaces[]`.
- Section headings on every details tab (**Route**, **Trust registry**, **Skills**, **Changes by
  the gateway**) use `.agent-preview-section-title`. Secondary text in `AgentRegistry.css` uses
  `--muted-text` at `0.875em`, the size of `.small`, never a fixed pixel size or a `--gray-*`
  shade, and the Agent Card avatar is white on `--primary-solid`.
- The **Connection** tab (`AgentDetailPage/ConnectionTab.tsx`) is read-only and has no surfaces
  list. Built from `endpoint` by `connectionTarget`, it shows a **Route** heading with a one-line
  description of the route under it, then a Field / Value table styled like the Agent Card's
  **Changes by the gateway** table (`agent-preview-changes`; the target rows; a URL endpoint has a
  copy button). It has no route path diagram. Under it, an **Identities** section
  (`agent-connection-identities`) lists every DID in `identities` in the same table style:
  Identity (the shortened DID with the full one as tooltip and a copy button, local to
  `ConnectionTab.tsx`) and Source (**Surface DID** or **Managed identity**); without any it says
  no surface using the agent has a DID. Then a **Trust registry** section
  (`agent-connection-trust-registry`) lists `trust_registry.registries` in the same table style:
  Trust registry (name, else id; links to the registry page only with `trust_registries.edit`),
  Identity (the same DID cell) and Status (`TrustRecorderStateBadge`, with the reason text under it).
  Without outcomes it says no identity was sent to a trust registry. The Agents API fills
  `registries` on the details only: the best outcome per (registry, DID) across the agent's
  surfaces, for its current identities.
  The API
  returns a URL endpoint without credentials, query string or fragment, and `connectionTarget`
  drops any that arrive; there is no "hidden" note. An endpoint whose host is `redacted.invalid`
  (the API could not strip its credentials) shows **Can't be shown** (`agent-connection-endpoint`),
  like any endpoint `connectionTarget` cannot parse. An
  `a2a-proxy://` or `fabric://` target shows the A2A proxy or remote gateway by its name
  (`target_name`, plain text, with the id as its tooltip), or by its
  id when the API returns no name. It links to the A2A proxy or remote gateway page only when
  the viewer has `a2a_proxies.edit` or `gateways.edit`, which those pages need; otherwise it is
  plain text.
- The Agent Card is untrusted: render it as plain text only (no HTML, Markdown or links). The tab
  opens on a visual **Preview**
  (`AgentDetailPage/AgentCardPreview.tsx`, reading known A2A card fields defensively, with the URL
  as text) and toggles to the raw **JSON**. The toggle follows `VpViewer`: `AppButton`s with an icon
  and a label (`fa-eye` Preview, `fa-code` JSON), `primary` when active and `outline-secondary`
  otherwise. The copy button shows in the JSON view only, inside it: right-aligned on its own row
  above the JSON, never in the toggle row or over the scrolling JSON. It looks like `VpViewer`'s
  copy button: an `outline-secondary` `AppButton` with `fa-copy` and "Copy", switching to a green
  `fa-check` and "Copied" for two seconds. The Preview sits directly in the tab's
  card body, with no inner card or "Agent Card" label, then a **Skills** section
  (`agent-card-preview-skills`, a heading with the count, then each skill's name and description).
- After Skills, the Preview ends with **Changes by the gateway** (`agent-card-gateway-changes`,
  `AgentDetailPage/gatewayChanges.ts`), a `table-sm` of what the gateway changed, compared with
  the API's `upstream_card`, with columns **Field**, **Change** and **Value**. **Change** is a
  badge (`<row>-change`): **Rewritten** (`text-bg-warning`) when the field existed before,
  **Added** (`text-bg-primary`) when it did not, **Removed** (`text-bg-secondary`) when the
  served card dropped it. **Value** (`<row>`) is what callers get, in regular-weight code, `-` when
  missing; a rewritten or removed one has a muted "Was <value>" line under it, its code muted too
  so the new value stands out (`<row>-was`), an added one none. `code` in `agent-preview-changes`
  cells is `inline-block` so wrapped chips don't overlap. Rows:
  the URL first (`-url`), then each extension the upstream card lacks or carries differently
  (`-extension`; paired with the next upstream extension the served card dropped, which is its
  "Was"; the identity-credential extension reads **Identity credential**), each followed by a
  **DID** row (`-did`) when its `params.did` differs from the paired extension's, and a
  **Verifiable Presentation** row (`-vp`) when it carries `params.verifiablePresentation`. That
  row's **Show** / **Hide** button (`-vp-toggle-button`, `aria-expanded`) expands the
  presentation in a row under it spanning all three columns (`-vp-view`), never in a modal, with `VpViewer`'s `VpView` (Readable /
  Raw JSON, Copy in Raw JSON). Then each dropped upstream extension no added one replaces
  (`-removed`), and each other changed top-level field, JSON for a non-string (`-other-<field>`).
  With no `upstream_card` (a generated card) only the identity-credential extension is listed.
  The table's borders use the section divider colour (`--gray-200`, `--dark-border` in the dark
  theme) and the Field column the heading colour, in both themes. Field cells are `td`
  (`.agent-preview-change-field`), never `th`, since the global `.table-sm th` rule gives every
  `th` a light background, uppercase text and a 2px border. A served card with no identity-credential
  extension adds a muted line under the table (`-no-did`): "This surface has no DID, so the card
  carries no identity credential." Nothing changed, no section. While the URL is listed here, the
  card details above leave out their **URL** row.
- The JSON view highlights the card with `VpViewer`'s tokenizer (`tokenizeJson`) in the
  `.vp-json-pre` style, wrapping long values (`.agent-card-json`).
- The Agent Card tab shows the card the gateway serves, for every route, read through one surface.
  Its header (`agent-card-source`, `data-source`) reads "Served by <surface> · <source>": the
  surface is the API's `surface_id`, named from the agent's surfaces, as a `SurfaceLinkButton`
  to `/surfaces/<id>` (`agent-card-surface`), or a `FormSelect` (`agent-card-surface-select`)
  over `card_surface_ids` when there are several, followed by an **Open surface** link to the
  selected one (`agent-card-open-surface-button`); choosing one reloads the card with
  `?surface_id=`, and an earlier answer is ignored. The source
  (`agent-card-source-text`) maps the API's `source`: `fetched` **Fetched & rewritten by the
  gateway** (Direct), `generated` **Generated by the A2A proxy** (Proxied), `remote_gateway`
  **Relayed from the remote gateway** (Fabric); an unknown or missing one is left out. A `404`
  with code `surface_unavailable` for a chosen surface (it isn't running on this gateway, or is
  no longer one of the card surfaces) keeps the select, with the previous answer's
  `card_surface_ids`, above "The Agent Card can't be read through this surface on this gateway"
  (`agent-card-surface-unavailable`) and a **Retry** (`agent-card-surface-retry-button`) that
  reads it through the same surface again. Any other failure, a plain `404` (the agent is gone)
  or a `404` with no surface chosen is the load error. `not_running` reads "None of this
  agent's surfaces is running on this gateway".
- Activity and traffic exist only inside the metrics retention window, so labels name it
  (`None in last 6h`, `Requests (last 6h)`) from the `window_minutes` that `GET /v1/agents` and
  `GET /v1/agents/{id}` (`traffic.window_minutes`) return. There is no 7-day card.
  **Failed requests** is `failed` + `gateway_faults`. Traffic counts Access Point (inbound)
  requests only, each once (a forwarded call's response record is not counted again); Transit
  Point (outbound) calls are not counted.
- With no requests in the window, the Traffic tab shows one `EmptyState`, "No requests in the last
  6h" (`agent-traffic-empty`), in place of the cards.
- The API returns agent totals only, so the Traffic tab has no per-surface breakdown.

| Element                         | Test id                                                                                         |
| ------------------------------- | ----------------------------------------------------------------------------------------------- |
| Pages                           | `page-agents`, `page-agent-details`                                                             |
| List row, chevron               | `agents-row-<id>`, `agents-row-chevron`                                                         |
| List filter, count, retry       | `agents-filter-input`, `agents-count`, `agents-retry-button`                                    |
| List load error, no match       | `agents-load-error`, `agents-no-match`                                                          |
| Empty state add surface         | `agents-add-surface-link`                                                                       |
| Name, unnamed, endpoint host    | `agents-name`, `agents-unnamed`, `agents-endpoint-host`                                         |
| Runtime, protocol, activity     | `agents-runtime`, `agents-protocol-badge`, `agents-last-activity`                               |
| Surfaces, count, names          | `agents-surfaces`, `agents-surfaces-count`, `agents-surface-names`                              |
| Identities, count, none         | `agents-identities`, `agents-identities-count`, `agents-no-identity`                            |
| Details DID, copy               | `agents-did`, `agents-copy-did-button`                                                          |
| Details identities, row, none   | `agent-connection-identities`, `agent-connection-identity`, `agent-connection-identities-empty` |
| Trust registry                  | `agents-trust-recorded`, `agents-trust-not-recorded`                                            |
| Back, details retry             | `agent-back-button`, `agent-retry-button`                                                       |
| Details not found, load error   | `agent-not-found`, `agent-load-error`                                                           |
| Details header                  | `agent-details-header`, `-name`, `-endpoint-host`                                               |
| Details tabs                    | `agent-details-tabs`, `agent-tab-<agent-card\|connection\|traffic>`                             |
| Agent Card states               | `agent-card-tab`, `-loading`, `-error`, `-retry-button`, `agent-card-<no_agent_card\|not_running\|operator_only>`, `agent-card-surface-unavailable`, `agent-card-surface-retry-button` |
| Agent Card source               | `agent-card-source`, `-source-text`, `agent-card-surface`, `agent-card-surface-select`, `agent-card-open-surface-button` |
| Changes by the gateway          | `agent-card-gateway-changes`, `-no-did`; rows `-url`, `-extension`, `-did`, `-vp`, `-removed`, `-other-<field>`, each with `-change` and `-was`; `-vp-toggle-button`, `-vp-view` |
| Agent Card JSON, copy           | `agent-card-json`, `agent-card-copy-button`                                                     |
| Agent Card view toggle, preview | `agent-card-view-preview`, `-view-json`, `agent-card-preview`, `-preview-name`, `-preview-details`, `-preview-skills`, `-preview-empty` |
| Traffic cards, empty            | `agent-traffic-tab`, `agent-traffic-requests`, `-failed`, `-p95`, `agent-traffic-empty` |
| Connection                      | `agent-connection-tab`, `-description`, `-endpoint`, `-copy-endpoint`, `-proxy`, `-proxy-link`, `-gateway`, `-gateway-link`, `-remote-surface` |
| Connection trust registry       | `agent-connection-trust-registry`, `-trust-registry-empty`, `agent-connection-registry-<registry-id>` |

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
  gated: its sidebar entry and `/x402payments` need only
  `payments.view`, so the ledger and the legacy x402/MPP list stay readable with the flag off;
  only its empty state changes, naming the flag instead of the Payment element.
  Like `mediator_federation`, it is
  system-only: a user's own flag overrides never change it, so the UI always matches the gateway,
  which refuses to add a payment gateway while it is off. The gateway turns it on at startup when a
  payment gateway already exists and no operator has set it either way. The Connections permission
  list (`connectionsPermissions`) is shared by the route and the sidebar. When the settings cannot
  be loaded, `FALLBACK_SETTINGS` (every flag off) is used so the pages waiting for them render.
- `policy_input_capture` (`settings-flag-policy_input_capture`) is default off and lets users
  with `surfaces.edit` and `policies.edit` listen to a surface's policy input on its Capture
  view (see _Policy input capture_). Read it through `utils/featureFlags.ts`
  (`policyInputCaptureEnabled`, `usePolicyInputCaptureFlag`), never inline. The gateway checks the
  same system flag: it refuses a listen while the flag is off and stops every listen at the next
  keep-alive check after it is turned off.
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
  `icon_emoji`, no channel; stream SASL only for Kafka, no AWS keys. Every Kafka endpoint shows
  **Security protocol** (`plaintext`, `ssl`, `sasl_plaintext` or `sasl_ssl`, default
  `plaintext`), which replaced the Authentication select; a SASL protocol adds **SASL
  mechanism** (`PLAIN`, `SCRAM-SHA-256` or `SCRAM-SHA-512`, default `PLAIN`), the username and
  the password. A stored endpoint shows its `security_protocol`; one without it shows what the
  gateway uses (`sasl_plaintext` for the older `auth_type: sasl` with a username, otherwise
  `plaintext`, through the field's `legacyValue`), and a save writes `security_protocol` and no
  `auth_type`, so every configuration the API accepts saves back unchanged. Each field is
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

- The **About the Audit Log** panel (`AuditInfoBanner`) lists the delegation events the gateway
  audits in one **Credential delegation** bullet (`consent_granted`, `consent_expired`,
  `consent_limited`, `token_revoked`, `user_tokens_revoked`) and says that what the gateway does
  with a delegated credential on each call is not audited but written to the gateway log, unless
  `[logging] delegation_events` is `false`. It names no per-call event as an audit event.
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
- Its **Storage** section explains the size shown above the table: the live log plus every
  rotated file, rotated at `vp_audit_log_max_bytes`, with every rotated file kept by default
  so nothing is deleted. It states that `vp_audit_log_soft_cap_bytes` is advisory — passing it
  deletes nothing and refuses no write — and that bounding the history means setting
  `vp_audit_log_keep`, which does delete the records that fall out of the window. The panel is
  where that is explained, because the bar itself carries no copy beyond the two actions.

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
- **Identities table**: up to eleven columns, so `.identities-table` (`dashboard.css`) keeps
  Bootstrap's `table-sm` horizontal cell padding (0.25rem) instead of the 0.75rem of the
  shared `.table-sm` rules. The Name (`.identities-name`, 14rem) and Agent Surface
  (`.identities-surface`, 12rem) cells wrap long values inside a capped width; the Origin badges
  wrap. Attestation, UAI and Created (`.identities-col-wide-only`) show only at 2000px wide and
  above. Below 1600px, Trust Score and Last Used (`.identities-col-mid-up`) hide too, and the
  DID cell (`IdentityNameCell` with `compactDid`) shows a shorter DID. The expanded details always
  show Created, Last Used and the Trust Score (`identities-detail-trust-score`), and for an
  identity without Agent DNA its UAI (`identities-detail-uai`); with Agent DNA the Agent DNA
  card shows the UAI. The table fits its box from the 1280px viewport that
  `laptop-layout.spec.ts` checks up to the 1512px and 1728px laptop viewports, with every row
  action inside it; the DID keeps its title and copy button.
- **Connection Points actions**: the row actions sit in a 6rem wide wrapping block (two
  buttons per line) with no left margins, so the Actions column stays near 120px and the
  Name and Mediator columns keep their room. Add a new row action inside that block.

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
