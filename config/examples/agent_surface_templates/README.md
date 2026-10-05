# Agent Surface Templates

This folder holds **starter and partial templates** for the agent-surface
builder. Each `.json` file is a surface-template document that the gateway
seeds into its template store on startup. The dashboard's _Create Surface_
picker and _Templates_ panel read from that store via the REST API.

## How the gateway loads this folder

1. On boot, the orchestrator reads `[config_files] agent_surface_templates_dir`
   from `config.toml`. Path is resolved relative to the config dir unless
   absolute. Example:
   ```toml
   [config_files]
   agent_surface_templates_dir = "agent_surface_templates"
   ```
2. Every `*.json` file in that directory is parsed and written to the
   runtime template store at `[storage_paths] agent_surface_templates`
   (default `_storage/agent_surface_templates/`). Files with any other
   extension (e.g. `README.md`) are ignored.
3. Each seeded template is stamped with `builtin: true` so the REST API
   refuses to delete or overwrite it. An admin who edits a builtin via
   the API flips that flag to `false`, after which the seeder leaves the
   on-disk copy alone (admin-owned fork).
4. **Storage filename is `{id}.json`**, derived from the template's
   `id` field — _not_ the source filename. Two files with the
   same `id` will collide; only the last one seeded survives.

See [`src/surface_templates/filesystem.rs`](../../../src/surface_templates/filesystem.rs)
and [`src/server/orchestrator.rs`](../../../src/server/orchestrator.rs) for
the loader, and [`src/surface_templates/types.rs`](../../../src/surface_templates/types.rs)
for the on-the-wire schema.

## File layout

```
config/examples/agent_surface_templates/
  full_*.json       # kind: "full"    — complete surface snapshot
  partial_*.json    # kind: "partial" — bundle of elements to drop in
  README.md
```

The `full_*` / `partial_*` filename prefix is **purely a convention**
for human readers; the gateway only looks at the JSON `kind` field.

## Schema (common fields)

```jsonc
{
  "$schema": "https://fabric.affinidi.io/schemas/surface-template/v1.json",
  "id": "<unique uuid>",          // REQUIRED, must be unique across all templates
  "name": "Short Display Name",   // shown in lists
  "kind": "full" | "partial",     // default: "partial"
  "description": "One-liner shown beside the title.",
  "details": "Longer markdown / plain text shown when expanded.",
  "icon": "rocket",               // FontAwesome name without the `fa-` prefix
  "tags": ["a2a", "starter", "full"],
  "author": "system",             // "system" for builtins; user/DID otherwise
  "builtin": true,                // server-managed; set true for shipped seeds
  "sort_priority": 10,            // OPTIONAL: lower sorts first in UX lists
                                  // (templates tab + create-surface picker).
                                  // Defaults to i32::MAX so unset items
                                  // sink to the bottom; ties tie-break on
                                  // case-insensitive name.

  // kind: "partial" -------------------------------------------------
  "items": [ /* TemplateItem[] */ ],

  // kind: "full" ----------------------------------------------------
  "surface": { /* AgentSurface-equivalent JSON */ }
}
```

### `kind: "partial"` — `items[]`

Each item drops a single element onto an existing canvas via the
placement engine. Shape:

```jsonc
{
  "scope": "surface" | "target" | "access_point" | "transit_point"
         | "gateway_policy" | "channel_policy" | "edge",
  "kind": "agent_identity",       // matches a frontend element registry kind
  "address": "access-point->target/request", // required for scope: "edge"
  "config": { /* partial config deep-merged onto element defaults */ }
}
```

Empty fields stay empty so the canvas validator can highlight them for
the user to fill in.

### `kind: "full"` — `surface`

The whole `AgentSurface` JSON the REST API accepts (`access_point`,
`target`, `canvas`, etc.), optionally containing placeholder tokens
that the dashboard substitutes at apply time:

| Token              | Substitution                                                   |
| ------------------ | -------------------------------------------------------------- |
| `$HOST`            | This gateway's outward listen address.                         |
| `$ROUTE`           | A free `/path` from the gateway's routing config.              |
| `$NAME`            | Stripped before apply — the user types a name on the wizard.   |
| `$SLUG`            | Slugified `$NAME` (deferred until the user names the surface). |
| `$TARGET_ENDPOINT` | Left blank for the user to fill in.                            |

Unresolved tokens are blanked out so the marching-ants validator can
flag them. Tagging a `full` template with `"starter"` makes it appear in
the _Create Surface_ picker overlay.

### Volatile fields blanked on apply

The placeholder vocabulary intentionally has no per-transit-point
tokens (a surface can hold many TPs). To prevent two surfaces created
from the same starter from clashing on listener routes or TP
identities, the dashboard **always** blanks the following fields when
it loads a full template — whether or not they contain tokens:

- `transit.points[*].listen_address`
- `transit.points[*].listen_path`
- `transit.points[*].id`
- `transit.points[*].alias`
- `canvas.nodes[*].config.{listen_address,route,route_prefix,route_suffix}` for the access-point node
- `canvas.nodes[*].config.{listen_address,listen_path,route_prefix,route_suffix,id,alias}` for any `transit-point-*` node

The Transit Point factory regenerates fresh `id` / `alias` values on
save, and the user fills in unique listener routes via the panel. The
same scrubber also runs when a surface is saved as a template via the
dashboard so authored templates never bake in environment-specific
listener paths.

### Save-as-template tokenization

When the user saves a live surface as a `full` template from the
dashboard, the pipeline is:

1. **Always** strip gateway-runtime fields (`surface_id`,
   `last_activity`, `agent_did`).
2. **Always** scrub volatile per-surface fields (see the list above)
   — the TPs have no scalar token vocabulary, so their listener
   `listen_address` / `listen_path` / `id` / `alias` are simply
   blanked. The form reports how many TPs were affected so the user
   knows those routes will need to be re-entered on apply.
3. Optionally (controlled by the _Tokenize_ toggle, default on)
   replace the four AP-level scalars with their placeholders:
   `name → $NAME`, `access_point.listen_address → $HOST`,
   `access_point.route → $ROUTE`, `target.endpoint → $TARGET_ENDPOINT`.

Turning the toggle off only suppresses step 3 — steps 1 and 2 are
structural and always run, because a template that leaks a TP
listener route or a runtime `surface_id` is always wrong.

See [`tokenizeSnapshot.ts`](../../../www/default/src/components/surface-builder/templates/tokenizeSnapshot.ts)
for the implementation.

A final pre-flight check rejects payloads that contain two listeners
sharing the same `(listen_address, route|listen_path)` tuple — see
`findDuplicateListenerRoutes` in
[`scrubVolatile.ts`](../../../www/default/src/components/surface-builder/templates/scrubVolatile.ts).

## Authoring a new template

1. Copy one of the existing `full_*.json` or `partial_*.json` files in
   this folder as a starting point.
2. Generate a fresh UUID for `id` (e.g. `uuidgen`). Reuse will silently
   overwrite an existing template at boot.
3. Update `name`, `description`, `details`, `icon`, `tags`.
4. For `kind: "full"`, add `"starter"` to `tags` if you want it in the
   create-surface picker.
5. Drop the file into the gateway's
   `[config_files] agent_surface_templates_dir` (e.g.
   `envs/local/config/agent_surface_templates/`).
6. Restart the gateway. The new template appears in the dashboard once
   it is back up.

## Updating shipped templates

The seeder re-writes an on-disk template only when:

- the persisted copy still has `builtin: true`, **and**
- its byte-for-byte serialization differs from the source `.json`.

If an admin has adopted a builtin (flipped `builtin: false` via the
REST API), the seeder leaves the persisted copy alone — to roll out a
fresh version you must delete the persisted `{id}.json` and restart.

## Deleting a template

Removing a source `.json` file does **not** purge the corresponding
`{id}.json` from `_storage/agent_surface_templates/`. Delete it via
the REST API (`DELETE /v1/surface-templates/{id}`) or by removing the
storage file directly and restarting.
