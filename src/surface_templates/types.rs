//! Types for surface templates.
//!
//! A [`SurfaceTemplate`] is a flat list of [`TemplateItem`]s. Each item
//! has a [`Scope`] tag the placement engine uses to route it onto the
//! correct surface anchor.

use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// Scope tag attached to every template item, telling the placement
/// engine where on the surface to anchor the item.
///
/// Kept as a string-typed enum with `#[serde(rename_all = "snake_case")]`
/// so JSON files stay readable. Unknown future scopes deserialize via
/// [`Scope::Other`] so old gateways can still load newer templates.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum Scope {
    Known(KnownScope),
    /// Forward-compat catch-all for scopes added in future template
    /// versions. The placement engine on older clients can choose to
    /// skip these instead of failing the import.
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KnownScope {
    /// Surface root (`target.*` + top-level fields).
    Surface,
    /// `target.*` anchor (agent_identity, identity_injection, ...).
    Target,
    /// The access-point node.
    AccessPoint,
    /// A new transit point appended to `transit.points`.
    TransitPoint,
    /// Gateway-level OPA policy block.
    GatewayPolicy,
    /// Channel-level OPA policy block.
    ChannelPolicy,
    /// Edge-bound items addressed as `edge:<from>:<to>`. The endpoint
    /// names are template-local (`access_point`, `transit_point[n]`,
    /// `target`).
    Edge,
}

/// A single item in a template. `kind` matches an element kind in the
/// frontend registry (e.g. `agent_identity`, `policy`, `rate_limit`);
/// `config` is a partial JSON payload merged onto the placed element.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateItem {
    pub scope: Scope,
    pub kind: String,
    /// Optional address detail used when `scope` needs more than the
    /// tag alone — e.g. `edge` items use `address = "access_point->target"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Partial configuration applied to the placed element. The
    /// placement engine deep-merges this onto the default config; empty
    /// fields stay empty so the marching-ants validator can flag them.
    #[serde(default)]
    pub config: serde_json::Value,
}

/// Template kind discriminator.
///
/// * `Partial` (default) — bundle of incremental [`TemplateItem`]s the
///   placement engine drops onto an existing canvas.
/// * `Full` — verbatim channel snapshot under [`SurfaceTemplate::channel`].
///   The dashboard applies these by replacing the current pipe
///   wholesale. The gateway treats `channel` as opaque JSON; only the
///   dashboard knows its schema and placeholder vocabulary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TemplateKind {
    #[default]
    Partial,
    Full,
}

fn default_sort_priority() -> i32 {
    i32::MAX
}

/// A reusable bundle of pre-configured surface items.
///
/// Persisted one file per id under the agent_surface_templates storage path.
/// `builtin: true` files are seeded from `config/agent_surface_templates/`
/// at first boot and are read-only via the REST API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceTemplate {
    /// Optional JSON schema URI for forward compatibility.
    #[serde(default, rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    /// Stable identifier. Server-minted on create — clients submit
    /// templates through [`CreateSurfaceTemplate`] (no `id` field) and
    /// receive the assigned id on the response.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub name: String,
    /// Partial (default) or full. Old files without this field
    /// continue to parse as partial.
    #[serde(default)]
    pub kind: TemplateKind,
    /// Short one-liner shown in the template list.
    #[serde(default)]
    pub description: String,
    /// Long-form explanation shown when the template row is expanded.
    /// Plain text or markdown — the UI renders it as plain text today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Body text for the welcome callout shown on the canvas the
    /// first time the user lands on a surface created from this
    /// template. The dashboard renders it inside its own balloon
    /// frame (title + dismiss + "don't show again" are added
    /// automatically) so this field is just the contextual hint.
    /// When absent, the callout falls back to the dashboard's
    /// generic default text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub starter_hint: Option<String>,
    /// FontAwesome icon name (without the `fa-` prefix, e.g. `id-badge`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// `"system"` for builtins, otherwise the author DID / user id.
    #[serde(default)]
    pub author: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Server-set. Builtins are immutable through the REST API.
    #[serde(default)]
    pub builtin: bool,
    /// Optional UX hint controlling display order. Lower values sort
    /// first; ties fall back to alphabetical by name. Defaults to
    /// `i32::MAX` so templates without an explicit priority sink to
    /// the bottom of any sorted list.
    #[serde(default = "default_sort_priority")]
    pub sort_priority: i32,
    /// Items for `kind: Partial` templates. Empty for full templates.
    #[serde(default)]
    pub items: Vec<TemplateItem>,
    /// Opaque surface snapshot for `kind: Full` templates. Same shape
    /// the surface REST API accepts (`AgentSurface`-equivalent payload,
    /// including any variants stored under the access_point node).
    /// May contain placeholder tokens (`$HOST`, `$ROUTE`, `$NAME`,
    /// `$SLUG`, `$TARGET_ENDPOINT`) that the dashboard substitutes at
    /// apply time. The gateway never inspects this — it's a passthrough.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface: Option<serde_json::Value>,
}

impl StorableEntity for SurfaceTemplate {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Request body for `POST /v1/surface-templates`.
///
/// Mirrors the editable subset of [`SurfaceTemplate`]. The `id` field
/// is deliberately absent (and rejected via `deny_unknown_fields`) so
/// the frontend cannot influence template ids — the server mints a
/// `user-<uuid>` id on every create. Other server-managed fields
/// (`author`, `created_at`, `updated_at`, `builtin`) are also rejected
/// for the same reason.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSurfaceTemplate {
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default, rename = "$schema")]
    pub schema: Option<String>,
    pub name: String,
    #[serde(default)]
    pub kind: TemplateKind,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub details: Option<String>,
    #[serde(default)]
    pub starter_hint: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_sort_priority")]
    pub sort_priority: i32,
    #[serde(default)]
    pub items: Vec<TemplateItem>,
    #[serde(default)]
    pub surface: Option<serde_json::Value>,
}

impl CreateSurfaceTemplate {
    /// Build a fully-populated [`SurfaceTemplate`] from this request,
    /// minting a server-side id and stamping `created_at` / `updated_at`.
    pub fn into_template(
        self,
        id: String,
        now: String,
    ) -> SurfaceTemplate {
        SurfaceTemplate {
            schema: self.schema,
            id,
            tenant_id: self.tenant_id,
            name: self.name,
            kind: self.kind,
            description: self.description,
            details: self.details,
            starter_hint: self.starter_hint,
            icon: self.icon,
            tags: self.tags,
            author: String::new(),
            created_at: Some(now.clone()),
            updated_at: Some(now),
            builtin: false,
            sort_priority: self.sort_priority,
            items: self.items,
            surface: self.surface,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_scope_roundtrip() {
        let item = TemplateItem {
            scope: Scope::Known(KnownScope::Target),
            kind: "agent_identity".to_string(),
            address: None,
            config: serde_json::json!({ "did": "did:example:abc" }),
        };
        let json = serde_json::to_string(&item).unwrap();
        let back: TemplateItem = serde_json::from_str(&json).unwrap();
        assert_eq!(back.scope, Scope::Known(KnownScope::Target));
        assert_eq!(back.kind, "agent_identity");
        assert_eq!(back.config["did"], "did:example:abc");
    }

    #[test]
    fn unknown_scope_deserializes_to_other() {
        let json = r#"{ "scope": "future_anchor", "kind": "x" }"#;
        let item: TemplateItem = serde_json::from_str(json).unwrap();
        assert_eq!(item.scope, Scope::Other("future_anchor".to_string()));
    }

    #[test]
    fn template_roundtrip_preserves_builtin_flag() {
        let tpl = SurfaceTemplate {
            schema: Some("https://example.com/v1".to_string()),
            id: "builtin-agent-identity-binding".to_string(),
            tenant_id: None,
            name: "Agent Identity Binding".to_string(),
            kind: TemplateKind::Partial,
            description: "test".to_string(),
            details: None,
            starter_hint: None,
            icon: Some("id-badge".to_string()),
            tags: vec!["identity".to_string()],
            author: "system".to_string(),
            created_at: None,
            updated_at: None,
            builtin: true,
            sort_priority: i32::MAX,
            items: vec![TemplateItem {
                scope: Scope::Known(KnownScope::Target),
                kind: "agent_identity".to_string(),
                address: None,
                config: serde_json::json!({}),
            }],
            surface: None,
        };
        let json = serde_json::to_string(&tpl).unwrap();
        let back: SurfaceTemplate = serde_json::from_str(&json).unwrap();
        assert!(back.builtin);
        assert_eq!(back.items.len(), 1);
        assert_eq!(back.tags, vec!["identity".to_string()]);
        assert_eq!(back.kind, TemplateKind::Partial);
        assert!(back.surface.is_none());
    }

    #[test]
    fn legacy_template_without_kind_defaults_to_partial() {
        let json = r#"{
            "id": "old-tpl",
            "name": "Old",
            "items": []
        }"#;
        let tpl: SurfaceTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.kind, TemplateKind::Partial);
        assert!(tpl.surface.is_none());
    }

    #[test]
    fn missing_sort_priority_defaults_to_i32_max() {
        // Templates authored before `sort_priority` shipped must keep
        // parsing — the loader defaults them to `i32::MAX` so they sort
        // last in any UX list.
        let json = r#"{ "id": "x", "name": "X", "items": [] }"#;
        let tpl: SurfaceTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.sort_priority, i32::MAX);
    }

    #[test]
    fn explicit_sort_priority_is_preserved_through_roundtrip() {
        let json = r#"{ "id": "x", "name": "X", "items": [], "sort_priority": 42 }"#;
        let tpl: SurfaceTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.sort_priority, 42);
        let back: SurfaceTemplate = serde_json::from_str(&serde_json::to_string(&tpl).unwrap()).unwrap();
        assert_eq!(back.sort_priority, 42);
    }

    #[test]
    fn full_template_carries_opaque_surface_blob() {
        let json = r#"{
            "id": "builtin-mtls-a2a",
            "name": "mTLS A2A",
            "kind": "full",
            "surface": {
                "access_point": {
                    "listen_address": "$HOST",
                    "route": "$ROUTE"
                },
                "target": { "endpoint": "$TARGET_ENDPOINT" },
                "name": "$NAME",
                "canvas": { "variants": [{ "alias": "v1" }] }
            }
        }"#;
        let tpl: SurfaceTemplate = serde_json::from_str(json).unwrap();
        assert_eq!(tpl.kind, TemplateKind::Full);
        assert!(tpl.items.is_empty());
        let surface = tpl
            .surface
            .clone()
            .expect("surface snapshot must round-trip");
        assert_eq!(surface["access_point"]["listen_address"], "$HOST");
        assert_eq!(surface["canvas"]["variants"][0]["alias"], "v1");
        // Re-serialize and re-parse to confirm passthrough is lossless.
        let reserialized = serde_json::to_string(&tpl).unwrap();
        let back: SurfaceTemplate = serde_json::from_str(&reserialized).unwrap();
        assert_eq!(back.kind, TemplateKind::Full);
        assert_eq!(back.surface.unwrap()["access_point"]["route"], "$ROUTE");
    }
}
