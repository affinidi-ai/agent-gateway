//! Proxy module for channel management and server operations

pub mod agent_card_cache;
pub mod backend_identity;
pub mod caller_identity;
pub mod channel_logging;
pub mod credential_delegation;
pub mod fabric_forward;
pub mod fabric_identity;
pub(crate) mod fabric_response_waiter;
pub(crate) mod fabric_stream;
pub mod handler;
pub mod outbound_handler;
pub mod paths;
pub mod protocol_router;
pub mod response_policy;
pub mod route_variant;
pub mod rules_engine;
pub mod server;
pub mod surface_manager;
pub mod trace;
pub mod transit_token;
pub(crate) mod upstream_body;
pub mod workload_binding;

pub use protocol_router::*;
pub use rules_engine::*;
pub use surface_manager::SurfaceTaskManager;

// ── Shared identity engine compilation ──────────────────────────────────────

/// Compiled identity engines (rules engine + selector) for a channel or variant.
///
/// `rules_engine` / `selector` are the channel-wide engines used by the legacy
/// inbound MCP/A2A path (`protocols/extensions.rs`) and by the response-side
/// `resolve_agent_identity_for_slot` when no slot-specific override exists.
///
/// `protected_*` / `external_*` are per-slot overrides built from
/// `channel.identity_slots.protected` / `identity_slots.external`. When set,
/// the response-side resolver should prefer them so each slot enforces its own
/// JSON schema and rules independently.
pub struct CompiledIdentityEngines {
    pub rules_engine: Option<std::sync::Arc<RulesEngine>>,
    pub selector: Option<std::sync::Arc<crate::identity::IdentitySelector>>,
    pub protected_rules_engine: Option<std::sync::Arc<RulesEngine>>,
    pub protected_selector: Option<std::sync::Arc<crate::identity::IdentitySelector>>,
    pub external_rules_engine: Option<std::sync::Arc<RulesEngine>>,
    pub external_selector: Option<std::sync::Arc<crate::identity::IdentitySelector>>,
}

/// Compile identity engines from a surface's identity configuration. Reads
/// the three identity slots straight off `AgentSurface.identity_slots`. The surface has
/// no top-level `managed_identity` field — that was a `ChannelMapping`-only
/// legacy slot — so the channel-wide engine here falls back through
/// `inbound → protected → external` only.
///
/// Per-slot engines (`protected_*`, `external_*`) are compiled independently
/// so each slot keeps its own schema and rules.
pub fn compile_identity_engines_from_surface(
    surface: &crate::config::agent_surface::AgentSurface,
    vc_issuer: Option<&std::sync::Arc<crate::identity::VCIssuer>>,
) -> anyhow::Result<CompiledIdentityEngines> {
    // Synthesize the legacy `managed_identity` channel-wide slot from the
    // surface's `target.identity_injection` so that surfaces produced by
    // `AgentSurface::from_channel_mapping` (which lifts
    // `ChannelMapping.managed_identity` into `target.identity_injection`)
    // continue to compile channel-wide engines equivalently. This keeps
    // the surface compiler at full parity with `compile_identity_engines`
    // for round-trip surfaces.
    let synthesized_managed_identity = crate::config::agent_surface_compat::identity_injection_to_managed_identity(
        &surface
            .target
            .identity_injection,
    );

    let channel_wide = synthesized_managed_identity
        .as_ref()
        .or(surface
            .identity_slots
            .inbound
            .as_ref())
        .or(surface
            .identity_slots
            .protected
            .as_ref())
        .or(surface
            .identity_slots
            .external
            .as_ref());

    let base = match channel_wide {
        Some(mi) => compile_identity_engines_from_managed_identity(mi, vc_issuer)?,
        None => CompiledIdentityEngines {
            rules_engine: None,
            selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
        },
    };

    let protected = match surface
        .identity_slots
        .protected
        .as_ref()
    {
        Some(mi) => compile_identity_engines_from_managed_identity(mi, vc_issuer)?,
        None => CompiledIdentityEngines {
            rules_engine: None,
            selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
        },
    };

    let external = match surface
        .identity_slots
        .external
        .as_ref()
    {
        Some(mi) => compile_identity_engines_from_managed_identity(mi, vc_issuer)?,
        None => CompiledIdentityEngines {
            rules_engine: None,
            selector: None,
            protected_rules_engine: None,
            protected_selector: None,
            external_rules_engine: None,
            external_selector: None,
        },
    };

    Ok(CompiledIdentityEngines {
        rules_engine: base.rules_engine,
        selector: base.selector,
        protected_rules_engine: protected.rules_engine,
        protected_selector: protected.selector,
        external_rules_engine: external.rules_engine,
        external_selector: external.selector,
    })
}

/// Compile identity engines from a single `ManagedIdentityConfig`.
///
/// Used both for channel-wide engines (via `compile_identity_engines`) and
/// for per-virtual-channel overrides built from
/// `TransitPoint.managed_identity` at request-resolution time.
pub fn compile_identity_engines_from_managed_identity(
    mi: &crate::source_auth::ManagedIdentityConfig,
    vc_issuer: Option<&std::sync::Arc<crate::identity::VCIssuer>>,
) -> anyhow::Result<CompiledIdentityEngines> {
    let cfg = match mi {
        crate::source_auth::ManagedIdentityConfig::PayloadExtraction(cfg) => cfg,
        // Credential-derived modes (`from_mtls`, `from_api_key`,
        // `from_jwt_claim`) mint a DID from a peppered HMAC rather than from a
        // request body. They need a VCIssuer selector to issue the credential
        // but no payload schema, so build a selector with a permissive (empty)
        // schema. `static` is intentionally absent: it always resolves to a
        // pre-known `Bound` DID and never needs the issuer.
        crate::source_auth::ManagedIdentityConfig::FromMtls { .. }
        | crate::source_auth::ManagedIdentityConfig::FromApiKey { .. }
        | crate::source_auth::ManagedIdentityConfig::FromJwtClaim { .. } => {
            let selector = match vc_issuer {
                Some(issuer) => {
                    let sel = crate::identity::IdentitySelector::new(&serde_json::json!({}), issuer.clone())
                        .map_err(|e| anyhow::anyhow!("Failed to compile identity selector: {}", e))?;
                    Some(std::sync::Arc::new(sel))
                }
                None => None,
            };
            return Ok(CompiledIdentityEngines {
                rules_engine: None,
                selector,
                protected_rules_engine: None,
                protected_selector: None,
                external_rules_engine: None,
                external_selector: None,
            });
        }
        crate::source_auth::ManagedIdentityConfig::Static { .. } => {
            return Ok(CompiledIdentityEngines {
                rules_engine: None,
                selector: None,
                protected_rules_engine: None,
                protected_selector: None,
                external_rules_engine: None,
                external_selector: None,
            });
        }
    };

    let rules_engine = match cfg.extension_rules.as_ref() {
        Some(rules) => match RulesEngine::new(rules) {
            Ok(engine) => Some(std::sync::Arc::new(engine)),
            Err(e) => {
                return Err(anyhow::anyhow!("Failed to compile identity rules engine: {}", e));
            }
        },
        None => None,
    };

    // Prefer the slot-level JSON schema; fall back to the legacy
    // `extension_rules.json_schema` so previously persisted configs keep
    // their validation behavior. A selector is built whenever ANY schema
    // is present so `resolve_agent_identity_for_slot` can enforce it,
    // even when the schema declares no `x-identity` fields.
    let schema = cfg
        .json_schema
        .as_ref()
        .or_else(|| {
            cfg.extension_rules
                .as_ref()
                .and_then(|r| r.json_schema.as_ref())
        });

    let selector = match (vc_issuer, schema) {
        (Some(issuer), Some(json_schema)) => {
            let sel = crate::identity::IdentitySelector::new(json_schema, issuer.clone())
                .map_err(|e| anyhow::anyhow!("Failed to compile identity selector: {}", e))?;
            Some(std::sync::Arc::new(sel))
        }
        _ => None,
    };

    Ok(CompiledIdentityEngines {
        rules_engine,
        selector,
        protected_rules_engine: None,
        protected_selector: None,
        external_rules_engine: None,
        external_selector: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_auth::ManagedIdentityConfig;
    use crate::source_auth::models::PayloadExtractionConfig;
    use serde_json::json;
    use std::sync::Arc;

    fn base_test_surface() -> crate::config::agent_surface::AgentSurface {
        use crate::config::agent_surface::{AccessPoint, AgentSurface, SurfaceProtocol, Target};
        AgentSurface {
            name: "test-channel".to_string(),
            description: "Test".to_string(),
            access_point: AccessPoint {
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/surfaces/test".to_string(),
                protocol: SurfaceProtocol::A2a,
                ..Default::default()
            },
            target: Target {
                endpoint: "http://localhost:9000".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn surface_with_managed_identity(mi: ManagedIdentityConfig) -> crate::config::agent_surface::AgentSurface {
        let mut surface = base_test_surface();
        surface
            .target
            .identity_injection =
            crate::config::agent_surface_compat::managed_identity_into_identity_injection(Some(&mi), false);
        surface
    }

    #[tokio::test]
    async fn compile_builds_selector_from_top_level_json_schema() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(vc_issuer);
        let surface =
            surface_with_managed_identity(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                extension_uri: None,
                meta_field: "agentIdentity".to_string(),
                fields: vec![],
                json_schema: Some(json!({
                    "type": "object",
                    "required": ["model"],
                    "properties": {"model": {"type": "string"}}
                })),
                extension_rules: None,
                strip_raw_meta: false,
            }));

        let engines = compile_identity_engines_from_surface(&surface, Some(&issuer)).expect("compile should succeed");
        let selector = engines
            .selector
            .expect("selector should be built from top-level json_schema");

        assert!(
            selector
                .validate(&json!({"model": "gpt-4"}))
                .is_ok()
        );
        assert!(
            selector
                .validate(&json!({}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn compile_returns_no_selector_when_schema_is_absent() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(vc_issuer);
        let surface =
            surface_with_managed_identity(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                extension_uri: None,
                meta_field: "agentIdentity".to_string(),
                fields: vec![],
                json_schema: None,
                extension_rules: None,
                strip_raw_meta: false,
            }));

        let engines = compile_identity_engines_from_surface(&surface, Some(&issuer)).expect("compile should succeed");
        assert!(engines.selector.is_none());
        assert!(engines.rules_engine.is_none());
    }

    #[tokio::test]
    async fn compile_falls_back_to_inbound_slot_when_managed_identity_absent() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(vc_issuer);
        let mut surface = base_test_surface();
        surface.identity_slots.inbound = Some(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: vec![],
            json_schema: Some(json!({
                "type": "object",
                "required": ["model"],
                "properties": {"model": {"type": "string"}}
            })),
            extension_rules: None,
            strip_raw_meta: false,
        }));

        let engines = compile_identity_engines_from_surface(&surface, Some(&issuer)).expect("compile should succeed");
        let selector = engines
            .selector
            .expect("selector should be compiled from identity_slots.inbound fallback");
        assert!(
            selector
                .validate(&json!({"model": "gpt-4"}))
                .is_ok()
        );
        assert!(
            selector
                .validate(&json!({}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn compile_managed_identity_takes_precedence_over_slot() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(vc_issuer);
        let mut surface =
            surface_with_managed_identity(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                extension_uri: None,
                meta_field: "agentIdentity".to_string(),
                fields: vec![],
                json_schema: Some(json!({
                    "type": "object",
                    "required": ["legacy"],
                    "properties": {"legacy": {"type": "string"}}
                })),
                extension_rules: None,
                strip_raw_meta: false,
            }));
        surface.identity_slots.inbound = Some(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: vec![],
            json_schema: Some(json!({
                "type": "object",
                "required": ["slot"],
                "properties": {"slot": {"type": "string"}}
            })),
            extension_rules: None,
            strip_raw_meta: false,
        }));

        let engines = compile_identity_engines_from_surface(&surface, Some(&issuer)).expect("compile should succeed");
        let selector = engines
            .selector
            .expect("selector should be compiled");
        // Legacy schema requires "legacy"; if precedence were inverted this would fail.
        assert!(
            selector
                .validate(&json!({"legacy": "x"}))
                .is_ok()
        );
        assert!(
            selector
                .validate(&json!({"slot": "x"}))
                .is_err()
        );
    }

    #[tokio::test]
    async fn compile_builds_independent_protected_and_external_engines() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(vc_issuer);
        let mut surface = base_test_surface();
        surface
            .identity_slots
            .protected = Some(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: vec![],
            json_schema: Some(json!({
                "type": "object",
                "required": ["protected_field"],
                "properties": {"protected_field": {"type": "string"}}
            })),
            extension_rules: None,
            strip_raw_meta: false,
        }));
        surface
            .identity_slots
            .external = Some(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            extension_uri: None,
            meta_field: "agentIdentity".to_string(),
            fields: vec![],
            json_schema: Some(json!({
                "type": "object",
                "required": ["external_field"],
                "properties": {"external_field": {"type": "string"}}
            })),
            extension_rules: None,
            strip_raw_meta: false,
        }));

        let engines = compile_identity_engines_from_surface(&surface, Some(&issuer)).expect("compile should succeed");

        let protected = engines
            .protected_selector
            .expect("protected selector should be compiled from identity_slots.protected");
        let external = engines
            .external_selector
            .expect("external selector should be compiled from identity_slots.external");

        assert!(
            protected
                .validate(&json!({"protected_field": "x"}))
                .is_ok(),
            "protected selector accepts its own schema"
        );
        assert!(
            protected
                .validate(&json!({"external_field": "x"}))
                .is_err(),
            "protected selector rejects external schema fields"
        );
        assert!(
            external
                .validate(&json!({"external_field": "x"}))
                .is_ok(),
            "external selector accepts its own schema"
        );
        assert!(
            external
                .validate(&json!({"protected_field": "x"}))
                .is_err(),
            "external selector rejects protected schema fields"
        );
    }

    #[tokio::test]
    async fn compile_omits_per_slot_engines_when_slots_unconfigured() {
        let (vc_issuer, _tmp) = crate::identity::test_helpers::test_vc_issuer().await;
        let issuer = Arc::new(vc_issuer);
        let surface =
            surface_with_managed_identity(ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                extension_uri: None,
                meta_field: "agentIdentity".to_string(),
                fields: vec![],
                json_schema: Some(json!({"type": "object"})),
                extension_rules: None,
                strip_raw_meta: false,
            }));

        let engines = compile_identity_engines_from_surface(&surface, Some(&issuer)).expect("compile should succeed");

        assert!(engines.selector.is_some(), "channel-wide selector built from legacy managed_identity");
        assert!(
            engines
                .protected_selector
                .is_none(),
            "no per-slot protected selector when identity_slots.protected is absent"
        );
        assert!(
            engines
                .external_selector
                .is_none(),
            "no per-slot external selector when identity_slots.external is absent"
        );
    }
}
