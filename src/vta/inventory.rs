//! Key inventory — what this appliance signs with, and what it still publishes.
//!
//! An operator cannot currently answer basic questions without reading logs and
//! config: *which key signed this token? which surface uses which context? what
//! happens if I rotate?* VTA-18/19 made the answers computable; this module
//! makes them readable in one place.
//!
//! Everything here is **derived**, never a second source of truth: connections
//! come from the connection store, mappings from each surface's `signing`
//! block, and contexts from the same derived-name function the provisioner
//! uses. A separate inventory store would be one more thing to drift.

use serde::Serialize;

use crate::config::agent_surface::{AgentSurface, derived_context_name};
use crate::config::vta::VtaConfig;
use crate::vta::connections::VtaConnection;

/// A key as the operator sees it.
#[derive(Debug, Clone, Serialize)]
pub struct KeyEntry {
    /// Also the published `kid` — the thing that correlates a token to its key.
    pub key_id: String,
    pub status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<String>,
}

/// A connection and everything it signs with.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionInventory {
    pub connection_id: String,
    pub name: String,
    pub enabled: bool,
    pub transport: String,
    pub vta_did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_context_id: Option<String>,
    pub pairing_state: String,
    /// Whether this connection may sign right now — the backend's own rule, so
    /// the UI cannot disagree with what will actually happen.
    pub usable: bool,
    pub keys: Vec<KeyEntry>,
}

/// Which key a surface (or one of its variants) signs with.
#[derive(Debug, Clone, Serialize)]
pub struct SurfaceMapping {
    pub surface_id: String,
    pub surface_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant_alias: Option<String>,
    /// `local`, `vta` or `hsm` — or `inherit` when nothing is mapped, which is
    /// the default and is shown as such rather than silently resolved.
    pub backend: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connection_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Whether this level declares nothing and therefore inherits.
    pub inherits: bool,
    /// The context name this surface/variant would use if one were
    /// provisioned, derived from its stable ids.
    pub derived_context: String,
}

/// The whole picture.
#[derive(Debug, Clone, Serialize)]
pub struct KeyInventory {
    pub tier: String,
    /// False for both local signing and a bundled sidecar. Computed here so no
    /// client can imply custody the deployment does not have.
    pub custody_claim: bool,
    pub connections: Vec<ConnectionInventory>,
    pub mappings: Vec<SurfaceMapping>,
    /// Contexts named by no live surface or variant.
    ///
    /// Reported, never reclaimed: deleting a surface deliberately does not
    /// delete its keys, because artifacts they signed must stay verifiable.
    pub orphaned_contexts: Vec<String>,
    /// Every private-key surface the gateway has and what was decided about
    /// it (VTA-14).
    pub key_surfaces: Vec<crate::vta::key_surfaces::KeySurface>,
    /// The surfaces that should be in the trust agent and are not.
    ///
    /// The honest form of "the gateway holds no signing key": it is empty, or
    /// it is this list.
    pub residual_exceptions: Vec<&'static str>,
    /// Whether the gateway holds no key that forges something others trust.
    ///
    /// Computed from the surfaces above, never configured, so it cannot be
    /// asserted by a deployment that has not earned it.
    pub holds_no_forging_key: bool,
}

fn key_entries(connection: &VtaConnection) -> Vec<KeyEntry> {
    connection
        .keys
        .published()
        .into_iter()
        .map(|key| KeyEntry {
            key_id: key.key_id.clone(),
            status: if key.retired_at.is_some() {
                "retiring"
            } else {
                "active"
            },
            public_key: key.public_key.clone(),
            label: key.label.clone(),
            retired_at: key
                .retired_at
                .map(|at| at.to_rfc3339()),
        })
        .collect()
}

fn mapping_for(
    surface: &AgentSurface,
    variant_id: Option<&str>,
    variant_alias: Option<&str>,
    signing: Option<&crate::config::agent_surface::SurfaceSigningConfig>,
) -> SurfaceMapping {
    let declared = signing.filter(|s| !s.is_empty());
    SurfaceMapping {
        surface_id: surface.surface_id.clone(),
        surface_name: surface.name.clone(),
        variant_id: variant_id.map(str::to_string),
        variant_alias: variant_alias.map(str::to_string),
        backend: declared
            .and_then(|s| s.backend)
            .map(|b| {
                match b {
                    crate::config::agent_surface::SigningBackendKind::Local => "local",
                    crate::config::agent_surface::SigningBackendKind::Vta => "vta",
                    crate::config::agent_surface::SigningBackendKind::Hsm => "hsm",
                }
                .to_string()
            })
            .unwrap_or_else(|| "inherit".to_string()),
        connection_id: declared.and_then(|s| s.connection_id.clone()),
        context_id: declared.and_then(|s| s.context_id.clone()),
        key_id: declared.and_then(|s| s.key_id.clone()),
        inherits: declared.is_none(),
        derived_context: derived_context_name(surface.tenant_id.as_deref(), &surface.surface_id, variant_id),
    }
}

/// Build the inventory from the live records.
///
/// `known_contexts` are the context names the provisioner has created or
/// adopted; anything in there that no surface claims is reported as orphaned.
pub fn build(
    config: &VtaConfig,
    connections: &[VtaConnection],
    surfaces: &[AgentSurface],
    known_contexts: &[String],
) -> KeyInventory {
    let mappings: Vec<SurfaceMapping> = surfaces
        .iter()
        .flat_map(|surface| {
            let base = mapping_for(surface, None, None, surface.signing.as_ref());
            let variants = surface
                .variants
                .iter()
                .map(|variant| {
                    mapping_for(
                        surface,
                        Some(&variant.id),
                        Some(&variant.alias),
                        variant
                            .overrides
                            .signing
                            .as_ref(),
                    )
                })
                .collect::<Vec<_>>();
            std::iter::once(base).chain(variants)
        })
        .collect();

    let live: std::collections::HashSet<&str> = mappings
        .iter()
        .map(|m| m.derived_context.as_str())
        .collect();
    let mut orphaned_contexts: Vec<String> = known_contexts
        .iter()
        .filter(|name| !live.contains(name.as_str()))
        .cloned()
        .collect();
    orphaned_contexts.sort();

    KeyInventory {
        tier: config.tier().to_string(),
        custody_claim: config.supports_custody_claim(),
        connections: connections
            .iter()
            .map(|connection| ConnectionInventory {
                connection_id: connection.id.clone(),
                name: connection.name.clone(),
                enabled: connection.enabled,
                transport: serde_json::to_value(connection.transport)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_string))
                    .unwrap_or_else(|| "https".to_string()),
                vta_did: connection.vta_did.clone(),
                default_context_id: connection
                    .default_context_id
                    .clone(),
                pairing_state: connection
                    .pairing
                    .state
                    .as_str()
                    .to_string(),
                usable: crate::vta::pairing::assert_usable(connection, &connection.pairing).is_ok(),
                keys: key_entries(connection),
            })
            .collect(),
        mappings,
        orphaned_contexts,
        key_surfaces: crate::vta::key_surfaces::surfaces(config.enabled),
        residual_exceptions: crate::vta::key_surfaces::residual_exceptions(config.enabled),
        holds_no_forging_key: crate::vta::key_surfaces::holds_no_forging_key(config.enabled),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{SigningBackendKind, SurfaceSigningConfig};
    use crate::vta::connections::{SigningKey, VtaConnectionStatus, VtaConnectionTransport};
    use chrono::Utc;

    fn connection(id: &str) -> VtaConnection {
        let now = Utc::now();
        VtaConnection {
            id: id.to_string(),
            tenant_id: None,
            name: format!("VTA {id}"),
            description: None,
            enabled: true,
            transport: VtaConnectionTransport::Https,
            endpoint: format!("https://{id}.example"),
            vta_did: format!("did:webvh:{id}.example"),
            default_context_id: Some("ctx".to_string()),
            control_key_ref: Some("secret".to_string()),
            status: VtaConnectionStatus::Connected,
            pairing: crate::vta::pairing::PairingRecord {
                state: crate::vta::pairing::PairingState::Connected,
                ..Default::default()
            },
            keys: Default::default(),
            created_at: now,
            updated_at: now,
        }
    }

    fn surface(
        id: &str,
        signing: Option<SurfaceSigningConfig>,
    ) -> AgentSurface {
        AgentSurface {
            surface_id: id.to_string(),
            name: format!("surface-{id}"),
            signing,
            ..Default::default()
        }
    }

    fn vta_config() -> VtaConfig {
        VtaConfig {
            enabled: true,
            base_url: Some("https://vta.example".to_string()),
            vta_did: Some("did:webvh:vta.example".to_string()),
            context_id: Some("ctx".to_string()),
            signing_key_id: Some("k1".to_string()),
            ..VtaConfig::default()
        }
    }

    #[test]
    fn an_unmapped_surface_is_reported_as_inheriting_rather_than_resolved() {
        let inventory = build(&vta_config(), &[], &[surface("s1", None)], &[]);
        let mapping = &inventory.mappings[0];
        // Showing the resolved value would hide that nothing is configured,
        // which is exactly what an operator is trying to find out.
        assert!(mapping.inherits);
        assert_eq!(mapping.backend, "inherit");
        assert!(mapping.context_id.is_none());
        assert_eq!(mapping.derived_context, "ctx:_global/s1");
    }

    #[test]
    fn an_empty_signing_block_still_counts_as_inheriting() {
        let inventory = build(&vta_config(), &[], &[surface("s1", Some(SurfaceSigningConfig::default()))], &[]);
        assert!(inventory.mappings[0].inherits);
    }

    #[test]
    fn a_mapped_surface_reports_its_backend_context_and_key() {
        let signing = SurfaceSigningConfig {
            backend: Some(SigningBackendKind::Vta),
            connection_id: Some("c1".to_string()),
            context_id: Some("ctx-sales".to_string()),
            key_id: Some("k-sales".to_string()),
        };
        let inventory = build(&vta_config(), &[], &[surface("s1", Some(signing))], &[]);
        let mapping = &inventory.mappings[0];
        assert!(!mapping.inherits);
        assert_eq!(mapping.backend, "vta");
        assert_eq!(
            mapping
                .connection_id
                .as_deref(),
            Some("c1")
        );
        assert_eq!(mapping.context_id.as_deref(), Some("ctx-sales"));
        assert_eq!(mapping.key_id.as_deref(), Some("k-sales"));
    }

    #[test]
    fn the_inventory_publishes_active_and_retiring_keys_with_their_kid() {
        let now = Utc::now();
        let mut connection = connection("c1");
        connection
            .keys
            .rotate_to(
                SigningKey {
                    key_id: "k1".to_string(),
                    public_key: Some("z6Mk1".to_string()),
                    label: None,
                    added_at: now,
                    retired_at: None,
                },
                now,
            )
            .unwrap();
        connection
            .keys
            .rotate_to(
                SigningKey {
                    key_id: "k2".to_string(),
                    public_key: Some("z6Mk2".to_string()),
                    label: None,
                    added_at: now,
                    retired_at: None,
                },
                now,
            )
            .unwrap();

        let inventory = build(&vta_config(), &[connection], &[], &[]);
        let keys = &inventory.connections[0].keys;
        assert_eq!(keys.len(), 2, "the retired key is still published");
        assert_eq!(keys[0].key_id, "k2");
        assert_eq!(keys[0].status, "active");
        assert_eq!(keys[1].key_id, "k1");
        assert_eq!(keys[1].status, "retiring");
        assert!(keys[1].retired_at.is_some());
    }

    #[test]
    fn a_context_no_surface_claims_is_reported_as_orphaned() {
        let known = vec!["ctx:_global/s1".to_string(), "ctx:_global/deleted".to_string()];
        let inventory = build(&vta_config(), &[], &[surface("s1", None)], &known);
        // Reported, not reclaimed: artifacts the orphan's key signed must stay
        // verifiable.
        assert_eq!(inventory.orphaned_contexts, vec!["ctx:_global/deleted".to_string()]);
    }

    #[test]
    fn the_custody_claim_is_computed_here_and_follows_the_tier() {
        let mut config = vta_config();
        assert!(build(&config, &[], &[], &[]).custody_claim, "a separately-operated VTA supports the claim");

        config.mode = crate::config::vta::VtaMode::Bundled;
        let bundled = build(&config, &[], &[], &[]);
        assert_eq!(bundled.tier, "bundled");
        assert!(!bundled.custody_claim, "a bundled sidecar is not a custody tier");

        let local = build(&VtaConfig::default(), &[], &[], &[]);
        assert_eq!(local.tier, "local");
        assert!(!local.custody_claim);
    }

    #[test]
    fn usability_mirrors_the_backend_rule_rather_than_guessing() {
        let mut disabled = connection("c1");
        disabled.enabled = false;
        let unpaired = VtaConnection {
            pairing: Default::default(),
            ..connection("c2")
        };
        let inventory = build(&vta_config(), &[connection("c0"), disabled, unpaired], &[], &[]);
        assert!(inventory.connections[0].usable);
        assert!(!inventory.connections[1].usable, "disabled cannot sign");
        assert!(!inventory.connections[2].usable, "unpaired cannot sign");
    }
}
