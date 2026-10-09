//! Agent Surface Store Trait

use anyhow::Context;
use async_trait::async_trait;
use tracing::{error, info, warn};

use crate::config::agent_surface::{A2aAccessPointSettings, A2aValidation, AgentSurface};

/// Trait for storing and retrieving Agent Surface configurations
#[async_trait]
pub trait AgentSurfaceStore: Send + Sync {
    /// Create or update an Agent Surface
    async fn save(
        &self,
        surface: &AgentSurface,
    ) -> anyhow::Result<()>;

    /// Get an Agent Surface by surface_id
    async fn get(
        &self,
        surface_id: &str,
    ) -> anyhow::Result<Option<AgentSurface>>;

    /// List all Agent Surfaces
    async fn list_all(&self) -> anyhow::Result<Vec<AgentSurface>>;

    /// Delete an Agent Surface by surface_id
    async fn delete(
        &self,
        surface_id: &str,
    ) -> anyhow::Result<()>;
}

/// Auto-clear `header_metadata_mapping` config that targets a protocol other
/// than A2A/AP2, persisting the correction to storage.
///
/// Save-time validation (`AgentSurface::validate`) rejects this combination,
/// but a hand-edited or restored surface file can still reach storage with
/// it — same class of problem as the duplicate access-point route/port check
/// in `main.rs::disable_duplicate_route_surfaces`, but remediated by clearing
/// the specific invalid field (`AgentSurface::clear_unsupported_header_metadata_mappings`)
/// rather than disabling the whole surface, since a bad mapping doesn't make
/// an otherwise-valid MCP/DIDComm surface unroutable. Re-adding a mapping
/// goes through full save-time validation, so the invalid combination cannot
/// be reintroduced silently.
///
/// Called from both surface load paths that read directly from storage:
/// gateway startup (`main.rs::load_surfaces`) and the local-source config
/// reload (`identity/handlers/config.rs::load_base_gateway_config`).
pub async fn strip_unsupported_header_metadata_mappings<S: AgentSurfaceStore + ?Sized>(
    store: &S,
    channels: &mut [AgentSurface],
) -> anyhow::Result<()> {
    for surface in channels.iter_mut() {
        let cleared = surface.clear_unsupported_header_metadata_mappings();
        if cleared.is_empty() {
            continue;
        }
        for reason in &cleared {
            error!(
                surface = %surface.name,
                surface_id = %surface.surface_id,
                "header_metadata_mapping found on an unsupported protocol in storage — clearing {reason} so the gateway can boot; \
                 resolve via the UI or API"
            );
        }
        store
            .save(surface)
            .await
            .with_context(|| {
                format!("Failed to persist header_metadata_mapping cleanup for surface '{}'", surface.surface_id)
            })?;
    }
    Ok(())
}

/// The retired dashboard feature flag that once turned A2A 0.3 off gateway-wide.
const RETIRED_A2A_LEGACY_COMPATIBILITY_FLAG: &str = "a2a_legacy_compatibility";

/// The gateway-wide A2A switches that per-surface A2A settings replaced, read
/// so that a surface stored before those settings existed keeps what it was
/// served with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetiredA2aSwitches {
    /// `[a2a] validate_messages` from the bootstrap configuration, when set.
    pub validate_messages: Option<bool>,
    /// The retired `a2a_legacy_compatibility` flag, when stored in settings.
    pub legacy_compatibility: Option<bool>,
}

impl RetiredA2aSwitches {
    /// Read both switches: the TOML value from `bootstrap`, the flag from the
    /// settings file. The settings store is read directly because surfaces load
    /// before the global settings store is registered.
    pub async fn read(bootstrap: &crate::config::BootstrapConfig) -> Self {
        let settings = crate::storage::settings_store::SettingsStore::new(
            &bootstrap
                .storage_paths
                .settings,
        );
        let legacy_compatibility = match settings.load().await {
            Ok(()) => settings
                .get()
                .feature_flags
                .get(RETIRED_A2A_LEGACY_COMPATIBILITY_FLAG)
                .copied(),
            Err(e) => {
                warn!(error = %e, "Could not read settings for the retired a2a_legacy_compatibility flag; treating it as unset");
                None
            }
        };
        Self {
            validate_messages: bootstrap
                .a2a
                .validate_messages,
            legacy_compatibility,
        }
    }

    /// The settings a surface without its own takes: A2A 1.0 only when the flag
    /// turned 0.3 off, and no validation when `[a2a] validate_messages` was
    /// `false`. Otherwise `envelope` validation, never `full`: before the
    /// request-shape check existed, `validate_messages` gated the envelope check
    /// alone, so carrying `true` over as `full` could refuse callers a gateway
    /// served before.
    pub fn settings(&self) -> A2aAccessPointSettings {
        let defaults = A2aAccessPointSettings::default();
        A2aAccessPointSettings {
            accepted_versions: if self.legacy_compatibility == Some(false) {
                vec![crate::a2a::version::VERSION_1_0.to_string()]
            } else {
                defaults.accepted_versions
            },
            validation: if self.validate_messages == Some(false) {
                A2aValidation::Off
            } else {
                A2aValidation::Envelope
            },
        }
    }
}

/// Store `access_point.a2a` on every A2A or AP2 surface loaded without one,
/// taken from the retired gateway-wide switches, and warn about a stored block
/// that is invalid. A surface whose block would apply to no request (an A2A-proxy
/// Target with no URL variant) is left without one: the runtime fixes its settings.
///
/// An invalid stored block (only reachable by editing storage by hand) is not
/// refused: the surface keeps being served, accepting both versions when its
/// version list is unusable, and the warning says so.
///
/// Called from the same load paths as [`strip_unsupported_header_metadata_mappings`].
pub async fn carry_over_a2a_settings<S: AgentSurfaceStore + ?Sized>(
    store: &S,
    surfaces: &mut [AgentSurface],
    retired: RetiredA2aSwitches,
) -> anyhow::Result<()> {
    let carried = retired.settings();
    let mut count = 0usize;
    for surface in surfaces.iter_mut() {
        if !surface.uses_a2a_settings() {
            continue;
        }
        if surface
            .access_point
            .a2a
            .is_some()
        {
            if let Err(reason) = surface.validate_a2a_settings() {
                let served = surface.a2a_settings();
                warn!(
                    surface = %surface.name,
                    surface_id = %surface.surface_id,
                    "access_point.a2a in storage is invalid: {reason}. The surface is served with A2A {} and \
                     validation={} until it is corrected through the dashboard or API",
                    served.accepted_versions.join(", "),
                    served.validation.as_str()
                );
            }
            continue;
        }
        if !surface.a2a_settings_apply() {
            continue;
        }
        surface.access_point.a2a = Some(carried.clone());
        store
            .save(surface)
            .await
            .with_context(|| format!("Failed to store A2A settings for surface '{}'", surface.surface_id))?;
        count += 1;
    }
    if count > 0 {
        info!(
            "Stored A2A settings on {count} A2A surface(s) that had none: accepted versions {}, validation={}",
            carried
                .accepted_versions
                .join(", "),
            carried.validation.as_str()
        );
        if retired.legacy_compatibility == Some(false) {
            warn!(
                "The a2a_legacy_compatibility setting is retired. It was off, so {count} A2A surface(s) were stored \
                 as A2A 1.0 only; accepted A2A versions are now set per surface"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::surfaces::FileSystemAgentSurfaceStore;

    fn mcp_surface_with_mapping(id: &str) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": format!("/agents/{id}"),
                "protocol": "mcp",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://mcp.internal/mcp" }
        }))
        .expect("test surface should deserialize")
    }

    fn a2a_surface_with_mapping(id: &str) -> AgentSurface {
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": format!("/agents/{id}"),
                "protocol": "a2a",
                "header_metadata_mapping": {
                    "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
                }
            },
            "target": { "endpoint": "https://a2a.internal/a2a" }
        }))
        .expect("test surface should deserialize")
    }

    async fn test_store(dir: &std::path::Path) -> FileSystemAgentSurfaceStore {
        FileSystemAgentSurfaceStore::new(dir.to_path_buf())
            .await
            .expect("test store should initialize")
    }

    #[tokio::test]
    async fn strips_and_persists_mapping_on_unsupported_protocol() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut channels = vec![mcp_surface_with_mapping("s-mcp")];

        strip_unsupported_header_metadata_mappings(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert!(
            channels[0]
                .access_point
                .header_metadata_mapping
                .is_none()
        );

        // Persisted: re-reading from storage reflects the cleared mapping.
        let reloaded = store
            .get("s-mcp")
            .await
            .expect("get should succeed")
            .expect("surface should exist");
        assert!(
            reloaded
                .access_point
                .header_metadata_mapping
                .is_none()
        );
    }

    #[tokio::test]
    async fn leaves_valid_mapping_untouched_and_does_not_rewrite_storage() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let surface = a2a_surface_with_mapping("s-a2a");
        store
            .save(&surface)
            .await
            .expect("save should succeed");
        let mut channels = vec![surface];

        strip_unsupported_header_metadata_mappings(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert!(
            channels[0]
                .access_point
                .header_metadata_mapping
                .is_some()
        );
    }

    #[tokio::test]
    async fn handles_multiple_surfaces_independently() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut channels = vec![mcp_surface_with_mapping("s-mcp"), a2a_surface_with_mapping("s-a2a")];

        strip_unsupported_header_metadata_mappings(&store, &mut channels)
            .await
            .expect("cleanup should succeed");

        assert!(
            channels[0]
                .access_point
                .header_metadata_mapping
                .is_none()
        );
        assert!(
            channels[1]
                .access_point
                .header_metadata_mapping
                .is_some()
        );
    }

    fn a2a_surface(
        id: &str,
        endpoint: &str,
        a2a: Option<serde_json::Value>,
    ) -> AgentSurface {
        let mut access_point = serde_json::json!({
            "listen_address": "0.0.0.0:8443",
            "route": format!("/agents/{id}"),
            "protocol": "a2a"
        });
        if let Some(a2a) = a2a {
            access_point["a2a"] = a2a;
        }
        serde_json::from_value(serde_json::json!({
            "surface_id": id,
            "name": id,
            "access_point": access_point,
            "target": { "endpoint": endpoint }
        }))
        .expect("test surface should deserialize")
    }

    fn settings(
        versions: &[&str],
        validation: A2aValidation,
    ) -> A2aAccessPointSettings {
        A2aAccessPointSettings {
            accepted_versions: versions
                .iter()
                .map(|v| v.to_string())
                .collect(),
            validation,
        }
    }

    #[test]
    fn retired_switches_map_to_surface_settings() {
        let switches = |validate_messages, legacy_compatibility| RetiredA2aSwitches {
            validate_messages,
            legacy_compatibility,
        };
        assert_eq!(
            switches(None, None).settings(),
            settings(&["0.3", "1.0"], A2aValidation::Envelope),
            "unset means both versions with envelope validation, the old default"
        );
        assert_eq!(
            switches(Some(true), Some(true)).settings(),
            settings(&["0.3", "1.0"], A2aValidation::Envelope),
            "true carries over as envelope, never full"
        );
        assert_eq!(switches(Some(false), None).settings(), settings(&["0.3", "1.0"], A2aValidation::Off));
        assert_eq!(switches(None, Some(false)).settings(), settings(&["1.0"], A2aValidation::Envelope));
        assert_eq!(switches(Some(false), Some(false)).settings(), settings(&["1.0"], A2aValidation::Off));
    }

    #[tokio::test]
    async fn an_a2a_surface_without_settings_takes_the_retired_switches_and_is_stored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = vec![a2a_surface("s-old", "https://a2a.internal/a2a", None)];
        let retired = RetiredA2aSwitches {
            validate_messages: Some(false),
            legacy_compatibility: Some(false),
        };

        carry_over_a2a_settings(&store, &mut surfaces, retired)
            .await
            .expect("carry-over should succeed");

        let expected = settings(&["1.0"], A2aValidation::Off);
        assert_eq!(surfaces[0].access_point.a2a, Some(expected.clone()));
        let stored = store
            .get("s-old")
            .await
            .expect("get")
            .expect("stored surface");
        assert_eq!(stored.access_point.a2a, Some(expected), "the carried settings are persisted");
        assert_eq!(
            stored
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::VERSIONS_1_0_ONLY
        );
        assert_eq!(
            stored
                .a2a_settings()
                .validation,
            A2aValidation::Off
        );
    }

    #[tokio::test]
    async fn existing_proxy_and_non_a2a_surfaces_are_left_alone() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let own = settings(&["0.3"], A2aValidation::Full);
        let mut surfaces = vec![
            a2a_surface("s-own", "https://a2a.internal/a2a", Some(serde_json::to_value(&own).unwrap())),
            a2a_surface("s-proxy", "a2a-proxy://worker", None),
            mcp_surface_with_mapping("s-mcp"),
        ];
        let retired = RetiredA2aSwitches {
            validate_messages: Some(false),
            legacy_compatibility: Some(false),
        };

        carry_over_a2a_settings(&store, &mut surfaces, retired)
            .await
            .expect("carry-over should succeed");

        assert_eq!(surfaces[0].access_point.a2a, Some(own), "a surface's own settings are kept");
        assert_eq!(surfaces[1].access_point.a2a, None, "an A2A proxy Target stores no block");
        assert_eq!(surfaces[2].access_point.a2a, None, "an MCP surface gets no block");
        for id in ["s-own", "s-proxy", "s-mcp"] {
            assert!(
                store
                    .get(id)
                    .await
                    .expect("get")
                    .is_none(),
                "{id} must not be rewritten"
            );
        }
    }

    #[tokio::test]
    async fn an_invalid_stored_version_list_is_kept_and_served_with_both_versions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = test_store(dir.path()).await;
        let mut surfaces = vec![
            a2a_surface(
                "s-empty",
                "https://a2a.internal/a2a",
                Some(serde_json::json!({ "accepted_versions": [], "validation": "full" })),
            ),
            a2a_surface(
                "s-unknown",
                "https://a2a.internal/a2a",
                Some(serde_json::json!({ "accepted_versions": ["2.0"] })),
            ),
        ];

        carry_over_a2a_settings(&store, &mut surfaces, RetiredA2aSwitches::default())
            .await
            .expect("an invalid stored block must not fail the load");

        assert_eq!(surfaces[0].access_point.a2a, Some(settings(&[], A2aValidation::Full)), "left as stored");
        assert_eq!(
            surfaces[0]
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::SUPPORTED_VERSIONS
        );
        assert_eq!(
            surfaces[0]
                .a2a_settings()
                .validation,
            A2aValidation::Full
        );
        assert_eq!(
            surfaces[1]
                .a2a_settings()
                .accepted_versions,
            crate::a2a::version::SUPPORTED_VERSIONS
        );
    }
}
