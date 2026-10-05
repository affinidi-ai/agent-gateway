//! Agent Surface Store Trait

use anyhow::Context;
use async_trait::async_trait;
use tracing::error;

use crate::config::agent_surface::AgentSurface;

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
}
