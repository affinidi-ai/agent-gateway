use axum::response::{IntoResponse, Response};
use std::sync::Arc;
use tracing::{error, warn};

use crate::config::agent_surface::AgentSurface;
use crate::secrets::SecretsStore;

use super::agent_card::PreparedA2aProxyAgentCard;
use super::filesystem::FileSystemA2aProxyStore;
use super::store::A2aProxyStore;
use super::types::{A2aProxy, A2aProxyStatus};

#[derive(Clone)]
pub struct A2aProxyTargetAdapter {
    store: Arc<FileSystemA2aProxyStore>,
}

#[derive(Debug, thiserror::Error)]
pub enum A2aProxyTargetError {
    #[error("A2A proxy store is not configured")]
    StoreUnavailable,
    #[error("A2A proxy not found")]
    NotFound,
    #[error("A2A proxy is disabled")]
    Disabled,
    #[error("A2A proxy endpoint is invalid")]
    InvalidEndpoint,
    #[error("Failed to load A2A proxy configuration")]
    LoadFailed,
    #[error("Failed to prepare A2A proxy agent card")]
    AgentCardPreparationFailed,
}

pub async fn resolve_prepared_agent_card_for_endpoint(
    store: Option<Arc<FileSystemA2aProxyStore>>,
    endpoint: &str,
    surface: &AgentSurface,
    channel_name: &str,
    vc_issuer: Option<&Arc<crate::identity::VCIssuer>>,
) -> Result<Option<PreparedA2aProxyAgentCard>, A2aProxyTargetError> {
    let Some(proxy_id) = A2aProxyTargetAdapter::proxy_id_from_endpoint(endpoint) else {
        return if endpoint.starts_with("a2a-proxy://") {
            Err(A2aProxyTargetError::InvalidEndpoint)
        } else {
            Ok(None)
        };
    };
    let adapter = A2aProxyTargetAdapter::from_optional_store(store)?;
    adapter
        .resolve_prepared_agent_card(proxy_id, surface, channel_name, vc_issuer)
        .await
        .map(Some)
}

impl A2aProxyTargetAdapter {
    pub fn new(store: Arc<FileSystemA2aProxyStore>) -> Self {
        Self { store }
    }

    pub fn from_optional_store(store: Option<Arc<FileSystemA2aProxyStore>>) -> Result<Self, A2aProxyTargetError> {
        store
            .map(Self::new)
            .ok_or(A2aProxyTargetError::StoreUnavailable)
    }

    pub fn proxy_id_from_endpoint(endpoint: &str) -> Option<&str> {
        let proxy_id = endpoint.strip_prefix("a2a-proxy://")?;
        if proxy_id.is_empty() || proxy_id.trim() != proxy_id {
            return None;
        }
        Some(proxy_id)
    }

    pub async fn resolve_prepared_agent_card(
        &self,
        proxy_id: &str,
        surface: &AgentSurface,
        channel_name: &str,
        vc_issuer: Option<&Arc<crate::identity::VCIssuer>>,
    ) -> Result<PreparedA2aProxyAgentCard, A2aProxyTargetError> {
        let proxy = self
            .load_active_proxy(proxy_id, channel_name)
            .await?;
        super::agent_card::prepare_agent_card(&proxy, surface, vc_issuer, channel_name)
            .await
            .map_err(|e| {
                error!(channel = channel_name, proxy_id = proxy_id, error = %e, "Failed to prepare A2A proxy agent card");
                A2aProxyTargetError::AgentCardPreparationFailed
            })
    }

    pub async fn dispatch_message_send(
        &self,
        proxy_id: &str,
        body_bytes: &[u8],
        secrets_store: Option<&Arc<dyn SecretsStore>>,
        channel_name: &str,
    ) -> Response {
        let proxy = match self
            .load_active_proxy(proxy_id, channel_name)
            .await
        {
            Ok(proxy) => proxy,
            Err(err) => return json_rpc_target_error(body_bytes, err),
        };

        super::runtime::handle_a2a_proxy_request(&proxy, body_bytes, secrets_store, channel_name).await
    }

    async fn load_active_proxy(
        &self,
        proxy_id: &str,
        channel_name: &str,
    ) -> Result<A2aProxy, A2aProxyTargetError> {
        let proxy = match self.store.get(proxy_id).await {
            Ok(Some(proxy)) => proxy,
            Ok(None) => {
                warn!(channel = channel_name, proxy_id = proxy_id, "A2A proxy not found");
                return Err(A2aProxyTargetError::NotFound);
            }
            Err(e) => {
                error!(channel = channel_name, proxy_id = proxy_id, error = %e, "Failed to load A2A proxy");
                return Err(A2aProxyTargetError::LoadFailed);
            }
        };

        if proxy.status == A2aProxyStatus::Disabled {
            warn!(channel = channel_name, proxy_id = proxy_id, "A2A proxy is disabled");
            return Err(A2aProxyTargetError::Disabled);
        }

        Ok(proxy)
    }
}

pub fn json_rpc_target_error(
    body_bytes: &[u8],
    err: A2aProxyTargetError,
) -> Response {
    let (code, message) = match err {
        A2aProxyTargetError::StoreUnavailable => (-32603, "Failed to access A2A proxy storage"),
        A2aProxyTargetError::NotFound => (-32020, "A2A proxy not found"),
        A2aProxyTargetError::Disabled => (-32020, "A2A proxy is disabled"),
        A2aProxyTargetError::InvalidEndpoint => (-32603, "A2A proxy endpoint is invalid"),
        A2aProxyTargetError::LoadFailed => (-32603, "Failed to load A2A proxy configuration"),
        A2aProxyTargetError::AgentCardPreparationFailed => (-32603, "Failed to prepare A2A proxy agent card"),
    };
    let id = serde_json::from_slice::<serde_json::Value>(body_bytes)
        .ok()
        .and_then(|body| body.get("id").cloned())
        .unwrap_or(serde_json::Value::Null);
    axum::response::Json(serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::A2aProxyTargetAdapter;

    #[test]
    fn proxy_id_from_endpoint_rejects_blank_or_padded_ids() {
        assert_eq!(A2aProxyTargetAdapter::proxy_id_from_endpoint("a2a-proxy://proxy-1"), Some("proxy-1"));
        assert_eq!(A2aProxyTargetAdapter::proxy_id_from_endpoint("a2a-proxy://"), None);
        assert_eq!(A2aProxyTargetAdapter::proxy_id_from_endpoint("a2a-proxy://proxy-1 "), None);
        assert_eq!(A2aProxyTargetAdapter::proxy_id_from_endpoint("https://example.test"), None);
    }
}
