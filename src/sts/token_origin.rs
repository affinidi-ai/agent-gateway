//! Which managed connection minted a token this gateway's STS issued.
//!
//! A JWT Bearer surface whose verification strategy trusts this STS accepts
//! every token the STS signs for one of its audiences. Caller authentication
//! asks [`StsTokenOrigins`] which connection minted a verified token, so a
//! token minted by another tenant's connection is refused at the surface
//! (`crate::source_auth::middleware`).

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

/// The claim holding the record id of the managed connection a token was
/// minted for. Unlike `client_id`, it never changes and is never reused.
pub const CONNECTION_ID_CLAIM: &str = "connection_id";

/// Who minted a verified token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenOrigin {
    /// Another issuer minted it.
    Elsewhere,
    /// This STS minted it for the managed connection of this tenant: `None`
    /// for an appliance-global connection.
    Connection { tenant_id: Option<String> },
    /// This STS minted it, but it names no managed connection that exists.
    UnknownConnection,
}

impl TokenOrigin {
    /// Whether a surface of `surface_tenant_id` may accept the token: the
    /// rule STS minting applies (`crate::sts::resource_owners`). A token of
    /// an appliance-global connection is accepted everywhere, and one of a
    /// tenant connection on that tenant's and global surfaces.
    pub fn may_reach(
        &self,
        surface_tenant_id: Option<&str>,
    ) -> bool {
        match self {
            Self::Elsewhere => true,
            Self::Connection { tenant_id: None } => true,
            Self::Connection { tenant_id: Some(tenant_id) } => {
                crate::tenancy::can_reference(Some(tenant_id), surface_tenant_id)
            }
            Self::UnknownConnection => false,
        }
    }
}

#[async_trait]
pub trait StsTokenOrigins: Send + Sync {
    /// The origin of a token whose signature and claims were verified.
    async fn origin(
        &self,
        claims: &Value,
    ) -> anyhow::Result<TokenOrigin>;
}

/// Why a verified token may not be accepted at a surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReachRefusal {
    /// The managed connections could not be read.
    Unavailable,
    /// The token was minted for a managed connection that does not exist or
    /// may not reach the surface.
    Refused,
}

/// The surface, and its tenant, that a verified token was presented to.
pub struct TokenReach<'a> {
    pub origins: &'a dyn StsTokenOrigins,
    pub surface: &'a str,
    pub tenant_id: Option<&'a str>,
}

impl TokenReach<'_> {
    /// Accept a token only when [`TokenOrigin::may_reach`] the surface, and
    /// log why not. The caller is not told which tenant owns the surface.
    pub async fn ensure(
        &self,
        claims: &Value,
    ) -> Result<(), ReachRefusal> {
        let origin = self
            .origins
            .origin(claims)
            .await
            .map_err(|error| {
                tracing::warn!(surface = %self.surface, %error, "Failed to read STS managed connections for a caller's token");
                ReachRefusal::Unavailable
            })?;
        if origin.may_reach(self.tenant_id) {
            return Ok(());
        }
        let claim = |name: &str| {
            claims
                .get(name)
                .and_then(Value::as_str)
                .unwrap_or("<none>")
        };
        tracing::warn!(
            surface = %self.surface,
            surface_tenant_id = self.tenant_id.unwrap_or("<global>"),
            origin = ?origin,
            connection_id = claim(CONNECTION_ID_CLAIM),
            client_id = claim("client_id"),
            jti = claim("jti"),
            "Refused a token minted for a managed connection that cannot reach this surface"
        );
        Err(ReachRefusal::Refused)
    }
}

/// The origins of tokens issued under the gateway DID or the MCP issuer, the
/// two issuers this STS signs under. Without a managed connection store, which
/// happens only when it failed to open at startup, the origin of every token
/// of those issuers is an error, so the check fails closed.
pub struct GatewayStsTokenOrigins {
    vc_issuer: Arc<crate::identity::VCIssuer>,
    mcp_issuer: Option<String>,
    clients: Option<Arc<dyn crate::sts::store::StsClientStorage>>,
}

impl GatewayStsTokenOrigins {
    pub fn new(
        vc_issuer: Arc<crate::identity::VCIssuer>,
        mcp_issuer: Option<String>,
        clients: Option<Arc<dyn crate::sts::store::StsClientStorage>>,
    ) -> Self {
        Self { vc_issuer, mcp_issuer, clients }
    }
}

#[async_trait]
impl StsTokenOrigins for GatewayStsTokenOrigins {
    async fn origin(
        &self,
        claims: &Value,
    ) -> anyhow::Result<TokenOrigin> {
        let Some(issuer) = claims
            .get("iss")
            .and_then(Value::as_str)
        else {
            return Ok(TokenOrigin::Elsewhere);
        };
        let ours = self.mcp_issuer.as_deref() == Some(issuer)
            || self
                .vc_issuer
                .get_issuer_did()
                .await?
                == issuer;
        if !ours {
            return Ok(TokenOrigin::Elsewhere);
        }
        let Some(clients) = &self.clients else {
            anyhow::bail!("the STS managed connection store is unavailable");
        };
        connection_origin(clients.as_ref(), claims).await
    }
}

async fn connection_origin(
    clients: &dyn crate::sts::store::StsClientStorage,
    claims: &Value,
) -> anyhow::Result<TokenOrigin> {
    let Some(connection_id) = claims
        .get(CONNECTION_ID_CLAIM)
        .and_then(Value::as_str)
        .filter(|id| !id.is_empty())
    else {
        return Ok(TokenOrigin::UnknownConnection);
    };
    Ok(
        match clients
            .get(connection_id)
            .await?
        {
            Some(client) => TokenOrigin::Connection { tenant_id: client.tenant_id },
            None => TokenOrigin::UnknownConnection,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn connection(tenant: Option<&str>) -> TokenOrigin {
        TokenOrigin::Connection {
            tenant_id: tenant.map(str::to_string),
        }
    }

    #[test]
    fn a_tenant_connection_reaches_its_own_and_global_surfaces_only() {
        let tenant_a = connection(Some("tenant-a"));
        assert!(tenant_a.may_reach(Some("tenant-a")));
        assert!(tenant_a.may_reach(None));
        assert!(!tenant_a.may_reach(Some("tenant-b")));
    }

    #[test]
    fn a_global_connection_and_another_issuer_reach_every_surface() {
        for origin in [connection(None), TokenOrigin::Elsewhere] {
            assert!(origin.may_reach(Some("tenant-b")), "{origin:?}");
            assert!(origin.may_reach(None), "{origin:?}");
        }
    }

    #[test]
    fn an_unknown_connection_reaches_no_surface() {
        assert!(!TokenOrigin::UnknownConnection.may_reach(None));
        assert!(!TokenOrigin::UnknownConnection.may_reach(Some("tenant-a")));
    }

    /// A store holding a connection per `(client_id, tenant)`, with the record
    /// id each was given.
    async fn store_with(
        clients: &[(&str, Option<&str>)]
    ) -> (Arc<dyn crate::sts::store::StsClientStorage>, Vec<String>) {
        let temp = tempfile::tempdir().unwrap();
        let store: Arc<dyn crate::sts::store::StsClientStorage> = Arc::new(
            crate::sts::store::FileSystemStsClientStore::new(temp.keep().join("sts"))
                .await
                .unwrap(),
        );
        let mut ids = Vec::new();
        for (client_id, tenant) in clients {
            ids.push(
                store
                    .create(client(client_id, *tenant))
                    .await
                    .unwrap()
                    .id,
            );
        }
        (store, ids)
    }

    fn client(
        client_id: &str,
        tenant: Option<&str>,
    ) -> crate::sts::store::StsClient {
        serde_json::from_value(json!({
            "id": "",
            "tenant_id": tenant,
            "client_id": client_id,
            "name": client_id,
            "created_at": "2026-01-01T00:00:00Z",
            "updated_at": "2026-01-01T00:00:00Z",
        }))
        .unwrap()
    }

    #[tokio::test]
    async fn the_connection_named_by_connection_id_gives_the_tenant() {
        let (clients, ids) = store_with(&[("alpha", Some("tenant-a")), ("global", None)]).await;
        assert_eq!(
            connection_origin(clients.as_ref(), &json!({"client_id": "alpha", CONNECTION_ID_CLAIM: ids[0]}))
                .await
                .unwrap(),
            connection(Some("tenant-a"))
        );
        assert_eq!(
            connection_origin(clients.as_ref(), &json!({"client_id": "global", CONNECTION_ID_CLAIM: ids[1]}))
                .await
                .unwrap(),
            connection(None)
        );
    }

    #[tokio::test]
    async fn a_token_stays_with_its_connection_when_the_client_id_is_renamed_or_reused() {
        let (clients, ids) = store_with(&[("alpha", Some("tenant-a"))]).await;
        let token = json!({"client_id": "alpha", CONNECTION_ID_CLAIM: ids[0]});

        let mut renamed = clients
            .get(&ids[0])
            .await
            .unwrap()
            .unwrap();
        renamed.client_id = "beta".into();
        clients
            .update(renamed)
            .await
            .unwrap();
        assert_eq!(
            connection_origin(clients.as_ref(), &token)
                .await
                .unwrap(),
            connection(Some("tenant-a"))
        );

        clients
            .delete(&ids[0])
            .await
            .unwrap();
        clients
            .create(client("alpha", Some("tenant-b")))
            .await
            .unwrap();
        assert_eq!(
            connection_origin(clients.as_ref(), &token)
                .await
                .unwrap(),
            TokenOrigin::UnknownConnection
        );
    }

    #[tokio::test]
    async fn only_tokens_of_the_gateway_did_or_the_mcp_issuer_are_this_sts_tokens() {
        let (vc_issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let gateway_did = vc_issuer
            .get_issuer_did()
            .await
            .unwrap();
        let mcp_issuer = "https://gw.example/api/oauth2/mcp";
        let (clients, ids) = store_with(&[("alpha", Some("tenant-a"))]).await;
        let origins = GatewayStsTokenOrigins::new(vc_issuer, Some(mcp_issuer.to_string()), Some(clients));
        for issuer in [gateway_did.as_str(), mcp_issuer] {
            assert_eq!(
                origins
                    .origin(&json!({"iss": issuer, "client_id": "alpha", CONNECTION_ID_CLAIM: ids[0]}))
                    .await
                    .unwrap(),
                connection(Some("tenant-a")),
                "{issuer}"
            );
        }
        for claims in [json!({"iss": "https://idp.example", "client_id": "alpha"}), json!({"client_id": "alpha"})] {
            assert_eq!(
                origins
                    .origin(&claims)
                    .await
                    .unwrap(),
                TokenOrigin::Elsewhere,
                "{claims}"
            );
        }
    }

    #[tokio::test]
    async fn without_a_connection_store_only_tokens_of_other_issuers_have_an_origin() {
        let (vc_issuer, _dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let gateway_did = vc_issuer
            .get_issuer_did()
            .await
            .unwrap();
        let mcp_issuer = "https://gw.example/api/oauth2/mcp";
        let origins = GatewayStsTokenOrigins::new(vc_issuer, Some(mcp_issuer.to_string()), None);
        for issuer in [gateway_did.as_str(), mcp_issuer] {
            let error = origins
                .origin(&json!({"iss": issuer, "client_id": "alpha"}))
                .await
                .expect_err(issuer);
            assert_eq!(error.to_string(), "the STS managed connection store is unavailable");
        }
        assert_eq!(
            origins
                .origin(&json!({"iss": "https://idp.example", "client_id": "alpha"}))
                .await
                .unwrap(),
            TokenOrigin::Elsewhere
        );
    }

    #[tokio::test]
    async fn a_token_without_a_live_connection_id_is_unknown() {
        let (clients, _) = store_with(&[("alpha", Some("tenant-a"))]).await;
        for claims in [
            json!({}),
            json!({"client_id": "alpha"}),
            json!({CONNECTION_ID_CLAIM: 7}),
            json!({CONNECTION_ID_CLAIM: ""}),
            json!({CONNECTION_ID_CLAIM: "deleted"}),
        ] {
            assert_eq!(
                connection_origin(clients.as_ref(), &claims)
                    .await
                    .unwrap(),
                TokenOrigin::UnknownConnection,
                "{claims}"
            );
        }
    }
}
