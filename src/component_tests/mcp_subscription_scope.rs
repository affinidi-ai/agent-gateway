//! MCP subscription invalidation scope: a configuration change ends only the
//! subscriptions on the surface or tenant it affects, and an appliance-wide
//! change ends every subscription.

use std::time::Duration;

use http_body_util::BodyExt;
use serde_json::json;

use crate::config::agent_surface::AgentSurface;
use crate::credential_providers::storage::{CredentialProviderStorage, FileSystemCredentialProviderStore};
use crate::jwt_bearer::storage::{FileSystemJwtVerificationStrategyStore, JwtVerificationStrategyStorage};
use crate::mcp::subscriptions::SubscriptionLifetime;
use crate::mcp_proxies::types::McpProxy;
use crate::mcp_proxies::{FileSystemMcpProxyStore, McpProxyStore};
use crate::surfaces::{AgentSurfaceStore, FileSystemAgentSurfaceStore};

const CHILD: &str = "ATG_MCP_SUBSCRIPTION_SCOPE_CHILD";

struct OpenSubscription {
    body: axum::body::Body,
    upstream: tokio::sync::mpsc::Sender<Result<bytes::Bytes, std::io::Error>>,
}

impl OpenSubscription {
    fn on(surface: &AgentSurface) -> Self {
        let mut lifetime = SubscriptionLifetime::new(Duration::from_secs(60), None);
        lifetime.record_owner(surface.surface_id.clone(), surface.tenant_id.as_deref());
        Self::wrap(lifetime)
    }

    fn on_proxy(proxy: &McpProxy) -> Self {
        let mut lifetime = SubscriptionLifetime::new(Duration::from_secs(60), None);
        lifetime.record_proxy_owner(proxy);
        Self::wrap(lifetime)
    }

    fn wrap(lifetime: SubscriptionLifetime) -> Self {
        let (upstream, receiver) = tokio::sync::mpsc::channel(1);
        let body = lifetime
            .wrap(axum::response::Response::new(axum::body::Body::from_stream(
                tokio_stream::wrappers::ReceiverStream::new(receiver),
            )))
            .into_body();
        Self { body, upstream }
    }

    async fn assert_open(
        &mut self,
        context: &str,
    ) {
        assert!(futures::poll!(self.body.frame()).is_pending(), "{context}");
        assert!(!self.upstream.is_closed(), "{context}");
    }

    async fn assert_ended(
        mut self,
        context: &str,
    ) {
        let frame = tokio::time::timeout(Duration::from_secs(1), self.body.frame())
            .await
            .unwrap_or_else(|_| panic!("{context}: the subscription stayed open"))
            .expect("an ended subscription reports an error frame");
        assert!(frame.is_err(), "{context}");
        assert!(self.upstream.is_closed(), "{context}");
    }
}

fn surface(
    id: &str,
    tenant: &str,
) -> AgentSurface {
    serde_json::from_value(json!({
        "surface_id": id, "name": id, "tenant_id": tenant,
        "access_point": {"listen_address": "https://gateway.example", "route": format!("/{id}"), "protocol": "mcp"},
        "target": {"endpoint": "https://target.example/mcp"}
    }))
    .unwrap()
}

fn gateway() -> crate::gateways::types::Gateway {
    use crate::gateways::types::{Gateway, GatewayCreationType, GatewayOpaPolicyConfig, GatewayStatus, GatewayType};
    Gateway {
        id: "self".into(),
        tenant_id: None,
        name: "self".into(),
        description: String::new(),
        did: "did:example:self".into(),
        issuer_did: None,
        issuer_did_source: None,
        trusted_issuer_dids: Vec::new(),
        gateway_type: GatewayType::SelfGateway,
        status: GatewayStatus::Active,
        creation_type: GatewayCreationType::User,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        exposed_channels: Vec::new(),
        opa_policy_config: Some(GatewayOpaPolicyConfig {
            enabled: true,
            policy: "package gateway.policy\ndefault allow = true".into(),
            policy_definition_id: None,
            ..Default::default()
        }),
    }
}

/// Runs in a child process so access changes made by tests running in
/// parallel cannot end the subscriptions this test expects to stay open.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn access_changes_end_only_subscriptions_in_their_scope() {
    if std::env::var_os(CHILD).is_none() {
        let test_name = std::thread::current()
            .name()
            .unwrap()
            .to_string();
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &test_name, "--nocapture"])
            .env(CHILD, "1")
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        assert!(
            output.status.success(),
            "isolated subscription scope test failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let surfaces = FileSystemAgentSurfaceStore::new(
        directory
            .path()
            .join("surfaces"),
    )
    .await
    .unwrap();
    let alpha = surface("alpha-surface", "alpha");
    let alpha_other = surface("alpha-other-surface", "alpha");
    let bravo = surface("bravo-surface", "bravo");
    for surface in [&alpha, &alpha_other, &bravo] {
        surfaces
            .save(surface)
            .await
            .unwrap();
    }

    let alpha_subscription = OpenSubscription::on(&alpha);
    let mut alpha_other_subscription = OpenSubscription::on(&alpha_other);
    let mut bravo_subscription = OpenSubscription::on(&bravo);
    surfaces
        .save(&alpha)
        .await
        .unwrap();
    alpha_subscription
        .assert_ended("saving alpha's surface ends its subscriptions")
        .await;
    alpha_other_subscription
        .assert_open("saving one surface leaves the tenant's other surfaces open")
        .await;
    bravo_subscription
        .assert_open("saving alpha's surface leaves bravo's subscriptions open")
        .await;

    let strategies = FileSystemJwtVerificationStrategyStore::new(
        directory
            .path()
            .join("strategies"),
    )
    .await
    .unwrap();
    let mut strategy =
        crate::sts::handlers::gateway_self_trust_strategy("https://identity.example/", &json!({"keys": []})).unwrap();
    strategy.tenant_id = Some("alpha".into());
    strategies
        .create(strategy)
        .await
        .unwrap();
    alpha_other_subscription
        .assert_ended("a change to an alpha-owned strategy ends alpha's subscriptions")
        .await;
    bravo_subscription
        .assert_open("a change to an alpha-owned strategy leaves bravo's subscriptions open")
        .await;

    surfaces
        .delete(&alpha.surface_id)
        .await
        .unwrap();
    bravo_subscription
        .assert_open("deleting alpha's surface leaves bravo's subscriptions open")
        .await;

    let proxies = FileSystemMcpProxyStore::new(
        directory
            .path()
            .join("proxies"),
    )
    .await
    .unwrap();
    let mut proxy = McpProxy::new(
        "alpha-proxy".into(),
        String::new(),
        "https://target.example".into(),
        String::new(),
        "/alpha-proxy".into(),
        "/mcp".into(),
    );
    proxy.tenant_id = Some("alpha".into());
    let alpha_proxy_subscription = OpenSubscription::on_proxy(&proxy);
    let alpha_other_subscription = OpenSubscription::on(&alpha_other);
    proxies
        .create(&proxy)
        .await
        .unwrap();
    alpha_proxy_subscription
        .assert_ended("a change to alpha's proxy ends subscriptions on it")
        .await;
    alpha_other_subscription
        .assert_ended("a change to alpha's proxy ends alpha's other subscriptions")
        .await;
    bravo_subscription
        .assert_open("a change to alpha's proxy leaves bravo's subscriptions open")
        .await;

    let providers = FileSystemCredentialProviderStore::new(
        directory
            .path()
            .join("providers"),
    )
    .await
    .unwrap();
    let mut provider: crate::credential_providers::CredentialProvider = serde_json::from_value(json!({
        "id": "provider", "name": "Provider", "provider_id": "provider", "tenant_id": "alpha",
        "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
    }))
    .unwrap();
    let alpha_proxy_subscription = OpenSubscription::on_proxy(&proxy);
    provider = providers
        .create(provider)
        .await
        .unwrap();
    alpha_proxy_subscription
        .assert_ended("a change to an alpha-owned provider ends alpha's proxy subscriptions")
        .await;
    bravo_subscription
        .assert_open("a change to an alpha-owned provider leaves bravo's subscriptions open")
        .await;
    let alpha_proxy_subscription = OpenSubscription::on_proxy(&proxy);
    provider.tenant_id = Some("bravo".into());
    providers
        .update(provider)
        .await
        .unwrap();
    bravo_subscription
        .assert_ended("moving a provider between tenants ends every subscription")
        .await;
    alpha_proxy_subscription
        .assert_ended("moving a provider between tenants ends every subscription")
        .await;

    let bravo_subscription = OpenSubscription::on(&bravo);
    let alpha_subscription = OpenSubscription::on(&alpha_other);
    crate::policies::GatewayPolicyManager::new()
        .update_gateway_policy(&gateway())
        .await
        .unwrap();
    alpha_subscription
        .assert_ended("a gateway policy change ends alpha's subscriptions")
        .await;
    bravo_subscription
        .assert_ended("a gateway policy change ends bravo's subscriptions")
        .await;
}
