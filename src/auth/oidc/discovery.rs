//! The provider's discovery document (`/.well-known/openid-configuration`). It is fetched on first
//! use and cached, so the gateway starts and serves traffic while the provider is unreachable; only
//! dashboard sign-in waits.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};
use url::Url;

use super::config::{OidcConfig, transport_problem};
use super::egress::ProviderEgress;

/// How long a fetched document is used before it is fetched again.
const DISCOVERY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// How long a document whose refresh failed is used before the next attempt.
const RETRY_AFTER_FAILED_REFRESH: Duration = Duration::from_secs(60);
/// The largest discovery document accepted.
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;

/// The parts of the discovery document sign-in uses.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

struct Cached {
    metadata: Arc<ProviderMetadata>,
    refresh_at: Instant,
}

enum Lookup {
    Fresh(Arc<ProviderMetadata>),
    Stale(Arc<ProviderMetadata>),
    Empty,
}

/// The cached discovery document.
pub struct Discovery {
    egress: ProviderEgress,
    cached: RwLock<Option<Cached>>,
    refreshing: Mutex<()>,
    /// When the first fetch last failed, and why.
    first_fetch_failed: Mutex<Option<(Instant, String)>>,
}

impl Discovery {
    pub fn new(egress: ProviderEgress) -> Self {
        Self {
            egress,
            cached: RwLock::new(None),
            refreshing: Mutex::new(()),
            first_fetch_failed: Mutex::new(None),
        }
    }

    /// The provider's metadata, from the cache while it is fresh, otherwise fetched and checked
    /// against `config`. Until a document has been fetched, one call fetches it while the others
    /// wait, and a failed fetch is not tried again for `RETRY_AFTER_FAILED_REFRESH`. Once a
    /// document has been fetched, sign-in keeps using it while the provider cannot be reached: one
    /// call refreshes it, calls meanwhile use the cached document, and a failed refresh is retried
    /// after `RETRY_AFTER_FAILED_REFRESH`.
    pub async fn metadata(
        &self,
        config: &OidcConfig,
    ) -> Result<Arc<ProviderMetadata>, String> {
        let stale = match self.lookup().await {
            Lookup::Fresh(metadata) => return Ok(metadata),
            Lookup::Stale(metadata) => metadata,
            Lookup::Empty => return self.first_fetch(config).await,
        };
        let Ok(_refreshing) = self.refreshing.try_lock() else {
            return Ok(stale);
        };
        if let Lookup::Fresh(metadata) = self.lookup().await {
            return Ok(metadata);
        }
        match self.fetch(config).await {
            Ok(metadata) => {
                let metadata = Arc::new(metadata);
                self.store(metadata.clone(), DISCOVERY_TTL)
                    .await;
                Ok(metadata)
            }
            Err(detail) => {
                warn!(
                    issuer = %config.issuer,
                    %detail,
                    "Refreshing the OpenID provider's discovery document failed; sign-in keeps using the cached one"
                );
                self.store(stale.clone(), RETRY_AFTER_FAILED_REFRESH)
                    .await;
                Ok(stale)
            }
        }
    }

    async fn first_fetch(
        &self,
        config: &OidcConfig,
    ) -> Result<Arc<ProviderMetadata>, String> {
        let _refreshing = self.refreshing.lock().await;
        if let Lookup::Fresh(metadata) | Lookup::Stale(metadata) = self.lookup().await {
            return Ok(metadata);
        }
        let mut failed = self
            .first_fetch_failed
            .lock()
            .await;
        if let Some((at, detail)) = failed.as_ref()
            && at.elapsed() < RETRY_AFTER_FAILED_REFRESH
        {
            return Err(detail.clone());
        }
        match self.fetch(config).await {
            Ok(metadata) => {
                *failed = None;
                let metadata = Arc::new(metadata);
                self.store(metadata.clone(), DISCOVERY_TTL)
                    .await;
                Ok(metadata)
            }
            Err(detail) => {
                *failed = Some((Instant::now(), detail.clone()));
                Err(detail)
            }
        }
    }

    /// Have the next sign-in fetch the document again (after a failure that a moved endpoint could
    /// explain). The cached document is kept, and used if that fetch fails.
    pub async fn mark_stale(&self) {
        if let Some(cached) = self
            .cached
            .write()
            .await
            .as_mut()
        {
            cached.refresh_at = Instant::now();
        }
    }

    async fn lookup(&self) -> Lookup {
        match self
            .cached
            .read()
            .await
            .as_ref()
        {
            Some(cached) if Instant::now() < cached.refresh_at => Lookup::Fresh(cached.metadata.clone()),
            Some(cached) => Lookup::Stale(cached.metadata.clone()),
            None => Lookup::Empty,
        }
    }

    async fn store(
        &self,
        metadata: Arc<ProviderMetadata>,
        use_for: Duration,
    ) {
        *self.cached.write().await = Some(Cached {
            metadata,
            refresh_at: Instant::now() + use_for,
        });
    }

    async fn fetch(
        &self,
        config: &OidcConfig,
    ) -> Result<ProviderMetadata, String> {
        let url = config.discovery_url();
        let client = self
            .egress
            .client_for(&url, Duration::from_secs(crate::http_client::SHORT_TIMEOUT_SECS))
            .await
            .map_err(|e| format!("discovery address refused: {e}"))?;
        let response = client
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("discovery request failed: {}", e.without_url()))?;
        if !response.status().is_success() {
            return Err(format!("discovery answered HTTP {}", response.status()));
        }
        let limits = crate::proxy::upstream_body::UpstreamBodyLimits::new(
            MAX_DISCOVERY_BYTES,
            None,
            crate::http_client::SHORT_TIMEOUT_SECS,
        );
        let body = crate::proxy::upstream_body::read_bounded(response, limits)
            .await
            .map_err(|e| format!("discovery document could not be read: {e}"))?;
        let metadata: ProviderMetadata =
            serde_json::from_slice(&body).map_err(|e| format!("discovery document is not usable: {e}"))?;
        check(&metadata, config)?;
        for (field, endpoint) in [("token_endpoint", &metadata.token_endpoint), ("jwks_uri", &metadata.jwks_uri)] {
            if let Some(refusal) = self
                .egress
                .refuses(endpoint)
                .await
            {
                return Err(format!("discovery {field} refused: {refusal}"));
            }
        }
        info!(issuer = %metadata.issuer, "Fetched the OpenID provider's discovery document");
        Ok(metadata)
    }
}

/// Check a discovery document against `oidc.json`: the issuer it names, the transport of every
/// endpoint, and what the provider says it supports.
fn check(
    metadata: &ProviderMetadata,
    config: &OidcConfig,
) -> Result<(), String> {
    if metadata.issuer != config.issuer {
        return Err(format!(
            "discovery names issuer {} but oidc.json has {}; they must be identical",
            metadata.issuer, config.issuer
        ));
    }
    for (field, endpoint) in [
        ("authorization_endpoint", &metadata.authorization_endpoint),
        ("token_endpoint", &metadata.token_endpoint),
        ("jwks_uri", &metadata.jwks_uri),
    ] {
        let url = Url::parse(endpoint).map_err(|_| format!("discovery {field} is not an absolute URL"))?;
        if let Some(problem) = transport_problem(&url) {
            return Err(format!("discovery {field} {problem}"));
        }
    }
    if let Some(methods) = &metadata.code_challenge_methods_supported
        && !methods
            .iter()
            .any(|method| method == "S256")
    {
        return Err("the provider does not support PKCE with S256".to_string());
    }
    let auth_method = config
        .token_endpoint_auth_method
        .as_str();
    if let Some(methods) = &metadata.token_endpoint_auth_methods_supported
        && !methods
            .iter()
            .any(|method| method == auth_method)
    {
        return Err(format!("the provider does not accept token_endpoint_auth_method {auth_method}"));
    }
    if let Some(algorithms) = &metadata.id_token_signing_alg_values_supported
        && !algorithms
            .iter()
            .filter_map(|offered| {
                offered
                    .parse::<jsonwebtoken::Algorithm>()
                    .ok()
            })
            .any(|offered| {
                config
                    .id_token_signing_algs
                    .contains(&offered)
            })
    {
        warn!(
            offered = ?algorithms,
            allowed = ?config.id_token_signing_algs,
            "The provider signs ID tokens with none of the algorithms in id_token_signing_algs; sign-in will fail"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::test_support::{StubProvider, config_for, metadata_for};

    async fn cached_from(provider: &StubProvider) -> (Discovery, OidcConfig, Arc<ProviderMetadata>) {
        let discovery = Discovery::new(provider.egress());
        let config = config_for(&provider.issuer);
        let first = discovery
            .metadata(&config)
            .await
            .unwrap();
        (discovery, config, first)
    }

    #[tokio::test]
    async fn a_failed_refresh_keeps_the_cached_document_and_waits_before_retrying() {
        let provider = StubProvider::start().await;
        let (discovery, config, first) = cached_from(&provider).await;
        provider.set_discovery_down(true);
        discovery.mark_stale().await;

        let served = discovery
            .metadata(&config)
            .await
            .unwrap();
        assert!(Arc::ptr_eq(&first, &served), "the cached document is used");
        assert_eq!(provider.discovery_fetches(), 2);

        discovery
            .metadata(&config)
            .await
            .unwrap();
        assert_eq!(provider.discovery_fetches(), 2, "no retry before RETRY_AFTER_FAILED_REFRESH");

        provider.set_discovery_down(false);
        discovery.mark_stale().await;
        let refreshed = discovery
            .metadata(&config)
            .await
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &refreshed), "a successful refresh replaces it");
        assert_eq!(provider.discovery_fetches(), 3);
    }

    #[tokio::test]
    async fn without_a_cached_document_a_failed_fetch_is_an_error() {
        let provider = StubProvider::start().await;
        provider.set_discovery_down(true);
        let discovery = Discovery::new(provider.egress());

        let refused = discovery
            .metadata(&config_for(&provider.issuer))
            .await
            .unwrap_err();

        assert!(refused.contains("HTTP 503"), "{refused}");
    }

    #[tokio::test]
    async fn without_a_cached_document_a_failed_fetch_is_not_tried_again_at_once() {
        let provider = StubProvider::start().await;
        provider.set_discovery_down(true);
        let discovery = Discovery::new(provider.egress());
        let config = config_for(&provider.issuer);

        for _ in 0..3 {
            let refused = discovery
                .metadata(&config)
                .await
                .unwrap_err();
            assert!(refused.contains("HTTP 503"), "{refused}");
        }
        assert_eq!(provider.discovery_fetches(), 1);

        provider.set_discovery_down(false);
        discovery
            .first_fetch_failed
            .lock()
            .await
            .as_mut()
            .unwrap()
            .0 -= RETRY_AFTER_FAILED_REFRESH;
        discovery
            .metadata(&config)
            .await
            .unwrap();
        assert_eq!(provider.discovery_fetches(), 2);
    }

    #[tokio::test]
    async fn concurrent_first_fetches_reach_the_provider_once() {
        let provider = StubProvider::start().await;
        let discovery = Arc::new(Discovery::new(provider.egress()));
        let config = Arc::new(config_for(&provider.issuer));

        let fetches = (0..10).map(|_| {
            let discovery = discovery.clone();
            let config = config.clone();
            tokio::spawn(async move {
                discovery
                    .metadata(&config)
                    .await
            })
        });
        for fetched in futures::future::join_all(fetches).await {
            fetched.unwrap().unwrap();
        }
        assert_eq!(provider.discovery_fetches(), 1);
    }

    #[tokio::test]
    async fn a_document_naming_a_token_endpoint_or_key_set_on_a_refused_address_is_refused() {
        for field in ["token_endpoint", "jwks_uri"] {
            let provider = StubProvider::start().await;
            provider.override_discovery(field, "https://169.254.169.254/latest");
            let discovery = Discovery::new(provider.egress());

            let refused = discovery
                .metadata(&config_for(&provider.issuer))
                .await
                .unwrap_err();

            assert!(refused.contains(&format!("discovery {field} refused")), "{field}: {refused}");
        }
    }

    #[tokio::test]
    async fn while_one_call_refreshes_the_others_use_the_cached_document() {
        let provider = StubProvider::start().await;
        let (discovery, config, first) = cached_from(&provider).await;
        discovery.mark_stale().await;
        let _refreshing = discovery
            .refreshing
            .try_lock()
            .unwrap();

        let served = discovery
            .metadata(&config)
            .await
            .unwrap();

        assert!(Arc::ptr_eq(&first, &served));
        assert_eq!(provider.discovery_fetches(), 1, "the waiting call does not fetch");
    }

    #[tokio::test]
    async fn a_provider_on_a_refused_address_is_not_fetched() {
        let provider = StubProvider::start().await;
        let discovery = Discovery::new(ProviderEgress::default());

        let refused = discovery
            .metadata(&config_for(&provider.issuer))
            .await
            .unwrap_err();

        assert!(refused.contains("discovery address refused"), "{refused}");
        assert_eq!(provider.discovery_fetches(), 0);
    }

    #[test]
    fn a_document_naming_another_issuer_is_refused() {
        let config = config_for("https://idp.example.com");
        let mut metadata = metadata_for("https://idp.example.com");
        assert!(check(&metadata, &config).is_ok());

        metadata.issuer = "https://idp.example.com/".to_string();
        let refused = check(&metadata, &config).unwrap_err();
        assert!(refused.contains("must be identical"), "{refused}");
    }

    #[test]
    fn every_endpoint_must_be_https() {
        let config = config_for("https://idp.example.com");
        for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let mut metadata = metadata_for("https://idp.example.com");
            let plain = "http://idp.example.com/endpoint".to_string();
            match field {
                "authorization_endpoint" => metadata.authorization_endpoint = plain,
                "token_endpoint" => metadata.token_endpoint = plain,
                _ => metadata.jwks_uri = plain,
            }
            let refused = check(&metadata, &config).unwrap_err();
            assert!(refused.contains(field) && refused.contains("https://"), "{refused}");
        }
    }

    #[test]
    fn a_provider_without_s256_pkce_is_refused() {
        let config = config_for("https://idp.example.com");
        let mut metadata = metadata_for("https://idp.example.com");
        metadata.code_challenge_methods_supported = Some(vec!["plain".to_string()]);
        assert!(
            check(&metadata, &config)
                .unwrap_err()
                .contains("S256")
        );

        metadata.code_challenge_methods_supported = None;
        assert!(check(&metadata, &config).is_ok(), "a provider that does not say is tried");
    }

    #[test]
    fn the_client_authentication_method_must_be_one_the_provider_accepts() {
        let config = config_for("https://idp.example.com");
        let mut metadata = metadata_for("https://idp.example.com");
        metadata.token_endpoint_auth_methods_supported = Some(vec!["client_secret_post".to_string()]);
        assert!(
            check(&metadata, &config)
                .unwrap_err()
                .contains("client_secret_basic")
        );

        metadata.token_endpoint_auth_methods_supported =
            Some(vec!["client_secret_post".to_string(), "client_secret_basic".to_string()]);
        assert!(check(&metadata, &config).is_ok());
    }
}
