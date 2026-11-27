//! Outbound calls to the OpenID provider's discovery document and token endpoint. Each address is
//! vetted with the Configured egress policy (cloud metadata, loopback and unspecified addresses
//! refused, private networks allowed) and called on a client pinned to the addresses it resolved
//! to, with redirects refused, so a host cannot rebind between the check and the call. The JWKS is
//! fetched by [`crate::jwt_bearer::JwksClient`], which vets it the same way.

use std::time::Duration;

/// The exact addresses the provider's endpoints may use although the Configured policy refuses
/// them: the BDD egress allow-list under `AG_TEST_MODE`, or a test's stub provider. `None` in
/// production.
#[derive(Debug, Clone, Default)]
pub struct ProviderEgress {
    exact_allowlist: Option<String>,
}

impl ProviderEgress {
    pub fn from_environment() -> Self {
        Self {
            exact_allowlist: crate::egress::bdd_egress_allowlist(),
        }
    }

    /// Egress that admits the stub provider at `origin` on loopback.
    #[cfg(test)]
    pub fn allowing(origin: &str) -> Self {
        Self {
            exact_allowlist: Some(origin.to_string()),
        }
    }

    /// Whether the policy refuses `url`, for a check made when the discovery document is read.
    pub async fn refuses(
        &self,
        url: &str,
    ) -> Option<String> {
        let raw = url.to_string();
        let allowlist = self.exact_allowlist.clone();
        match tokio::task::spawn_blocking(move || crate::egress::vet_configured(&raw, allowlist.as_deref())).await {
            Ok(Ok(_)) => None,
            Ok(Err(error)) => Some(error.to_string()),
            Err(error) => Some(format!("the address check failed: {error}")),
        }
    }

    /// A redirect-off client pinned to the addresses `url` resolves to, once the policy admits
    /// them.
    pub async fn client_for(
        &self,
        url: &str,
        timeout: Duration,
    ) -> Result<reqwest::Client, String> {
        let raw = url.to_string();
        let allowlist = self.exact_allowlist.clone();
        tokio::task::spawn_blocking(move || {
            crate::egress::pinned_configured_direct_client(&raw, timeout, allowlist.as_deref())
        })
        .await
        .map_err(|error| format!("the address check failed: {error}"))?
        .map(|(client, _target)| client)
        .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_and_cloud_metadata_are_refused_unless_a_test_admits_the_loopback_one() {
        let production = ProviderEgress::default();
        for url in ["http://127.0.0.1:9/token", "http://169.254.169.254/latest/meta-data"] {
            assert!(
                production
                    .refuses(url)
                    .await
                    .is_some(),
                "{url}"
            );
            assert!(
                production
                    .client_for(url, Duration::from_secs(1))
                    .await
                    .is_err(),
                "{url}"
            );
        }

        let admitted = ProviderEgress::allowing("http://127.0.0.1:9");
        assert_eq!(
            admitted
                .refuses("http://127.0.0.1:9/token")
                .await,
            None
        );
        assert!(
            admitted
                .refuses("http://169.254.169.254/latest/meta-data")
                .await
                .is_some(),
            "an allow-list never admits cloud metadata"
        );
    }
}
