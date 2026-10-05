use std::time::Duration;

use async_trait::async_trait;

use super::didcomm::client::DIDCommClient;
use super::didcomm::mediator::{MediatorAuthTestResult, MediatorTrustPingResult};

#[async_trait]
#[allow(dead_code)]
pub trait DIDCommContract: Send + Sync {
    async fn cache_did_document(
        &self,
        did: &str,
        did_document: serde_json::Value,
    ) -> Result<(), String>;

    async fn test_mediator_authentication(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorAuthTestResult, String>;

    async fn trust_ping_mediator(
        &self,
        mediator_did: &str,
        timeout: Duration,
    ) -> Result<MediatorTrustPingResult, String>;
}

pub struct CommClient {
    didcomm: Box<dyn DIDCommContract>,
}

#[allow(dead_code)]
impl CommClient {
    fn new(didcomm: DIDCommClient) -> Self {
        Self { didcomm: Box::new(didcomm) }
    }

    pub async fn new_with_didcomm(
        did: String,
        secrets: Vec<affinidi_tdk_common::secrets_resolver::secrets::Secret>,
        mediator_did: Option<String>,
        alias: Option<String>,
    ) -> Result<Self, String> {
        let didcomm = DIDCommClient::new(did, secrets, mediator_did, alias).await?;
        Ok(Self::new(didcomm))
    }

    pub fn didcomm(&self) -> &dyn DIDCommContract {
        self.didcomm.as_ref()
    }
}
