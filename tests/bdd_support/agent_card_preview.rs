use std::time::{Duration, Instant};

use reqwest::{Client, header};
use serde_json::{Value, json};

use crate::bdd_support::admin_client::{AdminApiClient, RecordedResponse, recorded_response};

const TENANT_HEADER: &str = "x-external-account";

/// Who asks the gateway for an agent card preview.
#[derive(Debug, Clone)]
pub enum PreviewCaller {
    Operator,
    Tenant(String),
    ViewOnly,
}

/// The agent card preview endpoints of a running gateway, called as an operator or as a
/// personal access token the operator minted.
pub struct CardPreviewApi<'a> {
    pub port: u16,
    pub operator: &'a AdminApiClient,
}

impl CardPreviewApi<'_> {
    fn url(
        &self,
        surface_id: &str,
        suffix: &str,
    ) -> String {
        format!("http://127.0.0.1:{}/api/v1/surfaces/{surface_id}/agent-card{suffix}", self.port)
    }

    async fn token_client(
        &self,
        caller: &PreviewCaller,
    ) -> Client {
        let request = match caller {
            PreviewCaller::Operator => unreachable!("an operator uses its own session"),
            PreviewCaller::Tenant(tenant) => json!({
                "name": "card preview token",
                "scopes": [],
                "resource_pattern": "TENANT:${x-external-account}:surfaces:.*",
                "required_headers": [{"name": TENANT_HEADER, "pattern": tenant}],
            }),
            PreviewCaller::ViewOnly => json!({"name": "card preview token", "scopes": ["surfaces.view"]}),
        };
        let mut headers = header::HeaderMap::new();
        if let PreviewCaller::Tenant(tenant) = caller {
            headers.insert(TENANT_HEADER, header::HeaderValue::from_str(tenant).expect("a tenant header"));
        }
        self.operator
            .personal_access_token_client(&request, headers)
            .await
    }

    async fn send(
        &self,
        caller: &PreviewCaller,
        surface_id: &str,
        refresh: bool,
    ) -> RecordedResponse {
        if matches!(caller, PreviewCaller::Operator) {
            let (method, suffix) = if refresh {
                (reqwest::Method::POST, "/refresh")
            } else {
                (reqwest::Method::GET, "")
            };
            let path = format!("/v1/surfaces/{surface_id}/agent-card{suffix}");
            return self
                .operator
                .send_recorded_json::<Value>(method, &path, None)
                .await
                .expect("calling the agent card preview");
        }
        let client = self
            .token_client(caller)
            .await;
        let request = if refresh {
            client.post(self.url(surface_id, "/refresh"))
        } else {
            client.get(self.url(surface_id, ""))
        };
        recorded_response(
            request
                .send()
                .await
                .expect("calling the agent card preview"),
        )
        .await
        .expect("reading the agent card preview")
    }

    /// The preview once the surface is running on its listener.
    pub async fn read(
        &self,
        caller: &PreviewCaller,
        surface_id: &str,
    ) -> RecordedResponse {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            let response = self
                .send(caller, surface_id, false)
                .await;
            if response.body["unsupported_reason"] != "not_running" || Instant::now() >= deadline {
                return response;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    pub async fn refresh(
        &self,
        caller: &PreviewCaller,
        surface_id: &str,
    ) -> RecordedResponse {
        self.send(caller, surface_id, true)
            .await
    }
}
