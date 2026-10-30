//! A client of a harness gateway's admin API, and the listen address a surface
//! saved through it uses to run on the harness listener.

use serde_json::Value;

use super::GatewayHarness;

/// Sends admin API requests to a harness gateway with the client
/// [`configure_admin_api`](super::configure_admin_api) returns.
pub(crate) struct AdminApi {
    pub(crate) client: reqwest::Client,
    pub(crate) base: String,
}

impl AdminApi {
    pub(crate) fn new(
        client: reqwest::Client,
        harness: &GatewayHarness,
    ) -> Self {
        Self {
            client,
            base: harness.gateway_base.clone(),
        }
    }

    /// The status, body and headers of the answer. A body that is not JSON is
    /// returned as a JSON string.
    pub(crate) async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> (u16, Value, reqwest::header::HeaderMap) {
        let response = request
            .send()
            .await
            .expect("admin API request");
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let text = response
            .text()
            .await
            .unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::String(text)), headers)
    }

    pub(crate) fn url(
        &self,
        path: &str,
    ) -> String {
        format!("{}/api/v1/{path}", self.base)
    }

    pub(crate) async fn post(
        &self,
        path: &str,
        body: &Value,
    ) -> (u16, Value) {
        let (status, body, _) = self
            .send(
                self.client
                    .post(self.url(path))
                    .json(body),
            )
            .await;
        (status, body)
    }
}

/// The origin of the harness listener under the `localhost` name, which a
/// surface's `listen_address` uses to run on that listener.
pub(crate) fn listener_origin(harness: &GatewayHarness) -> String {
    let mut listener = url::Url::parse(&harness.gateway_base).expect("gateway URL");
    listener
        .set_host(Some("localhost"))
        .expect("host");
    listener
        .origin()
        .ascii_serialization()
}
