use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::bdd_support::gateway_process::G2G_TEST_AUTH_TOKEN;
use crate::bdd_support::http::collect_headers;

#[derive(Debug, Clone)]
pub struct RecordedResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct AdminApiClient {
    base_url: String,
    root_url: String,
    http: Client,
    test_token: String,
    username: String,
    session_token: Arc<RwLock<Option<String>>>,
}

impl AdminApiClient {
    pub fn new(
        port: u16,
        test_token: impl Into<String>,
        username: impl Into<String>,
    ) -> Self {
        Self {
            base_url: format!("http://127.0.0.1:{port}/api"),
            root_url: format!("http://127.0.0.1:{port}"),
            http: Client::new(),
            test_token: test_token.into(),
            username: username.into(),
            session_token: Arc::new(RwLock::new(None)),
        }
    }

    pub async fn wait_until_healthy(
        &self,
        timeout: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            match self
                .http
                .get(self.admin_url("/v1/health"))
                .send()
                .await
            {
                Ok(response) if response.status().is_success() => return Ok(()),
                Ok(_) | Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(response) => bail!("health check failed with status {}", response.status()),
                Err(error) => bail!("health check failed: {error}"),
            }
        }
    }

    pub async fn bootstrap_test_session(&self) -> Result<()> {
        self.bootstrap_test_session_with_role("administrator")
            .await
    }

    pub async fn bootstrap_test_session_with_role(
        &self,
        role: &str,
    ) -> Result<()> {
        let response = self
            .bootstrap_test_session_recorded_with_role(role)
            .await?;
        if response.status >= 400 {
            bail!("test-support login failed with status {}: {}", response.status, response.body);
        }
        Ok(())
    }

    pub async fn bootstrap_test_session_recorded_with_role(
        &self,
        role: &str,
    ) -> Result<RecordedResponse> {
        let url = format!("{}/api/internal/test-support/auth/login", self.root_url);
        let response = self
            .http
            .post(&url)
            .header("X-Test-Token", &self.test_token)
            .header("Content-Type", "application/json")
            .json(&serde_json::json!({ "username": self.username, "role": role }))
            .send()
            .await
            .with_context(|| format!("test-support login request failed: {url}"))?;
        let recorded = recorded_response(response).await?;
        if recorded.status < 400
            && let Some(token) = recorded
                .body
                .get("session_token")
                .and_then(Value::as_str)
        {
            *self
                .session_token
                .write()
                .expect("session token write lock") = Some(token.to_string());
        }
        Ok(recorded)
    }

    pub async fn send_json<B, R>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<R>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        let url = self.admin_url(path);
        let response = self
            .send_request(method, &url, body)
            .await?;
        let response_status = response.status();
        let response_body = response
            .text()
            .await
            .context("read response body")?;

        if !response_status.is_success() {
            bail!("request to {url} failed with status {response_status}: {response_body}");
        }

        serde_json::from_str(&response_body)
            .with_context(|| format!("failed to decode JSON response from {url}: {response_body}"))
    }

    pub async fn send_recorded_json<B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<RecordedResponse>
    where
        B: Serialize + ?Sized,
    {
        let url = self.admin_url(path);
        let response = self
            .send_request(method, &url, body)
            .await?;
        recorded_response(response).await
    }

    pub async fn create_surface_recorded(
        &self,
        surface: &Value,
    ) -> Result<RecordedResponse> {
        self.send_recorded_json(Method::POST, "/v1/surfaces", Some(surface))
            .await
    }

    pub async fn get_surface_recorded(
        &self,
        surface_id: &str,
    ) -> Result<RecordedResponse> {
        self.send_recorded_json::<Value>(Method::GET, &format!("/v1/surfaces/{surface_id}"), None)
            .await
    }

    pub async fn update_surface_recorded(
        &self,
        surface_id: &str,
        surface: &Value,
    ) -> Result<RecordedResponse> {
        self.send_recorded_json(Method::PUT, &format!("/v1/surfaces/{surface_id}"), Some(surface))
            .await
    }

    pub async fn delete_surface_recorded(
        &self,
        surface_id: &str,
    ) -> Result<RecordedResponse> {
        self.send_recorded_json::<Value>(Method::DELETE, &format!("/v1/surfaces/{surface_id}"), None)
            .await
    }

    pub async fn list_gateways_recorded(&self) -> Result<RecordedResponse> {
        self.send_recorded_json::<Value>(Method::GET, "/v1/gateways", None)
            .await
    }

    pub async fn create_surface_policy_definition_recorded(
        &self,
        id: &str,
        name: &str,
        description: &str,
        policy: &str,
    ) -> Result<RecordedResponse> {
        self.send_recorded_json(
            Method::POST,
            "/v1/policy-definitions",
            Some(&CreatePolicyDefinitionRequest {
                id: id.to_string(),
                name: name.to_string(),
                description: description.to_string(),
                policy_type: "agent_surface".to_string(),
                policy: policy.to_string(),
                enabled: true,
                created_at: chrono::Utc::now().to_rfc3339(),
            }),
        )
        .await
    }

    pub async fn update_surface_policy_reference_recorded(
        &self,
        surface_id: &str,
        mut surface: Value,
        slot: SurfacePolicySlot,
        policy_definition_id: &str,
    ) -> Result<RecordedResponse> {
        slot.set_reference(&mut surface, policy_definition_id);
        self.update_surface_recorded(surface_id, &surface)
            .await
    }

    /// Scrape the gateway's Prometheus exposition (`/v1/metrics/prometheus`).
    /// This endpoint is public in test mode, so no session token is required.
    pub async fn prometheus_metrics(&self) -> Result<String> {
        let url = self.admin_url("/v1/metrics/prometheus");
        let response = self
            .http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("scrape prometheus metrics: {url}"))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .context("read prometheus metrics body")?;
        if !status.is_success() {
            bail!("prometheus metrics scrape failed with status {status}: {body}");
        }
        Ok(body)
    }

    // ── Trust Registry (surface-BDD) ───────────────────────────────────

    pub async fn create_trust_registry(
        &self,
        name: &str,
        description: &str,
        oob_url: &str,
    ) -> Result<TrustRegistryRecord> {
        self.send_json(
            Method::POST,
            "/v1/trust-registries",
            Some(&CreateTrustRegistryRequest {
                name: name.to_string(),
                description: description.to_string(),
                oob_url: oob_url.to_string(),
                did_method: Some("peer".to_string()),
            }),
        )
        .await
    }

    pub async fn get_trust_registry(
        &self,
        id: &str,
    ) -> Result<TrustRegistryRecord> {
        self.send_json::<(), _>(Method::GET, &format!("/v1/trust-registries/{id}"), None)
            .await
    }

    pub async fn wait_for_trust_registry_connected(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<TrustRegistryRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = match self
                .get_trust_registry(id)
                .await
            {
                Ok(tr) if tr.connection_status == "connected" => return Ok(tr),
                Ok(tr) => tr.connection_status.clone(),
                Err(error) => format!("error: {error}"),
            };
            if Instant::now() >= deadline {
                bail!("timed out waiting for trust registry {id} to connect; last status: {snapshot}");
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    /// PATCH a surface with `application/merge-patch+json`.
    pub async fn patch_surface(
        &self,
        surface_id: &str,
        patch: &Value,
    ) -> Result<Value> {
        let url = self.admin_url(&format!("/v1/surfaces/{surface_id}"));
        let mut request = self.http.patch(&url);
        if let Some(token) = self
            .session_token
            .read()
            .expect("session token read lock")
            .clone()
        {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .header("Content-Type", "application/merge-patch+json")
            .json(patch)
            .send()
            .await
            .with_context(|| format!("PATCH {url}"))?;
        let response_status = response.status();
        let response_body = response
            .text()
            .await
            .context("read PATCH response body")?;
        if !response_status.is_success() {
            bail!("PATCH {url} failed with status {response_status}: {response_body}");
        }
        serde_json::from_str(&response_body)
            .with_context(|| format!("decode PATCH response from {url}: {response_body}"))
    }

    fn admin_url(
        &self,
        path: &str,
    ) -> String {
        if path.starts_with("/api/") {
            format!("{}{}", self.root_url, path)
        } else {
            format!("{}{}", self.base_url, path)
        }
    }

    async fn send_request<B>(
        &self,
        method: Method,
        url: &str,
        body: Option<&B>,
    ) -> Result<reqwest::Response>
    where
        B: Serialize + ?Sized,
    {
        let mut request = self.http.request(method, url);

        if let Some(token) = self
            .session_token
            .read()
            .expect("session token read lock")
            .clone()
        {
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        if let Some(body) = body {
            request = request.json(body);
        }

        request
            .send()
            .await
            .with_context(|| format!("request failed: {url}"))
    }
}

pub async fn recorded_response(response: reqwest::Response) -> Result<RecordedResponse> {
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let body = response
        .json()
        .await
        .unwrap_or(serde_json::Value::Null);

    Ok(RecordedResponse { status, headers, body })
}

#[derive(Debug, Clone, Copy)]
pub enum SurfacePolicySlot {
    Request,
    Response,
}

impl SurfacePolicySlot {
    fn set_reference(
        self,
        surface: &mut Value,
        policy_definition_id: &str,
    ) {
        let field = match self {
            Self::Request => "policy",
            Self::Response => "response_policy",
        };
        surface["target"][field] = serde_json::json!({
            "policy_definition_id": policy_definition_id
        });
    }
}

#[derive(Debug, Serialize)]
struct CreatePolicyDefinitionRequest {
    id: String,
    name: String,
    description: String,
    policy_type: String,
    policy: String,
    enabled: bool,
    created_at: String,
}

#[cfg(test)]
mod tests {
    #[test]
    fn surface_policy_slot_sets_expected_target_reference() {
        let mut surface = serde_json::json!({ "target": {} });

        super::SurfacePolicySlot::Response.set_reference(&mut surface, "policy-alpha");

        assert_eq!(surface["target"]["response_policy"]["policy_definition_id"], "policy-alpha");
    }
}

const TEST_USERNAME: &str = "g2g-bdd-admin";

/// Mediator-shaped payload used by `GatewayAdminClient::create_mediator`. The
/// admin client deliberately does NOT depend on the `Mediator` trait so it
/// stays transport-agnostic.
#[derive(Debug, Clone)]
pub struct ExternalMediatorBlob {
    pub did: String,
    pub did_document: Option<Value>,
}

#[derive(Clone)]
pub struct GatewayAdminClient {
    client: AdminApiClient,
}

impl GatewayAdminClient {
    pub fn new(port: u16) -> Self {
        Self {
            client: AdminApiClient::new(port, G2G_TEST_AUTH_TOKEN, TEST_USERNAME),
        }
    }

    pub async fn wait_until_healthy(
        &self,
        timeout: Duration,
    ) -> Result<()> {
        self.client
            .wait_until_healthy(timeout)
            .await
    }

    /// Authenticate against the gateway's internal test-support endpoint and
    /// cache the session token. Only available when the gateway runs with
    /// `AG_TEST_MODE=true`.
    pub async fn bootstrap_test_session(&self) -> Result<()> {
        self.client
            .bootstrap_test_session()
            .await
    }

    /// Scrape the gateway's Prometheus exposition (`/v1/metrics/prometheus`).
    pub async fn prometheus_metrics(&self) -> Result<String> {
        self.client
            .prometheus_metrics()
            .await
    }

    /// PATCH a surface with `application/merge-patch+json`. Delegates to the
    /// inner `AdminApiClient` (which already has the session token from
    /// [`Self::bootstrap_test_session`]).
    pub async fn patch_surface(
        &self,
        surface_id: &str,
        patch: &Value,
    ) -> Result<Value> {
        self.client
            .patch_surface(surface_id, patch)
            .await
    }

    /// Enable the audit log and the `trust_checks` category on this gateway so
    /// per-element Trust Check outcomes are written to `/v1/audit`. Idempotent.
    pub async fn enable_trust_check_audit(&self) -> Result<()> {
        let response = self
            .client
            .send_recorded_json(
                Method::POST,
                "/v1/settings",
                Some(&serde_json::json!({
                    "audit_enabled": true,
                    "audit_categories": {
                        "policies": true,
                        "trust_checks": true,
                        "identity": true
                    }
                })),
            )
            .await?;
        if !(200..300).contains(&response.status) {
            bail!("enable trust-check audit failed with status {}: {}", response.status, response.body);
        }
        Ok(())
    }

    /// Read the most recent audit events (`GET /v1/audit?limit=200`), returning
    /// the raw `events` array (newest first).
    pub async fn read_audit_events(&self) -> Result<Vec<Value>> {
        let response = self
            .client
            .send_recorded_json::<Value>(Method::GET, "/v1/audit?limit=200", None)
            .await?;
        if !(200..300).contains(&response.status) {
            bail!("read audit events failed with status {}: {}", response.status, response.body);
        }
        Ok(response
            .body
            .get("events")
            .and_then(|events| events.as_array())
            .cloned()
            .unwrap_or_default())
    }

    pub async fn create_mediator(
        &self,
        name: &str,
        description: &str,
        mediator: &ExternalMediatorBlob,
    ) -> Result<MediatorRecord> {
        self.send_json(
            Method::POST,
            "/v1/mediators",
            Some(&CreateMediatorRequest {
                name: name.to_string(),
                description: description.to_string(),
                did: mediator.did.clone(),
                did_document: mediator.did_document.clone(),
            }),
        )
        .await
    }

    pub async fn list_gateways(&self) -> Result<Vec<GatewayRecord>> {
        self.send_json::<(), _>(Method::GET, "/v1/gateways", None)
            .await
    }

    pub async fn find_self_gateway(&self) -> Result<GatewayRecord> {
        let gateways = self.list_gateways().await?;
        gateways
            .into_iter()
            .find(|gateway| gateway.gateway_type == GatewayType::SelfGateway)
            .context("self gateway not found")
    }

    pub async fn get_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<GatewayRecord> {
        self.send_json::<(), _>(Method::GET, &format!("/v1/gateways/{gateway_id}"), None)
            .await
    }

    /// Forget the attested issuer DID of a Remote gateway
    /// (`DELETE /v1/gateways/{id}/issuer`); it is re-established by the next
    /// issuer exchange.
    pub async fn forget_remote_gateway_issuer(
        &self,
        gateway_id: &str,
    ) -> Result<GatewayRecord> {
        self.send_json::<(), _>(Method::DELETE, &format!("/v1/gateways/{gateway_id}/issuer"), None)
            .await
    }

    /// Trust an issuer DID for presentations arriving over a Remote gateway's
    /// connection (`POST /v1/gateways/{id}/trusted-issuers`).
    pub async fn add_trusted_issuer_did(
        &self,
        gateway_id: &str,
        issuer_did: &str,
    ) -> Result<GatewayRecord> {
        self.send_json(
            Method::POST,
            &format!("/v1/gateways/{gateway_id}/trusted-issuers"),
            Some(&serde_json::json!({ "issuer_did": issuer_did })),
        )
        .await
    }

    /// Ask the gateway to run the issuer exchange with a paired Remote gateway
    /// and return the verified issuer DID (`POST /v1/gateways/{id}/issuer`).
    pub async fn request_gateway_issuer(
        &self,
        gateway_id: &str,
    ) -> Result<GatewayIssuerResponse> {
        self.send_json::<(), _>(Method::POST, &format!("/v1/gateways/{gateway_id}/issuer"), None)
            .await
    }

    /// Create an enabled `agent_surface` policy definition the surface can
    /// reference from `target.policy`.
    pub async fn create_surface_policy_definition(
        &self,
        id: &str,
        name: &str,
        policy: &str,
    ) -> Result<()> {
        let response = self
            .client
            .create_surface_policy_definition_recorded(id, name, name, policy)
            .await?;
        if !(200..300).contains(&response.status) {
            bail!("create policy definition {id} failed with status {}: {}", response.status, response.body);
        }
        Ok(())
    }

    pub async fn create_connection_point(
        &self,
        gateway_id: &str,
        mediator_id: &str,
        name: &str,
        description: &str,
        secret: &str,
        did_method: &str,
    ) -> Result<ConnectionPointRecord> {
        let response: CreateConnectionPointResponse = self
            .send_json(
                Method::POST,
                "/v1/connection-points",
                Some(&CreateConnectionPointRequest {
                    gateway_id: gateway_id.to_string(),
                    mediator_id: mediator_id.to_string(),
                    name: name.to_string(),
                    description: description.to_string(),
                    expiry_seconds: Some(3600),
                    secret: secret.to_string(),
                    did_method: Some(did_method.to_string()),
                }),
            )
            .await?;
        Ok(response.connection_point)
    }

    pub async fn connect_via_oob(
        &self,
        oob_url: &str,
        secret: &str,
        name: &str,
        description: &str,
        did_method: &str,
    ) -> Result<GatewayRecord> {
        let response: ConnectViaOobResponse = self
            .send_json(
                Method::POST,
                "/v1/gateways/connect-via-oob",
                Some(&ConnectViaOobRequest {
                    oob_url: oob_url.to_string(),
                    secret: secret.to_string(),
                    name: name.to_string(),
                    description: description.to_string(),
                    did_method: Some(did_method.to_string()),
                }),
            )
            .await?;
        Ok(response.gateway)
    }

    pub async fn approve_gateway(
        &self,
        gateway_id: &str,
        name: &str,
        description: &str,
    ) -> Result<GatewayRecord> {
        // Retry on the specific transient error where the remote gateway has
        // already been marked `AwaitingApproval` (which is what the caller
        // polls for before calling approve) but the pending connection
        // context — populated on a separate write path in the WebSocket
        // listener — has not landed yet. The two writes are not atomic in
        // the gateway, so under load the harness can race the second write.
        // Bounded at ~5s total (25 * 200ms) so a genuine deletion still
        // surfaces as a hard failure.
        let body = ApproveGatewayRequest {
            name: name.to_string(),
            description: description.to_string(),
        };
        let path = format!("/v1/gateways/{gateway_id}/approve");
        let mut last_err = None;
        for _ in 0..25 {
            match self
                .send_json::<_, GatewayRecord>(Method::POST, &path, Some(&body))
                .await
            {
                Ok(record) => return Ok(record),
                Err(err) => {
                    let msg = format!("{err:#}");
                    if msg.contains("Pending connection context not found") {
                        last_err = Some(err);
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        continue;
                    }
                    return Err(err);
                }
            }
        }
        Err(last_err.expect("retry loop returned without success or error"))
    }

    pub async fn ping_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<GatewayPingResponse> {
        self.send_json::<(), _>(Method::POST, &format!("/v1/gateways/{gateway_id}/ping"), None)
            .await
    }

    pub async fn wait_for_remote_gateway(
        &self,
        status: GatewayStatus,
        timeout: Duration,
    ) -> Result<GatewayRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let gateways = self.list_gateways().await?;
            let snapshot = describe_gateway_records(&gateways);
            if let Some(gateway) = gateways
                .into_iter()
                .find(|gateway| gateway.gateway_type == GatewayType::Remote && gateway.status == status)
            {
                return Ok(gateway);
            }
            if Instant::now() >= deadline {
                bail!("timed out waiting for remote gateway with status {:?}; observed gateways: {snapshot}", status);
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn wait_for_new_remote_gateway(
        &self,
        existing_ids: &[String],
        status: GatewayStatus,
        timeout: Duration,
    ) -> Result<GatewayRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let gateways = self.list_gateways().await?;
            let snapshot = describe_gateway_records(&gateways);
            if let Some(gateway) = gateways
                .into_iter()
                .find(|gateway| {
                    gateway.gateway_type == GatewayType::Remote
                        && gateway.status == status
                        && !existing_ids.contains(&gateway.id)
                })
            {
                return Ok(gateway);
            }
            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for a new remote gateway with status {:?}; existing_ids={:?}; observed gateways: {snapshot}",
                    status,
                    existing_ids,
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn wait_for_changed_remote_gateway(
        &self,
        existing_remotes: &[GatewayRecord],
        status: GatewayStatus,
        timeout: Duration,
    ) -> Result<GatewayRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let gateways = self.list_gateways().await?;
            let snapshot = describe_gateway_records(&gateways);
            let mut matches = gateways
                .iter()
                .filter(|gateway| gateway.gateway_type == GatewayType::Remote && gateway.status == status)
                .filter(|gateway| {
                    existing_remotes
                        .iter()
                        .find(|existing| existing.id == gateway.id)
                        .is_none_or(|existing| existing.did != gateway.did)
                })
                .cloned()
                .collect::<Vec<_>>();

            if matches.len() == 1 {
                return Ok(matches.remove(0));
            }

            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for one changed remote gateway with status {:?}; existing_remotes={}; observed gateways: {snapshot}",
                    status,
                    describe_gateway_records(existing_remotes),
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn remote_gateway_ids(&self) -> Result<Vec<String>> {
        Ok(self
            .list_gateways()
            .await?
            .into_iter()
            .filter(|gateway| gateway.gateway_type == GatewayType::Remote)
            .map(|gateway| gateway.id)
            .collect())
    }

    pub async fn remote_gateways(&self) -> Result<Vec<GatewayRecord>> {
        Ok(self
            .list_gateways()
            .await?
            .into_iter()
            .filter(|gateway| gateway.gateway_type == GatewayType::Remote)
            .collect())
    }

    pub async fn wait_for_new_remote_gateway_status(
        &self,
        existing_ids: &[String],
        status: GatewayStatus,
        timeout: Duration,
    ) -> Result<GatewayRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let gateways = self.list_gateways().await?;
            let last_snapshot = describe_gateway_records(&gateways);
            let mut matches = gateways
                .into_iter()
                .filter(|gateway| {
                    gateway.gateway_type == GatewayType::Remote
                        && gateway.status == status
                        && !existing_ids.contains(&gateway.id)
                })
                .collect::<Vec<_>>();
            if matches.len() == 1 {
                return Ok(matches.remove(0));
            }

            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for exactly one new remote gateway with status {:?}; existing_ids={:?}; observed: {}",
                    status,
                    existing_ids,
                    last_snapshot
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn describe_gateways(&self) -> Result<String> {
        Ok(describe_gateway_records(&self.list_gateways().await?))
    }

    pub async fn wait_for_gateway_status(
        &self,
        gateway_id: &str,
        status: GatewayStatus,
        timeout: Duration,
    ) -> Result<GatewayRecord> {
        let deadline = Instant::now() + timeout;
        let mut last_observation = "gateway was not returned by the admin API".to_string();
        loop {
            let gateways = self.list_gateways().await?;
            if let Some(gateway) = gateways
                .into_iter()
                .find(|gateway| gateway.id == gateway_id)
            {
                if gateway.status == status {
                    return Ok(gateway);
                }
                last_observation = format!("gateway status was {:?}", gateway.status);
            }

            if Instant::now() >= deadline {
                let snapshot = self
                    .describe_gateways()
                    .await
                    .unwrap_or_else(|error| format!("failed to list gateways: {error}"));
                bail!(
                    "timed out waiting for gateway {gateway_id} to reach status {:?}: {last_observation}; observed gateways: {snapshot}",
                    status
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn wait_for_remote_gateway_did_status(
        &self,
        gateway_did: &str,
        status: GatewayStatus,
        timeout: Duration,
    ) -> Result<GatewayRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let gateways = self.list_gateways().await?;
            if let Some(gateway) = gateways
                .iter()
                .find(|gateway| {
                    gateway.gateway_type == GatewayType::Remote
                        && gateway.did.as_deref() == Some(gateway_did)
                        && gateway.status == status
                })
                .cloned()
            {
                return Ok(gateway);
            }

            if Instant::now() >= deadline {
                let snapshot = describe_gateway_records(&gateways);
                bail!(
                    "timed out waiting for remote gateway DID {gateway_did} to reach status {:?}; observed gateways: {snapshot}",
                    status
                );
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub async fn update_gateway_exposed_surfaces(
        &self,
        gateway_id: &str,
        surface_ids: Vec<String>,
    ) -> Result<GatewayRecord> {
        self.send_json(
            Method::PUT,
            &format!("/v1/gateways/{gateway_id}/exposed-surfaces"),
            Some(&UpdateExposedSurfacesRequest {
                exposure_mode: "list",
                exposed_surfaces: surface_ids,
            }),
        )
        .await
    }

    /// Install (or clear) the gateway-level OPA policy. The gateway compiles
    /// the Rego live and enforces `data.gateway.policy.allow` on inbound
    /// traffic — no restart required.
    pub async fn set_gateway_policy(
        &self,
        gateway_id: &str,
        enabled: bool,
        policy: &str,
    ) -> Result<Value> {
        self.send_json(
            Method::PUT,
            &format!("/v1/gateways/{gateway_id}/policy"),
            Some(&UpdateGatewayPolicyRequest {
                opa_policy_config: GatewayOpaPolicyConfigPayload {
                    enabled,
                    policy: policy.to_string(),
                },
            }),
        )
        .await
    }

    /// Reload a single surface config by id. NOTE: this rebuilds the listener
    /// but does NOT refresh the resolved-surface cache the request pipeline
    /// reads from — prefer `update_surface` for live target changes.
    #[allow(dead_code)]
    pub async fn reload_surface_config(
        &self,
        config_id: &str,
    ) -> Result<Value> {
        self.send_json::<(), _>(Method::POST, &format!("/v1/config/reload/{config_id}"), None)
            .await
    }

    /// Fetch a surface's full config as the running gateway sees it.
    pub async fn get_surface(
        &self,
        surface_id: &str,
    ) -> Result<Value> {
        self.send_json::<(), _>(Method::GET, &format!("/v1/surfaces/{surface_id}"), None)
            .await
    }

    /// Replace a surface's config. The handler refreshes the resolved-surface
    /// cache the request pipeline reads from, so changes (e.g. a new
    /// `target.endpoint`) take effect immediately — unlike the per-surface
    /// config reload, which only rebuilds the listener.
    pub async fn update_surface(
        &self,
        surface_id: &str,
        surface: &Value,
    ) -> Result<Value> {
        self.send_json(Method::PUT, &format!("/v1/surfaces/{surface_id}"), Some(surface))
            .await
    }

    pub async fn wait_for_ping_success(
        &self,
        gateway_id: &str,
        timeout: Duration,
    ) -> Result<GatewayPingResponse> {
        let deadline = Instant::now() + timeout;
        let mut last_error = None;
        loop {
            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for ping to succeed for gateway {gateway_id}: {}",
                    last_error.unwrap_or_else(|| "no ping response".to_string())
                );
            }
            match self
                .ping_gateway(gateway_id)
                .await
            {
                Ok(response) if response.success => return Ok(response),
                Ok(response) => last_error = Some(format!("ping returned success=false: {}", response.message)),
                Err(error) => last_error = Some(error.to_string()),
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }

    async fn send_json<B, R>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
    ) -> Result<R>
    where
        B: Serialize + ?Sized,
        R: DeserializeOwned,
    {
        self.client
            .send_json(method, path, body)
            .await
    }

    // ── Trust Registry ─────────────────────────────────────────────────

    pub async fn create_trust_registry(
        &self,
        name: &str,
        description: &str,
        oob_url: &str,
    ) -> Result<TrustRegistryRecord> {
        self.send_json(
            Method::POST,
            "/v1/trust-registries",
            Some(&CreateTrustRegistryRequest {
                name: name.to_string(),
                description: description.to_string(),
                oob_url: oob_url.to_string(),
                did_method: Some("peer".to_string()),
            }),
        )
        .await
    }

    pub async fn get_trust_registry(
        &self,
        id: &str,
    ) -> Result<TrustRegistryRecord> {
        self.send_json::<(), _>(Method::GET, &format!("/v1/trust-registries/{id}"), None)
            .await
    }

    pub async fn list_trust_registries(&self) -> Result<Vec<TrustRegistryRecord>> {
        self.send_json::<(), _>(Method::GET, "/v1/trust-registries", None)
            .await
    }

    /// Poll until the gateway's trust registry connection reaches `connected`.
    pub async fn wait_for_trust_registry_connected(
        &self,
        id: &str,
        timeout: Duration,
    ) -> Result<TrustRegistryRecord> {
        let deadline = Instant::now() + timeout;
        loop {
            let status_snapshot = match self
                .get_trust_registry(id)
                .await
            {
                Ok(tr) if tr.connection_status == "connected" => return Ok(tr),
                Ok(tr) => tr.connection_status.clone(),
                Err(error) => format!("error: {error}"),
            };
            if Instant::now() >= deadline {
                bail!(
                    "timed out waiting for trust registry {id} to reach connected status; last status: {status_snapshot}"
                );
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayType {
    #[serde(rename = "self")]
    SelfGateway,
    Remote,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GatewayStatus {
    Active,
    Pending,
    #[serde(rename = "awaiting-approval")]
    AwaitingApproval,
    Disabled,
    Failed,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayRecord {
    pub id: String,
    pub gateway_type: GatewayType,
    pub status: GatewayStatus,
    /// The remote gateway's DID. Present on Remote records after federation;
    /// used to author per-caller gateway policies (for example, allow only gateway 1).
    #[serde(default)]
    pub did: Option<String>,
    /// For a Remote record: the peer's gateway DID once its issuer attestation
    /// was verified (the DID the peer signs identity credentials with).
    #[serde(default)]
    pub issuer_did: Option<String>,
    /// How `issuer_did` was established (`handshake` or `exchange`).
    #[serde(default)]
    pub issuer_did_source: Option<String>,
    /// Issuer DIDs an operator trusts for presentations arriving over this connection.
    #[serde(default)]
    pub trusted_issuer_dids: Vec<String>,
    /// Surfaces exposed to a Remote record in `list` mode.
    #[serde(default, rename = "exposed_channels")]
    pub exposed_surfaces: Vec<String>,
}

/// Response of `POST /v1/gateways/{id}/issuer`.
#[derive(Debug, Clone, Deserialize)]
pub struct GatewayIssuerResponse {
    pub gateway_id: String,
    pub issuer_did: String,
}

fn describe_gateway_records(gateways: &[GatewayRecord]) -> String {
    gateways
        .iter()
        .map(|gateway| {
            format!(
                "{}:{:?}:{:?}:did={}:issuer_did={}",
                gateway.id,
                gateway.gateway_type,
                gateway.status,
                gateway
                    .did
                    .as_deref()
                    .unwrap_or("<none>"),
                gateway
                    .issuer_did
                    .as_deref()
                    .unwrap_or("<none>")
            )
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[derive(Debug, Clone, Deserialize)]
pub struct MediatorRecord {
    pub id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConnectionPointRecord {
    pub oob_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayPingResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
struct CreateMediatorRequest {
    name: String,
    description: String,
    did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_document: Option<Value>,
}

#[derive(Debug, Serialize)]
struct CreateConnectionPointRequest {
    gateway_id: String,
    mediator_id: String,
    name: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expiry_seconds: Option<u64>,
    secret: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_method: Option<String>,
}

#[derive(Debug, Serialize)]
struct ConnectViaOobRequest {
    oob_url: String,
    secret: String,
    name: String,
    description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_method: Option<String>,
}

#[derive(Debug, Serialize)]
struct ApproveGatewayRequest {
    name: String,
    description: String,
}

#[derive(Debug, Serialize)]
struct UpdateExposedSurfacesRequest {
    exposure_mode: &'static str,
    #[serde(rename = "exposed_channels")]
    exposed_surfaces: Vec<String>,
}

#[derive(Debug, Serialize)]
struct UpdateGatewayPolicyRequest {
    opa_policy_config: GatewayOpaPolicyConfigPayload,
}

#[derive(Debug, Serialize)]
struct GatewayOpaPolicyConfigPayload {
    enabled: bool,
    policy: String,
}

#[derive(Debug, Deserialize)]
struct CreateConnectionPointResponse {
    connection_point: ConnectionPointRecord,
}

#[derive(Debug, Deserialize)]
struct ConnectViaOobResponse {
    gateway: GatewayRecord,
}

// ── Trust Registry types ───────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct CreateTrustRegistryRequest {
    name: String,
    description: String,
    oob_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    did_method: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrustRegistryRecord {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub connection_status: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub did: Option<String>,
    #[serde(default)]
    pub our_did: Option<String>,
}
