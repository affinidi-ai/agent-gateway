//! Caller-side mechanics of modern MCP consent against a real gateway: token
//! exchange at the gateway's MCP issuer, reading the gateway's URL-mode input
//! request, and following the consent URL through the identity provider and
//! back to the gateway's callback.

use anyhow::{Context, Result, bail, ensure};
use reqwest::Client;
use reqwest::redirect::Policy;
use serde_json::{Value, json};
use url::Url;

use crate::bdd_support::config::modern_consent::{
    MCP_SCOPE, PUBLIC_ORIGIN, STS_CLIENT_ID, STS_CLIENT_SECRET, access_point_resource,
};
use crate::bdd_support::json_rpc::{McpVersion, build_modern_mcp_tool_call_body};
use crate::bdd_support::oidc::OidcProvider;

const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const CLIENT_CAPABILITIES_KEY: &str = "io.modelcontextprotocol/clientCapabilities";

/// The gateway's URL-mode consent request from an `input_required` result.
#[derive(Debug, Clone)]
pub struct ConsentRequest {
    pub input_key: String,
    pub url: Url,
    pub request_state: String,
}

impl ConsentRequest {
    /// Read the gateway's consent request from a JSON-RPC response, if it asks
    /// for one.
    pub fn from_response(response: &Value) -> Option<Self> {
        let result = &response["result"];
        if result["resultType"] != "input_required" {
            return None;
        }
        let (input_key, input) = result["inputRequests"]
            .as_object()?
            .iter()
            .find(|(_, input)| input["params"]["mode"] == "url")?;
        Some(Self {
            input_key: input_key.clone(),
            url: Url::parse(input["params"]["url"].as_str()?).ok()?,
            request_state: result["requestState"]
                .as_str()?
                .to_string(),
        })
    }

    /// The original request retried, under a new request id, with the consent
    /// outcome.
    pub fn retry_body(
        &self,
        original: &Value,
    ) -> Value {
        let mut body = original.clone();
        body["id"] = json!(format!(
            "{}-retry",
            original["id"]
                .as_str()
                .unwrap_or("request")
        ));
        body["params"]["requestState"] = json!(self.request_state);
        body["params"]["inputResponses"] = json!({ &self.input_key: { "action": "accept" } });
        body
    }
}

/// A modern `tools/call` from a client that accepts URL-mode elicitation.
pub fn build_consent_capable_tool_call_body(
    id: Value,
    tool_name: &str,
    protocol_version: &McpVersion,
) -> Value {
    let mut body = build_modern_mcp_tool_call_body(id, tool_name, protocol_version);
    body["params"]["_meta"][CLIENT_CAPABILITIES_KEY] = json!({ "elicitation": { "url": {} } });
    body
}

fn client() -> Client {
    Client::builder()
        .no_proxy()
        .redirect(Policy::none())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .expect("build consent HTTP client")
}

/// Map a URL on the gateway's public origin to its loopback listener.
fn gateway_local_url(
    url: &Url,
    gateway_port: u16,
) -> Result<Url> {
    ensure!(
        url.origin()
            .ascii_serialization()
            == PUBLIC_ORIGIN,
        "expected a URL on {PUBLIC_ORIGIN}, got {url}"
    );
    let mut local = url.clone();
    local
        .set_scheme("http")
        .map_err(|()| anyhow::anyhow!("set http scheme on {url}"))?;
    local
        .set_host(Some("127.0.0.1"))
        .context("set loopback host")?;
    local
        .set_port(Some(gateway_port))
        .map_err(|()| anyhow::anyhow!("set port on {url}"))?;
    Ok(local)
}

fn redirect_location(response: &reqwest::Response) -> Result<Url> {
    ensure!(
        response
            .status()
            .is_redirection(),
        "expected a redirect, got {}",
        response.status()
    );
    let location = response
        .headers()
        .get(reqwest::header::LOCATION)
        .context("redirect without Location")?
        .to_str()
        .context("non-ASCII Location")?;
    Url::parse(location).with_context(|| format!("parse Location {location}"))
}

/// Exchange an identity token for an MCP access token to the Access Point on
/// `route` at the gateway listening on `gateway_port`.
pub async fn exchange_identity_token(
    gateway_port: u16,
    identity_token: &str,
    route: &str,
) -> Result<String> {
    let response = client()
        .post(format!("http://127.0.0.1:{gateway_port}/api/oauth2/mcp/token"))
        .basic_auth(STS_CLIENT_ID, Some(STS_CLIENT_SECRET))
        .form(&[
            ("grant_type", TOKEN_EXCHANGE_GRANT),
            ("subject_token", identity_token),
            ("subject_token_type", JWT_TOKEN_TYPE),
            ("resource", &access_point_resource(route)),
            ("scope", MCP_SCOPE),
        ])
        .send()
        .await
        .context("send token exchange")?;
    let status = response.status();
    let body: Value = response
        .json()
        .await
        .context("token exchange response is JSON")?;
    ensure!(status.is_success(), "token exchange failed with {status}: {body}");
    body["access_token"]
        .as_str()
        .map(str::to_string)
        .with_context(|| format!("token exchange returned no access_token: {body}"))
}

/// Open the consent URL as the caller's browser and follow the gateway's
/// redirect to the identity provider, returning the gateway callback URL the
/// provider redirects back to, unopened.
async fn consent_callback_url(
    client: &Client,
    gateway_port: u16,
    consent: &ConsentRequest,
    provider: &OidcProvider,
) -> Result<Url> {
    let connect = client
        .get(gateway_local_url(&consent.url, gateway_port)?)
        .send()
        .await
        .context("open consent URL")?;
    let authorize = provider.local_url(&redirect_location(&connect).context("consent URL")?)?;
    let authorized = client
        .get(authorize)
        .send()
        .await
        .context("open authorization endpoint")?;
    gateway_local_url(&redirect_location(&authorized).context("authorization endpoint")?, gateway_port)
}

/// Follow the consent URL as [`complete_consent`] does, but open the
/// gateway's callback with one character of its `state` changed. Returns the
/// callback's status.
pub async fn open_consent_callback_with_tampered_state(
    gateway_port: u16,
    consent: &ConsentRequest,
    provider: &OidcProvider,
) -> Result<reqwest::StatusCode> {
    let client = client();
    let mut callback = consent_callback_url(&client, gateway_port, consent, provider).await?;
    let pairs: Vec<(String, String)> = callback
        .query_pairs()
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect();
    ensure!(
        pairs
            .iter()
            .any(|(name, _)| name == "state"),
        "consent callback {callback} carries no state"
    );
    let mut query = callback.query_pairs_mut();
    query.clear();
    for (name, value) in &pairs {
        if name == "state" {
            query.append_pair(name, &tamper(value));
        } else {
            query.append_pair(name, value);
        }
    }
    drop(query);
    let response = client
        .get(callback)
        .send()
        .await
        .context("open consent callback with a tampered state")?;
    Ok(response.status())
}

/// `value` with its last character replaced by a different one.
fn tamper(value: &str) -> String {
    let mut chars: Vec<char> = value.chars().collect();
    let last = chars.pop();
    chars.push(if last == Some('A') {
        'B'
    } else {
        'A'
    });
    chars.into_iter().collect()
}

/// Open the consent URL as the caller's browser: the gateway sends it to the
/// identity provider, which sends it back to the gateway's callback.
pub async fn complete_consent(
    gateway_port: u16,
    consent: &ConsentRequest,
    provider: &OidcProvider,
) -> Result<()> {
    let client = client();
    let callback = consent_callback_url(&client, gateway_port, consent, provider).await?;
    let completed = client
        .get(callback)
        .send()
        .await
        .context("open consent callback")?;
    let status = completed.status();
    if !status.is_success() {
        let body = completed
            .text()
            .await
            .unwrap_or_default();
        bail!("consent callback failed with {status}: {body}");
    }
    Ok(())
}
