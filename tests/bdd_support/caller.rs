use std::collections::HashMap;

use anyhow::{Context, Result};
use reqwest::Client;
use serde_json::Value;

use crate::bdd_support::http::{collect_headers, parse_json_or_sse_body};

#[derive(Debug, Clone)]
pub struct RecordedHttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: Value,
    pub content_type: Option<String>,
}

pub async fn post_json(
    client: &Client,
    url: &str,
    body: &Value,
    extra_headers: &[(String, String)],
) -> Result<RecordedHttpResponse> {
    let mut request = client
        .post(url)
        .header("content-type", "application/json")
        .json(body);

    for (name, value) in extra_headers {
        request = request.header(name, value);
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("caller request failed: {url}"))?;
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let content_type = headers
        .get("content-type")
        .cloned();
    let raw = response
        .text()
        .await
        .unwrap_or_default();
    let body = parse_json_or_sse_body(&raw, content_type.as_deref());

    Ok(RecordedHttpResponse {
        status,
        headers,
        body,
        content_type,
    })
}

/// POST an `application/x-www-form-urlencoded` body, optionally with HTTP Basic
/// authentication. Used to drive the OAuth token endpoint (`/oauth2/token`).
pub async fn post_form(
    client: &Client,
    url: &str,
    form: &[(String, String)],
    basic_auth: Option<(&str, &str)>,
) -> Result<RecordedHttpResponse> {
    let mut request = client.post(url).form(form);
    if let Some((user, pass)) = basic_auth {
        request = request.basic_auth(user, Some(pass));
    }

    let response = request
        .send()
        .await
        .with_context(|| format!("form post failed: {url}"))?;
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let content_type = headers
        .get("content-type")
        .cloned();
    let raw = response
        .text()
        .await
        .unwrap_or_default();
    let body = parse_json_or_sse_body(&raw, content_type.as_deref());

    Ok(RecordedHttpResponse {
        status,
        headers,
        body,
        content_type,
    })
}
