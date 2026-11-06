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

/// POST `body` to `path` on `127.0.0.1:port` exactly as written, since an HTTP client
/// resolves dot segments and decodes `%2e` before it sends a request, and without following
/// a redirect.
pub async fn post_raw_path(
    port: u16,
    path: &str,
    body: &str,
    extra_headers: &[(String, String)],
) -> Result<RecordedHttpResponse> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .with_context(|| format!("connecting to 127.0.0.1:{port}"))?;
    let mut request = format!(
        "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body.len()
    );
    for (name, value) in extra_headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");
    request.push_str(body);
    stream
        .write_all(request.as_bytes())
        .await
        .with_context(|| format!("sending POST {path}"))?;
    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .await
        .with_context(|| format!("reading the answer to POST {path}"))?;
    parse_raw_response(&String::from_utf8_lossy(&raw)).with_context(|| format!("parsing the answer to POST {path}"))
}

fn parse_raw_response(raw: &str) -> Result<RecordedHttpResponse> {
    let (head, payload) = raw
        .split_once("\r\n\r\n")
        .context("the answer has no header section")?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|status_line| status_line.split(' ').nth(1))
        .and_then(|status| status.parse().ok())
        .context("the answer has no status line")?;
    let headers: HashMap<String, String> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| {
            (
                name.trim()
                    .to_ascii_lowercase(),
                value.trim().to_string(),
            )
        })
        .collect();
    let content_type = headers
        .get("content-type")
        .cloned();
    let payload = if headers
        .get("transfer-encoding")
        .is_some_and(|encoding| encoding.eq_ignore_ascii_case("chunked"))
    {
        decode_chunked(payload)
    } else {
        payload.to_string()
    };
    let body = match parse_json_or_sse_body(&payload, content_type.as_deref()) {
        Value::Null if !payload.is_empty() => Value::String(payload),
        parsed => parsed,
    };
    Ok(RecordedHttpResponse {
        status,
        headers,
        body,
        content_type,
    })
}

fn decode_chunked(mut payload: &str) -> String {
    let mut decoded = String::new();
    while let Some((size, rest)) = payload.split_once("\r\n") {
        let Ok(size) = usize::from_str_radix(size.trim(), 16) else {
            break;
        };
        if size == 0 || rest.len() < size {
            break;
        }
        decoded.push_str(&rest[..size]);
        payload = rest[size..]
            .strip_prefix("\r\n")
            .unwrap_or(&rest[size..]);
    }
    decoded
}
