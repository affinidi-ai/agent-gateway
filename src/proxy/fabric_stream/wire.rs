use std::collections::BTreeMap;

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub(crate) const MAX_FRAME_BYTES: usize = 48 * 1024;
pub(crate) const MAX_CHUNK_BYTES: usize = 16 * 1024;
pub(crate) const MAX_WINDOW_BYTES: usize = 1024 * 1024;
pub(crate) const MAX_HEADER_BYTES: usize = 16 * 1024;

pub(crate) type WireHeaders = BTreeMap<String, Vec<String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StreamDirection {
    Request,
    Response,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OpenRequest {
    pub capability_nonce: Uuid,
    pub channel_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant_alias: Option<String>,
    pub path: String,
    pub headers: WireHeaders,
    pub body_bytes: u64,
    pub response_window_bytes: u32,
    pub deadline_ms: u64,
    pub trace_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum FramePayload {
    Open { request: OpenRequest },
    RequestData { sequence: u64, offset: u64, data: String },
    RequestEnd { next_sequence: u64, body_bytes: u64 },
    Start { status: u16, headers: WireHeaders },
    Data { sequence: u64, offset: u64, data: String },
    Credit { direction: StreamDirection, next_sequence: u64, consumed_bytes: u64 },
    End { next_sequence: u64, body_bytes: u64 },
    EndAck { next_sequence: u64, body_bytes: u64 },
    Cancel,
    Error { code: StreamErrorCode },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StreamErrorCode {
    #[error("Fabric stream is unavailable")]
    Unavailable,
    #[error("Invalid Fabric stream frame")]
    InvalidFrame,
    #[error("Fabric stream limit exceeded")]
    LimitExceeded,
    #[error("Fabric stream deadline exceeded")]
    DeadlineExceeded,
    #[error("Fabric stream upstream failed")]
    UpstreamFailed,
    #[error("Fabric stream cancelled")]
    Cancelled,
    /// The receiver holds no live capability offer for the `Open`'s nonce, so
    /// the sender negotiates again.
    #[error("Fabric stream capability offer is unknown or expired")]
    StaleOffer,
    /// The receiving surface does not serve modern MCP, so the sender answers
    /// as a legacy-only endpoint would.
    #[error("Fabric stream surface serves legacy MCP only")]
    LegacyOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StreamFrame {
    pub stream_id: Uuid,
    pub payload: FramePayload,
}

impl StreamFrame {
    pub fn parse(value: serde_json::Value) -> Result<Self, String> {
        if serde_json::to_vec(&value)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_FRAME_BYTES
        {
            return Err("Fabric stream frame exceeds its encoded byte limit".to_string());
        }
        let frame: Self = serde_json::from_value(value).map_err(|error| error.to_string())?;
        frame.validate()?;
        Ok(frame)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.stream_id.is_nil() {
            return Err("Fabric stream identifier must not be nil".to_string());
        }
        match &self.payload {
            FramePayload::Open { request } => {
                if request.channel_id.is_empty()
                    || request.channel_id.len() > 1024
                    || request
                        .channel_id
                        .chars()
                        .any(char::is_control)
                    || request
                        .channel_id
                        .contains('$')
                    || request
                        .capability_nonce
                        .is_nil()
                    || request
                        .variant_alias
                        .as_ref()
                        .is_some_and(|alias| {
                            alias.is_empty()
                                || alias.len() > 32
                                || !alias
                                    .bytes()
                                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                        })
                    || !request.path.starts_with('/')
                    || request.path.starts_with("//")
                    || request.path.len() > 4096
                    || request.path.contains('#')
                    || request
                        .path
                        .chars()
                        .any(char::is_control)
                    || request.trace_id.is_nil()
                    || request.deadline_ms == 0
                    || !(MAX_CHUNK_BYTES..=MAX_WINDOW_BYTES).contains(&(request.response_window_bytes as usize))
                {
                    return Err("Invalid Fabric stream request metadata or credit window".to_string());
                }
                decode_headers(&request.headers)?;
            }
            FramePayload::Start { status, headers } => {
                if !(200..=599).contains(status) {
                    return Err("Fabric stream start requires a final HTTP status".to_string());
                }
                decode_headers(headers)?;
            }
            FramePayload::RequestData { data, .. } | FramePayload::Data { data, .. } => {
                decode_chunk(data)?;
            }
            _ => {}
        }
        if serde_json::to_vec(self)
            .map_err(|error| error.to_string())?
            .len()
            > MAX_FRAME_BYTES
        {
            return Err("Fabric stream frame exceeds its encoded byte limit".to_string());
        }
        Ok(())
    }
}

pub(crate) fn encode_headers(headers: &HeaderMap) -> Result<WireHeaders, String> {
    let mut encoded = WireHeaders::new();
    for (name, value) in headers {
        let value = value
            .to_str()
            .map_err(|_| "Fabric stream headers require valid ASCII values")?;
        encoded
            .entry(name.as_str().to_string())
            .or_default()
            .push(value.to_string());
    }
    decode_headers(&encoded)?;
    Ok(encoded)
}

pub(crate) fn headers_from_json(value: Option<&serde_json::Value>) -> Result<HeaderMap, String> {
    let Some(value) = value else { return Ok(HeaderMap::new()) };
    let headers = value
        .as_object()
        .ok_or("Fabric headers must be an object")?;
    let mut encoded = WireHeaders::new();
    for (name, value) in headers {
        let values = match value {
            serde_json::Value::String(value) => vec![value.clone()],
            serde_json::Value::Array(values) => values
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_string)
                        .ok_or("Fabric header values must be strings")
                })
                .collect::<Result<Vec<_>, _>>()?,
            _ => return Err("Fabric header values must be strings or string arrays".to_string()),
        };
        encoded.insert(name.clone(), values);
    }
    decode_headers(&encoded)
}

pub(crate) fn decode_headers(headers: &WireHeaders) -> Result<HeaderMap, String> {
    let mut decoded = HeaderMap::new();
    let mut total = 0_usize;
    for (name, values) in headers {
        let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| "Invalid Fabric stream header name")?;
        if values.is_empty() {
            return Err("Fabric stream header lists must not be empty".to_string());
        }
        for value in values {
            total = total
                .saturating_add(name.len())
                .saturating_add(value.len())
                .saturating_add(4);
            if total > MAX_HEADER_BYTES {
                return Err("Fabric stream headers exceed the byte limit".to_string());
            }
            let header_value = HeaderValue::from_str(value).map_err(|_| "Invalid Fabric stream header value")?;
            decoded.append(header_name.clone(), header_value);
        }
    }
    Ok(decoded)
}

pub(crate) fn encode_chunk(bytes: &[u8]) -> Result<String, String> {
    if bytes.is_empty() || bytes.len() > MAX_CHUNK_BYTES {
        return Err("Fabric stream chunks must contain between 1 and 16384 bytes".to_string());
    }
    Ok(STANDARD.encode(bytes))
}

pub(crate) fn decode_chunk(encoded: &str) -> Result<Bytes, String> {
    if encoded.is_empty() || encoded.len() > MAX_CHUNK_BYTES.div_ceil(3) * 4 {
        return Err("Fabric stream chunk exceeds the encoded byte limit".to_string());
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| "Invalid Fabric stream chunk encoding")?;
    if decoded.is_empty() || decoded.len() > MAX_CHUNK_BYTES {
        return Err("Fabric stream chunk exceeds the decoded byte limit".to_string());
    }
    Ok(Bytes::from(decoded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn frames_round_trip_without_collapsing_repeated_headers() {
        let mut headers = HeaderMap::new();
        headers.append("mcp-method", "tools/call".parse().unwrap());
        headers.append("mcp-method", "tools/call".parse().unwrap());
        headers.append("mcp-param-custom", "one".parse().unwrap());
        headers.append("mcp-param-custom", "two".parse().unwrap());
        let encoded = encode_headers(&headers).unwrap();
        assert_eq!(decode_headers(&encoded).unwrap(), headers);
        let frame = StreamFrame {
            stream_id: Uuid::new_v4(),
            payload: FramePayload::Open {
                request: OpenRequest {
                    capability_nonce: Uuid::new_v4(),
                    channel_id: "surface".to_string(),
                    variant_alias: Some("variant".to_string()),
                    path: "/mcp?query=kept".to_string(),
                    headers: encoded,
                    body_bytes: 1024 * 1024,
                    response_window_bytes: 64 * 1024,
                    deadline_ms: 1,
                    trace_id: Uuid::new_v4(),
                },
            },
        };
        assert_eq!(StreamFrame::parse(serde_json::to_value(&frame).unwrap()).unwrap(), frame);
        let acknowledged = StreamFrame {
            stream_id: frame.stream_id,
            payload: FramePayload::EndAck {
                next_sequence: 0,
                body_bytes: 0,
            },
        };
        assert_eq!(StreamFrame::parse(serde_json::to_value(&acknowledged).unwrap()).unwrap(), acknowledged);
        let mut invalid = serde_json::to_value(&frame).unwrap();
        invalid["payload"]["request"]["method"] = json!("GET");
        assert!(StreamFrame::parse(invalid).is_err());
        for (field, value) in [
            ("capability_nonce", json!(Uuid::nil())),
            ("variant_alias", json!("unknown$alias")),
            ("channel_id", json!("surface$variant")),
        ] {
            let mut invalid = serde_json::to_value(&frame).unwrap();
            invalid["payload"]["request"][field] = value;
            assert!(StreamFrame::parse(invalid).is_err());
        }
    }

    #[test]
    fn frame_and_payload_limits_reject_overflow_and_malformed_input() {
        let data = vec![0xff; MAX_CHUNK_BYTES];
        let encoded = encode_chunk(&data).unwrap();
        assert_eq!(
            decode_chunk(&encoded)
                .unwrap()
                .as_ref(),
            data.as_slice()
        );
        assert!(encode_chunk(&vec![0; MAX_CHUNK_BYTES + 1]).is_err());
        assert!(decode_chunk(&STANDARD.encode(vec![0; MAX_CHUNK_BYTES + 1])).is_err());
        assert!(decode_chunk("not-base64").is_err());
        assert!(decode_chunk("").is_err());
        let frame = StreamFrame {
            stream_id: Uuid::new_v4(),
            payload: FramePayload::Data {
                sequence: 0,
                offset: 0,
                data: encoded,
            },
        };
        assert!(frame.validate().is_ok());
        assert!(
            serde_json::to_vec(&frame)
                .unwrap()
                .len()
                < MAX_FRAME_BYTES
        );
        let invalid = json!({"stream_id": Uuid::new_v4(), "payload": {"kind": "data", "sequence": 0, "offset": 0, "data": "x".repeat(MAX_FRAME_BYTES)}});
        assert!(StreamFrame::parse(invalid).is_err());
        assert!(StreamFrame::parse(json!({"stream_id": Uuid::nil(), "payload": {"kind": "cancel"}})).is_err());
    }

    #[test]
    fn wire_headers_reject_invalid_names_values_and_budgets() {
        for headers in [
            BTreeMap::from([("invalid name".to_string(), vec!["value".to_string()])]),
            BTreeMap::from([("origin".to_string(), vec!["a\r\nb".to_string()])]),
            BTreeMap::from([("origin".to_string(), Vec::new())]),
            BTreeMap::from([("x-value".to_string(), vec!["x".repeat(MAX_HEADER_BYTES)])]),
        ] {
            assert!(decode_headers(&headers).is_err());
        }
        let mut headers = BTreeMap::new();
        headers.insert("Origin".to_string(), vec!["https://first.example".to_string()]);
        headers.insert("origin".to_string(), vec!["https://second.example".to_string()]);
        assert_eq!(
            decode_headers(&headers)
                .unwrap()
                .get_all("origin")
                .iter()
                .count(),
            2
        );
        assert_eq!(
            headers_from_json(Some(&serde_json::to_value(headers).unwrap()))
                .unwrap()
                .get_all("origin")
                .iter()
                .count(),
            2
        );
        assert!(headers_from_json(Some(&json!({"origin": ["https://first.example", 7]}))).is_err());
        assert!(headers_from_json(Some(&json!({"origin": []}))).is_err());
        assert!(headers_from_json(Some(&json!({"accept": "application/json"}))).is_ok());
    }
}
