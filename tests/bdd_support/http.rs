use std::collections::HashMap;

pub fn collect_headers(headers: &reqwest::header::HeaderMap) -> HashMap<String, String> {
    headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                v.to_str()
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect()
}

pub fn parse_json_or_sse_body(
    raw: &str,
    content_type: Option<&str>,
) -> serde_json::Value {
    let is_sse = content_type.is_some_and(|ct| ct.contains("text/event-stream"));
    let parsed = if is_sse {
        decode_sse_json(raw)
    } else {
        serde_json::from_str(raw).ok()
    };
    parsed.unwrap_or(serde_json::Value::Null)
}

fn decode_sse_json(raw: &str) -> Option<serde_json::Value> {
    raw.lines()
        .filter_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .find_map(|payload| serde_json::from_str(payload).ok())
}
