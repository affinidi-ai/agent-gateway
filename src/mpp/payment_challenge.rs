//! Parsing of MPP `WWW-Authenticate: Payment` challenges.

/// A single parsed MPP challenge from a `WWW-Authenticate: Payment` header.
#[derive(Debug, Clone)]
pub struct ParsedChallenge {
    pub id: String,
    pub realm: String,
    pub method: String,
    pub intent: String,
    pub request: String,
    pub expires: Option<String>,
    pub digest: Option<String>,
    pub description: Option<String>,
    pub opaque: Option<String>,
}

/// Parse all `WWW-Authenticate: Payment` challenges from a response header map.
///
/// Per the spec, each header value has auth-param syntax:
/// `Payment id="...", realm="...", method="...", intent="...", request="..."`
///
/// Multiple challenges may appear as separate headers or comma-separated in one.
pub fn parse_www_authenticate_headers(headers: &reqwest::header::HeaderMap) -> Vec<ParsedChallenge> {
    let mut challenges = Vec::new();

    for value in headers.get_all("www-authenticate") {
        let Ok(s) = value.to_str() else {
            continue;
        };

        // Each "Payment ..." segment is one challenge.
        // They can be comma-separated at the top level but each starts with "Payment".
        // Split on "Payment " boundaries.
        for segment in split_payment_challenges(s) {
            if let Some(parsed) = parse_single_challenge(&segment) {
                challenges.push(parsed);
            }
        }
    }

    challenges
}

/// Split a header value into individual "Payment ..." segments.
fn split_payment_challenges(header_value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();

    // Split on "Payment " boundaries (case-sensitive per HTTP auth scheme rules).
    // Be careful not to split inside quoted strings.
    let chars = header_value
        .chars()
        .peekable();
    let mut in_quotes = false;

    for ch in chars {
        if ch == '"' {
            in_quotes = !in_quotes;
            current.push(ch);
        } else if !in_quotes && current.is_empty() && ch == 'P' {
            // Check if this starts "Payment "
            current.push(ch);
        } else {
            current.push(ch);
        }
    }

    if !current.is_empty() {
        segments.push(current);
    }

    // Each segment should start with "Payment" — filter
    segments
        .into_iter()
        .filter(|s| s.starts_with("Payment"))
        .collect()
}

/// Parse a single `Payment id="...", realm="...", ...` challenge string.
fn parse_single_challenge(segment: &str) -> Option<ParsedChallenge> {
    // Strip "Payment " prefix
    let params_str = segment.strip_prefix("Payment ")?;

    let params = parse_auth_params(params_str);

    let id = params.get("id")?.clone();
    let realm = params.get("realm")?.clone();
    let method = params.get("method")?.clone();
    let intent = params.get("intent")?.clone();
    let request = params.get("request")?.clone();

    Some(ParsedChallenge {
        id,
        realm,
        method,
        intent,
        request,
        expires: params.get("expires").cloned(),
        digest: params.get("digest").cloned(),
        description: params
            .get("description")
            .cloned(),
        opaque: params.get("opaque").cloned(),
    })
}

/// Parse auth-param pairs: `key="value", key2="value2"`, keys lower-cased.
/// Also reads the parameters of an RFC 6750 `Bearer` challenge.
pub(crate) fn parse_auth_params(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    let mut remaining = s.trim();

    while !remaining.is_empty() {
        // Skip leading commas and whitespace
        remaining = remaining.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
        if remaining.is_empty() {
            break;
        }

        // Find key
        let eq_pos = match remaining.find('=') {
            Some(p) => p,
            None => break,
        };
        let key = remaining[..eq_pos]
            .trim()
            .to_lowercase();
        remaining = &remaining[eq_pos + 1..];

        // Parse value (may be quoted or token)
        remaining = remaining.trim_start();
        if remaining.starts_with('"') {
            // Quoted string — find closing quote (handling escaped quotes)
            remaining = &remaining[1..]; // skip opening quote
            let mut value = String::new();
            let mut chars = remaining.chars();
            loop {
                match chars.next() {
                    Some('\\') => {
                        // Escaped character
                        if let Some(c) = chars.next() {
                            value.push(c);
                        }
                    }
                    Some('"') => break,
                    Some(c) => value.push(c),
                    None => break,
                }
            }
            remaining = chars.as_str();
            map.insert(key, value);
        } else {
            // Unquoted token — ends at comma or whitespace
            let end = remaining
                .find(|c: char| c == ',' || c.is_whitespace())
                .unwrap_or(remaining.len());
            let value = remaining[..end].to_string();
            remaining = &remaining[end..];
            map.insert(key, value);
        }
    }

    map
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_single_payment_challenge_with_all_params() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            "www-authenticate",
            r#"Payment id="ch-1", realm="mpp", method="tempo", intent="pay", request="eyJhIjoxfQ", expires="later", digest="d1""#
                .parse()
                .unwrap(),
        );

        let challenges = parse_www_authenticate_headers(&headers);

        assert_eq!(challenges.len(), 1);
        let c = &challenges[0];
        assert_eq!(c.id, "ch-1");
        assert_eq!(c.realm, "mpp");
        assert_eq!(c.method, "tempo");
        assert_eq!(c.intent, "pay");
        assert_eq!(c.request, "eyJhIjoxfQ");
        assert_eq!(c.expires.as_deref(), Some("later"));
        assert_eq!(c.digest.as_deref(), Some("d1"));
        assert_eq!(c.description, None);
        assert_eq!(c.opaque, None);
    }

    #[test]
    fn skips_segment_missing_required_params() {
        let mut headers = reqwest::header::HeaderMap::new();
        // Missing `request` — must be dropped, not panic.
        headers.insert(
            "www-authenticate",
            r#"Payment id="ch-2", realm="mpp", method="tempo", intent="pay""#
                .parse()
                .unwrap(),
        );

        let challenges = parse_www_authenticate_headers(&headers);
        assert!(challenges.is_empty());
    }

    #[test]
    fn parses_auth_params_into_lowercased_keys() {
        let params = parse_auth_params(r#"Id="x", Realm="r", Token=abc"#);
        assert_eq!(
            params
                .get("id")
                .map(String::as_str),
            Some("x")
        );
        assert_eq!(
            params
                .get("realm")
                .map(String::as_str),
            Some("r")
        );
        assert_eq!(
            params
                .get("token")
                .map(String::as_str),
            Some("abc")
        );
    }
}
