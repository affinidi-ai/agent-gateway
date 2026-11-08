//! MPP wire encodings: unpadded base64url and the `WWW-Authenticate: Payment`
//! challenge header.

use base64::Engine;

use super::types::MppChallenge;

/// Base64url encoding without padding (per RFC 4648 Section 5)
pub fn base64url_encode_nopad(data: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

/// Base64url decoding without padding
pub fn base64url_decode_nopad(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)
}

/// Format an `MppChallenge` as a `WWW-Authenticate: Payment` header value.
///
/// Per the spec, the challenge uses auth-param syntax:
/// ```text
/// Payment id="...", realm="...", method="...", intent="...", request="...", expires="..."
/// ```
pub fn format_www_authenticate(challenge: &MppChallenge) -> String {
    let mut parts = vec![
        format!("Payment id=\"{}\"", challenge.id),
        format!("realm=\"{}\"", challenge.realm),
        format!("method=\"{}\"", challenge.method),
        format!("intent=\"{}\"", challenge.intent),
        format!("request=\"{}\"", challenge.request),
    ];

    if let Some(ref expires) = challenge.expires {
        parts.push(format!("expires=\"{}\"", expires));
    }
    if let Some(ref digest) = challenge.digest {
        parts.push(format!("digest=\"{}\"", digest));
    }
    if let Some(ref description) = challenge.description {
        parts.push(format!("description=\"{}\"", description));
    }
    if let Some(ref opaque) = challenge.opaque {
        parts.push(format!("opaque=\"{}\"", opaque));
    }

    parts.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64url_encode_decode_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode_nopad(data);
        assert!(!encoded.contains('='), "should not have padding");
        assert!(!encoded.contains('+'), "should use URL-safe alphabet");
        assert!(!encoded.contains('/'), "should use URL-safe alphabet");
        let decoded = base64url_decode_nopad(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_format_www_authenticate() {
        let challenge = MppChallenge {
            id: "abc123".to_string(),
            realm: "api.example.com".to_string(),
            method: "tempo".to_string(),
            intent: "charge".to_string(),
            request: "eyJ0ZXN0IjoxfQ".to_string(),
            expires: Some("2026-01-15T12:05:00Z".to_string()),
            digest: None,
            description: None,
            opaque: None,
        };

        let header = format_www_authenticate(&challenge);
        assert!(header.starts_with("Payment id=\"abc123\""));
        assert!(header.contains("realm=\"api.example.com\""));
        assert!(header.contains("method=\"tempo\""));
        assert!(header.contains("intent=\"charge\""));
        assert!(header.contains("request=\"eyJ0ZXN0IjoxfQ\""));
        assert!(header.contains("expires=\"2026-01-15T12:05:00Z\""));
    }
}
