use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha2::Sha256;

pub fn sign_timestamped_payload(
    secret: &str,
    timestamp: &str,
    body: &[u8],
) -> Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).context("Invalid HMAC key")?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Ok(hex::encode(mac.finalize().into_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "0123456789abcdef0123456789abcdef";
    const BODY: &[u8] = br#"{"event":"connection_point.created","sequence":1}"#;

    #[test]
    fn matches_an_independently_computed_digest() {
        assert_eq!(
            sign_timestamped_payload(SECRET, "1700000000", BODY).unwrap(),
            "705ecd9b48f73af64f6b0b78cd728c1b3c3d7e6a9d3e74ac5d1eabc269092248"
        );
    }

    #[test]
    fn matches_the_inline_computation_the_publishers_used_before_sharing_this_function() {
        let timestamp = "1700000123";
        let payload = r#"{"event":"x","n":1}"#;
        let mut mac = Hmac::<Sha256>::new_from_slice(SECRET.as_bytes()).unwrap();
        mac.update(format!("{timestamp}.{payload}").as_bytes());
        let inline = hex::encode(mac.finalize().into_bytes());
        assert_eq!(sign_timestamped_payload(SECRET, timestamp, payload.as_bytes()).unwrap(), inline);
    }

    #[test]
    fn digest_depends_on_secret_timestamp_and_body() {
        let base = sign_timestamped_payload(SECRET, "1700000000", BODY).unwrap();
        assert_ne!(base, sign_timestamped_payload("another-secret-another-secret-00", "1700000000", BODY).unwrap());
        assert_ne!(base, sign_timestamped_payload(SECRET, "1700000001", BODY).unwrap());
        assert_ne!(base, sign_timestamped_payload(SECRET, "1700000000", b"{}").unwrap());
        assert_eq!(base.len(), 64);
        assert!(
            base.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
    }
}
