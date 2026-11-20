use axum::http::HeaderMap;

/// The x402 payment signature a request carries in `payment_signature_header`.
pub fn extract_payment_signature(
    headers: &HeaderMap,
    payment_signature_header: &str,
) -> Option<String> {
    headers
        .get(payment_signature_header)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_payment_signature_from_the_named_header_only() {
        let mut headers = HeaderMap::new();
        headers.insert("x-payment", "signed".parse().unwrap());
        assert_eq!(extract_payment_signature(&headers, "x-payment").as_deref(), Some("signed"));
        assert_eq!(extract_payment_signature(&headers, "payment-signature"), None);
    }
}
