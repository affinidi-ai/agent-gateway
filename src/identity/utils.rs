//! Utility functions for identity API

pub(crate) fn extract_domain_from_did(did: &str) -> String {
    if let Some(without_prefix) = did.strip_prefix("did:webvh:") {
        let parts: Vec<&str> = without_prefix
            .split(':')
            .collect();
        if parts.is_empty() {
            return did.replace("%3A", ":");
        }

        let has_scid = parts.len() >= 2 && !parts[0].contains('.') && !parts[0].contains('%');
        let domain_idx = if has_scid { 1 } else { 0 };

        return parts
            .get(domain_idx)
            .copied()
            .unwrap_or(did)
            .replace("%3A", ":");
    }

    did.strip_prefix("did:web:")
        .unwrap_or(did)
        .split(':')
        .next()
        .unwrap_or(did)
        .replace("%3A", ":")
}

#[cfg(test)]
mod tests {
    use super::extract_domain_from_did;

    #[test]
    fn extract_domain_from_did_decodes_didweb_localhost_port() {
        assert_eq!(extract_domain_from_did("did:web:localhost%3A8080"), "localhost:8080");
    }

    #[test]
    fn extract_domain_from_did_decodes_didwebvh_localhost_port() {
        assert_eq!(
            extract_domain_from_did(
                "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:localhost%3A8443:departments:test"
            ),
            "localhost:8443"
        );
    }

    #[test]
    fn extract_domain_from_did_preserves_fqdn() {
        assert_eq!(
            extract_domain_from_did(
                "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:gateway.example.com:departments:test"
            ),
            "gateway.example.com"
        );
    }
}
