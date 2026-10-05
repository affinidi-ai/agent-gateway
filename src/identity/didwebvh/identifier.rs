use anyhow::{Result, anyhow};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ParsedDidWebvh {
    pub scid: Option<String>,
    pub domain: String,
    pub path: Vec<String>,
}

pub(crate) fn parse_did_webvh(did: &str) -> Result<ParsedDidWebvh> {
    let remainder = did
        .strip_prefix("did:webvh:")
        .ok_or_else(|| anyhow!("invalid did:webvh: missing did:webvh: prefix"))?;

    let parts: Vec<&str> = remainder.split(':').collect();
    if parts.len() < 2 {
        return Err(anyhow!("invalid did:webvh: missing domain segment"));
    }

    if is_scid_segment(parts[0]) {
        let domain = parts[1];
        if domain.is_empty() {
            return Err(anyhow!("invalid did:webvh: missing domain segment"));
        }

        return Ok(ParsedDidWebvh {
            scid: Some(parts[0].to_string()),
            domain: domain.to_string(),
            path: parts[2..]
                .iter()
                .map(|segment| (*segment).to_string())
                .collect(),
        });
    }

    Ok(ParsedDidWebvh {
        scid: None,
        domain: parts[0].to_string(),
        path: parts[1..]
            .iter()
            .map(|segment| (*segment).to_string())
            .collect(),
    })
}

pub(crate) fn is_scid_segment(segment: &str) -> bool {
    let candidate = segment
        .strip_prefix('z')
        .unwrap_or(segment);
    let Ok(decoded) = bs58::decode(candidate).into_vec() else {
        return false;
    };

    decoded.len() >= 34 && decoded[0] == 0x12 && decoded[1] == 0x20
}

#[cfg(test)]
mod tests {
    use super::{is_scid_segment, parse_did_webvh};

    #[test]
    fn detects_raw_multihash_scid_segment() {
        assert!(is_scid_segment("QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz"));
    }

    #[test]
    fn detects_multibase_scid_segment() {
        assert!(is_scid_segment("zQmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz"));
    }

    #[test]
    fn rejects_domain_like_segment_as_scid() {
        assert!(!is_scid_segment("localhost"));
        assert!(!is_scid_segment("example.com"));
    }

    #[test]
    fn parses_spec_compliant_did_with_raw_scid() {
        let parsed =
            parse_did_webvh("did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:example.com:agents:alpha")
                .expect("did should parse");

        assert_eq!(parsed.scid.as_deref(), Some("QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz"));
        assert_eq!(parsed.domain, "example.com");
        assert_eq!(parsed.path, vec!["agents", "alpha"]);
    }

    #[test]
    fn parses_legacy_did_without_scid() {
        let parsed = parse_did_webvh("did:webvh:localhost%3A8080:agents:alpha").expect("did should parse");

        assert!(parsed.scid.is_none());
        assert_eq!(parsed.domain, "localhost%3A8080");
        assert_eq!(parsed.path, vec!["agents", "alpha"]);
    }
}
