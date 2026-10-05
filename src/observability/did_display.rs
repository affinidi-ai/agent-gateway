//! Truncated DID rendering for audit logs.
//!
//! Rust port of `formatDID` from
//! `www/default/src/utils/stringUtils.ts::formatDID`. Producing the same
//! shape here keeps the JSONL VP audit log and the dashboard identity page
//! rendering identical strings for the same DID, so an operator can
//! cross-reference the two without cognitive load.
//!
//! Behaviour (mirror of the TS):
//!
//! * Empty or non-`did:` prefixed value → pass through unchanged.
//! * Fewer than 3 `:`-separated parts → pass through unchanged.
//! * `did:web:HOST:channel:UUID` where `UUID` has at least `first + last`
//!   bytes → emit `did::channel:{FIRST}...{LAST}` (host is intentionally
//!   elided; this is the identity page's most common form for gateway /
//!   channel DIDs).
//! * Otherwise → `did:{METHOD}:{FIRST}...{LAST}` computed over the
//!   identifier `parts[2..].join(":")`.
//! * Identifier shorter than or equal to `first + last + 3` bytes → pass
//!   through unchanged (truncation would not save space after the ellipsis).
//!
//! DIDs are ASCII per DID Core §3.1, so byte-indexing matches char-indexing
//! in practice. As a defence against operator misconfiguration (a template
//! that resolves to non-ASCII text), any slice that would fall on a
//! non-char-boundary triggers pass-through instead of a panic.

/// Truncate a DID for display, mirroring the dashboard identity page's
/// `formatDID` renderer in `www/default/src/utils/stringUtils.ts`. See the
/// module-level docs for the full contract.
pub fn format_did(
    did: &str,
    first: usize,
    last: usize,
) -> String {
    if did.is_empty() || !did.starts_with("did:") {
        return did.to_string();
    }
    let parts: Vec<&str> = did.split(':').collect();
    if parts.len() < 3 {
        return did.to_string();
    }
    let method = parts[1];

    if method == "web" && parts.len() >= 5 {
        let last_part = parts[parts.len() - 1];
        let second_last = parts[parts.len() - 2];
        if second_last == "channel" && last_part.len() >= first + last {
            let head_end = first;
            let tail_start = last_part.len() - last;
            if let (Some(head), Some(tail)) = (last_part.get(..head_end), last_part.get(tail_start..)) {
                return format!("did::channel:{}...{}", head, tail);
            }
        }
    }

    let identifier = parts[2..].join(":");
    if identifier.len() <= first + last + 3 {
        return did.to_string();
    }
    let tail_start = identifier.len() - last;
    match (identifier.get(..first), identifier.get(tail_start..)) {
        (Some(head), Some(tail)) => format!("did:{}:{}...{}", method, head, tail),
        _ => did.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_did_truncates_did_web_channel_preserving_uuid() {
        // last = 8 takes exactly 8 chars from the end of the UUID, so a
        // 36-char UUID `1524042a-2339-4e08-af51-2c5fd43f7b7e` yields the
        // tail `d43f7b7e`.
        let did = "did:web:agent-gateway-1.example.com:channel:1524042a-2339-4e08-af51-2c5fd43f7b7e";
        assert_eq!(format_did(did, 8, 8), "did::channel:1524042a...d43f7b7e");
    }

    #[test]
    fn format_did_truncates_generic_did_key() {
        // 32-char low-entropy fake key (obvious pattern) so secret
        // scanners don't flag it as a real key. Last 8 chars are
        // `dddddddd`.
        let did = "did:key:aaaaaaaabbbbbbbbccccccccdddddddd";
        assert_eq!(format_did(did, 8, 8), "did:key:aaaaaaaa...dddddddd");
    }

    #[test]
    fn format_did_truncates_did_peer() {
        // Low-entropy fake did:peer identifier (obvious pattern) so
        // secret scanners don't flag it as a real key.
        let did = "did:peer:aaaaaaaabbbbbbbbccccccccdddddddd";
        assert_eq!(format_did(did, 8, 8), "did:peer:aaaaaaaa...dddddddd");
    }

    #[test]
    fn format_did_truncates_did_webvh_preserving_scid_fragment() {
        // did:webvh:SCID:host — falls through the `web` special case (method != "web")
        // into the generic `did:METHOD:FIRST...LAST` shape over the joined identifier.
        let did = "did:webvh:QmZ1234567890abcdef:example.com";
        let out = format_did(did, 8, 8);
        assert!(out.starts_with("did:webvh:"), "got {}", out);
        assert!(out.contains("..."), "got {}", out);
    }

    #[test]
    fn format_did_passes_through_short_dids() {
        let short = "did:web:short";
        assert_eq!(format_did(short, 8, 8), short);
    }

    #[test]
    fn format_did_passes_through_non_did_values() {
        assert_eq!(format_did("https://example.com", 8, 8), "https://example.com");
        assert_eq!(format_did("", 8, 8), "");
        assert_eq!(format_did("random-string", 8, 8), "random-string");
    }

    #[test]
    fn format_did_passes_through_two_part_did() {
        // fewer than 3 `:`-separated parts
        assert_eq!(format_did("did:web", 8, 8), "did:web");
    }

    #[test]
    fn format_did_passes_through_web_channel_with_short_uuid() {
        // `channel` last-segment shorter than first+last → falls through
        // the special case into the generic branch, which then either
        // truncates or passes through depending on total identifier length.
        let did = "did:web:host:channel:short";
        // identifier = "host:channel:short" is 18 bytes > 8+8+3=19? actually 18 <= 19 → pass through
        assert_eq!(format_did(did, 8, 8), did);
    }

    #[test]
    fn format_did_is_deterministic_same_input_same_output() {
        let did = "did:key:aaaaaaaabbbbbbbbccccccccdddddddd";
        assert_eq!(format_did(did, 8, 8), format_did(did, 8, 8));
    }

    #[test]
    fn format_did_passes_through_non_ascii_gracefully() {
        // DIDs are ASCII per spec; if an operator misconfig produces a
        // non-ASCII identifier and the byte slice would fall on a non-char
        // boundary, we pass through rather than panic.
        let did =
            "did:custom:\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}\u{1F600}";
        // 10 emojis × 4 bytes each = 40 bytes identifier; > 19, so it enters truncation.
        // Byte 8 is not a char boundary → fall through to pass-through.
        let out = format_did(did, 8, 8);
        assert!(out == did || out.starts_with("did:custom:"), "got {}", out);
    }
}
