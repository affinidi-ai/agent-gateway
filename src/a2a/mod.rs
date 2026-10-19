//! A2A protocol handling
//!
//! This module contains functions for handling A2A (Agent-to-Agent) protocol
//! features including extension inspection, metadata injection, URL rewriting,
//! schema derivation, and error responses.

pub mod auth;
pub mod errors;
pub mod extensions;
pub mod methods;
pub mod schema;
pub mod url_rewriter;
pub mod validation;
pub mod version;

pub use methods::{canonical_method, is_a2a_method, recognised_canonical};
pub use version::{ADVERTISED_VERSION, negotiate_from_headers};

pub use auth::clear_secret_cache;
pub use errors::create_error_response;
pub use errors::create_identity_error_response;
pub use errors::create_jsonrpc_error_response;
pub use errors::create_version_not_supported_response;
pub use errors::validate_jsonrpc_envelope;
pub use errors::{
    ERR_IDENTITY_DID_FAILED, ERR_IDENTITY_EXTENSION_MISSING, ERR_IDENTITY_INVALID_RESPONSE,
    ERR_IDENTITY_VALIDATION_FAILED,
};

pub use extensions::{
    inject_credential_into_agent_card, inject_custom_metadata_extension, inject_header_metadata_extension,
    inject_identity_credential_into_response, replace_credential_in_agent_card, upsert_credential_into_agent_card,
};

#[cfg(feature = "didwebvh")]
pub use extensions::inject_didwebvh_identity_extension;

// Re-export protocol-agnostic functions and types from their new locations for backward compatibility
pub use crate::protocols::{
    ExtensionInspectionContext, inspect_message_extensions, is_hop_by_hop_header, should_forward_request_header,
};
pub use url_rewriter::{
    AgentCardKind, EXTENDED_AGENT_CARD_BATCH_REFUSAL, build_target_url, is_extended_agent_card_batch,
    is_extended_agent_card_method, rewrap_extended_agent_card, rewrite_agent_card_urls, unwrap_extended_agent_card,
};

#[cfg(feature = "didwebvh")]
pub use url_rewriter::inject_didwebvh_identity_into_agent_card;

/// Longest caller-supplied value, in chars, that a log line carries.
pub const MAX_LOGGED_CHARS: usize = 64;

/// The first [`MAX_LOGGED_CHARS`] chars of a caller-supplied value, and whether
/// anything was cut.
pub fn clip(value: &str) -> (&str, bool) {
    match value
        .char_indices()
        .nth(MAX_LOGGED_CHARS)
    {
        Some((cut, _)) => (&value[..cut], true),
        None => (value, false),
    }
}

/// A caller-supplied value cut to [`MAX_LOGGED_CHARS`] chars for a log line,
/// with `…` marking a cut, so a request cannot write an unbounded value to the log.
pub fn clip_for_log(value: &str) -> std::borrow::Cow<'_, str> {
    match clip(value) {
        (head, true) => format!("{head}…").into(),
        (head, false) => head.into(),
    }
}

#[cfg(test)]
mod clip_for_log_tests {
    use super::*;

    #[test]
    fn a_short_value_is_logged_in_full() {
        assert_eq!(clip_for_log("SendMessage"), "SendMessage");
        let exact = "a".repeat(MAX_LOGGED_CHARS);
        assert_eq!(clip_for_log(&exact), exact);
    }

    #[test]
    fn a_long_value_is_cut_with_a_marker() {
        let long = "m".repeat(10_000);
        assert_eq!(clip_for_log(&long), format!("{}…", "m".repeat(MAX_LOGGED_CHARS)));
    }

    #[test]
    fn the_cut_counts_chars_not_bytes() {
        let long = "é".repeat(MAX_LOGGED_CHARS + 1);
        assert_eq!(clip_for_log(&long), format!("{}…", "é".repeat(MAX_LOGGED_CHARS)));
    }
}
