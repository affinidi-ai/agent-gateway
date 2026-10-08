//! A2A protocol version constants and request-version negotiation.
//!
//! A2A v1.0 introduced the `A2A-Version` request header for explicit version
//! negotiation. Per the spec, a client sends the version as `Major.Minor`, and an
//! **absent or empty value MUST be interpreted as `0.3`**; a version the agent does
//! not support is rejected with `VersionNotSupportedError`.
//!
//! The gateway is **bilingual**: it recognises both v0.3 and v1.0 (see
//! [`SUPPORTED_VERSIONS`]). It does **not** translate between them — a caller and
//! the managed agent it reaches must be version-compatible.
//!
//! [`ADVERTISED_VERSION`] is the single source of truth for the version the gateway
//! puts on the agent cards it **generates**. Cards belonging to a **managed agent**
//! are passed through at the upstream's own version and are never overridden.

use axum::http::HeaderMap;

/// The spec's version-negotiation request header.
pub const A2A_VERSION_HEADER: &str = "a2a-version";

/// A2A v0.3 (slash-form JSON-RPC methods).
pub const VERSION_0_3: &str = "0.3";

/// A2A v1.0 (PascalCase JSON-RPC methods).
pub const VERSION_1_0: &str = "1.0";

/// Every protocol version this gateway is capable of serving.
///
/// What a surface *accepts* is its own subset, configured on its A2A Access
/// Point (`access_point.a2a.accepted_versions`) and resolved by [`accepted_set`].
pub const SUPPORTED_VERSIONS: &[&str] = &[VERSION_0_3, VERSION_1_0];

/// The accepted set of a surface that serves A2A 1.0 only, which includes every
/// `a2a-proxy://` surface.
pub const VERSIONS_1_0_ONLY: &[&str] = &[VERSION_1_0];

/// The accepted set of a surface that serves A2A 0.3 only.
pub const VERSIONS_0_3_ONLY: &[&str] = &[VERSION_0_3];

/// The accepted set for a surface's configured versions, in
/// [`SUPPORTED_VERSIONS`] order.
///
/// Entries the gateway cannot serve are ignored, and a list naming none it can
/// serve falls back to every supported version; surface validation refuses both
/// on save, so neither reaches a request.
pub fn accepted_set(configured: &[String]) -> &'static [&'static str] {
    let has = |version: &str| {
        configured
            .iter()
            .any(|v| v == version)
    };
    match (has(VERSION_0_3), has(VERSION_1_0)) {
        (true, false) => VERSIONS_0_3_ONLY,
        (false, true) => VERSIONS_1_0_ONLY,
        _ => SUPPORTED_VERSIONS,
    }
}

/// The protocol version the gateway advertises on agent cards it **generates**
/// (the synthesized A2A-proxy card and the onboarding card).
///
/// Single source of truth: generated-card builders must reference this rather than
/// hardcoding a version literal.
pub const ADVERTISED_VERSION: &str = VERSION_1_0;

/// Operator-configured advertised version, installed once at startup from
/// `[a2a] default_version` by [`init_advertised_version`].
///
/// A global rather than a threaded parameter because the card builders are
/// reached through four layers that otherwise have no reason to carry config,
/// following the same pattern as `config::limits_config::GLOBAL_LIMITS`.
static CONFIGURED_ADVERTISED_VERSION: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

/// Resolve a configured version string onto one of [`SUPPORTED_VERSIONS`].
///
/// Matching is on `Major.Minor`, so `"1.0.1"` resolves to `"1.0"`, consistent
/// with how the `A2A-Version` request header is negotiated. Returns `None` when
/// the value names no version the gateway supports.
pub fn supported_version(raw: &str) -> Option<&'static str> {
    let wanted = major_minor(raw.trim());
    SUPPORTED_VERSIONS
        .iter()
        .copied()
        .find(|v| *v == wanted)
}

/// Install the operator-configured advertised version. Called once at startup,
/// after `A2aConfig::validate` has confirmed the value is supported.
///
/// Ignores an unsupported value rather than panicking; validation is what
/// rejects those, and a second call is a no-op.
pub fn init_advertised_version(configured: &str) {
    if let Some(version) = supported_version(configured) {
        let _ = CONFIGURED_ADVERTISED_VERSION.set(version);
    }
}

/// The A2A protocol version the gateway advertises in the cards it generates.
///
/// This is `[a2a] default_version` when configured, and [`ADVERTISED_VERSION`]
/// otherwise. Cards belonging to a managed agent are unaffected: they are always
/// served at the upstream's own `protocolVersion`.
///
/// It does not change which versions are *accepted*: each surface's accepted set
/// governs that, and a generated card never names a version outside it (see
/// [`effective_advertised_version`]).
pub fn advertised_version() -> &'static str {
    CONFIGURED_ADVERTISED_VERSION
        .get()
        .copied()
        .unwrap_or(ADVERTISED_VERSION)
}

/// JSON-RPC error code for `VersionNotSupportedError`.
pub const ERR_VERSION_NOT_SUPPORTED: i32 = -32009;

/// The A2A protocol-binding label for the JSON-RPC 2.0 transport, used in an agent
/// card's `supportedInterfaces[].protocolBinding`.
///
/// Note `HTTP+JSON` is the label for the **REST** binding, not JSON-RPC — the two
/// are distinct bindings and the gateway's `/rpc` endpoint is JSON-RPC.
pub const PROTOCOL_BINDING_JSONRPC: &str = "JSONRPC";

/// The media type A2A 1.0.1 prefers for agent-card responses.
pub const MEDIA_TYPE_A2A_JSON: &str = "application/a2a+json";

/// The legacy/default media type for agent-card responses.
pub const MEDIA_TYPE_JSON: &str = "application/json";

/// True when `Accept` explicitly lists the A2A 1.0 media type.
fn accepts_a2a_json(headers: &HeaderMap) -> bool {
    headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|accept| {
            accept
                .to_ascii_lowercase()
                .contains(MEDIA_TYPE_A2A_JSON)
        })
}

/// The content type to serve an agent card with, **negotiated** from the request.
///
/// A2A 1.0.1 prefers `application/a2a+json`, but a 0.3 client or tool may
/// strict-check `application/json`. So the new media type is used **only** when the
/// caller signals 1.0 — either via `A2A-Version: 1.0` or by asking for it in
/// `Accept`. Every other caller keeps `application/json`.
///
/// `accepted` is the surface's accepted set: a `1.0` header only counts when the
/// surface serves 1.0.
///
/// (Once v0.3 traffic has faded this can be simplified to always returning
/// [`MEDIA_TYPE_A2A_JSON`].)
pub fn agent_card_content_type(
    headers: &HeaderMap,
    accepted: &[&str],
) -> &'static str {
    if accepts_a2a_json(headers) || matches!(negotiate_from_headers(headers, accepted), Ok(VERSION_1_0)) {
        MEDIA_TYPE_A2A_JSON
    } else {
        MEDIA_TYPE_JSON
    }
}

/// Reduce a version string to its `Major.Minor` form, which is what the protocol
/// negotiates on (patch versions are excluded from client/server negotiation).
/// `"1.0.1"` becomes `"1.0"`; `"1.0"` is unchanged.
fn major_minor(raw: &str) -> &str {
    match raw.split('.').nth(2) {
        // There is a third segment — keep only `major.minor`.
        Some(_) => {
            let mut end = 0;
            let mut dots = 0;
            for (i, c) in raw.char_indices() {
                if c == '.' {
                    dots += 1;
                    if dots == 2 {
                        end = i;
                        break;
                    }
                }
            }
            &raw[..end]
        }
        None => raw,
    }
}

/// Negotiate the A2A protocol version for a request from a raw header value,
/// against the surface's accepted set.
///
/// Returns the accepted version on success. An absent or empty value resolves to
/// [`VERSION_0_3`] per the spec. A version the gateway does not recognise, or one
/// outside `accepted`, returns `Err` so the caller can answer with
/// [`ERR_VERSION_NOT_SUPPORTED`].
pub fn negotiate_version(
    raw: Option<&str>,
    accepted: &[&str],
) -> Result<&'static str, String> {
    // Interpretation first, and it is fixed by the spec: an absent or empty
    // header means v0.3. Whether that version is then accepted is a separate
    // question, answered by `accepted` below, so that a rejected v0.3
    // caller is refused for the right reason and told what is on offer.
    let resolved = match raw.map(str::trim) {
        None | Some("") => VERSION_0_3,
        Some(trimmed) => match major_minor(trimmed) {
            VERSION_0_3 => VERSION_0_3,
            VERSION_1_0 => VERSION_1_0,
            _ => return Err(trimmed.to_string()),
        },
    };

    if accepted.contains(&resolved) {
        Ok(resolved)
    } else {
        Err(resolved.to_string())
    }
}

/// Negotiate the A2A protocol version from request headers, against the
/// surface's accepted set.
/// A missing or non-UTF-8 header is treated as absent (⇒ [`VERSION_0_3`]).
pub fn negotiate_from_headers(
    headers: &HeaderMap,
    accepted: &[&str],
) -> Result<&'static str, String> {
    let raw = headers
        .get(A2A_VERSION_HEADER)
        .and_then(|v| v.to_str().ok());
    negotiate_version(raw, accepted)
}

/// Operator-facing reason a request was refused with [`ERR_VERSION_NOT_SUPPORTED`],
/// naming what the surface accepts and, when the caller sent no `A2A-Version`
/// header, that it was read as `0.3`.
pub fn version_refusal_reason(
    headers: &HeaderMap,
    requested: &str,
    accepted: &[&str],
    a2a_proxy_target: bool,
) -> String {
    let header_sent = headers
        .get(A2A_VERSION_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !v.trim().is_empty());
    let requested = super::clip_for_log(requested);
    let request = if header_sent {
        format!("A2A-Version '{requested}'")
    } else {
        format!("no A2A-Version header (read as {requested})")
    };
    let surface = if a2a_proxy_target {
        "the A2A proxy target serves"
    } else {
        "the surface accepts"
    };
    format!(
        "{request} is not accepted: {surface} {}; the caller must send A2A-Version: {}",
        accepted.join(", "),
        accepted.join(" or ")
    )
}

/// `negotiated_version` label value for the protocol-version metric: the
/// negotiated version, or `"rejected"` when the request is refused with
/// [`ERR_VERSION_NOT_SUPPORTED`].
pub fn negotiated_version_label(negotiation: &Result<&'static str, String>) -> &'static str {
    match negotiation {
        Ok(version) => version,
        Err(_) => "rejected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiated_version_label_reports_the_negotiated_version() {
        assert_eq!(negotiated_version_label(&Ok(VERSION_0_3)), "0.3");
        assert_eq!(negotiated_version_label(&Ok(VERSION_1_0)), "1.0");
    }

    #[test]
    fn negotiated_version_label_reports_a_refused_request_as_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(A2A_VERSION_HEADER, "2.0".parse().unwrap());
        let negotiation = negotiate_from_headers(&headers, SUPPORTED_VERSIONS);

        assert_eq!(negotiation, Err("2.0".to_string()));
        assert_eq!(negotiated_version_label(&negotiation), "rejected");
    }

    #[test]
    fn a_refusal_without_a_header_says_it_was_read_as_0_3() {
        let mut empty = HeaderMap::new();
        empty.insert(A2A_VERSION_HEADER, " ".parse().unwrap());
        for headers in [HeaderMap::new(), empty] {
            assert_eq!(
                version_refusal_reason(&headers, VERSION_0_3, VERSIONS_1_0_ONLY, true),
                "no A2A-Version header (read as 0.3) is not accepted: the A2A proxy target serves 1.0; \
                 the caller must send A2A-Version: 1.0"
            );
        }
    }

    #[test]
    fn a_refusal_of_a_sent_version_names_the_surface_accepted_versions() {
        let mut headers = HeaderMap::new();
        headers.insert(A2A_VERSION_HEADER, "2.0".parse().unwrap());
        assert_eq!(
            version_refusal_reason(&headers, "2.0", SUPPORTED_VERSIONS, false),
            "A2A-Version '2.0' is not accepted: the surface accepts 0.3, 1.0; \
             the caller must send A2A-Version: 0.3 or 1.0"
        );
    }

    #[test]
    fn a_refusal_cuts_a_long_version_value() {
        let long = "9".repeat(5_000);
        let mut headers = HeaderMap::new();
        headers.insert(A2A_VERSION_HEADER, long.parse().unwrap());
        let reason = version_refusal_reason(&headers, &long, SUPPORTED_VERSIONS, false);
        assert!(
            reason.starts_with(&format!("A2A-Version '{}…' is not accepted", "9".repeat(crate::a2a::MAX_LOGGED_CHARS))),
            "{reason}"
        );
        assert!(reason.len() < 200, "{reason}");
    }

    #[test]
    fn absent_or_empty_version_means_0_3() {
        // Spec: agents MUST interpret an empty value as 0.3.
        assert_eq!(negotiate_version(None, SUPPORTED_VERSIONS), Ok(VERSION_0_3));
        assert_eq!(negotiate_version(Some(""), SUPPORTED_VERSIONS), Ok(VERSION_0_3));
        assert_eq!(negotiate_version(Some("   "), SUPPORTED_VERSIONS), Ok(VERSION_0_3));
    }

    #[test]
    fn accepts_supported_versions() {
        assert_eq!(negotiate_version(Some("0.3"), SUPPORTED_VERSIONS), Ok(VERSION_0_3));
        assert_eq!(negotiate_version(Some("1.0"), SUPPORTED_VERSIONS), Ok(VERSION_1_0));
        assert_eq!(negotiate_version(Some(" 1.0 "), SUPPORTED_VERSIONS), Ok(VERSION_1_0));
    }

    #[test]
    fn patch_versions_negotiate_on_major_minor() {
        // Patch numbers are excluded from negotiation.
        assert_eq!(negotiate_version(Some("1.0.1"), SUPPORTED_VERSIONS), Ok(VERSION_1_0));
        assert_eq!(negotiate_version(Some("0.3.0"), SUPPORTED_VERSIONS), Ok(VERSION_0_3));
    }

    #[test]
    fn rejects_unsupported_versions() {
        assert_eq!(negotiate_version(Some("2.0"), SUPPORTED_VERSIONS), Err("2.0".to_string()));
        assert_eq!(negotiate_version(Some("0.2"), SUPPORTED_VERSIONS), Err("0.2".to_string()));
        assert_eq!(negotiate_version(Some("banana"), SUPPORTED_VERSIONS), Err("banana".to_string()));
    }

    #[test]
    fn negotiates_from_headers() {
        let mut headers = HeaderMap::new();
        // No header at all → 0.3 (spec default).
        assert_eq!(negotiate_from_headers(&headers, SUPPORTED_VERSIONS), Ok(VERSION_0_3));

        headers.insert(A2A_VERSION_HEADER, "1.0".parse().unwrap());
        assert_eq!(negotiate_from_headers(&headers, SUPPORTED_VERSIONS), Ok(VERSION_1_0));

        headers.insert(A2A_VERSION_HEADER, "0.3".parse().unwrap());
        assert_eq!(negotiate_from_headers(&headers, SUPPORTED_VERSIONS), Ok(VERSION_0_3));
    }

    #[test]
    fn empty_header_negotiates_as_0_3() {
        for empty in ["", "   "] {
            let mut headers = HeaderMap::new();
            headers.insert(A2A_VERSION_HEADER, axum::http::HeaderValue::from_static(empty));
            assert_eq!(
                negotiate_from_headers(&headers, SUPPORTED_VERSIONS),
                Ok(VERSION_0_3),
                "{empty:?} must mean 0.3"
            );
        }
    }

    #[test]
    fn unsupported_header_version_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(A2A_VERSION_HEADER, "3.1".parse().unwrap());
        assert_eq!(negotiate_from_headers(&headers, SUPPORTED_VERSIONS), Err("3.1".to_string()));
    }

    #[test]
    fn card_media_type_defaults_to_application_json() {
        // No 1.0 signal at all → 0.3 clients and tools keep application/json.
        let headers = HeaderMap::new();
        assert_eq!(agent_card_content_type(&headers, SUPPORTED_VERSIONS), MEDIA_TYPE_JSON);
    }

    #[test]
    fn card_media_type_upgrades_on_version_header() {
        let mut headers = HeaderMap::new();
        headers.insert(A2A_VERSION_HEADER, "1.0".parse().unwrap());
        assert_eq!(agent_card_content_type(&headers, SUPPORTED_VERSIONS), MEDIA_TYPE_A2A_JSON);
    }

    #[test]
    fn card_media_type_stays_json_for_v0_3_caller() {
        let mut headers = HeaderMap::new();
        headers.insert(A2A_VERSION_HEADER, "0.3".parse().unwrap());
        assert_eq!(agent_card_content_type(&headers, SUPPORTED_VERSIONS), MEDIA_TYPE_JSON);
    }

    #[test]
    fn card_media_type_upgrades_on_accept_header() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "application/a2a+json"
                .parse()
                .unwrap(),
        );
        assert_eq!(agent_card_content_type(&headers, SUPPORTED_VERSIONS), MEDIA_TYPE_A2A_JSON);

        // Also when listed among several types, and case-insensitively.
        headers.insert(
            axum::http::header::ACCEPT,
            "text/html, Application/A2A+JSON;q=0.9, */*"
                .parse()
                .unwrap(),
        );
        assert_eq!(agent_card_content_type(&headers, SUPPORTED_VERSIONS), MEDIA_TYPE_A2A_JSON);
    }

    /// A `1.0` header only upgrades the card on a surface that serves 1.0.
    #[test]
    fn card_media_type_follows_the_surface_accepted_set() {
        let mut headers = HeaderMap::new();
        headers.insert(A2A_VERSION_HEADER, "1.0".parse().unwrap());
        assert_eq!(agent_card_content_type(&headers, VERSIONS_1_0_ONLY), MEDIA_TYPE_A2A_JSON);
        assert_eq!(agent_card_content_type(&headers, VERSIONS_0_3_ONLY), MEDIA_TYPE_JSON);
    }

    #[test]
    fn card_media_type_stays_json_for_plain_json_accept() {
        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::ACCEPT,
            "application/json"
                .parse()
                .unwrap(),
        );
        assert_eq!(agent_card_content_type(&headers, SUPPORTED_VERSIONS), MEDIA_TYPE_JSON);
    }

    #[test]
    fn advertised_version_is_the_single_source_of_truth() {
        // Generated-card builders must use this constant, not a literal.
        assert_eq!(ADVERTISED_VERSION, "1.0");
        assert!(SUPPORTED_VERSIONS.contains(&ADVERTISED_VERSION));
    }
}

#[cfg(test)]
mod advertised_version_tests {
    use super::*;

    #[test]
    fn supported_version_resolves_both_eras_and_patch_suffixes() {
        assert_eq!(supported_version("1.0"), Some(VERSION_1_0));
        assert_eq!(supported_version("0.3"), Some(VERSION_0_3));
        // Matching is on Major.Minor, consistent with header negotiation.
        assert_eq!(supported_version("1.0.1"), Some(VERSION_1_0));
        assert_eq!(supported_version(" 1.0 "), Some(VERSION_1_0));
    }

    #[test]
    fn supported_version_rejects_anything_the_gateway_cannot_serve() {
        for raw in ["2.0", "0.2", "banana", ""] {
            assert_eq!(supported_version(raw), None, "{raw} must not resolve");
        }
    }

    /// With nothing installed, the compiled-in constant is what cards advertise.
    /// Every other test in the process relies on this fallback, so it must hold.
    #[test]
    fn advertised_version_falls_back_to_the_constant() {
        assert_eq!(advertised_version(), ADVERTISED_VERSION);
    }

    /// An unsupported configured value never reaches the accessor: validation
    /// rejects it first, and installing it is a no-op even if it did.
    #[test]
    fn installing_an_unsupported_version_is_ignored() {
        init_advertised_version("banana");
        assert_eq!(advertised_version(), ADVERTISED_VERSION);
    }

    #[test]
    fn installing_a_supported_version_changes_what_is_advertised() {
        if !run_isolated_from_other_tests() {
            return;
        }
        init_advertised_version("0.3");
        assert_eq!(advertised_version(), VERSION_0_3);

        init_advertised_version("1.0");
        assert_eq!(advertised_version(), VERSION_0_3, "the configured version is installed once");
    }
}

#[cfg(test)]
const ISOLATED_TEST_CHILD_ENV: &str = "AG_ISOLATED_TEST_CHILD";

/// Runs the calling `#[test]` again, alone, in a fresh process, so it can install
/// process-global state (the advertised version, global settings) without leaking
/// it into other tests.
///
/// Returns `true` in that child, where the test body should run, and `false` in
/// the parent once the child has passed.
#[cfg(test)]
pub(crate) fn run_isolated_from_other_tests() -> bool {
    if std::env::var_os(ISOLATED_TEST_CHILD_ENV).is_some() {
        return true;
    }
    let test_name = std::thread::current()
        .name()
        .expect("test thread name")
        .to_string();
    let output = std::process::Command::new(std::env::current_exe().expect("test binary path"))
        .args(["--exact", &test_name, "--nocapture", "--test-threads=1"])
        .env(ISOLATED_TEST_CHILD_ENV, "1")
        .output()
        .expect("run test in an isolated process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("1 passed"),
        "isolated run of {test_name} failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

#[cfg(test)]
mod accepted_set_tests {
    use super::*;

    fn configured(versions: &[&str]) -> Vec<String> {
        versions
            .iter()
            .map(|v| v.to_string())
            .collect()
    }

    #[test]
    fn a_configured_list_maps_onto_a_fixed_set_in_supported_order() {
        assert_eq!(accepted_set(&configured(&["0.3", "1.0"])), SUPPORTED_VERSIONS);
        assert_eq!(accepted_set(&configured(&["1.0", "0.3"])), SUPPORTED_VERSIONS);
        assert_eq!(accepted_set(&configured(&["1.0"])), VERSIONS_1_0_ONLY);
        assert_eq!(accepted_set(&configured(&["0.3"])), VERSIONS_0_3_ONLY);
    }

    #[test]
    fn an_unusable_list_falls_back_to_every_supported_version() {
        assert_eq!(accepted_set(&[]), SUPPORTED_VERSIONS);
        assert_eq!(accepted_set(&configured(&["2.0"])), SUPPORTED_VERSIONS);
        assert_eq!(accepted_set(&configured(&["2.0", "1.0"])), VERSIONS_1_0_ONLY);
    }

    /// A 1.0-only surface still reads an absent header as v0.3, as A2A requires,
    /// and then refuses it: that is what the specification prescribes for a
    /// version an interface does not support.
    #[test]
    fn a_1_0_only_surface_refuses_v0_3_including_an_absent_header() {
        assert_eq!(negotiate_version(Some("1.0"), VERSIONS_1_0_ONLY), Ok(VERSION_1_0));
        assert_eq!(negotiate_version(Some("1.0.1"), VERSIONS_1_0_ONLY), Ok(VERSION_1_0));

        assert_eq!(negotiate_version(Some("0.3"), VERSIONS_1_0_ONLY), Err("0.3".to_string()));
        assert_eq!(negotiate_version(None, VERSIONS_1_0_ONLY), Err("0.3".to_string()));
        assert_eq!(negotiate_version(Some(""), VERSIONS_1_0_ONLY), Err("0.3".to_string()));
    }

    #[test]
    fn a_0_3_only_surface_refuses_v1_0_and_serves_an_absent_header() {
        assert_eq!(negotiate_version(None, VERSIONS_0_3_ONLY), Ok(VERSION_0_3));
        assert_eq!(negotiate_version(Some("0.3"), VERSIONS_0_3_ONLY), Ok(VERSION_0_3));
        assert_eq!(negotiate_version(Some("1.0"), VERSIONS_0_3_ONLY), Err("1.0".to_string()));
    }

    #[test]
    fn a_version_the_gateway_never_serves_is_refused_whatever_the_surface_accepts() {
        for accepted in [SUPPORTED_VERSIONS, VERSIONS_1_0_ONLY, VERSIONS_0_3_ONLY] {
            assert_eq!(negotiate_version(Some("2.0"), accepted), Err("2.0".to_string()));
        }
    }

    #[test]
    fn a_surface_accepting_both_serves_both_eras() {
        assert_eq!(negotiate_version(None, SUPPORTED_VERSIONS), Ok(VERSION_0_3));
        assert_eq!(negotiate_version(Some("0.3"), SUPPORTED_VERSIONS), Ok(VERSION_0_3));
        assert_eq!(negotiate_version(Some("1.0"), SUPPORTED_VERSIONS), Ok(VERSION_1_0));
    }
}

/// The protocol version a card the gateway **generates** names as preferred:
/// `supportedInterfaces[0]` and the top-level `protocolVersion`.
///
/// `accepted` is the accepted set of the surface the card describes, so the
/// configured [`advertised_version`] can fall outside it. Never advertise a
/// version the surface would refuse: fall back to the first version on offer.
pub fn effective_advertised_version(accepted: &[&'static str]) -> &'static str {
    if accepted.contains(&advertised_version()) {
        advertised_version()
    } else {
        accepted
            .first()
            .copied()
            .unwrap_or(ADVERTISED_VERSION)
    }
}

/// Build the ordered `supportedInterfaces[]` array for a card the gateway
/// **generates** (the synthesized A2A-proxy card and the onboarding card).
///
/// A2A 1.0 lets an agent expose the same transport at more than one protocol
/// version, and order encodes client preference. So when the surface accepts
/// both eras, the card advertises both: [`effective_advertised_version`] first
/// as the preferred one, then every other version in `accepted`. Without the
/// second entry a caller has no way to discover that v0.3 is still served, and
/// would reasonably conclude from the card that it is not.
///
/// A surface accepting one version lists only that one.
pub fn generated_supported_interfaces(
    url: &str,
    accepted: &[&'static str],
) -> Vec<serde_json::Value> {
    let preferred = effective_advertised_version(accepted);
    let interface = |version: &str| {
        serde_json::json!({
            "url": url,
            "protocolBinding": PROTOCOL_BINDING_JSONRPC,
            "protocolVersion": version,
        })
    };

    let mut interfaces = vec![interface(preferred)];
    interfaces.extend(
        accepted
            .iter()
            .filter(|version| **version != preferred)
            .map(|version| interface(version)),
    );
    interfaces
}

#[cfg(test)]
mod generated_interface_tests {
    use super::*;

    fn listed_versions(interfaces: &[serde_json::Value]) -> Vec<&str> {
        interfaces
            .iter()
            .map(|i| {
                i["protocolVersion"]
                    .as_str()
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn advertises_every_accepted_version_preferred_first() {
        let interfaces = generated_supported_interfaces("https://gw.example/a2a", SUPPORTED_VERSIONS);

        assert_eq!(
            listed_versions(&interfaces),
            vec![VERSION_1_0, VERSION_0_3],
            "the advertised version comes first, since order encodes preference, and every accepted version is listed"
        );
    }

    #[test]
    fn a_single_version_surface_advertises_only_that_version() {
        assert_eq!(
            listed_versions(&generated_supported_interfaces("https://gw.example/a2a", VERSIONS_1_0_ONLY)),
            vec![VERSION_1_0]
        );
        assert_eq!(
            listed_versions(&generated_supported_interfaces("https://gw.example/a2a", VERSIONS_0_3_ONLY)),
            vec![VERSION_0_3],
            "a card never names a version its surface refuses"
        );
    }

    #[test]
    fn effective_version_is_the_advertised_one_by_default() {
        assert_eq!(effective_advertised_version(SUPPORTED_VERSIONS), advertised_version());
        assert_eq!(effective_advertised_version(SUPPORTED_VERSIONS), VERSION_1_0);
        assert_eq!(effective_advertised_version(VERSIONS_0_3_ONLY), VERSION_0_3);
    }

    #[test]
    fn effective_version_keeps_a_configured_version_the_surface_accepts_and_falls_back_otherwise() {
        if !run_isolated_from_other_tests() {
            return;
        }
        init_advertised_version("0.3");

        assert_eq!(effective_advertised_version(SUPPORTED_VERSIONS), VERSION_0_3);
        assert_eq!(effective_advertised_version(VERSIONS_1_0_ONLY), VERSION_1_0);
    }

    #[test]
    fn every_interface_points_at_the_same_endpoint_and_binding() {
        let interfaces = generated_supported_interfaces("https://gw.example/a2a", SUPPORTED_VERSIONS);
        for interface in &interfaces {
            assert_eq!(interface["url"], "https://gw.example/a2a");
            assert_eq!(interface["protocolBinding"], PROTOCOL_BINDING_JSONRPC);
        }
    }
}

/// The v0.3 fields to merge into a card the gateway **generates**, or `None`
/// when the surface's accepted set does not include v0.3.
///
/// A v0.3 client does not understand `supportedInterfaces[]` or
/// `provider.organization`, so without these it can read the card but not act on
/// it. Emitting them is what makes "we accept v0.3" true at the discovery step as
/// well as the request step.
///
/// Gating matters in both directions. A surface without v0.3 serves v1.0 only,
/// and publishing `url` + `preferredTransport` would invite a
/// v0.3 client to connect to an endpoint that then refuses it with
/// `VersionNotSupportedError`. The card must describe what the gateway will
/// actually serve.
///
/// `capabilities.stateTransitionHistory` is deliberately not re-emitted: v1.0
/// removed it outright with no successor, it is optional in v0.3 where it
/// defaults to `false`, and the cards the gateway generates would report `false`
/// anyway. Emitting a field the current spec deleted, to convey the value a
/// reader already assumes, buys nothing.
pub fn legacy_v0_3_card_fields(
    url: &str,
    provider: &serde_json::Value,
    extended_agent_card: bool,
    accepted: &[&'static str],
) -> Option<serde_json::Map<String, serde_json::Value>> {
    if !accepted.contains(&VERSION_0_3) {
        return None;
    }

    let mut fields = serde_json::Map::new();
    // v1.0 moved the version onto each `supportedInterfaces[]` entry.
    fields.insert(
        "protocolVersion".to_string(),
        serde_json::Value::String(effective_advertised_version(accepted).to_string()),
    );
    // v1.0 collapsed these into `supportedInterfaces[]`.
    fields.insert("url".to_string(), serde_json::Value::String(url.to_string()));
    fields.insert("preferredTransport".to_string(), serde_json::Value::String(PROTOCOL_BINDING_JSONRPC.to_string()));
    // v1.0 renamed this to `provider`.
    fields.insert("agentProvider".to_string(), provider.clone());
    // v1.0 moved this under `capabilities`. Derived from the same value as
    // `capabilities.extendedAgentCard` so the two cannot drift apart.
    fields.insert("supportsAuthenticatedExtendedCard".to_string(), serde_json::Value::Bool(extended_agent_card));
    Some(fields)
}

#[cfg(test)]
mod legacy_card_field_tests {
    use super::*;

    fn provider() -> serde_json::Value {
        serde_json::json!({ "organization": "Affinidi", "url": "https://affinidi.com" })
    }

    #[test]
    fn emits_the_fields_a_v0_3_reader_needs_when_the_surface_accepts_v0_3() {
        let fields = legacy_v0_3_card_fields("https://gw.example/a2a", &provider(), false, SUPPORTED_VERSIONS)
            .expect("the surface accepts v0.3");

        assert_eq!(fields["protocolVersion"], effective_advertised_version(SUPPORTED_VERSIONS));
        assert_eq!(fields["url"], "https://gw.example/a2a");
        assert_eq!(fields["preferredTransport"], PROTOCOL_BINDING_JSONRPC);
        assert_eq!(fields["agentProvider"], provider());
        assert_eq!(fields["supportsAuthenticatedExtendedCard"], false);
    }

    /// The legacy flag must track the 1.0 capability, not a hardcoded value.
    #[test]
    fn the_extended_card_flag_mirrors_the_1_0_capability() {
        let fields = legacy_v0_3_card_fields("https://gw.example/a2a", &provider(), true, SUPPORTED_VERSIONS).unwrap();
        assert_eq!(fields["supportsAuthenticatedExtendedCard"], true);
    }

    #[test]
    fn a_surface_without_v0_3_gets_no_legacy_fields() {
        assert!(legacy_v0_3_card_fields("https://gw.example/a2a", &provider(), false, VERSIONS_1_0_ONLY).is_none());
    }

    /// Removed in 1.0 with no successor and no information to convey.
    #[test]
    fn does_not_resurrect_state_transition_history() {
        let fields = legacy_v0_3_card_fields("https://gw.example/a2a", &provider(), false, SUPPORTED_VERSIONS).unwrap();
        assert!(!fields.contains_key("stateTransitionHistory"));
    }
}
