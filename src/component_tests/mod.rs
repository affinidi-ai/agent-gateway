mod a2a_extended_card_e2e;
mod a2a_flow_e2e;
mod a2a_proxy_e2e;
mod a2a_streaming_e2e;
mod access_point_closed_e2e;
mod access_tokens_pat;
mod agent_card_preview;
mod api_key_identity_e2e;
mod channel_e2e;
mod connection_point_integration_events_e2e;
mod custom_metadata_tenancy_e2e;
mod delegation_vault_tenancy;
#[cfg(feature = "didwebvh")]
mod didwebvh_e2e;
mod event_hook_e2e;
mod fabric_stream_revocation;
mod fabric_transit_token_e2e;
mod global_policy_e2e;
mod header_metadata_mapping_e2e;
pub(crate) mod helpers;
mod identity_e2e;
mod identity_naming_e2e;
mod mcp_authorization_discovery_e2e;
mod mcp_outbound_e2e;
mod mcp_policy_e2e;
mod mcp_record_compat;
mod mcp_sandbox_e2e;
mod mcp_subscription_scope;
mod mtls;
mod multi_method_source_auth_e2e;
mod provider_key_gate_e2e;
mod request_body_bounds_e2e;
mod stored_reference_transit_token_e2e;
mod surface_reload_listener_e2e;
mod target_auth_provider_e2e;
mod tenant_credential_save_e2e;
mod tr_naming_e2e;
mod transit_caller_auth_e2e;
mod transit_caller_policy_e2e;
mod transit_point_headers_e2e;
mod transit_point_lifecycle_e2e;
mod transit_point_rate_limit_e2e;
mod transit_source_auth_e2e;
mod transit_token_e2e;
mod trust_check_e2e;
mod trust_check_store_migration;
mod trust_recorder_status_e2e;
mod upstream_response_bounds_e2e;

#[cfg(test)]
mod freeze {
    use std::path::{Path, PathBuf};

    const FROZEN_FILES: &[(&str, usize)] = &[
        ("a2a_extended_card_e2e.rs", 17),
        ("a2a_flow_e2e.rs", 51),
        ("a2a_proxy_e2e.rs", 20),
        ("a2a_streaming_e2e.rs", 11),
        ("access_point_closed_e2e.rs", 12),
        ("access_tokens_pat.rs", 52),
        ("agent_card_preview.rs", 5),
        ("api_key_identity_e2e.rs", 12),
        ("channel_e2e.rs", 13),
        ("connection_point_integration_events_e2e.rs", 2),
        ("custom_metadata_tenancy_e2e.rs", 2),
        ("didwebvh_e2e.rs", 1),
        ("event_hook_e2e.rs", 28),
        ("fabric_stream_revocation.rs", 5),
        ("fabric_transit_token_e2e.rs", 3),
        ("global_policy_e2e.rs", 2),
        ("header_metadata_mapping_e2e.rs", 4),
        ("helpers/audit_events.rs", 0),
        ("helpers/formatted_logs.rs", 0),
        ("helpers/jwt.rs", 0),
        ("helpers/mod.rs", 2),
        ("helpers/thread_subscriber.rs", 1),
        ("identity_e2e.rs", 34),
        ("identity_naming_e2e.rs", 7),
        ("mcp_authorization_discovery_e2e.rs", 11),
        ("mcp_outbound_e2e.rs", 6),
        ("mcp_policy_e2e.rs", 16),
        ("mcp_record_compat.rs", 9),
        ("mcp_sandbox_e2e.rs", 2),
        ("mcp_subscription_scope.rs", 2),
        ("mod.rs", 3),
        ("mtls.rs", 6),
        ("multi_method_source_auth_e2e.rs", 7),
        ("provider_key_gate_e2e.rs", 6),
        ("request_body_bounds_e2e.rs", 12),
        ("stored_reference_transit_token_e2e.rs", 1),
        ("surface_reload_listener_e2e.rs", 3),
        ("target_auth_provider_e2e.rs", 2),
        ("tenant_credential_save_e2e.rs", 36),
        ("tr_naming_e2e.rs", 4),
        ("transit_caller_auth_e2e.rs", 12),
        ("transit_caller_policy_e2e.rs", 5),
        ("transit_point_headers_e2e.rs", 1),
        ("transit_point_lifecycle_e2e.rs", 4),
        ("transit_point_rate_limit_e2e.rs", 1),
        ("transit_source_auth_e2e.rs", 1),
        ("transit_token_e2e.rs", 12),
        ("trust_check_e2e.rs", 6),
        ("trust_check_store_migration.rs", 1),
        ("trust_recorder_status_e2e.rs", 1),
        ("upstream_response_bounds_e2e.rs", 12),
    ];

    const GUIDANCE: &str = "src/component_tests is frozen: cover new behaviour with a Gherkin scenario under tests/features (see docs/development/TESTING.md)";

    const FROM_MAIN: &str = "if a rebase brought this in from main, set its entry in FROZEN_FILES in src/component_tests/mod.rs to main's count";

    const LOWER_THE_PIN: &str = "lower or remove its entry in FROZEN_FILES in src/component_tests/mod.rs in the same change, so deleted tests cannot come back";

    fn component_tests_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("src/component_tests")
    }

    fn collect_files(
        root: &Path,
        dir: &Path,
        found: &mut Vec<String>,
    ) {
        for entry in std::fs::read_dir(dir).expect("component_tests directory") {
            let path = entry
                .expect("component_tests directory entry")
                .path();
            if path.is_dir() {
                collect_files(root, &path, found);
                continue;
            }
            if path
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("rs")
            {
                continue;
            }
            let relative = path
                .strip_prefix(root)
                .expect("path under component_tests")
                .components()
                .map(|component| {
                    component
                        .as_os_str()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect::<Vec<_>>()
                .join("/");
            found.push(relative);
        }
    }

    /// An attribute whose path ends in `test`, such as `#[test]`, `#[tokio::test(...)]` or
    /// `#[::tokio::test]`. Tests generated by a macro or behind `cfg_attr` are not counted.
    fn is_test_attribute(line: &str) -> bool {
        let Some(attribute) = line
            .trim_start()
            .strip_prefix("#[")
        else {
            return false;
        };
        let path = attribute
            .trim_start_matches("::")
            .split(['(', ']'])
            .next()
            .unwrap_or_default();
        path.rsplit("::").next() == Some("test")
    }

    #[test]
    fn the_component_test_files_are_the_frozen_ones() {
        let root = component_tests_dir();
        let mut present = Vec::new();
        collect_files(&root, &root, &mut present);
        assert!(!present.is_empty(), "no component test files were inspected; the guard would pass vacuously");

        let mut added: Vec<_> = present
            .iter()
            .filter(|file| {
                !FROZEN_FILES
                    .iter()
                    .any(|(frozen, _)| frozen == file)
            })
            .collect();
        added.sort();
        assert!(added.is_empty(), "{GUIDANCE}; new files: {added:?}; {FROM_MAIN}");

        let missing: Vec<_> = FROZEN_FILES
            .iter()
            .map(|(frozen, _)| *frozen)
            .filter(|frozen| {
                !present
                    .iter()
                    .any(|file| file == frozen)
            })
            .collect();
        assert!(missing.is_empty(), "frozen files that are gone: {missing:?}; {LOWER_THE_PIN}");
    }

    #[test]
    fn each_frozen_file_has_its_pinned_number_of_tests() {
        let root = component_tests_dir();
        let mut inspected = 0usize;
        let mut grown = Vec::new();
        let mut shrunk = Vec::new();
        for (file, pinned) in FROZEN_FILES {
            let Ok(source) = std::fs::read_to_string(root.join(file)) else {
                continue;
            };
            inspected += 1;
            let count = source
                .lines()
                .filter(|line| is_test_attribute(line))
                .count();
            let report = format!("{file} has {count} tests, pinned at {pinned}");
            match count.cmp(pinned) {
                std::cmp::Ordering::Greater => grown.push(report),
                std::cmp::Ordering::Less => shrunk.push(report),
                std::cmp::Ordering::Equal => {}
            }
        }
        assert!(inspected > 0, "no component test files were inspected; the guard would pass vacuously");
        assert!(grown.is_empty(), "{GUIDANCE}; grown files: {grown:?}; {FROM_MAIN}");
        assert!(shrunk.is_empty(), "fewer tests than pinned: {shrunk:?}; {LOWER_THE_PIN}");
    }

    #[test]
    fn test_attributes_are_recognised_by_the_end_of_their_path() {
        let counted =
            ["#[test]", "    #[tokio::test]", "#[tokio::test(flavor = \"multi_thread\")]", "#[::tokio::test]"];
        let ignored = ["#[cfg(test)]", "#[test_case(1)]", "// #[test]", "fn test() {}"];

        for line in counted {
            assert!(is_test_attribute(line), "{line} must count as a test");
        }
        for line in ignored {
            assert!(!is_test_attribute(line), "{line} must not count as a test");
        }
    }
}
