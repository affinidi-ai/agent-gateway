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
        ("channel_e2e.rs", 12),
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
        ("mod.rs", 0),
        ("mtls.rs", 6),
        ("multi_method_source_auth_e2e.rs", 7),
        ("provider_key_gate_e2e.rs", 6),
        ("request_body_bounds_e2e.rs", 12),
        ("stored_reference_transit_token_e2e.rs", 1),
        ("target_auth_provider_e2e.rs", 2),
        ("tenant_credential_save_e2e.rs", 36),
        ("tr_naming_e2e.rs", 4),
        ("transit_caller_auth_e2e.rs", 11),
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

    fn is_test_attribute(line: &str) -> bool {
        let trimmed = line.trim_start();
        trimmed.starts_with("#[test]") || trimmed.starts_with("#[tokio::test")
    }

    #[test]
    fn no_file_is_added_under_component_tests() {
        let root = component_tests_dir();
        let mut present = Vec::new();
        collect_files(&root, &root, &mut present);
        assert!(!present.is_empty(), "no component test files were inspected; the guard would pass vacuously");

        let mut added: Vec<_> = present
            .into_iter()
            .filter(|file| {
                !FROZEN_FILES
                    .iter()
                    .any(|(frozen, _)| frozen == file)
            })
            .collect();
        added.sort();
        assert!(added.is_empty(), "{GUIDANCE}; new files: {added:?}");
    }

    #[test]
    fn no_test_is_added_to_a_frozen_component_file() {
        let root = component_tests_dir();
        let mut inspected = 0usize;
        let mut grown = Vec::new();
        for (file, pinned) in FROZEN_FILES {
            if *file == "mod.rs" {
                continue;
            }
            let Ok(source) = std::fs::read_to_string(root.join(file)) else {
                continue;
            };
            inspected += 1;
            let count = source
                .lines()
                .filter(|line| is_test_attribute(line))
                .count();
            if count > *pinned {
                grown.push(format!("{file} has {count} tests, pinned at {pinned}"));
            }
        }
        assert!(inspected > 0, "no component test files were inspected; the guard would pass vacuously");
        assert!(grown.is_empty(), "{GUIDANCE}; grown files: {grown:?}");
    }
}
