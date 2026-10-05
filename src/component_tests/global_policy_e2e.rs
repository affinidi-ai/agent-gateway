//! Appliance-wide (global) policy assignments — deleting a policy definition
//! removes it from the served and persisted global assignments.
//!
//! Proxy enforcement is not asserted here: the appliance policy manager lives in
//! a process-wide `OnceLock`, so in a shared test process it belongs to whichever
//! harness booted first. Enforcement after pruning is covered by the
//! `global_policy` unit tests. For the same reason every assignment here is
//! `monitor_only`, so a deny-all assigned by these tests can never block
//! requests in other tests sharing the process.

use super::helpers::{GatewayHarness, configure_admin_api};
use crate::policies::{FileSystemGlobalPolicyStore, GlobalPolicyAssignments};
use serde_json::json;

const DENY_ALL_POLICY_ID: &str = "global-deny-all";
const ALLOW_ALL_POLICY_ID: &str = "global-allow-all";

fn write_surface_policy_definition(
    temp_dir: &std::path::Path,
    id: &str,
    allow: bool,
) {
    let definition = json!({
        "id": id,
        "name": id,
        "description": "Global policy fixture",
        "policy_type": "agent_surface",
        "policy": format!("package surface.policy\n\ndefault allow := {allow}\n"),
        "enabled": true,
        "created_at": "2026-01-01T00:00:00Z"
    });
    let dir = temp_dir.join("policy_definitions");
    std::fs::create_dir_all(&dir).expect("create policy_definitions dir");
    std::fs::write(
        dir.join(format!("{id}.json")),
        serde_json::to_string_pretty(&definition).expect("serialize policy definition"),
    )
    .expect("write policy definition fixture");
}

struct Fixture {
    harness: GatewayHarness,
    admin: reqwest::Client,
    global_policies_dir: String,
}

impl Fixture {
    async fn start() -> Self {
        let mut admin = None;
        let mut global_policies_dir = String::new();
        let harness = GatewayHarness::start(|temp_dir, _, bootstrap| {
            write_surface_policy_definition(temp_dir, DENY_ALL_POLICY_ID, false);
            write_surface_policy_definition(temp_dir, ALLOW_ALL_POLICY_ID, true);
            global_policies_dir = bootstrap
                .storage_paths
                .global_policies
                .clone();
            admin = Some(configure_admin_api(bootstrap));
        })
        .await;
        Self {
            harness,
            admin: admin.expect("admin client"),
            global_policies_dir,
        }
    }

    fn api(
        &self,
        path: &str,
    ) -> String {
        format!("{}/api/v1/{path}", self.harness.gateway_base)
    }

    async fn assign_globally(
        &self,
        policy_ids: &[&str],
    ) {
        let list: Vec<_> = policy_ids
            .iter()
            .map(|id| json!({ "policy_id": id, "monitor_only": true }))
            .collect();
        let resp = self
            .admin
            .put(self.api("policy-assignments"))
            .json(&json!({ "assignments": { "agent_surface": list } }))
            .send()
            .await
            .expect("PUT policy-assignments");
        assert_eq!(
            resp.status(),
            200,
            "assign globally: {}",
            resp.text()
                .await
                .unwrap_or_default()
        );
    }

    async fn delete_policy(
        &self,
        policy_id: &str,
    ) {
        let resp = self
            .admin
            .delete(self.api(&format!("policy-definitions/{policy_id}")))
            .send()
            .await
            .expect("DELETE policy-definition");
        assert_eq!(
            resp.status(),
            204,
            "delete policy: {}",
            resp.text()
                .await
                .unwrap_or_default()
        );
    }

    async fn live_assignments(&self) -> GlobalPolicyAssignments {
        let resp = self
            .admin
            .get(self.api("policy-assignments"))
            .send()
            .await
            .expect("GET policy-assignments");
        assert_eq!(resp.status(), 200);
        resp.json()
            .await
            .expect("parse policy-assignments")
    }

    async fn persisted_assignments(&self) -> GlobalPolicyAssignments {
        FileSystemGlobalPolicyStore::new(
            self.global_policies_dir
                .clone(),
        )
        .await
        .expect("open global policy store")
        .get()
        .await
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_globally_assigned_policy_removes_its_assignment() {
    let f = Fixture::start().await;
    f.assign_globally(&[DENY_ALL_POLICY_ID, ALLOW_ALL_POLICY_ID])
        .await;

    f.delete_policy(DENY_ALL_POLICY_ID)
        .await;

    for assignments in [
        f.live_assignments().await,
        f.persisted_assignments()
            .await,
    ] {
        assert!(!assignments.references_policy(DENY_ALL_POLICY_ID));
        assert!(assignments.references_policy(ALLOW_ALL_POLICY_ID));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn deleting_unassigned_policy_leaves_global_assignments_unchanged() {
    let f = Fixture::start().await;
    f.assign_globally(&[DENY_ALL_POLICY_ID])
        .await;
    let before = f
        .persisted_assignments()
        .await;

    f.delete_policy(ALLOW_ALL_POLICY_ID)
        .await;

    assert_eq!(
        f.persisted_assignments()
            .await,
        before
    );
    assert_eq!(f.live_assignments().await, before);
}
