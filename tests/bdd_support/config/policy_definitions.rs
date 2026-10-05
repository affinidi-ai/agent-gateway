use std::path::Path;

use chrono::Utc;
use serde_json::json;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PolicyDefinitionFixtureKind {
    SurfaceInbound,
    TransitShared,
    TransitPoint,
}

impl PolicyDefinitionFixtureKind {
    fn suffix(self) -> &'static str {
        match self {
            Self::SurfaceInbound => "inbound-policy",
            Self::TransitShared => "transit-policy",
            Self::TransitPoint => "transit-point-policy",
        }
    }
}

pub fn policy_definition_id(
    owner_id: &str,
    kind: PolicyDefinitionFixtureKind,
) -> String {
    format!("{}-{}", owner_id, kind.suffix())
}

pub fn inbound_policy_definition_id(surface_id: &str) -> String {
    policy_definition_id(surface_id, PolicyDefinitionFixtureKind::SurfaceInbound)
}

pub fn write_policy_definition_fixture(
    policies_dir: &Path,
    id: &str,
    description: &str,
    rego: &str,
) {
    std::fs::create_dir_all(policies_dir).unwrap();
    let now = Utc::now().to_rfc3339();
    let policy_json = json!({
        "id": id,
        "name": id,
        "description": description,
        "policy_type": "agent_surface",
        "policy": rego,
        "enabled": true,
        "created_at": now,
        "updated_at": now,
    });
    std::fs::write(policies_dir.join(format!("{id}.json")), serde_json::to_string_pretty(&policy_json).unwrap())
        .unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn policy_definition_fixture_writer_creates_expected_storage_record() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let policies_dir = temp_dir
            .path()
            .join("policies");
        let policy_id = super::inbound_policy_definition_id("alpha");

        super::write_policy_definition_fixture(
            &policies_dir,
            &policy_id,
            "BDD policy",
            "package policy\ndefault allow := true",
        );

        let policy_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(policies_dir.join("alpha-inbound-policy.json")).unwrap())
                .unwrap();
        assert_eq!(policy_json["id"], "alpha-inbound-policy");
        assert_eq!(policy_json["description"], "BDD policy");
        assert_eq!(policy_json["policy"], "package policy\ndefault allow := true");
        assert_eq!(
            super::policy_definition_id("alpha", super::PolicyDefinitionFixtureKind::TransitShared),
            "alpha-transit-policy"
        );
        assert_eq!(
            super::policy_definition_id("alpha-crm", super::PolicyDefinitionFixtureKind::TransitPoint),
            "alpha-crm-transit-point-policy"
        );
    }
}
