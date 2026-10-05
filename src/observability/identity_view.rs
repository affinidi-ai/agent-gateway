//! Dashboard view of identity records: origin, grouping, credential principal and naming.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::warn;

use super::caller_names::{CallerName, DisplayNameSource};
use crate::identity::display_name::ManagedDisplayName;
use crate::identity::filesystem::IdentityOrigin;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKind {
    Certificate,
    ApiKey,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialPrincipal {
    pub kind: PrincipalKind,
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

/// The certificate or API key a credential-derived identity was minted from; `name` is unset.
pub fn credential_principal(fields: &HashMap<String, Value>) -> Option<CredentialPrincipal> {
    let field = |key: &str| {
        fields
            .get(key)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    if let Some(id) = field("certificate_id") {
        return Some(CredentialPrincipal {
            kind: PrincipalKind::Certificate,
            id,
            name: None,
        });
    }
    field("api_key_id").map(|id| CredentialPrincipal {
        kind: PrincipalKind::ApiKey,
        id,
        name: None,
    })
}

/// Certificate and API key names, loaded once per identity list from the global stores.
#[derive(Debug, Default)]
pub struct PrincipalNames {
    certificates: HashMap<String, String>,
    api_keys: HashMap<String, String>,
}

impl PrincipalNames {
    pub async fn load<'a>(principals: impl IntoIterator<Item = &'a CredentialPrincipal>) -> Self {
        let (mut need_certificates, mut need_api_keys) = (false, false);
        for p in principals {
            match p.kind {
                PrincipalKind::Certificate => need_certificates = true,
                PrincipalKind::ApiKey => need_api_keys = true,
            }
        }
        let mut names = Self::default();
        if need_certificates && let Some(store) = crate::proxy::server::get_certificates_store() {
            match store.list_all().await {
                Ok(items) => {
                    for item in items {
                        names
                            .certificates
                            .insert(item.id, item.name.clone());
                        names
                            .certificates
                            .insert(item.certificate_id, item.name);
                    }
                }
                Err(e) => warn!(error = %e, "Failed to list certificates for identity principals"),
            }
        }
        if need_api_keys && let Some(store) = crate::gateways::connection_points::message_processor::get_secrets_store()
        {
            match store.list_all().await {
                Ok(items) => {
                    for item in items {
                        names
                            .api_keys
                            .insert(item.secret_id, item.name);
                    }
                }
                Err(e) => warn!(error = %e, "Failed to list secrets for identity principals"),
            }
        }
        names
    }

    pub fn named(
        &self,
        mut principal: CredentialPrincipal,
    ) -> CredentialPrincipal {
        let names = match principal.kind {
            PrincipalKind::Certificate => &self.certificates,
            PrincipalKind::ApiKey => &self.api_keys,
        };
        principal.name = names
            .get(&principal.id)
            .cloned();
        principal
    }
}

pub fn group_key(
    origin: Option<IdentityOrigin>,
    surface_id: Option<&str>,
    did: &str,
) -> String {
    match (origin, surface_id) {
        (Some(IdentityOrigin::Managed), Some(id)) if !id.is_empty() => format!("surface:{id}"),
        _ => format!("did:{did}"),
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NamingFields {
    pub display_name: Option<String>,
    pub display_name_source: Option<DisplayNameSource>,
    pub display_name_verified: bool,
    pub name_conflict: bool,
}

/// Managed rows take names only from their surface; caller rows only from caller lookups.
pub fn naming_for(
    origin: Option<IdentityOrigin>,
    managed: Option<&ManagedDisplayName>,
    caller: Option<&CallerName>,
) -> NamingFields {
    match (origin, managed, caller) {
        (Some(IdentityOrigin::Managed), Some(ManagedDisplayName::Named(name)), _) => NamingFields {
            display_name: Some(name.as_str().to_string()),
            display_name_source: Some(DisplayNameSource::SurfaceName),
            ..Default::default()
        },
        (Some(IdentityOrigin::Managed), Some(ManagedDisplayName::Conflict { .. }), _) => NamingFields {
            name_conflict: true,
            ..Default::default()
        },
        (Some(IdentityOrigin::ExternalCaller), _, Some(caller)) => NamingFields {
            display_name: Some(caller.name.clone()),
            display_name_source: Some(caller.source),
            display_name_verified: caller.verified && caller.source == DisplayNameSource::AgentName,
            name_conflict: false,
        },
        _ => NamingFields::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::display_name::DisplayName;
    use chrono::Utc;
    use serde_json::json;

    fn caller(
        source: DisplayNameSource,
        verified: bool,
    ) -> CallerName {
        CallerName {
            name: "acme.com/@billing".into(),
            source,
            verified,
            resolved_at: Utc::now(),
        }
    }

    fn named(name: &str) -> ManagedDisplayName {
        ManagedDisplayName::Named(DisplayName::parse(name).unwrap())
    }

    #[test]
    fn test_credential_principal_for_certificate_api_key_and_none() {
        let cert: HashMap<String, Value> = [("certificate_id".to_string(), json!("NITROGEN"))].into();
        assert_eq!(
            credential_principal(&cert),
            Some(CredentialPrincipal {
                kind: PrincipalKind::Certificate,
                id: "NITROGEN".into(),
                name: None
            })
        );
        let key: HashMap<String, Value> = [("api_key_id".to_string(), json!("atgk_1"))].into();
        assert_eq!(
            credential_principal(&key).map(|p| (p.kind, p.id)),
            Some((PrincipalKind::ApiKey, "atgk_1".to_string()))
        );
        let none: HashMap<String, Value> =
            [("name".to_string(), json!("x")), ("api_key_id".to_string(), json!(""))].into();
        assert_eq!(credential_principal(&none), None);
    }

    #[test]
    fn test_principal_names_fill_matching_kind_only() {
        let names = PrincipalNames {
            certificates: [("NITROGEN".to_string(), "Nitrogen cert".to_string())].into(),
            api_keys: HashMap::new(),
        };
        let cert = CredentialPrincipal {
            kind: PrincipalKind::Certificate,
            id: "NITROGEN".into(),
            name: None,
        };
        assert_eq!(
            names
                .named(cert.clone())
                .name
                .as_deref(),
            Some("Nitrogen cert")
        );
        let key = CredentialPrincipal {
            kind: PrincipalKind::ApiKey,
            ..cert
        };
        assert_eq!(names.named(key).name, None);
    }

    #[test]
    fn test_credential_principal_json_shape() {
        let value = serde_json::to_value(CredentialPrincipal {
            kind: PrincipalKind::ApiKey,
            id: "k".into(),
            name: Some("Key".into()),
        })
        .unwrap();
        assert_eq!(value, json!({ "kind": "api_key", "id": "k", "name": "Key" }));
    }

    #[test]
    fn test_group_key_by_surface_for_managed_and_by_did_otherwise() {
        assert_eq!(group_key(Some(IdentityOrigin::Managed), Some("s1"), "did:a"), "surface:s1");
        assert_eq!(group_key(Some(IdentityOrigin::Managed), None, "did:a"), "did:did:a");
        assert_eq!(group_key(Some(IdentityOrigin::ExternalCaller), Some("s1"), "did:a"), "did:did:a");
        assert_eq!(group_key(None, Some("s1"), "did:a"), "did:did:a");
    }

    #[test]
    fn test_naming_for_managed_ignores_caller_names() {
        let c = caller(DisplayNameSource::AgentName, true);
        let fields = naming_for(Some(IdentityOrigin::Managed), Some(&named("OXYGEN")), Some(&c));
        assert_eq!(fields.display_name.as_deref(), Some("OXYGEN"));
        assert_eq!(fields.display_name_source, Some(DisplayNameSource::SurfaceName));
        assert!(!fields.display_name_verified);

        assert_eq!(
            naming_for(Some(IdentityOrigin::Managed), Some(&ManagedDisplayName::Unnamed), Some(&c)),
            NamingFields::default()
        );
        assert_eq!(naming_for(Some(IdentityOrigin::Managed), None, Some(&c)), NamingFields::default());
    }

    #[test]
    fn test_naming_for_conflict_sets_flag_without_name() {
        let conflict = ManagedDisplayName::Conflict {
            surface_ids: vec!["a".into(), "b".into()],
        };
        let fields = naming_for(Some(IdentityOrigin::Managed), Some(&conflict), None);
        assert!(fields.name_conflict);
        assert_eq!(fields.display_name, None);
    }

    #[test]
    fn test_naming_for_caller_ignores_managed_names() {
        assert_eq!(
            naming_for(Some(IdentityOrigin::ExternalCaller), Some(&named("OXYGEN")), None),
            NamingFields::default()
        );
        let verified = naming_for(
            Some(IdentityOrigin::ExternalCaller),
            Some(&named("OXYGEN")),
            Some(&caller(DisplayNameSource::AgentName, true)),
        );
        assert_eq!(
            verified
                .display_name
                .as_deref(),
            Some("acme.com/@billing")
        );
        assert_eq!(verified.display_name_source, Some(DisplayNameSource::AgentName));
        assert!(verified.display_name_verified);

        let card =
            naming_for(Some(IdentityOrigin::ExternalCaller), None, Some(&caller(DisplayNameSource::AgentCard, true)));
        assert!(!card.display_name_verified);
    }

    #[test]
    fn test_naming_for_unknown_origin_is_empty() {
        assert_eq!(
            naming_for(None, Some(&named("OXYGEN")), Some(&caller(DisplayNameSource::AgentName, true))),
            NamingFields::default()
        );
    }
}
