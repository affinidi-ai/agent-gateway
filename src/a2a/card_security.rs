//! The security an agent card declares once the gateway serves it.
//!
//! Only an Access Point that declares, or asks for a declaration it cannot serve,
//! changes the security of the cards it serves; every other card keeps the security
//! and signatures its Target served. A secured card names the gateway's authorization
//! server, or no scheme at all, in place of any upstream security, and drops the
//! signatures made over the card the gateway changed.

use serde_json::{Map, Value, json};

use crate::source_auth::declaration::{Declaration, DeclarationOutcome};

/// Whether an Access Point's declaration outcome secures the cards it serves: it
/// declares, or it asks for a declaration it cannot serve, so its cards fail closed.
pub fn secures_cards(outcome: &DeclarationOutcome) -> bool {
    matches!(outcome, DeclarationOutcome::Declare(_) | DeclarationOutcome::Unservable(_))
}

/// The scheme name a declaring card uses for the gateway's authorization server.
pub const GATEWAY_SCHEME: &str = "agent_gateway";

const SECURITY_KEYS: [&str; 5] =
    ["security", "securitySchemes", "securityRequirements", "security_schemes", "security_requirements"];

const V1_KEYS: [&str; 2] = ["supportedInterfaces", "supported_interfaces"];

const V0_3_KEYS: [&str; 9] = [
    "url",
    "endpoint",
    "endpoints",
    "preferredTransport",
    "preferred_transport",
    "additionalInterfaces",
    "additional_interfaces",
    "protocolVersion",
    "protocol_version",
];

/// Apply a declaration outcome to a parsed card: pass-through keeps the card's
/// security, any other outcome removes it and its signatures, and a declaration then
/// writes the gateway's scheme. A value that is not an object is left unchanged;
/// callers parse cards with [`super::url_rewriter`] first, which refuses one.
pub fn apply_card_security(
    card: &mut Value,
    outcome: &DeclarationOutcome,
) {
    if *outcome == DeclarationOutcome::PassThrough {
        return;
    }
    let Some(card) = card.as_object_mut() else {
        return;
    };
    card.remove("signatures");
    remove_security(card);
    if let Some(skills) = card
        .get_mut("skills")
        .and_then(Value::as_array_mut)
    {
        for skill in skills
            .iter_mut()
            .filter_map(Value::as_object_mut)
        {
            remove_security(skill);
        }
    }
    if let DeclarationOutcome::Declare(declaration) = outcome {
        declare(card, declaration);
    }
}

fn remove_security(object: &mut Map<String, Value>) {
    for key in SECURITY_KEYS {
        object.remove(key);
    }
}

/// Write the gateway's scheme in the card's era: the flat 0.3 scheme with `security`,
/// the 1.0 `oauth2SecurityScheme` with `securityRequirements`, or the flat scheme with
/// both lists for a card of both eras. The flow offers every advertised scope, and
/// the requirement names only the required ones. A declaration with no pinned
/// authorization server has no token endpoint to name, so its card declares no scheme.
fn declare(
    card: &mut Map<String, Value>,
    declaration: &Declaration,
) {
    let Some(pin) = &declaration.pin else {
        return;
    };
    let has_key = |keys: &[&str]| {
        keys.iter()
            .any(|key| card.contains_key(*key))
    };
    let v1 = has_key(&V1_KEYS);
    let v0_3 = has_key(&V0_3_KEYS) || !v1;

    let scopes: Map<String, Value> = declaration
        .advertised_scopes
        .iter()
        .map(|scope| (scope.clone(), Value::String(String::new())))
        .collect();
    let mut scheme = json!({
        "oauth2MetadataUrl": pin.metadata_url,
        "flows": { "clientCredentials": { "tokenUrl": pin.token_endpoint, "scopes": scopes } },
    });
    if v0_3 {
        scheme["type"] = json!("oauth2");
    } else {
        scheme = json!({ "oauth2SecurityScheme": scheme });
    }
    card.insert("securitySchemes".into(), json!({ GATEWAY_SCHEME: scheme }));
    if v0_3 {
        card.insert("security".into(), json!([{ GATEWAY_SCHEME: declaration.required_scopes }]));
    }
    if v1 {
        card.insert(
            "securityRequirements".into(),
            json!([{ "schemes": { GATEWAY_SCHEME: { "list": declaration.required_scopes } } }]),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt_bearer::models::AuthorizationServerMetadata;
    use crate::source_auth::declaration::StripReason;

    const METADATA_URL: &str = "https://as.example/.well-known/oauth-authorization-server";
    const TOKEN_URL: &str = "https://as.example/oauth2/token";

    fn declaration() -> Declaration {
        Declaration {
            resource: "https://gw.example/a2a".into(),
            authorization_servers: vec!["https://as.example/".into()],
            pin: Some(AuthorizationServerMetadata {
                issuer: "https://as.example/".into(),
                metadata_url: METADATA_URL.into(),
                token_endpoint: TOKEN_URL.into(),
                jwks_uri: "https://as.example/jwks".into(),
            }),
            required_scopes: vec!["agent.invoke".into(), "agent.read".into()],
            advertised_scopes: vec!["agent.invoke".into(), "agent.read".into()],
        }
    }

    fn upstream_security() -> Value {
        json!({
            "security": [{ "upstream": [] }],
            "securitySchemes": { "upstream": { "type": "http", "scheme": "bearer" } },
            "securityRequirements": [{ "schemes": { "upstream": { "list": [] } } }],
            "security_schemes": { "upstream": {} },
            "security_requirements": [{ "schemes": { "upstream": {} } }],
        })
    }

    fn card(era_fields: Value) -> Value {
        let mut card = json!({
            "name": "agent",
            "signatures": [{ "protected": "e30", "signature": "c2ln" }],
            "skills": [
                { "id": "a", "name": "A" },
                { "id": "b", "name": "B" },
                "not an object",
            ],
        });
        let security = upstream_security();
        for (key, value) in security
            .as_object()
            .into_iter()
            .flatten()
        {
            card[key] = value.clone();
            card["skills"][0][key] = value.clone();
            card["skills"][1][key] = value.clone();
        }
        for (key, value) in era_fields
            .as_object()
            .into_iter()
            .flatten()
        {
            card[key] = value.clone();
        }
        card
    }

    fn v1_card() -> Value {
        card(json!({ "supportedInterfaces": [{ "url": "https://gw.example/a2a", "protocolVersion": "1.0" }] }))
    }

    fn v0_3_card() -> Value {
        card(json!({ "protocolVersion": "0.3.0", "url": "https://gw.example/a2a" }))
    }

    fn dual_card() -> Value {
        card(json!({
            "url": "https://gw.example/a2a",
            "supportedInterfaces": [{ "url": "https://gw.example/a2a", "protocolVersion": "1.0" }],
        }))
    }

    fn snake_v1_card() -> Value {
        card(json!({ "supported_interfaces": [{ "url": "https://gw.example/a2a", "protocol_version": "1.0" }] }))
    }

    fn assert_no_upstream_security(card: &Value) {
        let text = card.to_string();
        assert!(!text.contains("upstream"), "upstream security survived: {text}");
        assert!(
            card.get("signatures")
                .is_none()
        );
        for key in SECURITY_KEYS {
            for skill in card["skills"]
                .as_array()
                .expect("skills")
                .iter()
                .filter(|skill| skill.is_object())
            {
                assert!(skill.get(key).is_none(), "skill kept {key}");
            }
        }
        assert_eq!(card["skills"][2], "not an object");
        assert_eq!(card["name"], "agent");
    }

    fn flat_scheme(scopes: Value) -> Value {
        json!({ "agent_gateway": {
            "type": "oauth2",
            "oauth2MetadataUrl": METADATA_URL,
            "flows": { "clientCredentials": { "tokenUrl": TOKEN_URL, "scopes": scopes } },
        } })
    }

    #[test]
    fn only_a_declaring_or_unservable_access_point_secures_its_cards() {
        assert!(secures_cards(&DeclarationOutcome::Declare(declaration())));
        assert!(secures_cards(&DeclarationOutcome::Unservable(
            crate::source_auth::declaration::UnservableDeclaration::new(
                crate::source_auth::declaration::UnservableReason::StrategyStoreUnavailable,
                "unservable"
            )
        )));
        for outcome in [
            DeclarationOutcome::PassThrough,
            DeclarationOutcome::Strip(StripReason::NotDeclared),
            DeclarationOutcome::Strip(StripReason::FabricTarget),
        ] {
            assert!(!secures_cards(&outcome), "{outcome:?} secured its cards");
        }
    }

    #[test]
    fn pass_through_leaves_the_card_as_the_target_served_it() {
        for original in [v1_card(), v0_3_card(), dual_card(), snake_v1_card()] {
            let mut card = original.clone();
            apply_card_security(&mut card, &DeclarationOutcome::PassThrough);
            assert_eq!(card, original);
        }
    }

    #[test]
    fn strip_removes_every_security_key_in_both_spellings_and_signatures_and_declares_nothing() {
        for outcome in [
            DeclarationOutcome::Strip(StripReason::NotDeclared),
            DeclarationOutcome::Strip(StripReason::TransitPoint),
            DeclarationOutcome::Unservable(crate::source_auth::declaration::UnservableDeclaration::new(
                crate::source_auth::declaration::UnservableReason::StrategyStoreUnavailable,
                "unservable",
            )),
        ] {
            for mut card in [v1_card(), v0_3_card(), dual_card(), snake_v1_card()] {
                apply_card_security(&mut card, &outcome);
                assert_no_upstream_security(&card);
                for key in SECURITY_KEYS {
                    assert!(card.get(key).is_none(), "{outcome:?} kept {key}");
                }
                assert!(
                    !card
                        .to_string()
                        .contains(GATEWAY_SCHEME)
                );
            }
        }
    }

    #[test]
    fn declare_on_a_1_0_card_emits_the_oneof_scheme_and_security_requirements() {
        for mut card in [v1_card(), snake_v1_card()] {
            apply_card_security(&mut card, &DeclarationOutcome::Declare(declaration()));
            assert_no_upstream_security(&card);
            assert_eq!(
                card["securitySchemes"],
                json!({ "agent_gateway": { "oauth2SecurityScheme": {
                    "oauth2MetadataUrl": METADATA_URL,
                    "flows": { "clientCredentials": {
                        "tokenUrl": TOKEN_URL,
                        "scopes": { "agent.invoke": "", "agent.read": "" },
                    } },
                } } })
            );
            assert_eq!(
                card["securityRequirements"],
                json!([{ "schemes": { "agent_gateway": { "list": ["agent.invoke", "agent.read"] } } }])
            );
            assert!(card.get("security").is_none());
        }
    }

    #[test]
    fn declare_on_a_0_3_card_emits_the_flat_scheme_and_security() {
        let mut card = v0_3_card();
        apply_card_security(&mut card, &DeclarationOutcome::Declare(declaration()));
        assert_no_upstream_security(&card);
        assert_eq!(card["securitySchemes"], flat_scheme(json!({ "agent.invoke": "", "agent.read": "" })));
        assert_eq!(card["security"], json!([{ "agent_gateway": ["agent.invoke", "agent.read"] }]));
        assert!(
            card.get("securityRequirements")
                .is_none()
        );
    }

    #[test]
    fn declare_on_a_dual_era_card_emits_the_flat_scheme_and_both_lists() {
        let mut card = dual_card();
        apply_card_security(&mut card, &DeclarationOutcome::Declare(declaration()));
        assert_no_upstream_security(&card);
        assert_eq!(card["securitySchemes"], flat_scheme(json!({ "agent.invoke": "", "agent.read": "" })));
        assert_eq!(card["security"], json!([{ "agent_gateway": ["agent.invoke", "agent.read"] }]));
        assert_eq!(
            card["securityRequirements"],
            json!([{ "schemes": { "agent_gateway": { "list": ["agent.invoke", "agent.read"] } } }])
        );
    }

    #[test]
    fn a_card_with_no_era_marker_gets_the_flat_shape() {
        let mut card = card(json!({}));
        apply_card_security(&mut card, &DeclarationOutcome::Declare(declaration()));
        assert_no_upstream_security(&card);
        assert_eq!(card["securitySchemes"], flat_scheme(json!({ "agent.invoke": "", "agent.read": "" })));
        assert_eq!(card["security"], json!([{ "agent_gateway": ["agent.invoke", "agent.read"] }]));
        assert!(
            card.get("securityRequirements")
                .is_none()
        );
    }

    #[test]
    fn the_flow_offers_every_advertised_scope_and_the_requirement_names_only_the_required_ones() {
        let declaration = Declaration {
            required_scopes: vec!["b".into(), "c".into()],
            advertised_scopes: vec!["b".into(), "c".into(), "a".into()],
            ..declaration()
        };
        let mut card = dual_card();
        apply_card_security(&mut card, &DeclarationOutcome::Declare(declaration));
        assert_eq!(card["securitySchemes"], flat_scheme(json!({ "a": "", "b": "", "c": "" })));
        assert_eq!(card["security"], json!([{ "agent_gateway": ["b", "c"] }]));
        assert_eq!(card["securityRequirements"], json!([{ "schemes": { "agent_gateway": { "list": ["b", "c"] } } }]));
    }

    #[test]
    fn a_declaration_without_a_pinned_server_strips_the_card_and_declares_no_scheme() {
        let declaration = Declaration { pin: None, ..declaration() };
        for mut card in [v1_card(), v0_3_card(), dual_card()] {
            apply_card_security(&mut card, &DeclarationOutcome::Declare(declaration.clone()));
            assert_no_upstream_security(&card);
            for key in SECURITY_KEYS {
                assert!(card.get(key).is_none(), "card kept {key}");
            }
        }
    }

    #[test]
    fn a_value_that_is_not_an_object_is_left_alone() {
        let mut value = json!(["security"]);
        apply_card_security(&mut value, &DeclarationOutcome::Declare(declaration()));
        assert_eq!(value, json!(["security"]));
    }
}
