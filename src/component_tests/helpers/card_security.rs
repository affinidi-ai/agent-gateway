//! Fixtures for an Access Point that declares the gateway's OAuth protection, and
//! assertions on the security its agent card carries.

use std::path::Path;

use serde_json::{Value, json};

use crate::config::BootstrapConfig;

/// The public origin the inbound listener advertises, so the Access Point URL is a
/// canonical HTTPS URL even though the test listener serves plain HTTP.
pub const PUBLIC_ORIGIN: &str = "https://gw.example";
/// The Access Point URL of a surface on the `/smoke` route.
pub const SMOKE_RESOURCE: &str = "https://gw.example/smoke";
pub const REQUIRED_SCOPE: &str = "agent.invoke";
pub const STRATEGY_ID: &str = "card-security-strategy";
/// An authorization server no test calls: enough for a card or metadata that only
/// names it.
pub const ISSUER: &str = "https://as.example";
/// A marker every upstream security declaration and signature in the fixtures carries.
pub const UPSTREAM_MARKER: &str = "upstream-only";

const SECURITY_KEYS: [&str; 5] =
    ["security", "securitySchemes", "securityRequirements", "security_schemes", "security_requirements"];

/// Put [`PUBLIC_ORIGIN`] first in the inbound listener's `external_urls`, keeping the
/// local URL so the listener still matches the surface's `listen_address`.
pub fn advertise_public_origin(bootstrap: &BootstrapConfig) {
    let path = Path::new(&bootstrap.config_files.gateway);
    let mut network: Value =
        serde_json::from_str(&std::fs::read_to_string(path).expect("read gateway.json")).expect("gateway.json");
    network["listeners"][0]["external_urls"]
        .as_array_mut()
        .expect("external_urls")
        .insert(0, json!(PUBLIC_ORIGIN));
    std::fs::write(path, serde_json::to_string_pretty(&network).expect("serialize gateway.json"))
        .expect("write gateway.json");
}

pub fn authorization_server_metadata_url(issuer: &str) -> String {
    format!("{issuer}/.well-known/oauth-authorization-server")
}

pub fn token_endpoint(issuer: &str) -> String {
    format!("{issuer}/oauth2/token")
}

/// Write the strategy [`STRATEGY_ID`] trusting `issuer` and its keys at
/// `{issuer}/.well-known/jwks.json`. `pinned` decides whether it carries discovered
/// authorization server metadata.
pub fn write_strategy(
    temp_dir: &Path,
    issuer: &str,
    pinned: bool,
) {
    write_strategy_with_keys(temp_dir, issuer, &format!("{issuer}/.well-known/jwks.json"), pinned);
}

/// [`write_strategy`] with the keys served at `jwks_uri`.
pub fn write_strategy_with_keys(
    temp_dir: &Path,
    issuer: &str,
    jwks_uri: &str,
    pinned: bool,
) {
    let mut strategy = json!({
        "id": STRATEGY_ID,
        "name": "Card security",
        "expected_issuer": issuer,
        "jwks_source": { "type": "remote", "jwks_uri": jwks_uri },
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z"
    });
    if pinned {
        strategy["authorization_server"] = json!({
            "issuer": issuer,
            "metadata_url": authorization_server_metadata_url(issuer),
            "token_endpoint": token_endpoint(issuer),
            "jwks_uri": jwks_uri,
        });
    }
    let dir = temp_dir.join("jwt_verification_strategies");
    std::fs::create_dir_all(&dir).expect("create strategy dir");
    std::fs::write(dir.join(format!("{STRATEGY_ID}.json")), strategy.to_string()).expect("write strategy");
}

/// Caller authentication with one `jwt_bearer` method requiring [`REQUIRED_SCOPE`]. It
/// declares for a route when `resource` is `Some`: that is the route's Access Point URL.
pub fn jwt_bearer_caller_authentication(resource: Option<&str>) -> Value {
    let mut config = json!({
        "methods": [{
            "type": "jwt_bearer",
            "jwt_verification_strategy_id": STRATEGY_ID,
            "audiences": [],
            "required_scopes": [REQUIRED_SCOPE],
        }]
    });
    if let Some(resource) = resource {
        config["protected_resource"] = json!({ "resource": resource });
    }
    config
}

fn upstream_security() -> Value {
    json!({
        "security": [{ UPSTREAM_MARKER: [] }],
        "securitySchemes": { UPSTREAM_MARKER: { "type": "http", "scheme": "bearer" } },
        "securityRequirements": [{ "schemes": { UPSTREAM_MARKER: { "list": [] } } }],
        "security_schemes": { UPSTREAM_MARKER: {} },
        "security_requirements": [{ "schemes": { UPSTREAM_MARKER: {} } }],
    })
}

fn upstream_signatures() -> Value {
    json!([{ "protected": UPSTREAM_MARKER, "signature": UPSTREAM_MARKER }])
}

/// Upstream security in every spelling, at card level and on a skill, plus a signature.
pub fn add_upstream_security(card: &mut Value) {
    let mut skill = json!({ "id": "skill", "name": "Skill", "description": "", "tags": [] });
    for (key, value) in upstream_security()
        .as_object()
        .into_iter()
        .flatten()
    {
        card[key] = value.clone();
        skill[key] = value.clone();
    }
    card["skills"] = json!([skill]);
    card["signatures"] = upstream_signatures();
}

/// Assert no upstream security or signature survived anywhere in the card.
pub fn assert_no_upstream_security(card: &Value) {
    assert!(
        !card
            .to_string()
            .contains(UPSTREAM_MARKER),
        "upstream security survived: {card}"
    );
    assert!(
        card.get("signatures")
            .is_none(),
        "signatures survived: {card}"
    );
}

/// Assert the card carries the upstream security and signatures exactly as the
/// fixture added them.
pub fn assert_keeps_upstream_security(card: &Value) {
    let upstream = upstream_security();
    for key in ["security", "securitySchemes", "securityRequirements"] {
        assert_eq!(card[key], upstream[key], "the card changed {key}: {card}");
        assert_eq!(card["skills"][0][key], upstream[key], "the skill changed {key}: {card}");
    }
    assert_eq!(card["signatures"], upstream_signatures(), "the card changed its signatures: {card}");
}

/// Assert the card declares only the gateway scheme naming `issuer`'s authorization
/// server, in the shape of its era: the flat 0.3 scheme with `security` when it is a
/// 0.3 card, the `oauth2SecurityScheme` wrapper otherwise, and `securityRequirements`
/// when it is a 1.0 card. The scheme offers every scope the Access Point advertises;
/// the requirements name only [`REQUIRED_SCOPE`].
pub fn assert_declares(
    card: &Value,
    issuer: &str,
    v1: bool,
    v0_3: bool,
) {
    assert_no_upstream_security(card);
    let schemes = card["securitySchemes"]
        .as_object()
        .unwrap_or_else(|| panic!("no securitySchemes: {card}"));
    assert_eq!(
        schemes
            .keys()
            .collect::<Vec<_>>(),
        ["agent_gateway"],
        "{card}"
    );
    let scheme = &schemes["agent_gateway"];
    let flat = if v0_3 {
        assert_eq!(scheme["type"], "oauth2", "{card}");
        scheme
    } else {
        &scheme["oauth2SecurityScheme"]
    };
    assert_eq!(flat["oauth2MetadataUrl"], authorization_server_metadata_url(issuer), "{card}");
    assert_eq!(flat["flows"]["clientCredentials"]["tokenUrl"], token_endpoint(issuer), "{card}");
    let offered = flat["flows"]["clientCredentials"]["scopes"]
        .as_object()
        .unwrap_or_else(|| panic!("no clientCredentials.scopes: {card}"));
    assert_eq!(
        offered
            .keys()
            .collect::<Vec<_>>(),
        [REQUIRED_SCOPE],
        "{card}"
    );

    assert_eq!(card.get("security").is_some(), v0_3, "{card}");
    if v0_3 {
        assert_eq!(card["security"], json!([{ "agent_gateway": [REQUIRED_SCOPE] }]), "{card}");
    }
    assert_eq!(
        card.get("securityRequirements")
            .is_some(),
        v1,
        "{card}"
    );
    if v1 {
        assert_eq!(
            card["securityRequirements"],
            json!([{ "schemes": { "agent_gateway": { "list": [REQUIRED_SCOPE] } } }]),
            "{card}"
        );
    }
    for key in ["security_schemes", "security_requirements"] {
        assert!(card.get(key).is_none(), "card kept {key}: {card}");
    }
    for skill in card["skills"]
        .as_array()
        .into_iter()
        .flatten()
    {
        for key in SECURITY_KEYS {
            assert!(skill.get(key).is_none(), "a skill kept {key}: {card}");
        }
    }
}

/// Assert the card carries no security declaration at all.
pub fn assert_strips(card: &Value) {
    assert_no_upstream_security(card);
    for key in SECURITY_KEYS {
        assert!(card.get(key).is_none(), "card kept {key}: {card}");
    }
}
