//! Access Point rules for verified access tokens: required scopes, granted scopes,
//! the client id, and the checks that refuse ID tokens.
//!
//! These rules apply only to Access Point source authentication. STS, modern consent
//! and credential providers call [`crate::jwt_bearer::JwtBearerVerifier::validate`]
//! without them.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::jwt_bearer::errors::JwtBearerError;

const MAX_REQUIRED_SCOPES: usize = 32;
const MAX_SCOPE_LEN: usize = 128;
const CLIENT_ID_CLAIMS: [&str; 3] = ["client_id", "azp", "appid"];
const ID_TOKEN_CLAIMS: [&str; 4] = ["nonce", "at_hash", "c_hash", "s_hash"];
const ACCESS_TOKEN_TYPES: [&str; 3] = ["at+jwt", "application/at+jwt", "JWT"];

/// Refuse `required_scopes` entries that are not RFC 6749 scope tokens.
///
/// Each entry is 1 to 128 characters from `%x21 / %x23-5B / %x5D-7E`, with at most
/// 32 entries and no duplicates, so the values are safe to place in a challenge header.
pub fn validate_required_scopes(scopes: &[String]) -> Result<(), &'static str> {
    if scopes.len() > MAX_REQUIRED_SCOPES {
        return Err("required_scopes must list at most 32 scopes");
    }
    let mut seen = BTreeSet::new();
    for scope in scopes {
        let well_formed = !scope.is_empty()
            && scope.len() <= MAX_SCOPE_LEN
            && scope
                .bytes()
                .all(|byte| matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e));
        if !well_formed {
            return Err("required_scopes entries must be OAuth scope tokens of 1 to 128 characters");
        }
        if !seen.insert(scope.as_str()) {
            return Err("required_scopes must not repeat a scope");
        }
    }
    Ok(())
}

/// The scopes a token grants, sorted and de-duplicated.
///
/// The first claim in `scope_claims` that is present decides: a string is split on
/// spaces, an array of strings is used as is, and any other shape grants nothing.
pub fn granted_scopes<S: AsRef<str>>(
    claims: &Value,
    scope_claims: &[S],
) -> Vec<String> {
    let Some(value) = scope_claims
        .iter()
        .find_map(|name| {
            claims
                .get(name.as_ref())
                .filter(|value| !value.is_null())
        })
    else {
        return Vec::new();
    };
    let scopes: Option<BTreeSet<&str>> = match value {
        Value::String(text) => Some(
            text.split(' ')
                .filter(|scope| !scope.is_empty())
                .collect(),
        ),
        Value::Array(items) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .filter(|scope| !scope.is_empty())
            })
            .collect(),
        _ => None,
    };
    scopes
        .unwrap_or_default()
        .into_iter()
        .map(str::to_string)
        .collect()
}

/// The scopes in `required` that `granted` lacks, in `required` order.
pub fn missing_scopes<'a>(
    granted: &[String],
    required: &'a [String],
) -> Vec<&'a str> {
    required
        .iter()
        .filter(|scope| !granted.contains(scope))
        .map(String::as_str)
        .collect()
}

/// The OAuth client the token was issued to: `client_id`, then `azp`, then `appid`.
pub fn client_id(claims: &Value) -> Option<String> {
    CLIENT_ID_CLAIMS
        .iter()
        .find_map(|name| {
            claims
                .get(*name)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
        })
        .map(str::to_string)
}

/// Refuse a verified token that is shaped as an ID token rather than an access token.
///
/// A token fails when it carries `nonce`, `at_hash`, `c_hash` or `s_hash`, when its
/// payload `typ` claim is `ID` (case-insensitive, as Keycloak marks ID tokens), or when
/// its JOSE `typ` header is present and is not `at+jwt`, `application/at+jwt` or `JWT`
/// (case-insensitive, RFC 9068 §4). `JWT` stays accepted because common providers issue
/// access tokens with it.
///
/// The check is best-effort: an ID token without these markers, such as a Google
/// service-account ID token, passes, so required scopes or policy are the real control.
pub fn check_access_token_shape(
    token: &str,
    claims: &Value,
) -> Result<(), JwtBearerError> {
    let id_typ = claims
        .get("typ")
        .and_then(Value::as_str)
        .is_some_and(|typ| typ.eq_ignore_ascii_case("ID"));
    if id_typ
        || ID_TOKEN_CLAIMS
            .iter()
            .any(|name| claims.get(*name).is_some())
    {
        return Err(JwtBearerError::InvalidToken("ID token presented as an access token".to_string()));
    }
    let header = jsonwebtoken::decode_header(token)
        .map_err(|_| JwtBearerError::InvalidToken("Failed to decode JWT header".to_string()))?;
    match header.typ.as_deref() {
        Some(typ)
            if !ACCESS_TOKEN_TYPES
                .iter()
                .any(|accepted| accepted.eq_ignore_ascii_case(typ)) =>
        {
            Err(JwtBearerError::InvalidToken("Token type is not an access token".to_string()))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn strings(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_string())
            .collect()
    }

    const DEFAULT: [&str; 2] = ["scope", "scp"];

    fn unsigned_token(header: Value) -> String {
        use base64::Engine;
        let encode = |value: &Value| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string());
        format!("{}.{}.sig", encode(&header), encode(&json!({})))
    }

    #[test]
    fn required_scopes_accept_rfc6749_tokens() {
        assert_eq!(validate_required_scopes(&[]), Ok(()));
        assert_eq!(validate_required_scopes(&strings(&["a2a:invoke", "payments.write", "https://api/x"])), Ok(()));
        assert_eq!(validate_required_scopes(&strings(&[&"s".repeat(128)])), Ok(()));
        let many: Vec<String> = (0..32)
            .map(|index| format!("scope{index}"))
            .collect();
        assert_eq!(validate_required_scopes(&many), Ok(()));
    }

    #[test]
    fn required_scopes_refuse_unsafe_or_unbounded_values() {
        for bad in [
            strings(&[""]),
            strings(&["two words"]),
            strings(&["quote\"d"]),
            strings(&["back\\slash"]),
            strings(&["line\nbreak"]),
            strings(&["caf\u{e9}"]),
            strings(&[&"s".repeat(129)]),
            strings(&["dup", "dup"]),
        ] {
            assert!(validate_required_scopes(&bad).is_err(), "{bad:?}");
        }
        let many: Vec<String> = (0..33)
            .map(|index| format!("scope{index}"))
            .collect();
        assert_eq!(validate_required_scopes(&many), Err("required_scopes must list at most 32 scopes"));
    }

    #[test]
    fn granted_scopes_read_scope_and_scp_as_string_or_array() {
        let expected = strings(&["a2a:invoke", "read"]);
        assert_eq!(granted_scopes(&json!({"scope": "read a2a:invoke read"}), &DEFAULT), expected);
        assert_eq!(granted_scopes(&json!({"scope": ["read", "a2a:invoke"]}), &DEFAULT), expected);
        assert_eq!(granted_scopes(&json!({"scp": "a2a:invoke  read"}), &DEFAULT), expected);
        assert_eq!(granted_scopes(&json!({"scp": ["a2a:invoke", "read", "read"]}), &DEFAULT), expected);
    }

    #[test]
    fn granted_scopes_take_the_first_present_claim_only() {
        let claims = json!({"scope": "read", "scp": ["write"], "roles": ["Task.Run"]});
        assert_eq!(granted_scopes(&claims, &DEFAULT), strings(&["read"]));
        assert_eq!(granted_scopes(&claims, &["scp", "scope"]), strings(&["write"]));
        assert_eq!(granted_scopes(&claims, &["roles"]), strings(&["Task.Run"]));
        assert_eq!(granted_scopes(&json!({"scope": null, "scp": "write"}), &DEFAULT), strings(&["write"]));
    }

    #[test]
    fn granted_scopes_are_empty_for_absent_or_malformed_claims() {
        assert!(granted_scopes(&json!({}), &DEFAULT).is_empty());
        assert!(granted_scopes(&json!({"scope": 7}), &DEFAULT).is_empty());
        assert!(granted_scopes(&json!({"scope": {"read": true}, "scp": "read"}), &DEFAULT).is_empty());
        assert!(granted_scopes(&json!({"scope": ["read", 1]}), &DEFAULT).is_empty());
        assert!(granted_scopes(&json!({"scope": ""}), &DEFAULT).is_empty());
    }

    #[test]
    fn missing_scopes_lists_each_required_scope_not_granted() {
        let granted = strings(&["a", "b"]);
        assert!(missing_scopes(&granted, &[]).is_empty());
        assert!(missing_scopes(&granted, &strings(&["b", "a"])).is_empty());
        assert_eq!(missing_scopes(&granted, &strings(&["c", "a", "d"])), vec!["c", "d"]);
        assert_eq!(missing_scopes(&[], &strings(&["a"])), vec!["a"]);
    }

    #[test]
    fn client_id_prefers_client_id_then_azp_then_appid() {
        assert_eq!(client_id(&json!({"client_id": "c", "azp": "z", "appid": "p"})).as_deref(), Some("c"));
        assert_eq!(client_id(&json!({"azp": "z", "appid": "p"})).as_deref(), Some("z"));
        assert_eq!(client_id(&json!({"appid": "p"})).as_deref(), Some("p"));
        assert_eq!(client_id(&json!({"client_id": "", "azp": 3, "appid": "p"})).as_deref(), Some("p"));
        assert_eq!(client_id(&json!({"sub": "s"})), None);
    }

    #[test]
    fn access_token_shape_refuses_id_token_claims() {
        let token = unsigned_token(json!({"alg": "RS256", "typ": "JWT"}));
        assert!(check_access_token_shape(&token, &json!({"sub": "s"})).is_ok());
        for claims in [
            json!({"nonce": "n"}),
            json!({"at_hash": "h"}),
            json!({"c_hash": "h"}),
            json!({"s_hash": "h"}),
            json!({"typ": "ID"}),
            json!({"typ": "id"}),
        ] {
            assert!(
                matches!(check_access_token_shape(&token, &claims), Err(JwtBearerError::InvalidToken(_))),
                "{claims}"
            );
        }
    }

    #[test]
    fn access_token_shape_accepts_access_token_payload_typ() {
        let token = unsigned_token(json!({"alg": "RS256", "typ": "JWT"}));
        assert!(check_access_token_shape(&token, &json!({"typ": "Bearer"})).is_ok());
        assert!(check_access_token_shape(&token, &json!({"sub": "s", "scope": "read"})).is_ok());
    }

    #[test]
    fn access_token_shape_checks_the_typ_header() {
        for typ in ["at+jwt", "AT+JWT", "application/at+jwt", "JWT", "jwt"] {
            let token = unsigned_token(json!({"alg": "RS256", "typ": typ}));
            assert!(check_access_token_shape(&token, &json!({})).is_ok(), "{typ}");
        }
        let untyped = unsigned_token(json!({"alg": "RS256"}));
        assert!(check_access_token_shape(&untyped, &json!({})).is_ok());
        for typ in ["id+jwt", "logout+jwt", "application/jwt"] {
            let token = unsigned_token(json!({"alg": "RS256", "typ": typ}));
            assert!(
                matches!(check_access_token_shape(&token, &json!({})), Err(JwtBearerError::InvalidToken(_))),
                "{typ}"
            );
        }
    }
}
