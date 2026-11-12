//! A surface's `caller_key`: the per-caller key the gateway derives from a secret in the
//! secrets store and the caller's verified JWT, and sends the surface's Target.

use serde::{Deserialize, Serialize};

/// The header a caller key is sent in when `caller_key.header` is not set, and the first word
/// of every caller key header: `x-caller-key`, or `x-caller-key-` and more.
pub const DEFAULT_CALLER_KEY_HEADER: &str = "x-caller-key";

/// The longest caller key header.
pub const MAX_CALLER_KEY_HEADER_LEN: usize = 64;

/// The fewest bytes a caller key secret holds: fewer would let whoever sees the keys guess it.
pub const MIN_SECRET_BYTES: usize = 32;

/// Whether a header named `name` belongs to the caller key family, which only the gateway
/// sets: once lower-cased, with `_` read as `-` as some servers do, it is `x-caller-key` or
/// starts with `x-caller-key-`. A caller's, an agent's or a peer gateway's copy of such a
/// header is never forwarded, on any surface.
pub fn is_caller_key_header(name: &str) -> bool {
    let fold = |byte: u8| match byte {
        b'_' => b'-',
        byte => byte.to_ascii_lowercase(),
    };
    let name = name.as_bytes();
    let prefix = DEFAULT_CALLER_KEY_HEADER.as_bytes();
    name.len() >= prefix.len()
        && name
            .iter()
            .zip(prefix)
            .all(|(byte, expected)| fold(*byte) == *expected)
        && name
            .get(prefix.len())
            .is_none_or(|byte| fold(*byte) == b'-')
}

/// Where a surface's caller keys come from and how its Target receives them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CallerKeyConfig {
    /// The `secret_id` of the secret in the secrets store the keys are derived from.
    pub secret_id: String,

    /// The header the Target receives the key in.
    #[serde(default = "default_header")]
    pub header: String,

    /// The JWT claims that name the caller, in order: the first the token carries as a
    /// non-empty string does.
    #[serde(default = "default_identity_claims")]
    pub identity_claims: Vec<String>,
}

fn default_header() -> String {
    DEFAULT_CALLER_KEY_HEADER.to_string()
}

fn default_identity_claims() -> Vec<String> {
    vec![crate::jwt_bearer::models::DEFAULT_PRINCIPAL_CLAIM.to_string()]
}

impl CallerKeyConfig {
    /// The first problem with the setting on its own: no secret, a header outside the caller key
    /// family ([`header_problem`]), or an identity claim list that is empty, repeats a claim or
    /// names one that does not identify a caller.
    pub fn validate(&self) -> Result<(), String> {
        if self
            .secret_id
            .trim()
            .is_empty()
        {
            return Err("caller_key.secret_id must name a secret".to_string());
        }
        if let Some(problem) = header_problem(&self.header) {
            return Err(format!("caller_key.header {problem}"));
        }
        if self
            .identity_claims
            .is_empty()
        {
            return Err("caller_key.identity_claims must name at least one claim".to_string());
        }
        for (index, claim) in self
            .identity_claims
            .iter()
            .enumerate()
        {
            if let Some(problem) = crate::jwt_bearer::models::identifying_claim_problem(claim) {
                return Err(format!("caller_key.identity_claims entry {problem}"));
            }
            if self.identity_claims[..index].contains(claim) {
                return Err(format!("caller_key.identity_claims names '{claim}' more than once"));
            }
        }
        Ok(())
    }
}

/// What is wrong with `header` as a caller key header, if anything: it must be
/// `x-caller-key`, or `x-caller-key-` followed by words of lower-case letters and digits
/// joined by single hyphens, at most [`MAX_CALLER_KEY_HEADER_LEN`] characters in all.
fn header_problem(header: &str) -> Option<String> {
    let in_family = header == DEFAULT_CALLER_KEY_HEADER
        || header
            .strip_prefix(DEFAULT_CALLER_KEY_HEADER)
            .and_then(|rest| rest.strip_prefix('-'))
            .is_some_and(|rest| {
                rest.split('-').all(|word| {
                    !word.is_empty()
                        && word
                            .bytes()
                            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
                })
            });
    (!in_family || header.len() > MAX_CALLER_KEY_HEADER_LEN).then(|| {
        format!(
            "must be x-caller-key, or x-caller-key- followed by lower-case letters and digits in words joined \
             by single hyphens, at most {MAX_CALLER_KEY_HEADER_LEN} characters"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(json: serde_json::Value) -> CallerKeyConfig {
        serde_json::from_value(json).expect("caller_key parses")
    }

    #[test]
    fn a_caller_key_defaults_to_the_x_caller_key_header_and_the_sub_claim() {
        let parsed = config(serde_json::json!({ "secret_id": "caller-keys" }));
        assert_eq!(parsed.header, "x-caller-key");
        assert_eq!(parsed.identity_claims, vec!["sub".to_string()]);
        assert_eq!(parsed.validate(), Ok(()));
    }

    #[test]
    fn a_caller_key_refuses_unknown_fields_and_a_literal_secret() {
        for json in [
            serde_json::json!({ "secret_id": "caller-keys", "secret": "literal" }),
            serde_json::json!({ "secret_id": "caller-keys", "value": "literal" }),
        ] {
            assert!(serde_json::from_value::<CallerKeyConfig>(json.clone()).is_err(), "{json}");
        }
    }

    #[test]
    fn a_caller_key_names_a_secret() {
        for secret_id in ["", "  "] {
            assert_eq!(
                config(serde_json::json!({ "secret_id": secret_id })).validate(),
                Err("caller_key.secret_id must name a secret".to_string())
            );
        }
    }

    #[test]
    fn a_caller_key_header_is_x_caller_key_or_one_of_its_family() {
        let longest = format!("x-caller-key-{}", "a".repeat(MAX_CALLER_KEY_HEADER_LEN - 13));
        for accepted in
            ["x-caller-key", "x-caller-key-memory", "x-caller-key-user-vault-2", "x-caller-key-7", longest.as_str()]
        {
            let setting = config(serde_json::json!({ "secret_id": "caller-keys", "header": accepted }));
            assert_eq!(setting.validate(), Ok(()), "{accepted}");
        }
        let refusal = "caller_key.header must be x-caller-key, or x-caller-key- followed by lower-case letters and \
                       digits in words joined by single hyphens, at most 64 characters";
        let too_long = format!("{longest}a");
        for refused in [
            "",
            "X-Caller-Key",
            "x_caller_key",
            "x-caller-keys",
            "x-caller-key-",
            "x-caller-key--memory",
            "x-caller-key-memory-",
            "x-caller-key-Memory",
            "x-caller-key-user_vault",
            "x-caller-key-memory\r\n",
            "x-user-vault-key",
            "x-api-key",
            "authorization",
            "host",
            "x-transit-token",
            too_long.as_str(),
        ] {
            let setting = config(serde_json::json!({ "secret_id": "caller-keys", "header": refused }));
            assert_eq!(setting.validate(), Err(refusal.to_string()), "{refused:?}");
        }
    }

    #[test]
    fn the_caller_key_family_is_every_spelling_of_x_caller_key_and_its_longer_names() {
        for name in [
            "x-caller-key",
            "X-Caller-Key",
            "x_caller_key",
            "X_CALLER_KEY",
            "x-caller-key-memory",
            "X_Caller_Key_Memory",
            "x-caller-key_memory",
            "x-caller-key-",
            "x-caller-key-anything.at_all",
        ] {
            assert!(is_caller_key_header(name), "{name}");
        }
        for name in
            ["x-caller-keys", "x-caller-ke", "x-caller", "caller-key", "x-api-key", "x-caller-did", "xx-caller-key", ""]
        {
            assert!(!is_caller_key_header(name), "{name}");
        }
    }

    #[test]
    fn caller_key_identity_claims_are_plain_identifying_claims_named_once() {
        let accepted = config(serde_json::json!({
            "secret_id": "caller-keys",
            "identity_claims": ["oid", "sub", "https://example.com/claims/user_id"]
        }));
        assert_eq!(accepted.validate(), Ok(()));
        let refused = [
            (serde_json::json!([]), "caller_key.identity_claims must name at least one claim"),
            (serde_json::json!([""]), "caller_key.identity_claims entry must be 1 to 128 characters"),
            (serde_json::json!(["user id"]), "caller_key.identity_claims entry must be printable ASCII with no spaces"),
            (
                serde_json::json!(["sub", "iss"]),
                "caller_key.identity_claims entry cannot be 'iss': it does not identify a caller",
            ),
            (
                serde_json::json!(["tid"]),
                "caller_key.identity_claims entry cannot be 'tid': it does not identify a caller",
            ),
            (serde_json::json!(["sub", "oid", "sub"]), "caller_key.identity_claims names 'sub' more than once"),
        ];
        for (claims, message) in refused {
            let setting = config(serde_json::json!({ "secret_id": "caller-keys", "identity_claims": claims }));
            assert_eq!(setting.validate(), Err(message.to_string()), "{claims}");
        }
    }
}
