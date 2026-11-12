//! A surface's `caller_key`: the per-caller key the gateway derives from a secret in the
//! secrets store and the caller's verified JWT, and sends the surface's Target.

use serde::{Deserialize, Serialize};

use super::target_auth_rules::{is_header_name, reserved_header, same_header_name};

/// The header a caller key is sent in when `caller_key.header` is not set. A caller's header
/// of this name is never forwarded, on any surface.
pub const DEFAULT_CALLER_KEY_HEADER: &str = "x-caller-key";

/// The fewest bytes a caller key secret holds: fewer would let whoever sees the keys guess it.
pub const MIN_SECRET_BYTES: usize = 32;

/// Headers the gateway reads or sets on a forwarded request besides the reserved ones
/// ([`reserved_header`]): the caller's credentials and cookies, and the content and protocol
/// headers of the request it forwards.
const GATEWAY_HEADERS: [&str; 11] = [
    "authorization",
    "cookie",
    "accept",
    "accept-encoding",
    "content-type",
    "content-encoding",
    "mcp-protocol-version",
    "last-event-id",
    "a2a-version",
    "a2a-extensions",
    "x-a2a-extensions",
];

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
    /// The first problem with the setting on its own: no secret, a header that is no lower-case
    /// HTTP header name or that the gateway reserves, reads or sets, or an identity claim list
    /// that is empty, repeats a claim or names one that does not identify a caller.
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

/// What is wrong with `header` as a caller key header, if anything.
fn header_problem(header: &str) -> Option<String> {
    if !is_header_name(header) {
        return Some("must be an HTTP header name".to_string());
    }
    if header != header.to_ascii_lowercase() {
        return Some("must be lower case".to_string());
    }
    if header == DEFAULT_CALLER_KEY_HEADER {
        return None;
    }
    if let Some(reserved) = reserved_header(header) {
        return Some(format!("must not be the reserved header {reserved}"));
    }
    if GATEWAY_HEADERS
        .iter()
        .any(|gateway| same_header_name(gateway, header))
        || crate::proxy::outbound_handler::is_proxy_forwarding_header(header)
    {
        return Some(format!("must not be {header}, which the gateway reads or sets itself"));
    }
    None
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
    fn a_caller_key_header_is_a_lower_case_header_name_the_gateway_leaves_alone() {
        for accepted in ["x-caller-key", "x-user-vault-key", "x_tenant_key", "caller-key"] {
            let setting = config(serde_json::json!({ "secret_id": "caller-keys", "header": accepted }));
            assert_eq!(setting.validate(), Ok(()), "{accepted}");
        }
        let refused = [
            ("", "caller_key.header must be an HTTP header name"),
            ("x caller key", "caller_key.header must be an HTTP header name"),
            ("x-caller-key\r\n", "caller_key.header must be an HTTP header name"),
            ("X-Caller-Key", "caller_key.header must be lower case"),
            ("connection", "caller_key.header must not be the reserved header Connection"),
            ("transfer-encoding", "caller_key.header must not be the reserved header Transfer-Encoding"),
            ("host", "caller_key.header must not be the reserved header Host"),
            ("x-transit-token", "caller_key.header must not be the reserved header X-Transit-Token"),
            ("x-caller-did", "caller_key.header must not be the reserved header X-Caller-Did"),
            ("x_gateway_trace_id", "caller_key.header must not be the reserved header X-Gateway-Trace-Id"),
            ("mcp-session-id", "caller_key.header must not be the reserved header Mcp-Session-Id"),
            ("authorization", "caller_key.header must not be authorization, which the gateway reads or sets itself"),
            ("cookie", "caller_key.header must not be cookie, which the gateway reads or sets itself"),
            (
                "accept-encoding",
                "caller_key.header must not be accept-encoding, which the gateway reads or sets itself",
            ),
            (
                "x-forwarded-for",
                "caller_key.header must not be x-forwarded-for, which the gateway reads or sets itself",
            ),
            ("forwarded", "caller_key.header must not be forwarded, which the gateway reads or sets itself"),
        ];
        for (header, message) in refused {
            let setting = config(serde_json::json!({ "secret_id": "caller-keys", "header": header }));
            assert_eq!(setting.validate(), Err(message.to_string()), "{header:?}");
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
