pub fn build_surface_request_path_policy(allowed_path: &str) -> String {
    let allowed_path_literal = serde_json::to_string(allowed_path).expect("allowed path should serialize");
    format!(
        r#"package surface.policy

default allow = false

allow if {{
    startswith(input.http.path, {allowed_path_literal} )
}}
"#
    )
}

pub fn build_surface_request_content_policy(allowed_content: &str) -> String {
    let allowed_content_literal = serde_json::to_string(allowed_content).expect("allowed content should serialize");
    format!(
        r#"package surface.policy

default allow = false

allow if {{
  input.a2a.message.parts[_].text == {allowed_content_literal}

}}
"#
    )
}

/// A surface policy that allows only one **exact** A2A JSON-RPC method name.
///
/// Used to prove the gateway exposes `input.a2a.method` to policy **exactly as the
/// caller sent it**: it does not canonicalise a v1.0 `SendMessage` into
/// the v0.3 `message/send`, nor the reverse. A policy written against one spelling
/// therefore matches only that era, which is the behaviour customers must be able to
/// reason about.
pub fn build_surface_a2a_method_policy(allowed_method: &str) -> String {
    let allowed_method_literal = serde_json::to_string(allowed_method).expect("allowed method should serialize");
    format!(
        r#"package surface.policy

default allow = false

allow if {{
    input.a2a.method == {allowed_method_literal}
}}
"#
    )
}

pub fn build_gateway_request_path_policy(allowed_path: &str) -> String {
    let allowed_path_literal = serde_json::to_string(allowed_path).expect("allowed path should serialize");
    format!(
        r#"package gateway.policy

default allow = false

allow if {{
    startswith(input.http.path, {allowed_path_literal} )
}}
"#
    )
}

pub fn build_surface_response_content_type_policy(allowed_content_type: &str) -> String {
    let allowed_content_type_literal =
        serde_json::to_string(allowed_content_type).expect("allowed content type should serialize");
    format!(
        r#"package surface.policy

default allow = false

allow if {{
    input.response.content_type == {allowed_content_type_literal}
}}
"#
    )
}

pub fn build_mcp_tool_allow_policy(allowed_tool: &str) -> String {
    let allowed_tool_literal = serde_json::to_string(allowed_tool).expect("allowed tool should serialize");
    format!(
        r#"package surface.policy

default allow = false

allow if {{
    input.mcp.params.name == {allowed_tool_literal}
}}
"#
    )
}

pub fn build_mcp_tool_allow_all_policy() -> String {
    "package surface.policy\n\ndefault allow = true\n".to_string()
}

pub fn build_mcp_tool_deny_all_policy() -> String {
    "package surface.policy\n\ndefault allow = false\n".to_string()
}

pub fn build_gateway_deny_all_policy() -> String {
    "package gateway.policy\n\ndefault allow := false\n".to_string()
}

/// Gateway-level policy that denies callers whose source authentication failed.
/// A caller-attributable source-auth failure is non-blocking and surfaces to
/// policy as `input.source_auth.method == "failed"`; this policy is how an
/// operator opts into blocking such callers at the gateway ingress.
pub fn build_gateway_deny_unverified_source_auth_policy() -> String {
    "package gateway.policy\n\ndefault allow := false\n\nallow if {\n    input.source_auth.method != \"failed\"\n}\n"
        .to_string()
}

pub fn build_gateway_source_did_allow_policy(did: &str) -> String {
    let did_literal = serde_json::to_string(did).expect("DID should serialize");
    format!(
        r#"package gateway.policy

default allow := false

allow if {{
  input.gateway.source_id == {did_literal}
}}

deny_reason := sprintf("fabric source_id %v did not match expected %v", [input.gateway.source_id, {did_literal}])
"#
    )
}

/// Surface policy that allows only requests whose verified identity binding
/// was issued by `issuer_did`. The receiving gateway sets
/// `input.identity_binding` only when the binding VP verified against the
/// sending gateway's issuer DID (or a trusted binding issuer), so a
/// presentation that is not attributed to the sender is denied here.
pub fn build_surface_identity_binding_issuer_policy(issuer_did: &str) -> String {
    let did_literal = serde_json::to_string(issuer_did).expect("DID should serialize");
    format!(
        r#"package surface.policy

default allow := false

allow if {{
  input.identity_binding.issuer_gateway == {did_literal}
}}

deny_reason := sprintf("caller identity was not issued by gateway %v", [{did_literal}]) if not allow
"#
    )
}

pub fn build_transit_point_request_path_policy(allowed_path: &str) -> String {
    let allowed_path_literal = serde_json::to_string(allowed_path).expect("allowed path should serialize");

    format!(
        r#"package surface.policy

default allow = false

allow if {{
    startswith(input.http.path, {allowed_path_literal} )
}}
"#
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn request_path_policy_json_escapes_path_literal() {
        let policy = super::build_surface_request_path_policy("/alpha/\"quoted\"");

        assert!(policy.contains("package surface.policy"));
        assert!(policy.contains(r#"startswith(input.http.path, "/alpha/\"quoted\""#));
    }

    #[test]
    fn gateway_source_did_policy_json_escapes_did_literal() {
        let policy = super::build_gateway_source_did_allow_policy("did:example:abc\"def");

        assert!(policy.contains("package gateway.policy"));
        assert!(policy.contains(r#"input.gateway.source_id == "did:example:abc\"def""#));
    }
}
