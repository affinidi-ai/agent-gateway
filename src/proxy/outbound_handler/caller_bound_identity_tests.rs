//! A Transit Point whose managed agent identity comes from its own caller's
//! credential: the DID it takes, the identities the request body asserts that
//! it removes, and the managed agent policy and Trust Check see.

use serde_json::json;

use super::tests::{
    RecognisedIn, attach_transit_point_trust_check_list, extension_identity_json,
    make_test_element_referencing_provider_did, managed_agent_element, managed_agent_results, test_outbound_state,
    test_pipeline_context,
};
use super::*;

#[tokio::test]
async fn an_inherited_from_mtls_without_a_certificate_id_is_refused_with_the_fixed_body() {
    let state = test_outbound_state();
    let mut ctx = test_pipeline_context();
    ctx.virtual_channel
        .identity_injection
        .inject_vp = true;
    Arc::make_mut(&mut ctx.surface)
        .identity_slots
        .protected = Some(crate::source_auth::ManagedIdentityConfig::FromMtls { certificate_id: None });

    let err = step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect_err("a stored from_mtls without a certificate_id is refused");

    assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    let response = err.into_response();
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("Identity resolution failed: Caller identity could not be resolved"), "{body}");
    assert!(!body.contains("certificate"), "the caller is not told why: {body}");
}

#[tokio::test]
async fn an_inherited_identity_whose_did_cannot_be_issued_is_refused_with_the_fixed_body() {
    let (failing, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_with(Arc::new(
        crate::identity::test_helpers::FailingIdentityStore,
    ))
    .await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(failing));
    let mut ctx = test_pipeline_context();
    ctx.virtual_channel
        .identity_injection
        .inject_vp = true;
    Arc::make_mut(&mut ctx.surface)
        .identity_slots
        .protected = Some(crate::source_auth::ManagedIdentityConfig::FromApiKey {
        api_key_id: Some("atgk_inherited_key".to_string()),
    });

    let err = step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect_err("a DID the VC issuer cannot issue is refused");

    assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
    let response = err.into_response();
    let body = String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("Identity resolution failed: Caller identity could not be resolved"), "{body}");
    assert!(!body.contains(crate::identity::test_helpers::FailingIdentityStore::DETAIL), "{body}");
    assert!(!body.contains("DID creation/lookup failed"), "{body}");
    assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
}

fn presented_key_context(caller: Option<crate::source_auth::AuthenticatedIdentity>) -> OutboundPipelineContext {
    let mut ctx = test_pipeline_context();
    ctx.virtual_channel
        .managed_identity = Some(crate::source_auth::ManagedIdentityConfig::FromApiKey { api_key_id: None });
    ctx.authenticated_by = caller
        .is_some()
        .then_some(crate::surface_context::TransitClientVerification::SourceAuth);
    ctx.authenticated_identity = caller;
    ctx
}

fn presented_provider_key(key_name: &str) -> crate::source_auth::AuthenticatedIdentity {
    crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: key_name.to_string(),
        provider_agent_id: Some("agents".to_string()),
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_takes_the_did_of_the_key_the_transit_point_caller_presented() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let (fields, hash) = crate::identity::credential_identity::global_resolver()
        .resolve_presented_api_key("atgk_tp_presented", true, None)
        .await
        .unwrap();
    let access_point_caller = vc_issuer
        .issue_or_get_caller_credential(fields, Some(hash.clone()), None, None)
        .await
        .unwrap();
    let vc_issuer = Arc::new(vc_issuer);
    let mut state = test_outbound_state();
    state.vc_issuer = Some(vc_issuer.clone());
    let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_presented")));
    ctx.body_bytes = Some(Bytes::from(
        json!({ "params": { "message": { "metadata": {
            "agent-identity/v1": { "did": "did:example:copied-managed-agent" }
        } } } })
        .to_string(),
    ));

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("the presented key resolves the managed agent identity");

    match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, identity_fields } => {
            assert_eq!(did, &access_point_caller.did, "the same key gives the Access Point's DID");
            assert_eq!(identity_fields.get("api_key_id"), Some(&json!("atgk_tp_presented")));
        }
        ProtectedAgentIdentity::Anonymous => panic!("expected Managed identity, got Anonymous"),
    }
    assert_eq!(
        extension_identity_json(&ctx),
        json!({
            "did": access_point_caller.did,
            "identity_hash": hash,
            "verified": true,
            "verification": "source_auth"
        }),
        "a provider key is the Access Point's verified caller identity"
    );
    let record = vc_issuer
        .get_identity_store()
        .find_by_hash(&hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        record.origin,
        Some(crate::identity::IdentityOrigin::ExternalCaller),
        "a DID first issued to an Access Point caller stays a caller record"
    );
    assert_eq!(record.slot, None);

    let mut other = presented_key_context(Some(presented_provider_key("atgk_tp_other")));
    step_resolve_agent_identity(&state, &mut other)
        .await
        .unwrap();
    match (&ctx.resolved_identity, &other.resolved_identity) {
        (ProtectedAgentIdentity::Managed { did, .. }, ProtectedAgentIdentity::Managed { did: other_did, .. }) => {
            assert_ne!(did, other_did, "each key has its own DID");
        }
        _ => panic!("expected Managed identities"),
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_records_a_new_caller_bound_did_as_the_transit_points_managed_agent() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let vc_issuer = Arc::new(vc_issuer);
    let mut state = test_outbound_state();
    state.vc_issuer = Some(vc_issuer.clone());
    let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_first_use")));
    let alias = ctx
        .virtual_channel
        .alias
        .clone();

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("the presented key resolves the managed agent identity");

    let ProtectedAgentIdentity::Managed { did, .. } = ctx.resolved_identity.clone() else {
        panic!("expected a managed identity");
    };
    let hash = ctx
        .resolved_identity_hash
        .clone()
        .expect("the identity hash is recorded");
    let record = vc_issuer
        .get_identity_store()
        .find_by_hash(&hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record.did, did);
    assert_eq!(record.origin, Some(crate::identity::IdentityOrigin::Managed));
    assert_eq!(record.slot, Some(crate::identity::filesystem::ManagedSlot::TransitPoint { alias, caller_bound: true }));
}

#[tokio::test]
async fn test_step_resolve_agent_identity_leaves_a_transit_point_caller_to_policy_without_a_vc_issuer() {
    let state = test_outbound_state();
    let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_no_issuer")));
    ctx.body_bytes = Some(Bytes::from(
        json!({ "params": { "message": { "metadata": {
            "agent-identity/v1": { "did": "did:example:copied-managed-agent" }
        } } } })
        .to_string(),
    ));

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("without a VC issuer the request is left to policy, not refused");

    assert!(
        matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous),
        "no managed agent identity, and the copied body identity is not used: {:?}",
        ctx.resolved_identity
    );
    assert_eq!(extension_identity_json(&ctx), serde_json::Value::Null);
}

#[tokio::test]
async fn test_step_resolve_agent_identity_reports_a_plain_key_the_transit_point_caller_presented_as_unverified() {
    use crate::secrets::SecretsStore;
    let (vc_issuer, temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let secrets = crate::secrets::FilesystemSecretsStore::new_async(
        temp_dir
            .path()
            .join("secrets")
            .to_str()
            .unwrap(),
    )
    .await
    .unwrap();
    secrets
        .create(
            serde_json::from_value(json!({
                "name": "Plain caller key", "secret_id": "tp-plain-caller-key", "value": "plain-secret"
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    state.secrets_store = Some(Arc::new(secrets));
    let mut ctx = presented_key_context(Some(crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "tp-plain-caller-key".to_string(),
        provider_agent_id: None,
    }));

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("the presented plain key resolves the managed agent identity");

    let identity = extension_identity_json(&ctx);
    assert!(
        identity["did"]
            .as_str()
            .is_some_and(|did| did.starts_with("did:")),
        "{identity}"
    );
    assert_eq!(identity["verification"], "unverified", "every holder of the secret shares the DID");
    assert_eq!(identity["verified"], false);
}

#[tokio::test]
async fn test_step_resolve_agent_identity_refuses_a_transit_point_caller_without_an_api_key() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    let did_caller = crate::source_auth::AuthenticatedIdentity::DidAuth {
        did: "did:example:caller".to_string(),
    };
    for (case, mut ctx) in [
        ("no verified caller", presented_key_context(None)),
        ("a caller verified another way", presented_key_context(Some(did_caller))),
    ] {
        let err = step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect_err(case);
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR, "{case}");
        assert_eq!(err.to_string(), "Identity resolution failed: Caller identity could not be resolved", "{case}");
        assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous), "{case}");
    }

    let mut plain = presented_key_context(Some(crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "plain-secret".to_string(),
        provider_agent_id: None,
    }));
    let err = step_resolve_agent_identity(&state, &mut plain)
        .await
        .expect_err("a plain key needs the secrets store");
    assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(err.to_string(), "Identity resolution failed: Caller identity could not be resolved");
}

#[tokio::test]
async fn test_a_caller_bound_transit_point_without_a_did_forwards_no_identity_the_body_asserts() {
    use crate::config::{
        AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION as BINDING,
        AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION as CREDENTIAL, AFFINIDI_AGENT_IDENTITY_EXTENSION as RAW,
        MCP_AGENT_IDENTITY_CREDENTIAL_KEY, MCP_AGENT_IDENTITY_KEY,
    };
    let mut state = test_outbound_state();
    state.vc_issuer = None;
    let copied = json!({ "did": "did:example:copied-managed-agent", "verifiablePresentation": "copied.vp.jwt" });
    let a2a = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": { "message": {
        "role": "user", "parts": [{ "kind": "text", "text": "hello" }],
        "extensions": [RAW, CREDENTIAL, BINDING, "https://example.com/other/v1"],
        "metadata": { RAW: copied, CREDENTIAL: copied, BINDING: copied, "https://example.com/other/v1": { "kept": true } }
    } } });
    let mcp = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "_meta": { CREDENTIAL: copied },
        "params": { "name": "echo", "arguments": { "value": 1 }, "_meta": {
            MCP_AGENT_IDENTITY_KEY: copied, MCP_AGENT_IDENTITY_CREDENTIAL_KEY: copied,
            BINDING: copied, "progressToken": 7
        } } });
    for (protocol, body) in [(ChannelProtocol::A2a, a2a), (ChannelProtocol::Mcp, mcp)] {
        let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_no_issuer")));
        ctx.protocol = Some(protocol.clone());
        ctx.body_bytes = Some(Bytes::from(body.to_string()));

        step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect("a caller without a DID goes on to policy");
        step_inject_trusted_identity(&state, &mut ctx)
            .await
            .expect("nothing is injected");

        assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous), "{protocol:?}");
        let forwarded: serde_json::Value = serde_json::from_slice(
            ctx.body_bytes
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        let text = forwarded.to_string();
        for asserted in ["did:example:copied-managed-agent", "copied.vp.jwt"] {
            assert!(!text.contains(asserted), "{protocol:?} forwards no copied identity: {forwarded}");
        }
        if protocol == ChannelProtocol::A2a {
            let message = &forwarded["params"]["message"];
            assert_eq!(message["extensions"], json!(["https://example.com/other/v1"]));
            assert_eq!(message["metadata"], json!({ "https://example.com/other/v1": { "kept": true } }));
            assert_eq!(message["parts"], body["params"]["message"]["parts"]);
        } else {
            assert_eq!(forwarded["params"]["_meta"], json!({ "progressToken": 7 }));
            assert_eq!(forwarded["_meta"], json!({}));
            assert_eq!(forwarded["params"]["arguments"], body["params"]["arguments"]);
        }
    }
}

#[tokio::test]
async fn test_a_caller_bound_transit_point_with_a_did_forwards_only_its_own_credential() {
    use crate::config::{
        AFFINIDI_AGENT_IDENTITY_BINDING_EXTENSION as BINDING,
        AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION as CREDENTIAL, AFFINIDI_AGENT_IDENTITY_EXTENSION as RAW,
        MCP_AGENT_IDENTITY_CREDENTIAL_KEY, MCP_AGENT_IDENTITY_KEY,
    };
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    let copied = json!({ "did": "did:example:copied-managed-agent", "verifiablePresentation": "copied.vp.jwt" });
    let a2a = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": { "message": {
        "role": "user", "parts": [{ "kind": "text", "text": "hello" }],
        "extensions": [RAW, CREDENTIAL, BINDING, "https://example.com/other/v1"],
        "metadata": { RAW: copied, CREDENTIAL: copied, BINDING: copied, "https://example.com/other/v1": { "kept": true } }
    } } });
    let mcp = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call", "_meta": { CREDENTIAL: copied },
        "params": { "name": "echo", "arguments": { "value": 1 }, "_meta": {
            MCP_AGENT_IDENTITY_KEY: copied, MCP_AGENT_IDENTITY_CREDENTIAL_KEY: copied,
            BINDING: copied, "progressToken": 7
        } } });
    for (protocol, body) in [(ChannelProtocol::A2a, a2a), (ChannelProtocol::Mcp, mcp)] {
        let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_fresh_credential")));
        ctx.protocol = Some(protocol.clone());
        ctx.body_bytes = Some(Bytes::from(body.to_string()));

        step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect("the presented key resolves the managed agent identity");
        let ProtectedAgentIdentity::Managed { did, .. } = ctx.resolved_identity.clone() else {
            panic!("{protocol:?}: expected a managed identity");
        };
        step_inject_trusted_identity(&state, &mut ctx)
            .await
            .expect("the gateway's credential is injected");

        let forwarded: serde_json::Value = serde_json::from_slice(
            ctx.body_bytes
                .as_ref()
                .unwrap(),
        )
        .unwrap();
        let text = forwarded.to_string();
        for asserted in ["did:example:copied-managed-agent", "copied.vp.jwt"] {
            assert!(!text.contains(asserted), "{protocol:?} forwards no copied identity: {forwarded}");
        }
        assert!(text.contains(&format!(r#""did":"{did}""#)), "{protocol:?}: {forwarded}");
        if protocol == ChannelProtocol::A2a {
            let message = &forwarded["params"]["message"];
            assert_eq!(message["extensions"], json!(["https://example.com/other/v1", CREDENTIAL]));
            let metadata = message["metadata"]
                .as_object()
                .unwrap();
            let mut keys: Vec<&str> = metadata
                .keys()
                .map(String::as_str)
                .collect();
            keys.sort_unstable();
            let mut expected = vec![CREDENTIAL, "https://example.com/other/v1"];
            expected.sort_unstable();
            assert_eq!(keys, expected);
            assert_eq!(metadata[CREDENTIAL]["did"], json!(did));
        } else {
            for meta in [&forwarded["params"]["_meta"], &forwarded["_meta"]] {
                for key in [RAW, BINDING, MCP_AGENT_IDENTITY_KEY, crate::config::MCP_AGENT_IDENTITY_BINDING_KEY] {
                    assert!(meta.get(key).is_none(), "{key} is not forwarded: {forwarded}");
                }
            }
            assert_eq!(forwarded["params"]["_meta"]["progressToken"], json!(7));
            assert_eq!(forwarded["params"]["arguments"], body["params"]["arguments"]);
        }
    }
}

#[tokio::test]
async fn test_a_caller_bound_transit_point_with_no_identity_carrier_refuses_rather_than_forward_without_a_did() {
    let mut state = test_outbound_state();
    state.vc_issuer = None;
    let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_didcomm_no_issuer")));
    ctx.protocol = Some(ChannelProtocol::DIDComm);
    let body = Bytes::from(json!({ "agent-identity": "copied.vp.jwt" }).to_string());
    ctx.body_bytes = Some(body.clone());

    let err = step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect_err("a body with no identity carrier is refused, as identity injection refuses it");

    assert!(
        matches!(err, OutboundPipelineError::IdentityInjectionFailed(ref reason) if reason.contains("DIDComm")),
        "{err:?}"
    );
    assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
    assert_eq!(ctx.body_bytes, Some(body));
}

#[tokio::test]
async fn a_caller_bound_a2a_transit_point_refuses_a_body_that_is_not_one_json_object() {
    let mut state = test_outbound_state();
    state.vc_issuer = None;
    let message = json!({ "jsonrpc": "2.0", "id": 1, "method": "message/send", "params": { "message": {
        "role": "user", "parts": [{ "kind": "text", "text": "hello" }],
        "extensions": [crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION],
        "metadata": { crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION: { "did": "did:example:copied" } }
    } } });
    for (case, body) in [
        (
            "batch",
            json!([message])
                .to_string()
                .into_bytes(),
        ),
        ("byte order mark", [b"\xEF\xBB\xBF".as_slice(), message.to_string().as_bytes()].concat()),
    ] {
        let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_unremovable")));
        ctx.protocol = Some(ChannelProtocol::A2a);
        let body = Bytes::from(body);
        ctx.body_bytes = Some(body.clone());

        let err = step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect_err(case);

        assert!(matches!(err, OutboundPipelineError::AssertedIdentityUnremovable), "{case}: {err:?}");
        assert_eq!(ctx.body_bytes, Some(body), "{case}: nothing is forwarded");
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{case}");
        let answer: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(answer["error"]["code"], json!(-32600), "{case}: {answer}");
        assert_eq!(answer["id"], serde_json::Value::Null, "{case}");
    }
}

async fn read_mcp_request_through_an_mcp_transit_point_on_an_a2a_surface(
    state: &OutboundProxyState,
    mut ctx: OutboundPipelineContext,
    body: &serde_json::Value,
) -> OutboundPipelineContext {
    assert_eq!(ctx.surface.channel_protocol(), ChannelProtocol::A2a);
    ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
    ctx.request = Some(axum::http::Request::new(axum::body::Body::from(body.to_string())));
    assert!(
        step_extract_protocol_context(state, &mut ctx)
            .await
            .expect("the MCP request is admitted")
            .is_none()
    );
    assert_eq!(ctx.protocol, Some(ChannelProtocol::Mcp));
    ctx
}

#[tokio::test]
async fn an_mcp_transit_point_on_an_a2a_surface_injects_its_managed_identity_into_mcp_meta() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "search", "arguments": { "q": "hello" } } });
    let mut ctx = read_mcp_request_through_an_mcp_transit_point_on_an_a2a_surface(
        &state,
        presented_key_context(Some(presented_provider_key("atgk_tp_mcp_presented"))),
        &body,
    )
    .await;

    let policy_input = build_outbound_policy_input(&ctx);
    assert!(policy_input.a2a.is_none());
    assert_eq!(
        policy_input
            .mcp
            .expect("policy reads the request as MCP")
            .tool_name
            .as_deref(),
        Some("search")
    );

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("the presented key resolves the managed agent identity");
    let ProtectedAgentIdentity::Managed { did, .. } = ctx.resolved_identity.clone() else {
        panic!("expected a managed identity");
    };
    step_inject_trusted_identity(&state, &mut ctx)
        .await
        .expect("the identity is injected into the MCP request");

    let forwarded: serde_json::Value = serde_json::from_slice(
        ctx.body_bytes
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert!(
        forwarded["params"]
            .get("message")
            .is_none(),
        "{forwarded}"
    );
    assert_eq!(forwarded["params"]["arguments"], body["params"]["arguments"]);
    assert!(
        forwarded
            .to_string()
            .contains(&format!(r#""did":"{did}""#)),
        "{forwarded}"
    );
}

#[tokio::test]
async fn a_caller_bound_mcp_transit_point_on_an_a2a_surface_without_a_did_strips_a_copied_meta_identity() {
    let mut state = test_outbound_state();
    state.vc_issuer = None;
    let body = json!({ "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": { "name": "echo", "arguments": { "value": 1 }, "_meta": {
            crate::config::MCP_AGENT_IDENTITY_KEY: { "did": "did:example:copied-managed-agent" }, "progressToken": 7
        } } });
    let mut ctx = read_mcp_request_through_an_mcp_transit_point_on_an_a2a_surface(
        &state,
        presented_key_context(Some(presented_provider_key("atgk_tp_mcp_no_issuer"))),
        &body,
    )
    .await;

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("a caller without a DID goes on to policy");
    step_inject_trusted_identity(&state, &mut ctx)
        .await
        .expect("nothing is injected");

    assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
    let forwarded: serde_json::Value = serde_json::from_slice(
        ctx.body_bytes
            .as_ref()
            .unwrap(),
    )
    .unwrap();
    assert_eq!(forwarded["params"]["_meta"], json!({ "progressToken": 7 }), "{forwarded}");
    assert_eq!(forwarded["params"]["arguments"], body["params"]["arguments"]);
}

fn jwt_claim_context(claims: Option<serde_json::Value>) -> OutboundPipelineContext {
    let mut ctx = test_pipeline_context();
    ctx.virtual_channel
        .managed_identity = Some(crate::source_auth::ManagedIdentityConfig::FromJwtClaim {
        claim: "oid".to_string(),
        namespace_claims: vec!["tid".to_string()],
    });
    if let Some(claims) = claims {
        ctx.authenticated_identity = Some(crate::source_auth::AuthenticatedIdentity::JwtBearer {
            subject: "agent".to_string(),
            principal_claim: "sub".to_string(),
            claims,
            verification: Default::default(),
            strategy_id: None,
        });
        ctx.authenticated_by = Some(crate::surface_context::TransitClientVerification::SourceAuth);
    }
    ctx
}

#[tokio::test]
async fn test_step_resolve_agent_identity_takes_the_did_of_the_jwt_claim_the_transit_point_caller_presented() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let claims = json!({ "oid": "tp-agent-1", "tid": "tenant-a", "sub": "app" });
    let mut ctx = jwt_claim_context(Some(claims));
    let access_point_identity = crate::identity::credential_identity::global_resolver()
        .resolve_verified_caller(
            &crate::source_auth::ManagedIdentityConfig::FromJwtClaim {
                claim: "oid".to_string(),
                namespace_claims: vec!["tid".to_string()],
            },
            ctx.authenticated_identity
                .as_ref()
                .unwrap(),
            None,
            None,
        )
        .await
        .unwrap();
    let access_point_caller = vc_issuer
        .issue_or_get_caller_credential(
            access_point_identity.identity_fields,
            Some(access_point_identity.identity_hash),
            None,
            None,
        )
        .await
        .unwrap();
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    ctx.body_bytes = Some(Bytes::from(
        json!({ "params": { "message": { "metadata": {
            "agent-identity/v1": { "did": "did:example:copied-managed-agent" }
        } } } })
        .to_string(),
    ));

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("the verified JWT claim resolves the managed agent identity");

    match &ctx.resolved_identity {
        ProtectedAgentIdentity::Managed { did, identity_fields } => {
            assert_eq!(did, &access_point_caller.did, "the same claim value gives the Access Point's DID");
            assert_eq!(identity_fields.get("value"), Some(&json!("tp-agent-1")));
        }
        ProtectedAgentIdentity::Anonymous => panic!("expected Managed identity, got Anonymous"),
    }
    let identity = extension_identity_json(&ctx);
    assert_eq!(identity["did"], json!(access_point_caller.did));
    assert_eq!(identity["verification"], "source_auth");
    assert_eq!(identity["verified"], true);

    let mut other = jwt_claim_context(Some(json!({ "oid": "tp-agent-2", "tid": "tenant-a" })));
    step_resolve_agent_identity(&state, &mut other)
        .await
        .unwrap();
    match (&ctx.resolved_identity, &other.resolved_identity) {
        (ProtectedAgentIdentity::Managed { did, .. }, ProtectedAgentIdentity::Managed { did: other_did, .. }) => {
            assert_ne!(did, other_did, "each claim value has its own DID");
        }
        _ => panic!("expected Managed identities"),
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_refuses_a_transit_point_caller_without_the_jwt_claim() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    for (case, mut ctx, status) in [
        (
            "a token without the claim",
            jwt_claim_context(Some(json!({ "tid": "tenant-a", "sub": "app" }))),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        (
            "a token without the namespace claim",
            jwt_claim_context(Some(json!({ "oid": "tp-agent-1" }))),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        ("no verified JWT", jwt_claim_context(None), StatusCode::INTERNAL_SERVER_ERROR),
    ] {
        let err = step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect_err(case);
        assert_eq!(err.status_code(), status, "{case}");
        assert_eq!(err.to_string(), "Identity resolution failed: Caller identity could not be resolved", "{case}");
        assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous), "{case}");
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_refuses_a_transit_point_jwt_caller_it_cannot_issue_a_did_for() {
    let claims = json!({ "oid": "tp-agent-1", "tid": "tenant-a" });
    let (failing, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_with(Arc::new(
        crate::identity::test_helpers::FailingIdentityStore,
    ))
    .await;
    let mut failing_state = test_outbound_state();
    failing_state.vc_issuer = Some(Arc::new(failing));
    let mut no_issuer_state = test_outbound_state();
    no_issuer_state.vc_issuer = None;
    for (case, state, status, message) in [
        (
            "no VC issuer",
            &no_issuer_state,
            StatusCode::INTERNAL_SERVER_ERROR,
            "Identity resolution failed: from_jwt_claim requires a configured VC issuer",
        ),
        (
            "issuance fails",
            &failing_state,
            StatusCode::BAD_GATEWAY,
            "Identity resolution failed: VCIssuer failure during from_jwt_claim resolution",
        ),
    ] {
        let mut ctx = jwt_claim_context(Some(claims.clone()));
        let err = step_resolve_agent_identity(state, &mut ctx)
            .await
            .expect_err(case);
        assert_eq!(err.status_code(), status, "{case}");
        assert_eq!(err.to_string(), message, "{case}");
        assert!(
            !err.to_string()
                .contains(crate::identity::test_helpers::FailingIdentityStore::DETAIL),
            "{case}"
        );
        assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous), "{case}");
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_leaves_a_transit_point_key_caller_to_policy_when_issuance_fails() {
    let (failing, _temp_dir) = crate::identity::test_helpers::test_vc_issuer_with(Arc::new(
        crate::identity::test_helpers::FailingIdentityStore,
    ))
    .await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(failing));
    let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_issuance_fails")));
    ctx.body_bytes = Some(Bytes::from(
        json!({ "params": { "message": { "metadata": {
            crate::config::AFFINIDI_AGENT_IDENTITY_EXTENSION: { "did": "did:example:copied-managed-agent" }
        } } } })
        .to_string(),
    ));

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("an API key caller without a DID goes on to policy");

    assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
    assert!(
        !String::from_utf8_lossy(
            ctx.body_bytes
                .as_ref()
                .unwrap()
        )
        .contains("did:example:copied-managed-agent")
    );
}

struct UnreadableSecretsStore;

#[async_trait::async_trait]
impl crate::secrets::SecretsStore for UnreadableSecretsStore {
    async fn create(
        &self,
        _request: crate::secrets::CreateSecretRequest,
    ) -> anyhow::Result<crate::secrets::Secret> {
        anyhow::bail!("secrets store offline")
    }

    async fn get(
        &self,
        _id: &str,
    ) -> anyhow::Result<Option<crate::secrets::Secret>> {
        anyhow::bail!("secrets store offline")
    }

    async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
        anyhow::bail!("secrets store offline")
    }

    async fn update(
        &self,
        _id: &str,
        _request: crate::secrets::UpdateSecretRequest,
    ) -> anyhow::Result<crate::secrets::Secret> {
        anyhow::bail!("secrets store offline")
    }

    async fn delete(
        &self,
        _id: &str,
    ) -> anyhow::Result<()> {
        anyhow::bail!("secrets store offline")
    }

    async fn find_by_tag(
        &self,
        _tag: &str,
    ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
        anyhow::bail!("secrets store offline")
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_refuses_a_transit_point_plain_key_caller_while_the_secrets_store_is_unreadable()
 {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    state.secrets_store = Some(Arc::new(UnreadableSecretsStore));
    let mut ctx = presented_key_context(Some(crate::source_auth::AuthenticatedIdentity::ApiKey {
        key_name: "tp-plain-unreadable".to_string(),
        provider_agent_id: None,
    }));

    let err = step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect_err("a plain key the store cannot read is refused");

    assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(err.to_string(), "Identity resolution failed: Caller identity could not be resolved");
    assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
}

fn caller_certificate_context(caller: Option<crate::source_auth::AuthenticatedIdentity>) -> OutboundPipelineContext {
    let mut ctx = test_pipeline_context();
    ctx.virtual_channel
        .managed_identity = Some(crate::source_auth::ManagedIdentityConfig::FromMtls { certificate_id: None });
    ctx.virtual_channel
        .source_auth = Some(
        serde_json::from_value(json!({
            "type": "mtls",
            "trust": { "type": "ca", "ca_certificate_ids": ["agents-ca"] },
            "identity_binding": { "type": "subject_cn" }
        }))
        .unwrap(),
    );
    ctx.authenticated_by = caller
        .is_some()
        .then_some(crate::surface_context::TransitClientVerification::SourceAuth);
    ctx.authenticated_identity = caller;
    ctx
}

fn certificate_caller(principal: &str) -> crate::source_auth::AuthenticatedIdentity {
    crate::source_auth::AuthenticatedIdentity::Mtls {
        principal: principal.to_string(),
        fingerprint: format!("leaf-{principal}"),
        subject_dn: format!("CN={principal}"),
        issuer_dn: "CN=agents-ca".to_string(),
        trust_anchor_fingerprint: "agents-ca-anchor".to_string(),
        sans: Default::default(),
        source: crate::source_auth::models::PeerCertSource::DirectTls,
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_takes_the_did_of_the_certificate_the_transit_point_caller_presented() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    let mut ctx = caller_certificate_context(Some(certificate_caller("agent-1")));
    ctx.body_bytes = Some(Bytes::from(
        json!({ "params": { "message": { "metadata": {
            "agent-identity/v1": { "did": "did:example:copied-managed-agent" }
        } } } })
        .to_string(),
    ));
    let mut other = caller_certificate_context(Some(certificate_caller("agent-2")));

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("the verified certificate resolves the managed agent identity");
    step_resolve_agent_identity(&state, &mut other)
        .await
        .unwrap();

    match (&ctx.resolved_identity, &other.resolved_identity) {
        (
            ProtectedAgentIdentity::Managed { did, identity_fields },
            ProtectedAgentIdentity::Managed { did: other_did, .. },
        ) => {
            assert_ne!(did, "did:example:copied-managed-agent");
            assert_eq!(identity_fields.get("principal"), Some(&json!("agent-1")));
            assert_ne!(did, other_did, "each principal has its own DID");
            assert_eq!(extension_identity_json(&ctx)["did"], json!(did));
        }
        _ => panic!("expected Managed identities"),
    }
    assert_eq!(extension_identity_json(&ctx)["verification"], "source_auth");
    assert_eq!(extension_identity_json(&ctx)["verified"], true);
}

#[tokio::test]
async fn test_step_resolve_agent_identity_refuses_a_transit_point_caller_without_a_certificate() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    for (case, mut ctx) in [
        ("no verified caller", caller_certificate_context(None)),
        ("a caller verified another way", caller_certificate_context(Some(presented_provider_key("atgk_tp")))),
    ] {
        let err = step_resolve_agent_identity(&state, &mut ctx)
            .await
            .expect_err(case);
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR, "{case}");
        assert_eq!(err.to_string(), "Identity resolution failed: Caller identity could not be resolved", "{case}");
        assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous), "{case}");
    }
}

#[tokio::test]
async fn test_step_resolve_agent_identity_skips_a_from_jwt_claim_the_transit_point_inherits() {
    let mut state = test_outbound_state();
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    state.vc_issuer = Some(Arc::new(vc_issuer));
    let mut ctx = jwt_claim_context(Some(json!({ "oid": "tp-agent-1", "tid": "tenant-a" })));
    let mut surface = (*ctx.surface).clone();
    surface
        .identity_slots
        .protected = ctx
        .virtual_channel
        .managed_identity
        .take();
    ctx.surface = Arc::new(surface);
    ctx.virtual_channel
        .identity_injection
        .inject_vp = true;

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("an inherited from_jwt_claim is skipped");

    assert!(matches!(ctx.resolved_identity, ProtectedAgentIdentity::Anonymous));
}

#[tokio::test]
async fn test_step_resolve_agent_identity_keeps_a_stored_transit_point_key() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    let mut stored = presented_key_context(Some(presented_provider_key("atgk_tp_caller_key")));
    stored
        .virtual_channel
        .managed_identity = Some(crate::source_auth::ManagedIdentityConfig::FromApiKey {
        api_key_id: Some("atgk_tp_stored_key".to_string()),
    });
    step_resolve_agent_identity(&state, &mut stored)
        .await
        .unwrap();
    let mut presented = presented_key_context(Some(presented_provider_key("atgk_tp_caller_key")));
    step_resolve_agent_identity(&state, &mut presented)
        .await
        .unwrap();

    match (&stored.resolved_identity, &presented.resolved_identity) {
        (
            ProtectedAgentIdentity::Managed { identity_fields, did },
            ProtectedAgentIdentity::Managed { did: presented_did, .. },
        ) => {
            assert_eq!(identity_fields.get("api_key_id"), Some(&json!("atgk_tp_stored_key")));
            assert_ne!(did, presented_did, "a stored key is not the caller's key");
        }
        _ => panic!("expected Managed identities"),
    }
}

#[tokio::test]
async fn a_managed_agent_element_asks_about_the_did_of_the_key_a_caller_bound_transit_point_verified() {
    let (vc_issuer, _temp_dir) = crate::identity::test_helpers::test_vc_issuer().await;
    let mut state = test_outbound_state();
    state.vc_issuer = Some(Arc::new(vc_issuer));
    let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_self_check")));
    ctx.virtual_channel
        .trust_check_list = vec![managed_agent_element("self", "alpha")];
    ctx.body_bytes = Some(Bytes::from(
        json!({ "params": { "message": { "metadata": {
            "agent-identity/v1": { "did": "did:example:copied-managed-agent" }
        } } } })
        .to_string(),
    ));
    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .unwrap();
    let ProtectedAgentIdentity::Managed { did, .. } = ctx.resolved_identity.clone() else {
        panic!("expected the DID of the presented key");
    };
    let elements = managed_agent_elements(&ctx);
    let client = RecognisedIn::new(&["alpha"]);

    run_managed_agent_trust_checks(&mut ctx, &elements, &client).await;

    assert_eq!(client.asked_about(), [did]);
    assert_eq!(managed_agent_results(&ctx), [("self".to_string(), true, None)]);
}

#[test]
fn outbound_policy_input_has_no_extension_identity_without_a_managed_agent_identity() {
    let input = serde_json::to_value(build_outbound_policy_input(&test_pipeline_context())).unwrap();
    assert!(
        input
            .get("extension_identity")
            .is_none(),
        "{input}"
    );
}

#[test]
fn outbound_policy_input_reports_the_managed_agent_as_extension_identity_and_the_destination_as_agent() {
    let mut ctx = test_pipeline_context();
    ctx.resolved_identity = ProtectedAgentIdentity::Managed {
        did: "did:web:managed.example".to_string(),
        identity_fields: std::collections::HashMap::new(),
    };
    ctx.resolved_identity_hash = Some("managed-hash".to_string());
    ctx.resolved_identity_verification = crate::surface_context::IdentityVerification::SourceAuth;
    ctx.target_agent_context = Some(crate::surface_context::AgentContext {
        did_verified: false,
        did_verification: None,
        did: Some("did:web:destination.example".to_string()),
        provider_did: None,
        authority_did: None,
        identity_issuer_did: None,
        trust_registry_did: None,
        agent_dna: None,
        trust_verification: None,
        source_trust_verification: None,
        target_trust_verification: None,
        tr_identity_mismatch: false,
    });

    let input = serde_json::to_value(build_outbound_policy_input(&ctx)).unwrap();

    assert_eq!(
        input["extension_identity"],
        json!({
            "did": "did:web:managed.example",
            "identity_hash": "managed-hash",
            "verified": true,
            "verification": "source_auth"
        })
    );
    assert_eq!(input["agent"]["did"], "did:web:destination.example");
    assert_eq!(input["gateway"]["source_id"], "did:web:managed.example");
}

#[test]
fn outbound_policy_input_reports_a_bound_managed_agent_did_as_unverified() {
    let mut ctx = test_pipeline_context();
    ctx.resolved_identity = ProtectedAgentIdentity::Managed {
        did: "did:web:managed.example".to_string(),
        identity_fields: std::collections::HashMap::new(),
    };
    assert_eq!(
        extension_identity_json(&ctx),
        json!({ "did": "did:web:managed.example", "verified": false, "verification": "unverified" })
    );
}

#[tokio::test]
async fn outbound_target_leg_trust_check_never_falls_back_to_the_managed_agent() {
    crate::proxy::agent_card_cache::invalidate_all();
    let state = test_outbound_state();
    let mut ctx = test_pipeline_context();
    let mut element = make_test_element_referencing_provider_did("tc-1");
    element.query.entity_id = "{{ input.agent.provider_did || input.extension_identity.did }}".to_string();
    attach_transit_point_trust_check_list(&mut ctx, vec![element]);
    ctx.resolved_identity = ProtectedAgentIdentity::Managed {
        did: "did:web:managed.example".to_string(),
        identity_fields: std::collections::HashMap::new(),
    };
    ctx.target_agent_context = Some(crate::surface_context::AgentContext {
        did_verified: false,
        did_verification: None,
        did: Some("did:web:target".to_string()),
        provider_did: None,
        authority_did: None,
        identity_issuer_did: None,
        trust_registry_did: None,
        agent_dna: None,
        trust_verification: None,
        source_trust_verification: None,
        target_trust_verification: None,
        tr_identity_mismatch: false,
    });

    step_trust_check(&state, &mut ctx)
        .await
        .expect("synthesis never errors");

    let results = ctx
        .trust_check_results
        .expect("results populated");
    assert_eq!(results.target.len(), 1);
    assert_eq!(
        results.target[0]
            .error
            .as_ref()
            .map(|error| error.code.as_str()),
        Some("TRUST_REGISTRY_METADATA_UNAVAILABLE")
    );
}

#[tokio::test]
async fn a_caller_bound_mcp_transit_point_removes_the_asserted_identity_from_the_modern_policy_input() {
    use crate::mcp::request_validation::{LegacySessionEvidence, validate_mcp_post};
    let copied = json!({ "did": "did:example:copied-managed-agent" });
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
        "name": "echo", "arguments": { "value": 1 }, "_meta": {
            "io.modelcontextprotocol/protocolVersion": crate::mcp::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {},
            crate::config::MCP_AGENT_IDENTITY_KEY: copied,
            crate::config::MCP_AGENT_IDENTITY_CREDENTIAL_KEY: copied,
            crate::config::MCP_AGENT_IDENTITY_BINDING_KEY: copied,
            "agentIdentity": copied,
            "progressToken": 7
        }
    }});
    let mut state = test_outbound_state();
    state.vc_issuer = None;
    let mut ctx = presented_key_context(Some(presented_provider_key("atgk_tp_modern_meta")));
    ctx.virtual_channel.protocol = crate::config::agent_surface::TransitProtocol::Mcp;
    ctx.protocol = Some(ChannelProtocol::Mcp);
    ctx.original_headers.insert(
        "mcp-protocol-version",
        crate::mcp::MCP_MODERN_VERSION
            .parse()
            .unwrap(),
    );
    ctx.original_headers
        .insert("mcp-method", "tools/call".parse().unwrap());
    ctx.original_headers
        .insert("mcp-name", "echo".parse().unwrap());
    ctx.mcp_classification = Some(
        validate_mcp_post(
            &ctx.original_headers,
            &serde_json::to_vec(&body).unwrap(),
            LegacySessionEvidence::Absent,
            crate::mcp::request_validation::MODERN_ONLY_POLICY,
        )
        .unwrap(),
    );
    ctx.body_bytes = Some(Bytes::from(body.to_string()));

    step_resolve_agent_identity(&state, &mut ctx)
        .await
        .expect("a caller without a DID goes on to policy");

    let mcp = serde_json::to_value(
        build_outbound_policy_input(&ctx)
            .mcp
            .unwrap(),
    )
    .unwrap();
    let meta = mcp["params"]["_meta"]
        .as_object()
        .unwrap();
    let mut keys: Vec<&str> = meta
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["io.modelcontextprotocol/clientCapabilities", "io.modelcontextprotocol/protocolVersion", "progressToken"],
        "{mcp}"
    );
    assert_eq!(mcp["tool_name"], json!("echo"));
}
