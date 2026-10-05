use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::ContinuationError;
use super::protected::{ContinuationBinding, ContinuationRoute, request_arguments_digest};
use crate::config::agent_surface::AgentSurface;
use crate::credential_providers::CredentialProvider;
use crate::mcp::request_validation::ValidatedModernMessage;
use crate::mcp::resource_server::McpResourceServerConfig;
use crate::source_auth::AuthenticatedIdentity;

pub fn make_binding(
    deployment: &str,
    surface: &AgentSurface,
    variant_id: Option<String>,
    route: ContinuationRoute,
    authorization: &McpResourceServerConfig,
    provider: &CredentialProvider,
    scopes: Vec<String>,
    agent_did: &str,
    identity: &AuthenticatedIdentity,
    request: &ValidatedModernMessage,
) -> Result<ContinuationBinding, ContinuationError> {
    let (principal, user_identity_hash) = verified_principal(identity)?;
    let binding = ContinuationBinding {
        deployment: deployment.into(),
        principal,
        agent_did: agent_did.into(),
        user_identity_hash,
        authorization_digest: authorization_digest(surface, provider, identity)?,
        tenant_id: surface.tenant_id.clone(),
        surface_id: surface.surface_id.clone(),
        variant_id,
        route,
        resource: authorization.resource.clone(),
        provider_id: provider.id.clone(),
        scopes,
        method: request.method.clone(),
        arguments_digest: request_arguments_digest(request)?,
    };
    binding.digest()?;
    Ok(binding)
}

fn verified_principal(identity: &AuthenticatedIdentity) -> Result<(String, String), ContinuationError> {
    let AuthenticatedIdentity::JwtBearer { subject, claims } = identity else {
        return Err(ContinuationError::BindingMismatch);
    };
    let issuer = claims
        .get("iss")
        .and_then(Value::as_str)
        .filter(|issuer| !issuer.is_empty())
        .ok_or(ContinuationError::BindingMismatch)?;
    if subject.is_empty()
        || claims
            .get("sub")
            .and_then(Value::as_str)
            != Some(subject)
    {
        return Err(ContinuationError::BindingMismatch);
    }
    Ok((hex::encode(digest(&(issuer, subject))?), hex::encode(Sha256::digest(subject.as_bytes()))))
}

fn authorization_digest(
    surface: &AgentSurface,
    provider: &CredentialProvider,
    identity: &AuthenticatedIdentity,
) -> Result<[u8; 32], ContinuationError> {
    let claims = identity
        .jwt_claims()
        .ok_or(ContinuationError::BindingMismatch)?;
    let mut scopes = claims
        .get("scope")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .split_whitespace()
        .collect::<Vec<_>>();
    scopes.sort_unstable();
    scopes.dedup();
    digest(&json!({
        "surface": surface, "provider": provider,
        "principal": verified_principal(identity)?.0,
        "scopes": scopes, "actor": claims.get("act"), "client_id": claims.get("client_id")
    }))
}

pub fn provider_digest(provider: &CredentialProvider) -> Result<[u8; 32], ContinuationError> {
    digest(provider)
}

pub fn surface_digest(surface: &AgentSurface) -> Result<[u8; 32], ContinuationError> {
    digest(surface)
}

pub fn identity_strategy_digest(
    strategy: &crate::jwt_bearer::models::JwtVerificationStrategy
) -> Result<[u8; 32], ContinuationError> {
    digest(strategy)
}

fn digest(value: &impl serde::Serialize) -> Result<[u8; 32], ContinuationError> {
    let encoded = serde_json_canonicalizer::to_vec(value).map_err(|_| ContinuationError::InvalidRecord)?;
    Ok(Sha256::digest(encoded).into())
}

#[cfg(test)]
pub fn validate_consent_identity(
    ticket: &super::protected::ConsentTicket,
    surface: &AgentSurface,
    provider: &CredentialProvider,
    identity: &AuthenticatedIdentity,
) -> Result<(), ContinuationError> {
    let (principal, user_identity_hash) = verified_principal(identity)?;
    if principal != ticket.binding.principal
        || user_identity_hash
            != ticket
                .binding
                .user_identity_hash
        || surface.surface_id != ticket.binding.surface_id
        || surface.tenant_id != ticket.binding.tenant_id
        || surface.status != crate::config::agent_surface::SurfaceStatus::Active
        || provider.id != ticket.binding.provider_id
        || provider_digest(provider)? != ticket.provider_digest
        || authorization_digest(surface, provider, identity)?
            != ticket
                .binding
                .authorization_digest
    {
        return Err(ContinuationError::BindingMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::protected::ConsentTicket;
    use super::*;
    use crate::mcp::request_validation::McpMessageKind;

    #[test]
    fn consent_identity_checks_verified_issuer_subject_and_current_authority() {
        let mut surface: AgentSurface = serde_json::from_value(json!({
            "surface_id": "surface", "name": "surface", "access_point": {"listen_address": "https://gateway.example", "route": "/mcp", "protocol": "mcp"},
            "target": {"endpoint": "https://provider.example/api"}
        })).unwrap();
        let provider: CredentialProvider = serde_json::from_value(json!({
            "id": "provider", "name": "Provider", "provider_id": "provider", "created_at": "2026-09-01T00:00:00Z", "updated_at": "2026-09-01T00:00:00Z"
        })).unwrap();
        let identity = AuthenticatedIdentity::JwtBearer {
            subject: "user".into(),
            claims: json!({"iss": "https://gateway.example/oauth2/mcp", "sub": "user", "scope": "write read", "act": {"sub": "client"}, "exp": 100}),
        };
        let authorization = McpResourceServerConfig {
            resource: "https://gateway.example/mcp".into(),
            scopes: vec!["read".into()],
        };
        let request = ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: Some(json!({"elicitation": {"url": {}}})),
            client_info: None,
            method: "tools/call".into(),
            params: Some(json!({"name": "write"})),
            id: Some(json!(1)),
            kind: McpMessageKind::Request,
        };
        let binding = make_binding(
            "deployment",
            &surface,
            None,
            ContinuationRoute::AccessPoint,
            &authorization,
            &provider,
            vec!["read".into()],
            "did:web:agent.example",
            &identity,
            &request,
        )
        .unwrap();
        let ticket = ConsentTicket {
            id: uuid::Uuid::new_v4(),
            continuation_id: uuid::Uuid::new_v4(),
            binding,
            issued_at: 10,
            expires_at: 100,
            provider_digest: provider_digest(&provider).unwrap(),
            surface_digest: surface_digest(&surface).unwrap(),
            identity_strategy_digest: [5; 32],
            callback_url: "https://gateway.example/consent/callback".into(),
            code_verifier: None,
            vault_snapshot: None,
        };
        assert_eq!(validate_consent_identity(&ticket, &surface, &provider, &identity), Ok(()));
        let mut renewed = identity.clone();
        let AuthenticatedIdentity::JwtBearer { claims, .. } = &mut renewed else { unreachable!() };
        claims["scope"] = json!("read write");
        claims["exp"] = json!(200);
        claims["jti"] = json!("new-token");
        assert_eq!(validate_consent_identity(&ticket, &surface, &provider, &renewed), Ok(()));
        for (field, value) in [("iss", "https://other.example"), ("sub", "other-user"), ("scope", "read")] {
            let mut changed = identity.clone();
            let AuthenticatedIdentity::JwtBearer { claims, .. } = &mut changed else { unreachable!() };
            claims[field] = json!(value);
            assert_eq!(
                validate_consent_identity(&ticket, &surface, &provider, &changed),
                Err(ContinuationError::BindingMismatch)
            );
        }
        surface.target.endpoint = "https://other.example/api".into();
        assert_eq!(
            validate_consent_identity(&ticket, &surface, &provider, &identity),
            Err(ContinuationError::BindingMismatch)
        );
    }
}
