//! Whether a legacy consent link confirms its caller at their identity
//! provider before the vendor: only for a JWT caller of the provider's
//! `consent_confirmation` strategy whose vault key the strategy recomputes.

use chrono::Utc;
use serde_json::Value;
use tracing::{debug, warn};

use super::consent_id_token::{ConsentIdTokenExpectation, verify_consent_id_token};
use super::handlers::DelegationVaultState;
use super::{ConfirmationSignIn, ConsentConfirmBinding, OAuthState};
use crate::audit::events::DelegationFailureReason;
use crate::credential_providers::{
    ConfirmationClaims, ConfirmationStrategyRefusal, ConsentConfirmation, CredentialProvider,
};
use crate::jwt_bearer::JwtVerificationStrategyStorage;
use crate::source_auth::AuthenticatedIdentity;

/// How a consent link for one caller is minted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ConfirmDecision {
    /// The provider has no `consent_confirmation`.
    Off,
    /// Seal a confirm start state with this binding.
    Confirm(ConsentConfirmBinding),
    /// The setting is on, but this caller cannot be confirmed through it.
    Unconfirmed(Unconfirmed),
}

/// Why a caller of a provider with `consent_confirmation` is minted a link
/// that does not confirm them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unconfirmed {
    PathNotCovered,
    NotLegacyConsent,
    PepperUnset,
    NotJwtCaller,
    StrategyUnavailable,
    GatewayIssuer,
    EntraCallerNamedBySub,
    /// `id_token_principal_claim` names no caller.
    IdTokenClaimInvalid,
    /// The strategy or the ID token names the caller by `email` or another
    /// claim the person can change.
    EditableClaim,
    OtherIssuer,
    OtherPrincipalClaim,
    OtherIdentityHash,
}

/// Who a consent link is minted for.
#[derive(Clone, Copy)]
pub(crate) enum ConsentCaller<'a> {
    /// A caller of the surface's Access Point, the strategies that may
    /// confirm it, and gateway.json's `sts.mcp_issuer`.
    AccessPoint {
        identity: Option<&'a AuthenticatedIdentity>,
        strategies: Option<&'a dyn JwtVerificationStrategyStorage>,
        gateway_issuer: Option<&'a str>,
    },
    /// A request through a Transit Point or over Fabric: Transit and Fabric
    /// consent is not confirmed.
    TransitOrFabric,
}

impl<'a> ConsentCaller<'a> {
    fn identity(&self) -> Option<&'a AuthenticatedIdentity> {
        match self {
            Self::AccessPoint { identity, .. } => *identity,
            Self::TransitOrFabric => None,
        }
    }
}

/// How a consent link for `caller`, whose vault key on the surface of
/// `surface_tenant_id` is `user_identity_hash`, is minted. A caller is
/// confirmed when it reached the Access Point, the provider still uses legacy
/// consent with a configured pepper, the strategy the setting names exists,
/// the provider's tenant can reference it, the save rules still accept
/// confirming through it ([`ConsentConfirmation::claims_through`]), and the caller's
/// `iss` and principal claim are the strategy's and give that vault key. A
/// caller verified by another strategy with the same issuer and claim has the
/// same vault key, so it is confirmed too. An error reading the strategy is an
/// error, never an unconfirmed link.
pub(crate) async fn decide(
    provider: &CredentialProvider,
    caller: ConsentCaller<'_>,
    surface_tenant_id: Option<&str>,
    user_identity_hash: &str,
) -> anyhow::Result<ConfirmDecision> {
    use ConfirmDecision::Unconfirmed as No;
    let Some(confirmation) = provider
        .consent_confirmation
        .as_ref()
    else {
        return Ok(ConfirmDecision::Off);
    };
    let ConsentCaller::AccessPoint {
        identity,
        strategies,
        gateway_issuer,
    } = caller
    else {
        return Ok(No(Unconfirmed::PathNotCovered));
    };
    if !provider.uses_legacy_consent() {
        return Ok(No(Unconfirmed::NotLegacyConsent));
    }
    if !crate::identity::credential_identity::pepper_is_configured() {
        return Ok(No(Unconfirmed::PepperUnset));
    }
    let Some(caller @ AuthenticatedIdentity::JwtBearer { principal_claim, claims, .. }) = identity else {
        return Ok(No(Unconfirmed::NotJwtCaller));
    };
    let Some(strategies) = strategies else {
        return Ok(No(Unconfirmed::StrategyUnavailable));
    };
    let Some(strategy) = strategies
        .get(&confirmation.jwt_verification_strategy_id)
        .await?
        .filter(|strategy| crate::tenancy::can_reference(provider.tenant_id.as_deref(), strategy.tenant_id.as_deref()))
    else {
        return Ok(No(Unconfirmed::StrategyUnavailable));
    };
    let Some(strategy_digest) = strategy.verification_digest() else {
        return Ok(No(Unconfirmed::StrategyUnavailable));
    };
    let strategy_claim = match confirmation.claims_through(&strategy, gateway_issuer) {
        Ok(claims) => claims.strategy_claim,
        Err(refusal) => return Ok(No(unconfirmed_by(refusal))),
    };
    if claims
        .get("iss")
        .and_then(Value::as_str)
        != Some(
            strategy
                .expected_issuer
                .as_str(),
        )
    {
        return Ok(No(Unconfirmed::OtherIssuer));
    }
    if principal_claim != strategy_claim {
        return Ok(No(Unconfirmed::OtherPrincipalClaim));
    }
    if caller
        .principal_hash(surface_tenant_id)
        .as_deref()
        != Some(user_identity_hash)
    {
        return Ok(No(Unconfirmed::OtherIdentityHash));
    }
    Ok(ConfirmDecision::Confirm(ConsentConfirmBinding {
        strategy_id: strategy.id,
        strategy_digest,
        tenant_id: surface_tenant_id.map(String::from),
    }))
}

/// Why the save rules refusing a confirmation through its strategy leave a
/// caller unconfirmed.
fn unconfirmed_by(refusal: ConfirmationStrategyRefusal) -> Unconfirmed {
    match refusal {
        ConfirmationStrategyRefusal::StrategyClaim => Unconfirmed::StrategyUnavailable,
        ConfirmationStrategyRefusal::GatewayIssuer => Unconfirmed::GatewayIssuer,
        ConfirmationStrategyRefusal::EntraCallerNamedBySub => Unconfirmed::EntraCallerNamedBySub,
        ConfirmationStrategyRefusal::IdTokenClaim(_) => Unconfirmed::IdTokenClaimInvalid,
        ConfirmationStrategyRefusal::CallerNamedByEmail | ConfirmationStrategyRefusal::EditableClaim => {
            Unconfirmed::EditableClaim
        }
    }
}

/// Where the caller of a confirm start state signs in: the login client at
/// the authorization endpoint, redirected back to the confirmation redirect
/// URI, with the scope that gives the claim naming the caller.
pub(crate) struct SignIn {
    pub authorization_endpoint: url::Url,
    pub client_id: String,
    pub redirect_uri: url::Url,
    pub scope: &'static str,
}

/// The sign-in a confirm start state sealed with `binding` leads to, checked
/// again at the start POST: the provider still has `consent_confirmation`, it
/// names the sealed strategy, the provider's tenant can still reference that
/// strategy, its verification digest is the sealed one, and the authorization
/// endpoint passes the save rules without its host being resolved. A start
/// POST that fails one is refused, never sent to the vendor.
pub(crate) async fn sign_in(
    provider: &CredentialProvider,
    binding: &ConsentConfirmBinding,
    strategies: &dyn JwtVerificationStrategyStorage,
    gateway_base_url: &str,
) -> Result<SignIn, DelegationFailureReason> {
    let confirmation = provider
        .consent_confirmation
        .as_ref()
        .filter(|confirmation| confirmation.jwt_verification_strategy_id == binding.strategy_id)
        .ok_or(DelegationFailureReason::ConsentStateInvalid)?;
    let strategy = strategies
        .get(&binding.strategy_id)
        .await
        .map_err(|_| DelegationFailureReason::CredentialsUnavailable)?
        .filter(|strategy| {
            crate::tenancy::can_reference(provider.tenant_id.as_deref(), strategy.tenant_id.as_deref())
                && strategy
                    .verification_digest()
                    .as_deref()
                    == Some(
                        binding
                            .strategy_digest
                            .as_str(),
                    )
        })
        .ok_or(DelegationFailureReason::ConsentStateInvalid)?;
    let strategy_claim = strategy
        .principal_claim_name()
        .map_err(|_| DelegationFailureReason::ConsentStateInvalid)?;
    let authorization_endpoint = confirmation
        .authorization_endpoint_url_unresolved()
        .map_err(|_| DelegationFailureReason::AuthorizationUrlInvalid)?;
    let redirect_uri = url::Url::parse(&provider.consent_confirmation_redirect_uri(gateway_base_url))
        .map_err(|_| DelegationFailureReason::RedirectUriInvalid)?;
    Ok(SignIn {
        authorization_endpoint,
        client_id: confirmation.client_id.clone(),
        redirect_uri,
        scope: sign_in_scope(
            confirmation
                .id_token_principal_claim
                .as_deref()
                .unwrap_or(strategy_claim),
        ),
    })
}

/// `openid` alone gives `sub`, the only claim naming the caller it
/// guarantees; an ID token naming the caller by any other claim needs
/// `profile` too.
fn sign_in_scope(id_token_claim: &str) -> &'static str {
    if id_token_claim == crate::jwt_bearer::models::DEFAULT_PRINCIPAL_CLAIM {
        "openid"
    } else {
        "openid profile"
    }
}

/// The provider's `consent_confirmation` when it still confirms through the
/// strategy `binding` was sealed with.
pub(crate) fn confirmation_for<'a>(
    provider: &'a CredentialProvider,
    binding: &ConsentConfirmBinding,
) -> Option<&'a ConsentConfirmation> {
    provider
        .consent_confirmation
        .as_ref()
        .filter(|confirmation| confirmation.jwt_verification_strategy_id == binding.strategy_id)
}

/// Confirm the caller a confirmation state `sealed` was minted for, from the
/// identity provider's `code` and `iss`. The sealed strategy is reloaded and
/// must be one the provider's tenant can reference, with the sealed digest,
/// that the save rules still accept
/// ([`ConsentConfirmation::claims_through`]). The code is exchanged at the
/// login client's token endpoint with PKCE, and the ID token is verified by
/// that strategy for the login client, with the sealed nonce and issued no
/// earlier than the sign-in began. The vault key recomputed from it, under
/// the strategy's claim name, must be the sealed one. Nothing of the ID token
/// is logged or audited.
pub(crate) async fn confirm_caller(
    vault: &DelegationVaultState,
    provider: &CredentialProvider,
    confirmation: &ConsentConfirmation,
    sealed: &OAuthState,
    sign_in: &ConfirmationSignIn,
    code: &str,
    iss: Option<&str>,
) -> Result<(), DelegationFailureReason> {
    let binding = &sign_in.binding;
    let strategy = vault
        .identity_strategies
        .get(&binding.strategy_id)
        .await
        .map_err(|_| DelegationFailureReason::CredentialsUnavailable)?
        .filter(|strategy| {
            crate::tenancy::can_reference(provider.tenant_id.as_deref(), strategy.tenant_id.as_deref())
                && strategy
                    .verification_digest()
                    .as_deref()
                    == Some(
                        binding
                            .strategy_digest
                            .as_str(),
                    )
        })
        .ok_or(DelegationFailureReason::ConsentStateInvalid)?;
    let claims = confirmation
        .claims_through(
            &strategy,
            vault
                .gateway_mcp_issuer
                .as_deref(),
        )
        .map_err(|_| DelegationFailureReason::ConsentStateInvalid)?;
    // RFC 9207: an `iss` sent must be the strategy's; none is accepted, since no metadata is fetched here.
    if iss.is_some_and(|iss| iss != strategy.expected_issuer) {
        return Err(DelegationFailureReason::IssMismatch);
    }
    let redirect_uri = url::Url::parse(&provider.consent_confirmation_redirect_uri(&vault.gateway_base_url))
        .map_err(|_| DelegationFailureReason::RedirectUriInvalid)?;
    let code_verifier = sealed
        .code_verifier
        .as_deref()
        .ok_or(DelegationFailureReason::ConsentStateInvalid)?;
    let id_token = exchange_code(vault, provider, confirmation, code, code_verifier, &redirect_uri).await?;
    let expected = ConsentIdTokenExpectation {
        client_id: &confirmation.client_id,
        principal_claim: claims.id_token_claim,
        nonce: &sign_in.nonce,
        issued_at: unix_seconds(sign_in.issued_at),
    };
    let verified = verify_consent_id_token(&vault.verifier, &strategy, &expected, &id_token, unix_seconds(Utc::now()))
        .await
        .map_err(|_| DelegationFailureReason::ConsentIdentityMissing)?;
    let confirmed = confirmed_identity_hash(verified, claims, &strategy.id, binding.tenant_id.as_deref())
        .ok_or(DelegationFailureReason::ConsentIdentityMissing)?;
    if confirmed != sealed.user_identity_hash {
        return Err(DelegationFailureReason::ConsentIdentityMismatch);
    }
    Ok(())
}

fn unix_seconds(at: chrono::DateTime<Utc>) -> u64 {
    u64::try_from(at.timestamp()).unwrap_or_default()
}

/// The vault key of the caller an ID token's `claims` name: the value of the
/// ID token's claim hashed under the strategy's claim name, as the caller's
/// access token is ([`AuthenticatedIdentity::principal_hash`]).
fn confirmed_identity_hash(
    mut claims: Value,
    ConfirmationClaims { strategy_claim, id_token_claim }: ConfirmationClaims<'_>,
    strategy_id: &str,
    tenant_id: Option<&str>,
) -> Option<String> {
    let value = claims
        .get(id_token_claim)?
        .as_str()?
        .to_string();
    claims
        .as_object_mut()?
        .insert(strategy_claim.to_string(), Value::String(value.clone()));
    AuthenticatedIdentity::JwtBearer {
        subject: value,
        principal_claim: strategy_claim.to_string(),
        claims,
        strategy_id: Some(strategy_id.to_string()),
    }
    .principal_hash(tenant_id)
}

/// The ID token the login client's token endpoint answers `code` with,
/// exchanged through the provider egress with the login client's id and
/// secret in the form and the PKCE verifier, the answer read up to
/// [`MAX_TOKEN_RESPONSE_BYTES`](super::oauth::MAX_TOKEN_RESPONSE_BYTES)
/// within the egress timeout.
async fn exchange_code(
    vault: &DelegationVaultState,
    provider: &CredentialProvider,
    confirmation: &ConsentConfirmation,
    code: &str,
    code_verifier: &str,
    redirect_uri: &url::Url,
) -> Result<zeroize::Zeroizing<String>, DelegationFailureReason> {
    if code.len() > 4096
        || code
            .chars()
            .any(char::is_control)
    {
        return Err(DelegationFailureReason::ConsentResponseInvalid);
    }
    let egress = &vault.provider_egress;
    let endpoint = confirmation
        .token_endpoint
        .as_str();
    egress
        .check_token_endpoint(&provider.provider_id, endpoint)
        .map_err(|_| DelegationFailureReason::TokenExchangeFailed)?;
    let client_secret = zeroize::Zeroizing::new(
        super::oauth::resolve_secret(
            provider,
            &vault.secrets_store,
            &confirmation.client_secret_secret_ref,
            super::oauth::isolation_mode(),
        )
        .await
        .map_err(|_| DelegationFailureReason::CredentialsUnavailable)?,
    );
    let exchange = async {
        let (client, url) = egress
            .pinned_client(endpoint)
            .await
            .map_err(|_| DelegationFailureReason::TokenExchangeFailed)?;
        let answer = super::oauth::post_token_request(
            &client,
            url.as_str(),
            &[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", redirect_uri.as_str()),
                (
                    "client_id",
                    confirmation
                        .client_id
                        .as_str(),
                ),
                ("client_secret", client_secret.as_str()),
                ("code_verifier", code_verifier),
            ],
            None,
        )
        .await
        .map_err(|failure| {
            warn!(
                target: "credential_delegation",
                provider_id = %provider.provider_id,
                cause = %failure,
                "Consent confirmation token request failed"
            );
            DelegationFailureReason::TokenExchangeFailed
        })?;
        if !answer.status.is_success() {
            warn!(
                target: "credential_delegation",
                provider_id = %provider.provider_id,
                status = %answer.status,
                reason = %super::oauth::token_error_code(&String::from_utf8_lossy(&answer.body)),
                "Consent confirmation token exchange failed"
            );
            return Err(DelegationFailureReason::TokenExchangeFailed);
        }
        #[derive(serde::Deserialize)]
        struct IdTokenAnswer {
            id_token: Option<String>,
        }
        serde_json::from_slice::<IdTokenAnswer>(&answer.body)
            .ok()
            .and_then(|answer| answer.id_token)
            .filter(|id_token| !id_token.is_empty())
            .map(zeroize::Zeroizing::new)
            .ok_or(DelegationFailureReason::ConsentIdentityMissing)
    };
    tokio::time::timeout(egress.timeout, exchange)
        .await
        .map_err(|_| DelegationFailureReason::TokenExchangeFailed)?
}

/// Log at debug, once per provider, surface and reason, why a caller of a
/// provider with `consent_confirmation` was minted a link that does not
/// confirm them, or that a confirmed caller was verified by another strategy
/// than the one that confirms them. Nothing about the caller is logged.
pub(crate) fn note(
    provider: &CredentialProvider,
    surface_id: &str,
    decision: &ConfirmDecision,
    caller: ConsentCaller<'_>,
) {
    match decision {
        ConfirmDecision::Off => {}
        ConfirmDecision::Unconfirmed(reason) => {
            if first_note(&provider.id, surface_id, &format!("{reason:?}")) {
                debug!(
                    target: "credential_delegation",
                    provider_id = %provider.provider_id,
                    surface_id = %surface_id,
                    reason = ?reason,
                    "Consent link minted without confirming its caller at their identity provider"
                );
            }
        }
        ConfirmDecision::Confirm(binding) => {
            if verified_by_another_strategy(caller.identity(), binding)
                && first_note(&provider.id, surface_id, "verified_by_another_strategy")
            {
                debug!(
                    target: "credential_delegation",
                    provider_id = %provider.provider_id,
                    surface_id = %surface_id,
                    "Consent confirmation for a caller verified by another strategy with the same issuer and \
                     principal claim"
                );
            }
        }
    }
}

/// Whether a Caller Context strategy other than the one `binding` confirms
/// against verified `identity`. A caller no strategy verified, such as one of
/// the Resource Server, was verified by no other strategy.
fn verified_by_another_strategy(
    identity: Option<&AuthenticatedIdentity>,
    binding: &ConsentConfirmBinding,
) -> bool {
    matches!(identity, Some(AuthenticatedIdentity::JwtBearer { strategy_id: Some(strategy_id), .. })
        if *strategy_id != binding.strategy_id)
}

/// Whether this is the first note of `reason` for this provider and surface.
fn first_note(
    provider_id: &str,
    surface_id: &str,
    reason: &str,
) -> bool {
    static NOTED: std::sync::LazyLock<dashmap::DashSet<(String, String, String)>> =
        std::sync::LazyLock::new(dashmap::DashSet::new);
    NOTED.insert((provider_id.to_string(), surface_id.to_string(), reason.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt_bearer::models::{JwksSource, JwtVerificationStrategy};
    use serde_json::json;

    const ISSUER: &str = "https://idp.example";
    const TENANT: Option<&str> = Some("tenant-a");

    /// Answers a lookup of its one strategy by id, or fails every lookup.
    struct Strategies {
        strategy: Option<JwtVerificationStrategy>,
        fails: bool,
    }

    #[async_trait::async_trait]
    impl JwtVerificationStrategyStorage for Strategies {
        async fn create(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            unimplemented!()
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            if self.fails {
                anyhow::bail!("strategy store unavailable");
            }
            Ok(self
                .strategy
                .clone()
                .filter(|strategy| strategy.id == id))
        }
        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            unimplemented!()
        }
        async fn update(
            &self,
            _strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
    }

    fn strategy(
        expected_issuer: &str,
        principal_claim: Option<&str>,
    ) -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: "confirming".to_string(),
            tenant_id: TENANT.map(String::from),
            name: "Callers".to_string(),
            expected_issuer: expected_issuer.to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: format!("{expected_issuer}/jwks"),
            },
            principal_claim: principal_claim.map(String::from),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn stored(strategy: JwtVerificationStrategy) -> Strategies {
        Strategies {
            strategy: Some(strategy),
            fails: false,
        }
    }

    fn provider(confirmation: bool) -> CredentialProvider {
        let mut provider: CredentialProvider = serde_json::from_value(json!({
            "id": "cp", "name": "GitHub", "provider_id": "github", "tenant_id": TENANT,
            "provider_type": "oauth2_authorization_code",
            "created_at": "2026-11-01T00:00:00Z", "updated_at": "2026-11-01T00:00:00Z"
        }))
        .unwrap();
        provider.consent_confirmation = confirmation.then(|| {
            serde_json::from_value(json!({
                "client_id": "login-client", "client_secret_secret_ref": "LOGIN_SECRET",
                "authorization_endpoint": "https://idp.example/authorize",
                "token_endpoint": "https://idp.example/token",
                "jwt_verification_strategy_id": "confirming"
            }))
            .unwrap()
        });
        provider
    }

    fn caller(
        issuer: &str,
        principal_claim: &str,
        strategy_id: Option<&str>,
    ) -> AuthenticatedIdentity {
        AuthenticatedIdentity::JwtBearer {
            subject: "alice".to_string(),
            principal_claim: principal_claim.to_string(),
            claims: json!({"iss": issuer, principal_claim: "alice"}),
            strategy_id: strategy_id.map(String::from),
            verification: Default::default(),
        }
    }

    fn hash_of(identity: &AuthenticatedIdentity) -> String {
        identity
            .principal_hash(TENANT)
            .unwrap()
    }

    const GATEWAY_ISSUER: &str = "https://gateway.example/oauth2/mcp";

    /// [`decide`] for a caller of the Access Point, on a gateway whose STS
    /// issuer is [`GATEWAY_ISSUER`].
    async fn decide_with(
        provider: &CredentialProvider,
        identity: Option<&AuthenticatedIdentity>,
        surface_tenant_id: Option<&str>,
        user_identity_hash: &str,
        strategies: Option<&dyn JwtVerificationStrategyStorage>,
    ) -> anyhow::Result<ConfirmDecision> {
        let caller = ConsentCaller::AccessPoint {
            identity,
            strategies,
            gateway_issuer: Some(GATEWAY_ISSUER),
        };
        decide(provider, caller, surface_tenant_id, user_identity_hash).await
    }

    async fn decide_for(
        provider: &CredentialProvider,
        identity: Option<&AuthenticatedIdentity>,
        strategies: Option<&dyn JwtVerificationStrategyStorage>,
    ) -> ConfirmDecision {
        let alice = caller(ISSUER, "sub", Some("confirming"));
        decide_with(provider, identity, TENANT, &hash_of(&alice), strategies)
            .await
            .unwrap()
    }

    /// A caller holding this gateway's own STS token has no identity provider
    /// to sign in at, so a strategy that expects the gateway's issuer, found
    /// by an edit after the save, confirms nobody.
    #[tokio::test]
    async fn a_strategy_for_the_gateways_own_issuer_confirms_nobody() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        for issuer in [GATEWAY_ISSUER, "https://gateway.example/oauth2/mcp/"] {
            let own = caller(issuer, "sub", None);
            assert_eq!(
                decide_with(&provider(true), Some(&own), TENANT, &hash_of(&own), Some(&stored(strategy(issuer, None))))
                    .await
                    .unwrap(),
                ConfirmDecision::Unconfirmed(Unconfirmed::GatewayIssuer),
                "{issuer}"
            );
        }
        let own = caller(GATEWAY_ISSUER, "sub", None);
        let without_sts = ConsentCaller::AccessPoint {
            identity: Some(&own),
            strategies: Some(&stored(strategy(GATEWAY_ISSUER, None))),
            gateway_issuer: None,
        };
        assert!(
            matches!(
                decide(&provider(true), without_sts, TENANT, &hash_of(&own))
                    .await
                    .unwrap(),
                ConfirmDecision::Confirm(_)
            ),
            "a gateway with no STS issuer has none to refuse"
        );
    }

    /// Transit and Fabric consent is not confirmed, whoever the caller is.
    #[tokio::test]
    async fn a_transit_or_fabric_caller_is_never_confirmed() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let alice = caller(ISSUER, "sub", Some("confirming"));
        assert_eq!(
            decide(&provider(true), ConsentCaller::TransitOrFabric, TENANT, &hash_of(&alice))
                .await
                .unwrap(),
            ConfirmDecision::Unconfirmed(Unconfirmed::PathNotCovered)
        );
        assert_eq!(
            decide(&provider(false), ConsentCaller::TransitOrFabric, TENANT, &hash_of(&alice))
                .await
                .unwrap(),
            ConfirmDecision::Off,
            "a provider without the setting is minted as before"
        );
    }

    #[test]
    fn only_a_caller_another_strategy_verified_counts_as_verified_by_another() {
        let binding = ConsentConfirmBinding {
            strategy_id: "confirming".to_string(),
            strategy_digest: "ab".repeat(32),
            tenant_id: None,
        };
        let api_key = AuthenticatedIdentity::ApiKey {
            key_name: "key".to_string(),
            provider_agent_id: None,
        };
        for (verified_by, expected) in [(Some("another-strategy"), true), (Some("confirming"), false), (None, false)] {
            assert_eq!(
                verified_by_another_strategy(Some(&caller(ISSUER, "sub", verified_by)), &binding),
                expected,
                "verified by {verified_by:?}"
            );
        }
        assert!(!verified_by_another_strategy(Some(&api_key), &binding));
        assert!(!verified_by_another_strategy(None, &binding));
    }

    #[tokio::test]
    async fn a_caller_of_the_confirming_strategy_is_confirmed_against_it() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let strategy = strategy(ISSUER, None);
        let strategies = stored(strategy.clone());
        let alice = caller(ISSUER, "sub", Some("confirming"));
        assert_eq!(
            decide_for(&provider(true), Some(&alice), Some(&strategies)).await,
            ConfirmDecision::Confirm(ConsentConfirmBinding {
                strategy_id: "confirming".to_string(),
                strategy_digest: strategy
                    .verification_digest()
                    .unwrap(),
                tenant_id: Some("tenant-a".to_string()),
            })
        );

        let oid = self::strategy(ISSUER, Some("oid"));
        let named_by_oid = caller(ISSUER, "oid", Some("confirming"));
        assert!(matches!(
            decide_with(&provider(true), Some(&named_by_oid), TENANT, &hash_of(&named_by_oid), Some(&stored(oid)))
                .await
                .unwrap(),
            ConfirmDecision::Confirm(_)
        ));
    }

    /// The vault key depends on the issuer and the principal claim, not on
    /// which strategy verified the token, so a caller verified by another
    /// strategy, or by none, with the same issuer and claim holds the same
    /// grants and is confirmed alike.
    #[tokio::test]
    async fn a_caller_with_the_strategys_issuer_and_claim_is_confirmed_whatever_verified_it() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let strategies = stored(strategy(ISSUER, None));
        for verified_by in [Some("another-strategy"), None] {
            let alice = caller(ISSUER, "sub", verified_by);
            assert!(
                matches!(
                    decide_for(&provider(true), Some(&alice), Some(&strategies)).await,
                    ConfirmDecision::Confirm(ConsentConfirmBinding { ref strategy_id, .. }) if strategy_id == "confirming"
                ),
                "verified by {verified_by:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_provider_without_the_setting_is_minted_as_before() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let alice = caller(ISSUER, "sub", Some("confirming"));
        let failing = Strategies { strategy: None, fails: true };
        assert_eq!(decide_for(&provider(false), Some(&alice), Some(&failing)).await, ConfirmDecision::Off);
        assert_eq!(decide_for(&provider(false), None, None).await, ConfirmDecision::Off);
    }

    #[tokio::test]
    async fn a_caller_the_setting_cannot_confirm_is_minted_unconfirmed() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let strategies = stored(strategy(ISSUER, None));
        let alice = caller(ISSUER, "sub", Some("confirming"));
        let api_key = AuthenticatedIdentity::ApiKey {
            key_name: "key".to_string(),
            provider_agent_id: None,
        };
        let mut other_tenant = strategy(ISSUER, None);
        other_tenant.tenant_id = Some("tenant-b".to_string());
        let mut renamed = strategy(ISSUER, None);
        renamed.id = "another-strategy".to_string();
        let mut external = provider(true);
        external.issuer = Some("https://vendor.example".to_string());
        let mut client_credentials = provider(true);
        client_credentials.provider_type = crate::credential_providers::CredentialProviderType::OAuth2ClientCredentials;
        let other_issuer = caller("https://other.example", "sub", Some("confirming"));
        let other_claim = caller(ISSUER, "email", Some("confirming"));

        type Case<'a> = (
            &'a str,
            &'a CredentialProvider,
            Option<&'a AuthenticatedIdentity>,
            Option<&'a dyn JwtVerificationStrategyStorage>,
            Unconfirmed,
        );
        let cases: [Case; 11] = [
            ("an external consent provider", &external, Some(&alice), Some(&strategies), Unconfirmed::NotLegacyConsent),
            (
                "a client credentials provider",
                &client_credentials,
                Some(&alice),
                Some(&strategies),
                Unconfirmed::NotLegacyConsent,
            ),
            ("an API key caller", &provider(true), Some(&api_key), Some(&strategies), Unconfirmed::NotJwtCaller),
            ("no caller", &provider(true), None, Some(&strategies), Unconfirmed::NotJwtCaller),
            ("no strategy store", &provider(true), Some(&alice), None, Unconfirmed::StrategyUnavailable),
            (
                "a deleted strategy",
                &provider(true),
                Some(&alice),
                Some(&Strategies { strategy: None, fails: false }),
                Unconfirmed::StrategyUnavailable,
            ),
            (
                "another strategy id",
                &provider(true),
                Some(&alice),
                Some(&stored(renamed)),
                Unconfirmed::StrategyUnavailable,
            ),
            (
                "a strategy of another tenant",
                &provider(true),
                Some(&alice),
                Some(&stored(other_tenant)),
                Unconfirmed::StrategyUnavailable,
            ),
            (
                "a strategy whose claim names nobody",
                &provider(true),
                Some(&alice),
                Some(&stored(strategy(ISSUER, Some("iss")))),
                Unconfirmed::StrategyUnavailable,
            ),
            ("another issuer", &provider(true), Some(&other_issuer), Some(&strategies), Unconfirmed::OtherIssuer),
            (
                "another principal claim",
                &provider(true),
                Some(&other_claim),
                Some(&strategies),
                Unconfirmed::OtherPrincipalClaim,
            ),
        ];
        for (case, provider, identity, strategies, reason) in cases {
            assert_eq!(
                decide_for(provider, identity, strategies).await,
                ConfirmDecision::Unconfirmed(reason),
                "{case}"
            );
        }

        assert_eq!(
            decide_with(&provider(true), Some(&alice), TENANT, "another-hash", Some(&strategies))
                .await
                .unwrap(),
            ConfirmDecision::Unconfirmed(Unconfirmed::OtherIdentityHash)
        );
        assert_eq!(
            decide_with(&provider(true), Some(&alice), Some("tenant-b"), &hash_of(&alice), Some(&strategies))
                .await
                .unwrap(),
            ConfirmDecision::Unconfirmed(Unconfirmed::OtherIdentityHash),
            "a vault key of another surface tenant"
        );
    }

    /// A strategy's issuer can change after the setting was saved, so the
    /// Entra rule the save checked is checked again at mint.
    #[tokio::test]
    async fn a_strategy_edited_to_name_an_entra_caller_by_sub_confirms_nobody() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let entra = "https://login.microsoftonline.com/tenant/v2.0";
        let alice = caller(entra, "sub", Some("confirming"));
        assert_eq!(
            decide_with(&provider(true), Some(&alice), TENANT, &hash_of(&alice), Some(&stored(strategy(entra, None))))
                .await
                .unwrap(),
            ConfirmDecision::Unconfirmed(Unconfirmed::EntraCallerNamedBySub)
        );
        let mut naming_sub_in_the_id_token = provider(true);
        naming_sub_in_the_id_token
            .consent_confirmation
            .as_mut()
            .unwrap()
            .id_token_principal_claim = Some("sub".to_string());
        let by_oid = caller(entra, "oid", Some("confirming"));
        let oid_strategy = stored(strategy(entra, Some("oid")));
        assert_eq!(
            decide_with(&naming_sub_in_the_id_token, Some(&by_oid), TENANT, &hash_of(&by_oid), Some(&oid_strategy))
                .await
                .unwrap(),
            ConfirmDecision::Unconfirmed(Unconfirmed::EntraCallerNamedBySub)
        );
        assert!(matches!(
            decide_with(&provider(true), Some(&by_oid), TENANT, &hash_of(&by_oid), Some(&oid_strategy))
                .await
                .unwrap(),
            ConfirmDecision::Confirm(_)
        ));
    }

    /// Mint refuses through the save rules too: a setting edited to name the
    /// caller by a claim the save rules refuse confirms nobody.
    #[tokio::test]
    async fn a_setting_the_save_rules_now_refuse_confirms_nobody() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let alice = caller(ISSUER, "sub", Some("confirming"));
        let strategies = stored(strategy(ISSUER, None));
        for (claim, reason) in [
            ("preferred_username", Unconfirmed::EditableClaim),
            ("email", Unconfirmed::EditableClaim),
            ("iss", Unconfirmed::IdTokenClaimInvalid),
        ] {
            let mut edited = provider(true);
            edited
                .consent_confirmation
                .as_mut()
                .unwrap()
                .id_token_principal_claim = Some(claim.to_string());
            assert_eq!(
                decide_for(&edited, Some(&alice), Some(&strategies)).await,
                ConfirmDecision::Unconfirmed(reason),
                "{claim}"
            );
        }
    }

    #[tokio::test]
    async fn without_a_configured_pepper_nobody_is_confirmed() {
        crate::identity::credential_identity::configure_pepper_for_tests(false);
        let alice = caller(ISSUER, "sub", Some("confirming"));
        assert_eq!(
            decide_for(&provider(true), Some(&alice), Some(&stored(strategy(ISSUER, None)))).await,
            ConfirmDecision::Unconfirmed(Unconfirmed::PepperUnset)
        );
    }

    #[tokio::test]
    async fn a_strategy_store_error_mints_no_link() {
        crate::identity::credential_identity::configure_pepper_for_tests(true);
        let alice = caller(ISSUER, "sub", Some("confirming"));
        let failing = Strategies { strategy: None, fails: true };
        assert!(
            decide_with(&provider(true), Some(&alice), TENANT, &hash_of(&alice), Some(&failing))
                .await
                .is_err()
        );
    }

    /// The vault key recomputed from an ID token is the one the Access Point
    /// computed from the same person's access token: the value comes from the
    /// ID token's claim and is hashed under the strategy's claim name, whatever
    /// else the ID token says.
    #[test]
    fn an_id_token_gives_the_vault_key_of_the_same_persons_access_token() {
        let access_token = |claim: &str, value: &str| {
            AuthenticatedIdentity::JwtBearer {
                subject: value.to_string(),
                principal_claim: claim.to_string(),
                claims: json!({"iss": ISSUER, claim: value, "scp": "read"}),
                strategy_id: Some("confirming".to_string()),
            }
            .principal_hash(TENANT)
        };
        let id_token = |claims: Value, strategy_claim: &str, id_token_claim: &str| {
            confirmed_identity_hash(claims, ConfirmationClaims { strategy_claim, id_token_claim }, "confirming", TENANT)
        };
        assert_eq!(
            id_token(json!({"iss": ISSUER, "sub": "alice", "nonce": "n"}), "sub", "sub"),
            access_token("sub", "alice")
        );
        assert_eq!(
            id_token(json!({"iss": ISSUER, "sub": "pairwise", "oid": "person-1"}), "oid", "oid"),
            access_token("oid", "person-1"),
            "an Entra caller named by oid, whose sub differs per application"
        );
        assert_eq!(
            id_token(json!({"iss": ISSUER, "sub": "00u1", "uid": "alice"}), "sub", "uid"),
            access_token("sub", "alice"),
            "the ID token's uid hashed as the access token's sub"
        );
        assert_ne!(
            id_token(json!({"iss": ISSUER, "sub": "00u1", "uid": "alice"}), "sub", "uid"),
            access_token("uid", "alice"),
            "the hash takes the strategy's claim name, not the ID token's"
        );
        assert_ne!(id_token(json!({"iss": ISSUER, "sub": "mallory"}), "sub", "sub"), access_token("sub", "alice"));
        assert_eq!(id_token(json!({"iss": ISSUER, "sub": 7}), "sub", "sub"), None);
        assert_eq!(id_token(json!({"sub": "alice"}), "sub", "sub"), None, "no issuer");
    }

    #[test]
    fn each_reason_is_noted_once_per_provider_and_surface() {
        let provider_id = uuid::Uuid::new_v4().to_string();
        assert!(first_note(&provider_id, "surface-1", "NotJwtCaller"));
        assert!(!first_note(&provider_id, "surface-1", "NotJwtCaller"));
        assert!(first_note(&provider_id, "surface-2", "NotJwtCaller"));
        assert!(first_note(&provider_id, "surface-1", "OtherIssuer"));
        assert!(!first_note(&provider_id, "surface-1", "OtherIssuer"));
    }
}
