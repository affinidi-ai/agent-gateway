//! Whether a legacy consent link confirms its caller at their identity
//! provider before the vendor: only for a JWT caller of the provider's
//! `consent_confirmation` strategy whose vault key the strategy recomputes.

use serde_json::Value;
use tracing::debug;

use super::ConsentConfirmBinding;
use crate::audit::events::DelegationFailureReason;
use crate::credential_providers::CredentialProvider;
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
/// the provider's tenant can reference it, it expects no issuer of this
/// gateway's own STS and names no Entra caller by `sub`, and the caller's
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
    let (Ok(strategy_claim), Some(strategy_digest)) = (strategy.principal_claim_name(), strategy.verification_digest())
    else {
        return Ok(No(Unconfirmed::StrategyUnavailable));
    };
    if crate::credential_providers::is_gateway_issuer(&strategy.expected_issuer, gateway_issuer) {
        return Ok(No(Unconfirmed::GatewayIssuer));
    }
    if confirmation.names_entra_caller_by_sub(&strategy.expected_issuer, strategy_claim) {
        return Ok(No(Unconfirmed::EntraCallerNamedBySub));
    }
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
