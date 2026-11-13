//! How long a person's consent to a credential provider may be used: the time
//! limits a binding, its credential provider and `[credential_policy]` set, and
//! whether a stored consent is still within them.

use chrono::{DateTime, Duration, Utc};
use tracing::{info, warn};

use super::DelegationToken;
use super::audit::{self, DelegationAuditAction, DelegationAuditEvent};
use super::grants::DelegatedGrant;
use super::storage::{DelegationVaultStorage, access_token_fingerprint};
use crate::config::credential_policy::{CredentialPolicyConfig, credential_policy};
use crate::credential_providers::{CredentialProvider, CredentialProviderType};

/// How far ahead of this gateway's clock a consent time may lie, as another
/// node's clock may run, before a consent under a limit counts as ended.
const CLOCK_SKEW_SECS: i64 = 300;

/// Why a caller is asked for consent again: the consent ended at its time
/// limit, and the stored credential was removed.
pub const CONSENT_EXPIRED: &str = "consent_expired";

/// Why a caller is asked for consent again: the consent has not ended, but
/// the binding serving the request needs a newer one.
pub const CONSENT_TOO_OLD: &str = "consent_too_old";

/// The time limits on the consents one binding of one credential provider uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ConsentLimits {
    /// The connection's limit: the provider's, else the gateway default, else
    /// the ceiling, and never above the ceiling.
    connection_secs: Option<u64>,
    /// The binding's own limit, never above the ceiling.
    binding_secs: Option<u64>,
}

/// Whether a stored consent may still be used through a binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentAge {
    /// Within every limit, or under none.
    Current,
    /// Not ended, but older than this binding allows: the binding asks for
    /// consent again, and the stored credential is kept for other bindings.
    TooOldForBinding,
    /// Past its end, for every binding: the stored credential is removed.
    Ended,
}

impl ConsentLimits {
    /// The limits of a binding that sets `binding_secs` on a provider that sets
    /// `provider_secs`, under the gateway's `[credential_policy]`.
    pub fn of(
        binding_secs: Option<u64>,
        provider_secs: Option<u64>,
    ) -> Self {
        Self::under(binding_secs, provider_secs, credential_policy())
    }

    /// [`Self::of`], under `policy`.
    pub fn under(
        binding_secs: Option<u64>,
        provider_secs: Option<u64>,
        policy: &CredentialPolicyConfig,
    ) -> Self {
        let capped = |secs: u64| {
            policy
                .max_consent_age_ceiling_secs
                .map_or(secs, |ceiling| secs.min(ceiling))
        };
        Self {
            connection_secs: provider_secs
                .or(policy.default_max_consent_age_secs)
                .or(policy.max_consent_age_ceiling_secs)
                .map(capped),
            binding_secs: binding_secs.map(capped),
        }
    }

    /// The limits on the consents given to `provider`, whichever binding uses
    /// them: its own and the gateway's when a person consents to it. Any other
    /// provider, and one that is gone, has none, so only the end stored with
    /// a consent ends it.
    pub fn of_provider(provider: Option<&CredentialProvider>) -> Self {
        match provider {
            Some(provider) if provider.provider_type == CredentialProviderType::OAuth2AuthorizationCode => {
                Self::of(None, provider.max_consent_age_secs)
            }
            _ => Self::default(),
        }
    }

    /// Seconds a consent given now through the binding may be used: the
    /// shorter of the binding's limit and the connection's.
    pub fn lifetime_secs(&self) -> Option<u64> {
        earlier(self.binding_secs, self.connection_secs)
    }

    /// When a consent given at `granted_at` through the binding ends, which is
    /// what the person is told and what is stored with the credential.
    pub fn expires_at(
        &self,
        granted_at: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        end_of(granted_at, self.lifetime_secs())
    }

    /// When a stored consent ends for every binding: the earlier of the end
    /// stored with it and its consent time plus the connection's limit as set
    /// now. A limit shortened since the consent ends it sooner; one lengthened
    /// never moves the stored end.
    pub fn ends_at(
        &self,
        granted_at: DateTime<Utc>,
        stored_end: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        let by_connection = self
            .connection_secs
            .map(|secs| after(granted_at, secs));
        earlier(stored_end, by_connection)
    }

    /// When a stored consent stops serving this binding: [`Self::ends_at`], or
    /// its consent time plus the binding's own limit when that comes first.
    /// A grant by binding has one binding, so this is when its consent ends.
    pub fn ends_for_binding_at(
        &self,
        granted_at: DateTime<Utc>,
        stored_end: Option<DateTime<Utc>>,
    ) -> Option<DateTime<Utc>> {
        earlier(self.ends_at(granted_at, stored_end), self.binding_end(granted_at))
    }

    fn binding_end(
        &self,
        granted_at: DateTime<Utc>,
    ) -> Option<DateTime<Utc>> {
        self.binding_secs
            .map(|secs| after(granted_at, secs))
    }

    /// Whether the consent given at `granted_at`, stored with the end
    /// `stored_end`, may be used through the binding at `now`. A consent time
    /// further ahead of `now` than clocks may differ counts as ended whenever
    /// a limit applies.
    pub fn judge(
        &self,
        granted_at: DateTime<Utc>,
        stored_end: Option<DateTime<Utc>>,
        now: DateTime<Utc>,
    ) -> ConsentAge {
        let end = self.ends_at(granted_at, stored_end);
        let binding_end = self.binding_end(granted_at);
        if end.is_none() && binding_end.is_none() {
            return ConsentAge::Current;
        }
        if granted_at > now + Duration::seconds(CLOCK_SKEW_SECS) || end.is_some_and(|end| now >= end) {
            return ConsentAge::Ended;
        }
        if binding_end.is_some_and(|end| now >= end) {
            return ConsentAge::TooOldForBinding;
        }
        ConsentAge::Current
    }
}

/// When a consent given at `granted_at`, to be used for `lifetime_secs`, ends;
/// `None` under no limit.
pub fn end_of(
    granted_at: DateTime<Utc>,
    lifetime_secs: Option<u64>,
) -> Option<DateTime<Utc>> {
    lifetime_secs.map(|secs| after(granted_at, secs))
}

/// Remove the agent-keyed `token`, whose consent ended at `ended_at`, while
/// the vault still holds it with the access token read, and audit the expiry
/// as `consent_expired`, never as a revocation: `source` says what found it
/// ended, and `describe` adds what the caller knows of the request. Whether it
/// was removed: a token refreshed or removed since is left to the next
/// request, and a removal that fails is logged, so one expiry is audited once.
pub async fn end_consent(
    vault: &dyn DelegationVaultStorage,
    token: &DelegationToken,
    ended_at: Option<DateTime<Utc>>,
    source: &'static str,
    surface_id: Option<&str>,
    describe: impl FnOnce(&mut DelegationAuditEvent),
) -> bool {
    let surface_variant = crate::observability::policy_audit::current_request_variant();
    match vault
        .delete_token_holding(&token.id, &access_token_fingerprint(&token.access_token))
        .await
    {
        Ok(true) => {}
        Ok(false) => return false,
        Err(error) => {
            warn!(
                target: "credential_delegation",
                surface_variant = surface_variant.as_deref(),
                token_id = %token.id,
                error = %error,
                "Failed to remove a delegation token whose consent ended at its time limit"
            );
            return false;
        }
    }
    info!(
        target: "credential_delegation",
        surface_variant = surface_variant.as_deref(),
        surface_id = ?surface_id,
        provider_id = %token.credential_provider_id,
        user_hash = %token.user_identity_hash,
        token_id = %token.id,
        source,
        "Consent ended at its time limit - removed the delegation token"
    );
    audit::emit("consent_expired", || {
        let mut event = audit::audit_event(
            DelegationAuditAction::ConsentExpired,
            Some(&token.agent_did),
            Some(&token.user_identity_hash),
            Some(&token.credential_provider_id),
            surface_id,
        );
        event.token_id = Some(token.id.clone());
        event.scopes = Some(token.scopes.clone());
        event.detail = Some(expiry_detail(token.consent_granted_at, ended_at, source));
        describe(&mut event);
        event
    });
    true
}

/// Audit, as `consent_expired`, that `removed`, a grant by binding whose
/// consent ended at `ended_at`, was removed from the vault. `source` says what
/// found it ended, and `provider_name` names its provider when it is known.
pub fn record_grant_expiry(
    removed: &DelegatedGrant,
    provider_name: Option<&str>,
    ended_at: Option<DateTime<Utc>>,
    source: &'static str,
) {
    audit::emit("consent_expired", || {
        let mut event = audit::audit_event(
            DelegationAuditAction::ConsentExpired,
            None,
            Some(&removed.principal),
            Some(&removed.credential_provider_id),
            Some(&removed.surface_id),
        );
        event.token_id = Some(removed.id.clone());
        event.provider_name = provider_name.map(str::to_string);
        event.scopes = Some(removed.scopes.clone());
        event.tenant_id = removed.tenant_id.clone();
        event.detail = Some(expiry_detail(removed.created_at, ended_at, source));
        event
    });
}

/// The `detail` of a `consent_expired` audit record: when the consent was
/// given, when it ended, and what found it ended: `release`, a request that
/// needed the credential, or `sweep`.
pub fn expiry_detail(
    granted_at: DateTime<Utc>,
    ended_at: Option<DateTime<Utc>>,
    source: &str,
) -> String {
    let stamp = |time: DateTime<Utc>| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let ended_at = ended_at.map_or_else(String::new, |time| format!(",consent_expired_at:{}", stamp(time)));
    format!("consent_granted_at:{}{ended_at},source:{source}", stamp(granted_at))
}

/// The earlier of two ends, or of two limits the shorter; the one there is
/// when the other is absent.
fn earlier<T: Ord>(
    one: Option<T>,
    other: Option<T>,
) -> Option<T> {
    match (one, other) {
        (Some(one), Some(other)) => Some(one.min(other)),
        (one, other) => one.or(other),
    }
}

/// `secs` after `from`, or `from` itself when that is out of range, so a time
/// that cannot be represented ends the consent rather than leaving it unlimited.
fn after(
    from: DateTime<Utc>,
    secs: u64,
) -> DateTime<Utc> {
    i64::try_from(secs)
        .ok()
        .and_then(Duration::try_seconds)
        .and_then(|span| from.checked_add_signed(span))
        .unwrap_or(from)
}

/// What a person asked for consent is told about its time limit: why they are
/// asked again (`reason`, [`CONSENT_EXPIRED`] or [`CONSENT_TOO_OLD`]), and how
/// long the new consent may be used. `None` when there is nothing to say.
pub fn notice(
    reason: Option<&str>,
    lifetime_secs: Option<u64>,
) -> Option<String> {
    let asked_again = match reason {
        Some(CONSENT_EXPIRED) => Some("Your earlier access ended at its time limit.".to_string()),
        Some(CONSENT_TOO_OLD) => Some("Your earlier access is too old for this request.".to_string()),
        _ => None,
    };
    let lifetime = lifetime_secs.map(|secs| format!("The agent may use this access for {}.", describe(secs)));
    let sentences: Vec<String> = asked_again
        .into_iter()
        .chain(lifetime)
        .collect();
    (!sentences.is_empty()).then(|| sentences.join(" "))
}

/// `secs` in the largest whole unit, as a person reads it: `6 hours`, `30 days`,
/// `90 minutes`.
pub fn describe(secs: u64) -> String {
    let (count, unit) = match secs {
        secs if secs % 86_400 == 0 => (secs / 86_400, "day"),
        secs if secs % 3_600 == 0 => (secs / 3_600, "hour"),
        secs if secs % 60 == 0 => (secs / 60, "minute"),
        secs => (secs, "second"),
    };
    format!(
        "{count} {unit}{}",
        if count == 1 {
            ""
        } else {
            "s"
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(
        default: Option<u64>,
        ceiling: Option<u64>,
    ) -> CredentialPolicyConfig {
        CredentialPolicyConfig {
            default_max_consent_age_secs: default,
            max_consent_age_ceiling_secs: ceiling,
            ..CredentialPolicyConfig::default()
        }
    }

    fn unlimited() -> CredentialPolicyConfig {
        policy(None, None)
    }

    fn at(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn without_any_limit_a_consent_is_current_however_old() {
        let limits = ConsentLimits::under(None, None, &unlimited());
        assert_eq!(limits.lifetime_secs(), None);
        assert_eq!(limits.expires_at(at(0)), None);
        assert_eq!(limits.ends_at(at(0), None), None);
        assert_eq!(limits.judge(at(0), None, at(10 * 365 * 86_400)), ConsentAge::Current);
        assert_eq!(limits.judge(at(3_600), None, at(0)), ConsentAge::Current, "a future consent time under no limit");
    }

    #[test]
    fn a_consent_ends_exactly_at_its_limit() {
        let limits = ConsentLimits::under(None, Some(3_600), &unlimited());
        assert_eq!(limits.expires_at(at(0)), Some(at(3_600)));
        assert_eq!(limits.judge(at(0), Some(at(3_600)), at(3_599)), ConsentAge::Current);
        assert_eq!(limits.judge(at(0), Some(at(3_600)), at(3_600)), ConsentAge::Ended);
        assert_eq!(limits.judge(at(0), Some(at(3_600)), at(3_601)), ConsentAge::Ended);
    }

    #[test]
    fn the_provider_limit_takes_the_place_of_the_default_and_the_ceiling_caps_both() {
        let lifetime = |binding, provider, default, ceiling| {
            ConsentLimits::under(binding, provider, &policy(default, ceiling)).lifetime_secs()
        };
        assert_eq!(lifetime(None, None, Some(86_400), None), Some(86_400), "the default alone");
        assert_eq!(lifetime(None, Some(3_600), Some(86_400), None), Some(3_600), "the provider below the default");
        assert_eq!(lifetime(None, Some(172_800), Some(86_400), None), Some(172_800), "the provider above the default");
        assert_eq!(lifetime(None, None, None, Some(7_200)), Some(7_200), "the ceiling limits what nothing else does");
        assert_eq!(lifetime(None, Some(86_400), None, Some(7_200)), Some(7_200), "the ceiling caps the provider");
        assert_eq!(lifetime(Some(86_400), None, None, Some(7_200)), Some(7_200), "the ceiling caps the binding");
        assert_eq!(lifetime(Some(600), Some(3_600), None, None), Some(600), "the binding below the provider");
        assert_eq!(lifetime(Some(7_200), Some(3_600), None, None), Some(3_600), "the binding above the provider");
        assert_eq!(lifetime(Some(600), None, None, None), Some(600), "the binding alone");
    }

    #[test]
    fn a_shortened_limit_ends_a_stored_consent_sooner_and_a_lengthened_one_never_later() {
        let stored_end = Some(at(3_600));
        let shortened = ConsentLimits::under(None, Some(600), &unlimited());
        assert_eq!(shortened.ends_at(at(0), stored_end), Some(at(600)));
        assert_eq!(shortened.judge(at(0), stored_end, at(600)), ConsentAge::Ended);

        let lengthened = ConsentLimits::under(None, Some(86_400), &unlimited());
        assert_eq!(lengthened.ends_at(at(0), stored_end), stored_end);
        assert_eq!(lengthened.judge(at(0), stored_end, at(3_600)), ConsentAge::Ended);

        let removed = ConsentLimits::under(None, None, &unlimited());
        assert_eq!(removed.ends_at(at(0), stored_end), stored_end);
        assert_eq!(removed.judge(at(0), stored_end, at(3_600)), ConsentAge::Ended, "the stored end still holds");
    }

    #[test]
    fn a_consent_stored_without_an_end_takes_the_limit_set_since() {
        let limits = ConsentLimits::under(None, None, &policy(Some(3_600), None));
        assert_eq!(limits.judge(at(0), None, at(3_599)), ConsentAge::Current);
        assert_eq!(limits.judge(at(0), None, at(3_600)), ConsentAge::Ended);
    }

    #[test]
    fn a_binding_with_a_shorter_limit_finds_a_consent_too_old_before_it_ends() {
        let limits = ConsentLimits::under(Some(600), Some(3_600), &unlimited());
        let stored_end = Some(at(3_600));
        assert_eq!(limits.judge(at(0), stored_end, at(599)), ConsentAge::Current);
        assert_eq!(limits.judge(at(0), stored_end, at(600)), ConsentAge::TooOldForBinding);
        assert_eq!(limits.judge(at(0), stored_end, at(3_599)), ConsentAge::TooOldForBinding);
        assert_eq!(limits.judge(at(0), stored_end, at(3_600)), ConsentAge::Ended);

        let binding_alone = ConsentLimits::under(Some(600), None, &unlimited());
        assert_eq!(binding_alone.judge(at(0), None, at(600)), ConsentAge::TooOldForBinding, "given through another");
        assert_eq!(binding_alone.judge(at(0), Some(at(600)), at(600)), ConsentAge::Ended, "given through this one");
    }

    #[test]
    fn a_grant_by_binding_ends_at_the_earliest_of_its_stored_end_and_both_limits() {
        let stored_end = Some(at(3_600));
        let end = |binding, provider| {
            ConsentLimits::under(binding, provider, &unlimited()).ends_for_binding_at(at(0), stored_end)
        };
        assert_eq!(end(None, None), stored_end, "the stored end alone");
        assert_eq!(end(Some(600), Some(3_600)), Some(at(600)), "the binding's limit, shortened since");
        assert_eq!(end(Some(7_200), Some(1_800)), Some(at(1_800)), "the provider's limit, shortened since");
        assert_eq!(end(Some(7_200), Some(86_400)), stored_end, "limits lengthened since");
        assert_eq!(ConsentLimits::under(None, None, &unlimited()).ends_for_binding_at(at(0), None), None);
    }

    #[test]
    fn only_a_provider_a_person_consents_to_limits_its_consents() {
        let provider = |provider_type: &str, limit| {
            let mut provider: CredentialProvider = serde_json::from_value(serde_json::json!({
                "id": "cp", "name": "Provider", "provider_id": "provider", "provider_type": provider_type,
                "callback_path": "/v1/identity/oauth/callback/provider",
                "created_at": "2027-01-15T08:00:00Z", "updated_at": "2027-01-15T08:00:00Z"
            }))
            .unwrap();
            provider.max_consent_age_secs = limit;
            provider
        };
        let consented = provider("oauth2_authorization_code", Some(3_600));
        assert_eq!(ConsentLimits::of_provider(Some(&consented)).lifetime_secs(), Some(3_600));
        let service = provider("oauth2_client_credentials", Some(3_600));
        assert_eq!(ConsentLimits::of_provider(Some(&service)), ConsentLimits::default());
        assert_eq!(ConsentLimits::of_provider(None), ConsentLimits::default(), "a provider that is gone");
        assert_eq!(
            ConsentLimits::of_provider(None).judge(at(0), Some(at(3_600)), at(3_600)),
            ConsentAge::Ended,
            "the end stored with a consent still ends it"
        );
    }

    #[test]
    fn a_consent_time_ahead_of_the_clock_ends_a_limited_consent_beyond_the_skew_allowed() {
        let limits = ConsentLimits::under(None, Some(3_600), &unlimited());
        assert_eq!(limits.judge(at(CLOCK_SKEW_SECS), None, at(0)), ConsentAge::Current);
        assert_eq!(limits.judge(at(CLOCK_SKEW_SECS + 1), None, at(0)), ConsentAge::Ended);
    }

    #[test]
    fn a_limit_that_cannot_be_added_to_the_consent_time_ends_the_consent() {
        let limits = ConsentLimits::under(None, Some(u64::MAX), &unlimited());
        assert_eq!(limits.expires_at(at(0)), Some(at(0)));
        assert_eq!(limits.judge(at(0), None, at(0)), ConsentAge::Ended);
        let limits = ConsentLimits::under(None, Some(3_600), &unlimited());
        assert_eq!(limits.judge(DateTime::<Utc>::MAX_UTC, None, at(0)), ConsentAge::Ended);
    }

    #[test]
    fn the_notice_says_why_consent_is_asked_again_and_how_long_it_lasts() {
        assert_eq!(notice(None, None), None);
        assert_eq!(notice(None, Some(21_600)).as_deref(), Some("The agent may use this access for 6 hours."));
        assert_eq!(
            notice(Some(CONSENT_EXPIRED), Some(21_600)).as_deref(),
            Some("Your earlier access ended at its time limit. The agent may use this access for 6 hours.")
        );
        assert_eq!(
            notice(Some(CONSENT_TOO_OLD), None).as_deref(),
            Some("Your earlier access is too old for this request.")
        );
        assert_eq!(notice(Some("another_reason"), None), None);
    }

    #[test]
    fn the_expiry_detail_names_both_ends_of_the_consent_and_what_found_it() {
        assert_eq!(
            expiry_detail(at(0), Some(at(3_600)), "release"),
            "consent_granted_at:2027-01-15T08:00:00Z,consent_expired_at:2027-01-15T09:00:00Z,source:release"
        );
        assert_eq!(expiry_detail(at(0), None, "sweep"), "consent_granted_at:2027-01-15T08:00:00Z,source:sweep");
    }

    #[test]
    fn a_limit_is_described_in_its_largest_whole_unit() {
        assert_eq!(describe(60), "1 minute");
        assert_eq!(describe(5_400), "90 minutes");
        assert_eq!(describe(3_600), "1 hour");
        assert_eq!(describe(21_600), "6 hours");
        assert_eq!(describe(86_400), "1 day");
        assert_eq!(describe(2_592_000), "30 days");
        assert_eq!(describe(61), "61 seconds");
    }
}
