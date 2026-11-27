//! The per-client limits on OIDC sign-in, always on: a request budget that `/oidc/login` and
//! `/oidc/callback` share, and a lockout after repeated callbacks whose code the provider refused.
//! A client is its address (an IPv6 address by its /64), resolved by
//! [`crate::source_auth::client_ip`], which trusts forwarded headers only from
//! `client_ip.trusted_proxies`.

use std::net::IpAddr;

use crate::config::types::{LoginThrottleConfig, RateLimitConfig, TokenEndpointThrottleConfig};
use crate::sts::throttle::TokenEndpointThrottle;

/// Sign-in requests (login and callback together) one client may send per window.
pub const SIGN_IN_REQUESTS_PER_WINDOW: u32 = 10;
/// How long one request budget lasts.
const WINDOW_SECS: u64 = 60;
/// Refused codes after which a client is locked out of OIDC sign-in.
pub const MAX_FAILED_SIGN_INS: u32 = 10;
/// How long a lockout lasts.
const LOCKOUT_SECS: u64 = 15 * 60;

/// The request budget, as the login throttle settings it is built from.
pub fn request_budget() -> LoginThrottleConfig {
    LoginThrottleConfig {
        enabled: true,
        per_ip: RateLimitConfig {
            requests: SIGN_IN_REQUESTS_PER_WINDOW,
            window_secs: WINDOW_SECS,
            burst: None,
        },
    }
}

pub struct SignInThrottle {
    requests: TokenEndpointThrottle,
    failures: TokenEndpointThrottle,
}

impl Default for SignInThrottle {
    fn default() -> Self {
        let failures_per_client = RateLimitConfig {
            requests: MAX_FAILED_SIGN_INS - 1,
            window_secs: LOCKOUT_SECS,
            burst: None,
        };
        Self {
            requests: TokenEndpointThrottle::per_client_ip(&request_budget()),
            failures: TokenEndpointThrottle::from_config(&TokenEndpointThrottleConfig {
                enabled: true,
                failed_attempts_only: true,
                per_client: failures_per_client.clone(),
                per_ip: failures_per_client,
                lockout_secs: LOCKOUT_SECS,
            }),
        }
    }
}

impl SignInThrottle {
    /// Count one sign-in request from `client`, and return how long it must wait when it is
    /// locked out or over its budget.
    pub fn admit(
        &self,
        client: Option<IpAddr>,
    ) -> Option<u64> {
        self.failures
            .client_retry_after(client)
            .or_else(|| {
                self.requests
                    .record_client_attempt(client)
            })
    }

    /// A callback whose code the provider refused: the one thing a caller sends that could be a
    /// guess.
    pub fn record_failure(
        &self,
        client: Option<IpAddr>,
    ) {
        self.failures
            .record_client_failure(client);
    }

    /// A completed sign-in clears the client's failures.
    pub fn clear_failures(
        &self,
        client: Option<IpAddr>,
    ) {
        self.failures
            .forget_client(client);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(last: u8) -> Option<IpAddr> {
        Some(IpAddr::from([192, 0, 2, last]))
    }

    #[test]
    fn a_client_gets_its_request_budget_and_then_waits_at_most_a_window() {
        let throttle = SignInThrottle::default();
        for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
            assert_eq!(throttle.admit(client(1)), None);
        }

        let wait = throttle
            .admit(client(1))
            .expect("over the budget");

        assert!(wait <= WINDOW_SECS, "{wait}");
        assert_eq!(throttle.admit(client(2)), None, "another client has its own budget");
    }

    #[test]
    fn repeated_refused_codes_lock_a_client_out_until_a_sign_in_completes() {
        let throttle = SignInThrottle::default();
        for _ in 0..MAX_FAILED_SIGN_INS - 1 {
            throttle.record_failure(client(3));
        }
        assert_eq!(throttle.admit(client(3)), None, "one failure short of the lockout");

        throttle.record_failure(client(3));
        let wait = throttle
            .admit(client(3))
            .expect("locked out");
        assert!(wait > WINDOW_SECS && wait <= LOCKOUT_SECS, "{wait}");
        assert_eq!(throttle.admit(client(4)), None);

        throttle.clear_failures(client(3));
        assert_eq!(throttle.admit(client(3)), None);
    }
}
