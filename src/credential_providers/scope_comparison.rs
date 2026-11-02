//! How an external consent provider's granted scopes are compared with the
//! scopes asked for.
//!
//! A token answer's `scope` says what the token holds, in the vendor's own
//! spelling. Vendors add standard scopes nobody asked for, and rename the ones
//! asked for, so a byte-for-byte comparison refuses grants that are not wider
//! at all. Each provider names its vendor's habits with `scope_comparison`;
//! the default compares exactly, so a vendor whose habits nobody vouched for
//! gets nothing beyond what was asked for, in the very words asked for.
//!
//! Whatever the comparison, a scope that is neither one asked for, in any of
//! its spellings, nor one of the vendor's standard identity scopes widens the
//! grant, and the grant is refused.

use serde::{Deserialize, Serialize};

/// How a provider's granted scopes are compared with those asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeComparison {
    /// Exactly as written (RFC 6749 scope tokens are case-sensitive), and
    /// nothing granted beyond those asked for. The default.
    #[default]
    Exact,
    /// OpenID Connect vendors: as `exact`, but the `openid` and
    /// `offline_access` a vendor adds are not taken for a wider grant.
    Oidc,
    /// Google: the `openid`, `email` and `profile` it adds, which it answers
    /// as `https://www.googleapis.com/auth/userinfo.email` and
    /// `https://www.googleapis.com/auth/userinfo.profile`, are not taken for
    /// a wider grant. Google's scopes keep their case.
    Google,
    /// Microsoft Entra ID: names compared without case, and without the
    /// resource that qualifies them (`https://graph.microsoft.com/Mail.Read`
    /// is `Mail.Read`, `api://<app>/Files.Read` is `Files.Read`: an Entra
    /// token is for one resource), and the `openid`, `profile`, `email`,
    /// `offline_access` and `User.Read` it adds are not taken for a wider
    /// grant. `User.Read` reads the signed-in person's own profile, and Entra
    /// grants it to every app registration by default.
    Microsoft,
}

impl ScopeComparison {
    /// Whether this is the default, exact comparison.
    pub fn is_exact(&self) -> bool {
        *self == Self::Exact
    }

    /// The scopes of `granted` that widen a grant asked for with `requested`:
    /// those that are neither one asked for, in this comparison's spelling,
    /// nor one of the vendor's standard identity scopes. Empty when the grant
    /// lies within the request.
    pub fn widened<'a>(
        self,
        requested: &[String],
        granted: &'a [String],
    ) -> Vec<&'a str> {
        let asked: Vec<String> = requested
            .iter()
            .map(|scope| self.normal(scope))
            .collect();
        granted
            .iter()
            .map(String::as_str)
            .filter(|scope| {
                let normal = self.normal(scope);
                !self
                    .standard()
                    .contains(&normal.as_str())
                    && !asked.contains(&normal)
            })
            .collect()
    }

    /// `scope` as this comparison spells it.
    fn normal(
        self,
        scope: &str,
    ) -> String {
        match self {
            Self::Exact | Self::Oidc | Self::Google => scope.to_string(),
            Self::Microsoft => {
                let name = if scope.contains("://") {
                    scope
                        .rsplit_once('/')
                        .map_or(scope, |(_, name)| name)
                } else {
                    scope
                };
                name.to_ascii_lowercase()
            }
        }
    }

    /// The standard identity scopes the vendor adds, as [`Self::normal`]
    /// spells them, which never widen a grant.
    fn standard(self) -> &'static [&'static str] {
        match self {
            Self::Exact => &[],
            Self::Oidc => &["openid", "offline_access"],
            Self::Google => &["openid", "email", "profile", GOOGLE_USERINFO_EMAIL, GOOGLE_USERINFO_PROFILE],
            Self::Microsoft => &["openid", "profile", "email", "offline_access", "user.read"],
        }
    }
}

const GOOGLE_USERINFO_EMAIL: &str = "https://www.googleapis.com/auth/userinfo.email";
const GOOGLE_USERINFO_PROFILE: &str = "https://www.googleapis.com/auth/userinfo.profile";

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(text: &str) -> Vec<String> {
        text.split_whitespace()
            .map(str::to_string)
            .collect()
    }

    /// Google answers `email` as its userinfo URL and adds `openid`; a Drive
    /// connect is not wider for it. A scope nobody asked for still is.
    #[test]
    fn a_google_answer_is_compared_as_google_spells_its_scopes() {
        let requested = scopes("https://www.googleapis.com/auth/drive.readonly email");
        let answered = scopes(
            "https://www.googleapis.com/auth/userinfo.email openid https://www.googleapis.com/auth/drive.readonly",
        );
        assert!(
            ScopeComparison::Google
                .widened(&requested, &answered)
                .is_empty()
        );
        assert_eq!(
            ScopeComparison::Exact.widened(&requested, &answered),
            ["https://www.googleapis.com/auth/userinfo.email", "openid"],
            "the default compares exactly"
        );
        let wider = scopes("https://www.googleapis.com/auth/drive.readonly https://www.googleapis.com/auth/gmail.send");
        assert_eq!(ScopeComparison::Google.widened(&requested, &wider), ["https://www.googleapis.com/auth/gmail.send"]);
        assert_eq!(
            ScopeComparison::Google.widened(&requested, &scopes("https://www.googleapis.com/auth/Drive.ReadOnly")),
            ["https://www.googleapis.com/auth/Drive.ReadOnly"],
            "Google's scopes keep their case"
        );
    }

    /// Entra qualifies Graph scopes with their resource, changes their case
    /// and adds the OpenID Connect scopes and `User.Read`; a mail connect is
    /// not wider for it. Another permission still is, even one the person
    /// consented to the same app for another connect.
    #[test]
    fn an_entra_answer_is_compared_without_its_resource_or_case() {
        let requested = scopes("Mail.Read offline_access");
        let answered =
            scopes("https://graph.microsoft.com/mail.read https://graph.microsoft.com/User.Read openid profile email");
        assert!(
            ScopeComparison::Microsoft
                .widened(&requested, &answered)
                .is_empty()
        );
        assert!(
            ScopeComparison::Microsoft
                .widened(&scopes("api://0f1e/Files.Read"), &scopes("api://0f1e/files.read"))
                .is_empty()
        );
        assert_eq!(
            ScopeComparison::Microsoft.widened(
                &requested,
                &scopes("https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/Files.ReadWrite.All")
            ),
            ["https://graph.microsoft.com/Files.ReadWrite.All"]
        );
        assert_eq!(
            ScopeComparison::Exact.widened(&requested, &answered),
            [
                "https://graph.microsoft.com/mail.read",
                "https://graph.microsoft.com/User.Read",
                "openid",
                "profile",
                "email"
            ]
        );
    }

    /// An OpenID Connect vendor's `openid` and `offline_access` are not a
    /// wider grant; its `profile` and `email`, which a vendor may define as it
    /// likes, still are. Order never matters.
    #[test]
    fn an_oidc_vendor_adds_only_openid_and_offline_access() {
        let requested = scopes("issues:write issues:read");
        assert!(
            ScopeComparison::Oidc
                .widened(&requested, &scopes("openid issues:read offline_access issues:write"))
                .is_empty()
        );
        assert_eq!(ScopeComparison::Oidc.widened(&requested, &scopes("issues:read email")), ["email"]);
        assert_eq!(ScopeComparison::Oidc.widened(&requested, &scopes("Issues:Read")), ["Issues:Read"]);
    }
}
