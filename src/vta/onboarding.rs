//! Customer-sovereign onboarding (VTA-05).
//!
//! In the customer-sovereign model the **customer** owns and runs the VTA; the
//! gateway is only an authorized relying party. The gateway therefore never
//! holds the VTA's super-admin — it:
//!
//! 1. emits its control `did:key` and the **exact one-consent-step grant
//!    command** the customer runs on their VTA ([`grant_command`]),
//! 2. after authenticating, confirms the grant it received is **least-privilege**
//!    — a sign/issue-only role scoped to **one** context, never super-admin
//!    ([`GrantScope`]),
//! 3. persists the resulting onboarding state **encrypted at rest** and
//!    idempotently ([`OnboardingRecord`]),
//! 4. rotates its control key under a guard that proves the new key before the
//!    old is revoked, rate-limited and audited ([`RotationGuard`]).
//!
//! The distinct identities (VTA service DID, gateway **control** DID, **issuer**
//! DID) are kept separate throughout.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::error::VtaError;

/// The exact one-consent-step grant command the customer runs on their VTA to
/// authorize the gateway's control DID with a **sign/issue-only** role scoped to
/// a single context. Printed by the gateway; run by the customer (who holds VTA
/// admin) — the gateway never holds admin itself.
pub fn grant_command(
    control_did: &str,
    context_id: &str,
) -> String {
    format!("vta import-did --did {control_did} --role application --context {context_id} --label agent-gateway")
}

/// The grant command for a gateway that also provisions its own per-surface
/// contexts (`[vta] auto_provision_contexts`).
///
/// Adds the narrow `context-create` capability (VTA-16) and the two the
/// provisioning sequence actually uses. It is **not** folded into
/// [`grant_command`] because it is a strictly larger grant: an operator who
/// does not auto-provision should not be asked for it, and one who does should
/// see that they are granting something extra.
///
/// What it confers stays bounded by rules the VTA already enforced — top-level
/// creation remains super-admin-only, and the caller must reach the parent — so
/// it means "a subtree under the context named here", never "create anywhere".
///
/// **Why `acl create` and not `import-did`.** `import-did` takes no
/// `--capabilities` flag at all, so the command this used to print was refused
/// by the CLI outright — an operator could not have run it. `acl create` is the
/// one that accepts capabilities, and spells contexts `--contexts`.
///
/// **Why `initiator` and not `application`.** Provisioning mints a key inside
/// the context it created, which needs `key-mint`, and the VTA derives that
/// capability for `admin` and `initiator` only — never `application`. The
/// earlier form named `application`, so an operator who got past the flag would
/// have had a gateway that could create a context and then fail to put a key in
/// it.
///
/// **Why the capabilities are spelled out.** `effective_capabilities` treats
/// explicitly named role-derived capabilities as a *narrowing*: naming them
/// reduces the grant to exactly those. So this command confers precisely
/// `{context-create, key-mint, sign}` — strictly less than the whole
/// `application` role the original command handed over, despite the
/// higher-sounding role name.
pub fn grant_command_with_provisioning(
    control_did: &str,
    context_id: &str,
) -> String {
    format!(
        "vta acl create --did {control_did} --role initiator --contexts {context_id} \
         --capabilities context-create,key-mint,sign --label agent-gateway"
    )
}

/// The scope of the grant the VTA issued to the gateway, read from its session
/// token's claims. Used to confirm the grant is least-privilege and **not**
/// super-admin / appliance-wide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantScope {
    pub role: String,
    pub contexts: Vec<String>,
}

impl GrantScope {
    /// Parse the `role` + `contexts` claims from a VTA session JWT (the access
    /// token). This reads the token's **own** payload — the VTA already signed
    /// it and the gateway holds it; this is self-inspection, not trust
    /// establishment, so the signature is not re-verified here.
    pub fn from_session_token(token: &str) -> Result<Self, VtaError> {
        let payload_b64 = token
            .split('.')
            .nth(1)
            .ok_or_else(|| VtaError::Protocol("session token is not a JWT".to_string()))?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .map_err(|e| VtaError::Protocol(format!("session token payload is not base64url: {e}")))?;
        let claims: Value = serde_json::from_slice(&bytes)
            .map_err(|e| VtaError::Protocol(format!("session token claims are not JSON: {e}")))?;
        let role = claims
            .get("role")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let contexts = claims
            .get("contexts")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self { role, contexts })
    }

    /// Whether this grant is super-admin / appliance-wide: a privileged role, or
    /// an **unrestricted** grant (no bounding context).
    pub fn is_super_admin(&self) -> bool {
        matches!(self.role.as_str(), "admin" | "super-admin" | "superadmin" | "owner" | "root")
            || self.contexts.is_empty()
    }

    /// Assert the grant is least-privilege: a non-admin role scoped to **exactly
    /// one** context. The gateway must never be onboarded with super-admin.
    pub fn assert_scoped(&self) -> Result<(), VtaError> {
        if self.is_super_admin() {
            return Err(VtaError::Config(format!(
                "VTA grant is too broad (role `{}`, {} context(s)); grant the gateway a \
                 sign/issue-only role in exactly one context",
                self.role,
                self.contexts.len()
            )));
        }
        if self.contexts.len() != 1 {
            return Err(VtaError::Config(format!(
                "VTA grant must be scoped to exactly one context, found {}",
                self.contexts.len()
            )));
        }
        Ok(())
    }
}

/// Persisted onboarding state. Written **encrypted at rest** via the shared
/// secret-file helper (whole-file `.enc` when encryption is active).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnboardingRecord {
    /// The gateway's control `did:key` the grant was issued to.
    pub control_did: String,
    /// The VTA context the scoped grant lives in.
    pub context_id: String,
    /// The issuer DID the gateway's artifacts are signed under.
    pub issuer_did: String,
    /// When the grant was recorded.
    pub granted_at: DateTime<Utc>,
}

impl OnboardingRecord {
    pub async fn load(path: &Path) -> Result<Option<Self>, VtaError> {
        match crate::encryption::secret_file::read_secret_file(path).await {
            Ok(Some(json)) => serde_json::from_str(&json)
                .map(Some)
                .map_err(|e| VtaError::Config(format!("onboarding record is malformed: {e}"))),
            Ok(None) => Ok(None),
            Err(e) => Err(VtaError::Config(format!("read onboarding record: {e}"))),
        }
    }

    pub async fn save(
        &self,
        path: &Path,
    ) -> Result<(), VtaError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| VtaError::Config(format!("serialize onboarding record: {e}")))?;
        crate::encryption::secret_file::write_secret_file(path, &json)
            .await
            .map_err(|e| VtaError::Config(format!("persist onboarding record: {e}")))
    }
}

/// Audit trail entry for a control-key rotation.
// The guarded-rotation primitive below (`rotate` + this record) is exercised by
// tests and is the entry point the operator rotation flow calls; wiring that
// admin trigger is a follow-up (VTA-13 moves the control DID to did:webvh), so
// the primitive ships ahead of its runtime caller.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationAudit {
    pub old_control_did: String,
    pub new_control_did: String,
    pub rotated_at: DateTime<Utc>,
}

/// Guards control-key rotation: **rate-limited**, **prove-new-before-revoke-old**,
/// and **audited**. A stolen control key must not be able to silently self-rotate
/// and lock the real gateway out, so an off-schedule rotation is rejected and
/// alerted, and the old key is only authorized for revocation once the new key
/// has proven it can authenticate.
pub struct RotationGuard {
    min_interval: Duration,
}

impl RotationGuard {
    pub fn new(min_interval: Duration) -> Self {
        Self { min_interval }
    }

    /// Reject an **off-schedule** rotation (one attempted before the minimum
    /// interval has elapsed since the last), raising an audit alert.
    pub fn check_schedule(
        &self,
        now: DateTime<Utc>,
        last_rotation: Option<DateTime<Utc>>,
    ) -> Result<(), VtaError> {
        if let Some(last) = last_rotation {
            let min = chrono::Duration::from_std(self.min_interval).unwrap_or_else(|_| chrono::Duration::zero());
            if now.signed_duration_since(last) < min {
                tracing::warn!(
                    target: "vta_audit",
                    event = "control_key_rotation_off_schedule",
                    "rejected an off-schedule control-key rotation attempt"
                );
                return Err(VtaError::Config(
                    "control-key rotation attempted before the minimum interval (off-schedule; alerted)".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// Guarded rotation: run `prove_new` (authenticate with the new key) and only
    /// on success authorize revoking the old key (**new-before-delete**), then
    /// emit an audit record. If the new key cannot be proven the old key is
    /// retained.
    #[allow(dead_code)] // rotation primitive; the admin trigger is a follow-up (see RotationAudit note)
    pub async fn rotate<F, Fut>(
        &self,
        old_control_did: &str,
        new_control_did: &str,
        now: DateTime<Utc>,
        last_rotation: Option<DateTime<Utc>>,
        prove_new: F,
    ) -> Result<RotationAudit, VtaError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), VtaError>>,
    {
        self.check_schedule(now, last_rotation)?;
        prove_new().await.map_err(|e| {
            tracing::warn!(target: "vta_audit", event = "control_key_rotation_proof_failed", "new control key failed proof; old key retained");
            VtaError::Config(format!("new control key failed proof; old key retained: {}", e.log_detail()))
        })?;
        tracing::info!(
            target: "vta_audit",
            event = "control_key_rotated",
            %old_control_did,
            %new_control_did,
            "control-key rotation: new key proven; old key may now be revoked (one-ACL-delete)"
        );
        Ok(RotationAudit {
            old_control_did: old_control_did.to_string(),
            new_control_did: new_control_did.to_string(),
            rotated_at: now,
        })
    }
}

/// Runtime onboarding orchestration held by the VTA connector: verify the grant
/// scope on first authentication and persist the onboarding record (idempotent;
/// a changed control DID is a guarded, rate-limited rotation).
pub struct OnboardingState {
    record_path: Option<std::path::PathBuf>,
    context_id: String,
    issuer_did: String,
    rotation_guard: RotationGuard,
    verified: std::sync::atomic::AtomicBool,
}

impl OnboardingState {
    /// `record_path` persists the onboarding record encrypted at rest (skip when
    /// the control key is ephemeral/env-sourced). `rotation_min_interval` bounds
    /// how often the control DID may change before it is flagged off-schedule.
    pub fn new(
        record_path: Option<std::path::PathBuf>,
        context_id: String,
        issuer_did: String,
        rotation_min_interval: Duration,
    ) -> Self {
        Self {
            record_path,
            context_id,
            issuer_did,
            rotation_guard: RotationGuard::new(rotation_min_interval),
            verified: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Run once after the first successful authentication: confirm the grant is
    /// least-privilege (warn if broad), then persist/update the onboarding
    /// record. Never fails the request — onboarding signalling is advisory; the
    /// VTA enforces the grant per-operation.
    pub async fn on_authenticated(
        &self,
        control_did: &str,
        session_token: &str,
    ) {
        if self
            .verified
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            return; // already ran
        }

        match GrantScope::from_session_token(session_token) {
            Ok(scope) => {
                if let Err(e) = scope.assert_scoped() {
                    tracing::warn!(
                        target: "vta_audit",
                        event = "vta_grant_over_privileged",
                        detail = %e.log_detail(),
                        "the gateway's VTA grant is broader than least-privilege; grant a sign/issue-only role in one context"
                    );
                } else {
                    tracing::info!(target: "vta_audit", event = "vta_grant_scoped", role = %scope.role, "VTA grant verified least-privilege");
                }
            }
            Err(e) => {
                tracing::warn!(target: "vta_audit", "could not read VTA grant scope: {}", e.log_detail());
            }
        }

        let Some(path) = &self.record_path else {
            return;
        };
        match OnboardingRecord::load(path).await {
            // Idempotent: an unchanged control DID needs no rewrite.
            Ok(Some(existing)) if existing.control_did == control_did => {}
            Ok(prior) => {
                if let Some(prior) = &prior
                    && prior.control_did != control_did
                    && let Err(e) = self
                        .rotation_guard
                        .check_schedule(Utc::now(), Some(prior.granted_at))
                {
                    tracing::warn!(target: "vta_audit", "control DID changed off-schedule: {}", e.log_detail());
                }
                let record = OnboardingRecord {
                    control_did: control_did.to_string(),
                    context_id: self.context_id.clone(),
                    issuer_did: self.issuer_did.clone(),
                    granted_at: Utc::now(),
                };
                if let Err(e) = record.save(path).await {
                    tracing::warn!(target: "vta_audit", "failed to persist onboarding record: {}", e.log_detail());
                }
            }
            Err(e) => {
                tracing::warn!(target: "vta_audit", "onboarding record load failed: {}", e.log_detail());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    /// The provisioning grant must confer the three capabilities the sequence
    /// uses, under a role that actually derives `key-mint`.
    ///
    /// Regression: the command used to name `--role application`, which the
    /// VTA derives **without** `key-mint`, so an operator who ran it got a
    /// gateway that could create a context and then failed to mint the key
    /// inside it — a working instruction that produced a broken deployment.
    #[test]
    fn the_provisioning_grant_can_actually_provision() {
        let command = grant_command_with_provisioning("did:key:zGateway", "acme");
        assert!(
            command.starts_with("vta acl create"),
            "`import-did` takes no --capabilities flag, so the CLI refuses it outright: {command}"
        );
        assert!(
            command.contains("--role initiator"),
            "`application` does not derive key-mint, so provisioning would fail: {command}"
        );
        for capability in ["context-create", "key-mint", "sign"] {
            assert!(command.contains(capability), "the provisioning sequence needs `{capability}`: {command}");
        }
        assert!(command.contains("--contexts acme"), "`acl create` spells it --contexts: {command}");
        assert!(command.contains("did:key:zGateway"), "{command}");
    }

    /// Naming role-derived capabilities *narrows* the grant, so spelling them
    /// out is what keeps this least-privilege despite the higher-sounding
    /// role. Asserted so nobody "simplifies" it by dropping the list.
    #[test]
    fn the_provisioning_grant_names_its_capabilities_to_stay_narrow() {
        let command = grant_command_with_provisioning("did:key:zGateway", "acme");
        assert!(command.contains("--capabilities"), "without an explicit list the whole role is conferred: {command}");
    }

    /// Build a minimal unsigned JWT with the given claims for scope parsing.
    fn jwt_with_claims(claims: Value) -> String {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"EdDSA\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        format!("{header}.{payload}.sig")
    }

    #[test]
    fn grant_command_is_scoped_and_not_admin() {
        let cmd = grant_command("did:key:z6MkGateway", "ctx-gateway");
        assert!(cmd.contains("--role application"), "sign/issue role, not admin: {cmd}");
        assert!(cmd.contains("--context ctx-gateway"), "bound to one context: {cmd}");
        assert!(!cmd.contains("admin"), "never grants admin: {cmd}");
    }

    #[test]
    fn scoped_grant_passes_assertion() {
        let token = jwt_with_claims(serde_json::json!({ "role": "application", "contexts": ["ctx-gateway"] }));
        let scope = GrantScope::from_session_token(&token).unwrap();
        assert!(!scope.is_super_admin());
        scope
            .assert_scoped()
            .expect("a single-context application grant is least-privilege");
    }

    #[test]
    fn admin_grant_is_rejected_as_super_admin() {
        // An admin role with an unrestricted (empty) context — exactly what the
        // live VTA's `import-did --role admin` issues — must be refused.
        let token = jwt_with_claims(serde_json::json!({ "role": "admin", "contexts": [] }));
        let scope = GrantScope::from_session_token(&token).unwrap();
        assert!(scope.is_super_admin());
        let err = scope
            .assert_scoped()
            .expect_err("super-admin must be rejected");
        assert!(
            err.log_detail()
                .contains("too broad")
        );
    }

    #[test]
    fn multi_context_grant_is_rejected() {
        let token = jwt_with_claims(serde_json::json!({ "role": "application", "contexts": ["a", "b"] }));
        let scope = GrantScope::from_session_token(&token).unwrap();
        assert!(scope.assert_scoped().is_err(), "must be exactly one context");
    }

    #[tokio::test]
    async fn onboarding_record_round_trips_encrypted_at_rest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join("vta_onboarding");
        let record = OnboardingRecord {
            control_did: "did:key:z6MkGateway".to_string(),
            context_id: "ctx-gateway".to_string(),
            issuer_did: "did:webvh:vta.example".to_string(),
            granted_at: Utc::now(),
        };
        assert!(
            OnboardingRecord::load(&path)
                .await
                .unwrap()
                .is_none(),
            "absent before save"
        );
        record
            .save(&path)
            .await
            .unwrap();
        let loaded = OnboardingRecord::load(&path)
            .await
            .unwrap()
            .expect("present after save");
        assert_eq!(loaded, record, "idempotent round-trip");
    }

    #[tokio::test]
    async fn rotation_proves_new_key_before_authorizing_old_revocation() {
        let guard = RotationGuard::new(Duration::from_secs(3600));
        let now = Utc::now();

        // New key proves out → rotation authorized + audited.
        let audit = guard
            .rotate("did:key:zOld", "did:key:zNew", now, None, || async { Ok(()) })
            .await
            .expect("proven new key rotates");
        assert_eq!(audit.old_control_did, "did:key:zOld");
        assert_eq!(audit.new_control_did, "did:key:zNew");

        // New key fails proof → old key retained (rotation refused).
        let refused = guard
            .rotate("did:key:zOld", "did:key:zBad", now, None, || async {
                Err(VtaError::Transport("cannot auth".to_string()))
            })
            .await;
        assert!(refused.is_err(), "unproven key must not trigger old-key revocation");
    }

    #[test]
    fn off_schedule_rotation_is_rejected() {
        let guard = RotationGuard::new(Duration::from_secs(3600));
        let now = Utc::now();
        let last = now - chrono::Duration::minutes(5); // only 5 min ago
        assert!(
            guard
                .check_schedule(now, Some(last))
                .is_err(),
            "too soon → rejected"
        );
        assert!(
            guard
                .check_schedule(now, None)
                .is_ok(),
            "first rotation allowed"
        );
        let old = now - chrono::Duration::hours(2);
        assert!(
            guard
                .check_schedule(now, Some(old))
                .is_ok(),
            "past the interval → allowed"
        );
    }
}
