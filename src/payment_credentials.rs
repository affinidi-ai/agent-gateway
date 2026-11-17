//! Payment dispute-evidence Verifiable Credentials.
//!
//! Promotes the terminal payment lifecycle stages (`verified`/`settled` →
//! receipt, `failed`/`settlement_failed` → rejection; a Model B delegated
//! `proceed` → access grant) to a signed, portable credential — independent
//! evidence a dispute arbiter can verify without trusting either party's
//! private audit log. Opt-in via the `payment_receipt_vc` feature flag
//! (Settings) so no signing overhead is incurred unless enabled; issuance
//! never blocks or fails a payment (every function returns `None` on any
//! error).

use std::sync::{Arc, RwLock};

use serde::Serialize;

use crate::identity::VCIssuer;
use crate::identity::authority::CredentialAuthority;

/// The signing backend payment credentials are minted with.
///
/// A `RwLock` rather than a `OnceLock` because this is set **twice** during
/// startup, in order: the orchestrator registers the local issuer early (so a
/// deployment that never builds a VTA connector behaves exactly as before), and
/// the identity router then **upgrades** it to whichever connector `[vta]`
/// selected. A `OnceLock` would silently keep the first value and leave payment
/// receipts signed locally while STS signed via the VTA (VTA-10).
static GLOBAL_AUTHORITY: RwLock<Option<Arc<dyn CredentialAuthority>>> = RwLock::new(None);

/// Register the gateway's `VCIssuer` for payment-credential issuance. Called
/// once from the orchestrator, alongside its other global registrations. This
/// is the **local** default; [`set_global_payment_credential_authority`]
/// replaces it once the signing connector has been selected.
pub fn set_global_payment_vc_issuer(issuer: Arc<VCIssuer>) {
    set_global_payment_credential_authority(Arc::new(crate::identity::authority::LocalCredentialAuthority::new(
        issuer,
    )));
}

/// Point payment-credential signing at the **selected** signing connector
/// (VTA-10). Called from the identity router once `[vta]` has been resolved, so
/// payment receipts are signed by the same backend as STS tokens rather than
/// always by the local key.
pub fn set_global_payment_credential_authority(authority: Arc<dyn CredentialAuthority>) {
    match GLOBAL_AUTHORITY.write() {
        Ok(mut slot) => *slot = Some(authority),
        // Poisoned only if a previous writer panicked mid-set. Payment VC
        // issuance is best-effort and must never affect a payment, so log and
        // carry on rather than propagating.
        Err(_) => tracing::error!("payment credential authority registration failed: lock poisoned"),
    }
}

fn global_payment_authority() -> Option<Arc<dyn CredentialAuthority>> {
    GLOBAL_AUTHORITY
        .read()
        .ok()?
        .clone()
}

/// Whether payment dispute-evidence VC issuance is enabled
/// (`feature_flags["payment_receipt_vc"]` in dashboard settings). Defaults to
/// off so existing deployments see no behavior change.
fn payment_receipt_vc_enabled() -> bool {
    crate::storage::settings_store::global_settings()
        .map(|s| {
            s.feature_flags
                .get("payment_receipt_vc")
                .copied()
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

/// On-chain / processor settlement evidence embedded in a receipt once funds
/// have moved.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SettlementEvidence {
    #[serde(rename = "txHash", skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
}

/// Input to [`issue_payment_receipt`]. Every optional field is included in
/// `credentialSubject` only when present, so a provisional (`verified`, not
/// yet `settled`) receipt is smaller than the final, settlement-augmented one.
#[derive(Debug, Clone, Default)]
pub struct PaymentReceiptInput {
    pub rail: &'static str,
    pub payment_id: String,
    pub trace_id: Option<String>,
    pub amount: Option<String>,
    pub currency: Option<String>,
    pub method: Option<String>,
    pub payer: Option<String>,
    pub resource: Option<String>,
    pub settled: bool,
    pub settlement: Option<SettlementEvidence>,
    /// The payer's own signed authorization (x402 EIP-3009/Permit2 signature),
    /// embedded so the receipt is bilaterally provable, not merely
    /// self-attested by the issuing gateway.
    pub payer_signature: Option<String>,
}

/// Input to [`issue_payment_rejection`].
#[derive(Debug, Clone, Default)]
pub struct PaymentRejectionInput {
    pub rail: &'static str,
    pub payment_id: String,
    pub trace_id: Option<String>,
    pub method: Option<String>,
    pub payer: Option<String>,
    pub reason: String,
}

/// Input to [`issue_access_grant`] — the delegated (Model B) counterpart to a
/// receipt: agent-gateway is the relying/access party, not the money mover, so
/// it attests to granting access on a payment it relayed to a remote payment
/// gateway rather than to settlement itself.
#[derive(Debug, Clone, Default)]
pub struct AccessGrantInput {
    pub rail: &'static str,
    pub trace_id: Option<String>,
    pub payment_gateway_id: Option<String>,
    pub payment_surface_id: Option<String>,
    pub remote_status: u16,
}

#[derive(Debug, Clone, Serialize)]
struct ReceiptSubject {
    #[serde(rename = "paymentId")]
    payment_id: String,
    rail: &'static str,
    stage: &'static str,
    #[serde(rename = "traceId", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    settlement: Option<SettlementEvidence>,
}

#[derive(Debug, Clone, Serialize)]
struct RejectionSubject {
    #[serde(rename = "paymentId")]
    payment_id: String,
    rail: &'static str,
    #[serde(rename = "traceId", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payer: Option<String>,
    reason: String,
}

#[derive(Debug, Clone, Serialize)]
struct AccessGrantSubject {
    rail: &'static str,
    #[serde(rename = "traceId", skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    remote: AccessGrantRemote,
}

#[derive(Debug, Clone, Serialize)]
struct AccessGrantRemote {
    #[serde(rename = "gatewayId", skip_serializing_if = "Option::is_none")]
    gateway_id: Option<String>,
    #[serde(rename = "surfaceId", skip_serializing_if = "Option::is_none")]
    surface_id: Option<String>,
    #[serde(rename = "status")]
    status: u16,
}

/// A minted credential + its fingerprint, ready to persist on the transaction
/// record and stamp onto the corresponding payment audit event via
/// `record_payment_event`'s `vc_jwt` parameter.
#[derive(Debug, Clone)]
pub struct IssuedCredential {
    pub jwt: String,
    pub fingerprint: String,
}

async fn sign_credential(
    vc_type: &str,
    subject: impl Serialize,
) -> Option<IssuedCredential> {
    // The **selected** signing backend (VTA-10): local by default, or the VTA
    // connector when `[vta]` is enabled. A payment receipt is a VC-JWT, so it
    // signs through the same `keys/sign-jws` path STS uses — no VTA-side
    // credential task is needed.
    let authority = global_payment_authority()?;
    let issuer_did = authority
        .issuer_did()
        .await
        .ok()?;
    let subject_value = serde_json::to_value(subject).ok()?;
    let claims = serde_json::json!({
        "@context": ["https://www.w3.org/ns/credentials/v2"],
        "type": ["VerifiableCredential", vc_type],
        "issuer": issuer_did,
        "issuanceDate": chrono::Utc::now().to_rfc3339(),
        "credentialSubject": subject_value,
        "jti": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
    });
    // Fail closed: if the backend is unreachable or over quota this yields
    // `None`, which means "no credential" — never an unsigned or
    // locally-substituted one. A payment is never blocked on issuance.
    let jwt = authority
        .sign_token(&claims)
        .await
        .ok()?;
    let fingerprint = crate::delegation_vault::audit::vp_fingerprint(&jwt);
    Some(IssuedCredential { jwt, fingerprint })
}

/// Issue (or re-issue, at settlement) a `PaymentReceiptCredential`. Returns
/// `None` when the feature is disabled, no gateway `VCIssuer` is registered,
/// or signing fails — a payment is never blocked on VC issuance.
pub async fn issue_payment_receipt(input: PaymentReceiptInput) -> Option<IssuedCredential> {
    if !payment_receipt_vc_enabled() {
        return None;
    }
    let mut subject = serde_json::to_value(ReceiptSubject {
        payment_id: input.payment_id,
        rail: input.rail,
        stage: if input.settled {
            "settled"
        } else {
            "verified"
        },
        trace_id: input.trace_id,
        amount: input.amount,
        currency: input.currency,
        method: input.method,
        payer: input.payer,
        resource: input.resource,
        settlement: input.settlement,
    })
    .ok()?;
    if let Some(sig) = input.payer_signature
        && let Some(obj) = subject.as_object_mut()
    {
        obj.insert("payerSignature".to_string(), serde_json::Value::String(sig));
    }
    sign_credential("PaymentReceiptCredential", subject).await
}

/// Issue a `PaymentRejectionCredential` for a failed verification or a
/// settlement that failed after a successful verification.
pub async fn issue_payment_rejection(input: PaymentRejectionInput) -> Option<IssuedCredential> {
    if !payment_receipt_vc_enabled() {
        return None;
    }
    sign_credential(
        "PaymentRejectionCredential",
        RejectionSubject {
            payment_id: input.payment_id,
            rail: input.rail,
            trace_id: input.trace_id,
            method: input.method,
            payer: input.payer,
            reason: input.reason,
        },
    )
    .await
}

/// Issue a `PaymentAccessGrantCredential` for a Model B delegated payment this
/// gateway authorised to proceed. agent-gateway is the relying/access party
/// here, not the money mover, so this attests to *granting access* on a
/// payment relayed to `payment_gateway_id`/`payment_surface_id` — it does not
/// assert settlement, which is the remote payment gateway's own responsibility
/// to attest to (via its own receipt credential, correlated by `trace_id`).
pub async fn issue_access_grant(input: AccessGrantInput) -> Option<IssuedCredential> {
    if !payment_receipt_vc_enabled() {
        return None;
    }
    sign_credential(
        "PaymentAccessGrantCredential",
        AccessGrantSubject {
            rail: input.rail,
            trace_id: input.trace_id,
            remote: AccessGrantRemote {
                gateway_id: input.payment_gateway_id,
                surface_id: input.payment_surface_id,
                status: input.remote_status,
            },
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn receipt_subject_omits_absent_optionals_and_reports_stage_from_settled() {
        let provisional = ReceiptSubject {
            payment_id: "txn-1".to_string(),
            rail: "x402",
            stage: "verified",
            trace_id: None,
            amount: None,
            currency: None,
            method: None,
            payer: None,
            resource: None,
            settlement: None,
        };
        let json = serde_json::to_value(&provisional).unwrap();
        assert_eq!(json["paymentId"], "txn-1");
        assert_eq!(json["stage"], "verified");
        assert!(json.get("traceId").is_none());
        assert!(
            json.get("settlement")
                .is_none()
        );

        let settled = ReceiptSubject {
            stage: "settled",
            settlement: Some(SettlementEvidence {
                tx_hash: Some("0xabc".to_string()),
                network: Some("eip155:1".to_string()),
                confirmations: Some(3),
            }),
            ..provisional
        };
        let json = serde_json::to_value(&settled).unwrap();
        assert_eq!(json["stage"], "settled");
        assert_eq!(json["settlement"]["txHash"], "0xabc");
        assert_eq!(json["settlement"]["confirmations"], 3);
    }

    #[test]
    fn rejection_subject_always_carries_reason() {
        let subject = RejectionSubject {
            payment_id: "txn-2".to_string(),
            rail: "mpp",
            trace_id: Some("trace-1".to_string()),
            method: None,
            payer: None,
            reason: "invalid signature".to_string(),
        };
        let json = serde_json::to_value(&subject).unwrap();
        assert_eq!(json["rail"], "mpp");
        assert_eq!(json["traceId"], "trace-1");
        assert_eq!(json["reason"], "invalid signature");
        assert!(json.get("method").is_none());
    }

    #[test]
    fn access_grant_subject_nests_remote_fields() {
        let subject = AccessGrantSubject {
            rail: "x402",
            trace_id: Some("trace-2".to_string()),
            remote: AccessGrantRemote {
                gateway_id: Some("gw-pay".to_string()),
                surface_id: Some("pay-ch".to_string()),
                status: 200,
            },
        };
        let json = serde_json::to_value(&subject).unwrap();
        assert_eq!(json["remote"]["gatewayId"], "gw-pay");
        assert_eq!(json["remote"]["surfaceId"], "pay-ch");
        assert_eq!(json["remote"]["status"], 200);
    }

    #[tokio::test]
    async fn issuance_returns_none_without_settings_or_issuer() {
        let _guard = AUTHORITY_TEST_LOCK
            .lock()
            .await;
        clear_global_authority();
        // Neither a global settings store nor a VCIssuer is registered in a
        // bare unit-test process, so every issuance path must fail closed to
        // `None` rather than panicking or blocking a payment.
        let receipt = issue_payment_receipt(PaymentReceiptInput {
            rail: "x402",
            payment_id: "txn-3".to_string(),
            ..Default::default()
        })
        .await;
        assert!(receipt.is_none());

        let rejection = issue_payment_rejection(PaymentRejectionInput {
            rail: "x402",
            payment_id: "txn-3".to_string(),
            reason: "denied".to_string(),
            ..Default::default()
        })
        .await;
        assert!(rejection.is_none());

        let grant = issue_access_grant(AccessGrantInput {
            rail: "x402",
            remote_status: 200,
            ..Default::default()
        })
        .await;
        assert!(grant.is_none());
    }

    /// `GLOBAL_AUTHORITY` is process-wide, so the tests that install one must
    /// not run concurrently with each other.
    static AUTHORITY_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn clear_global_authority() {
        *GLOBAL_AUTHORITY
            .write()
            .unwrap() = None;
    }

    /// Stands in for whichever backend `[vta]` selected: records the claims it
    /// was handed and either returns a canned token or reports the backend as
    /// unreachable.
    struct RecordingAuthority {
        did: &'static str,
        reachable: bool,
        signed: std::sync::Mutex<Vec<Value>>,
    }

    impl RecordingAuthority {
        fn new(
            did: &'static str,
            reachable: bool,
        ) -> Arc<Self> {
            Arc::new(Self {
                did,
                reachable,
                signed: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn claims(&self) -> Vec<Value> {
            self.signed
                .lock()
                .unwrap()
                .clone()
        }
    }

    #[async_trait::async_trait]
    impl CredentialAuthority for RecordingAuthority {
        async fn issuer_did(&self) -> anyhow::Result<String> {
            Ok(self.did.to_string())
        }

        async fn issuer_jwks(&self) -> anyhow::Result<Value> {
            Ok(serde_json::json!({ "keys": [] }))
        }

        async fn sign_token(
            &self,
            claims: &Value,
        ) -> anyhow::Result<String> {
            self.signed
                .lock()
                .unwrap()
                .push(claims.clone());
            if !self.reachable {
                anyhow::bail!("backend unreachable");
            }
            Ok("header.payload.signature".to_string())
        }

        async fn sign_token_typ(
            &self,
            claims: &Value,
            _typ: &str,
        ) -> anyhow::Result<String> {
            self.sign_token(claims).await
        }
    }

    #[tokio::test]
    async fn signing_routes_through_the_selected_authority() {
        let _guard = AUTHORITY_TEST_LOCK
            .lock()
            .await;
        let authority = RecordingAuthority::new("did:webvh:vta-under-test", true);
        set_global_payment_credential_authority(authority.clone());

        let issued = sign_credential("PaymentReceiptCredential", serde_json::json!({ "paymentId": "txn-9" }))
            .await
            .expect("the selected authority signs the receipt");

        assert_eq!(issued.jwt, "header.payload.signature");
        assert_eq!(issued.fingerprint, crate::delegation_vault::audit::vp_fingerprint(&issued.jwt));

        let claims = authority.claims();
        assert_eq!(claims.len(), 1, "exactly one signing call is made");
        // The issuer DID comes from the selected backend, not from a local key.
        assert_eq!(claims[0]["issuer"], "did:webvh:vta-under-test");
        assert_eq!(claims[0]["type"][1], "PaymentReceiptCredential");
        assert_eq!(claims[0]["credentialSubject"]["paymentId"], "txn-9");
        assert!(
            claims[0]["jti"]
                .as_str()
                .unwrap()
                .starts_with("urn:uuid:")
        );

        clear_global_authority();
    }

    #[tokio::test]
    async fn an_unreachable_authority_yields_no_credential_rather_than_a_local_one() {
        let _guard = AUTHORITY_TEST_LOCK
            .lock()
            .await;
        let authority = RecordingAuthority::new("did:webvh:vta-under-test", false);
        set_global_payment_credential_authority(authority.clone());

        let issued = sign_credential("PaymentReceiptCredential", serde_json::json!({ "paymentId": "txn-10" })).await;

        // Fail closed: no credential at all, never one substituted from a
        // different (local) key that a dispute arbiter would mis-attribute.
        assert!(issued.is_none());
        assert_eq!(authority.claims().len(), 1, "the failure came from the selected backend, not a fallback");

        clear_global_authority();
    }

    #[tokio::test]
    async fn registering_the_selected_authority_replaces_the_local_default() {
        let _guard = AUTHORITY_TEST_LOCK
            .lock()
            .await;
        let first = RecordingAuthority::new("did:key:local-default", true);
        set_global_payment_credential_authority(first.clone());
        let second = RecordingAuthority::new("did:webvh:selected-connector", true);
        set_global_payment_credential_authority(second.clone());

        sign_credential("PaymentReceiptCredential", serde_json::json!({ "paymentId": "txn-11" }))
            .await
            .expect("signs");

        assert!(first.claims().is_empty(), "the local default must not keep signing once a connector is selected");
        assert_eq!(second.claims()[0]["issuer"], "did:webvh:selected-connector");

        clear_global_authority();
    }

    #[tokio::test]
    async fn the_feature_flag_gates_issuance_before_the_authority_is_consulted() {
        let _guard = AUTHORITY_TEST_LOCK
            .lock()
            .await;
        let authority = RecordingAuthority::new("did:webvh:vta-under-test", true);
        set_global_payment_credential_authority(authority.clone());

        // `payment_receipt_vc` is off in a bare test process, so no signing
        // overhead is incurred even with a connector registered.
        let issued = issue_payment_receipt(PaymentReceiptInput {
            rail: "x402",
            payment_id: "txn-12".to_string(),
            ..Default::default()
        })
        .await;

        assert!(issued.is_none());
        assert!(authority.claims().is_empty());

        clear_global_authority();
    }
}
