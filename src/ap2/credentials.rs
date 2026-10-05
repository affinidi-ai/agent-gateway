// AP2 credential transformation module
// Converts VDC mandates to W3C Verifiable Credentials

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::vdc::{MandateType, VDC};

/// W3C Verifiable Credential structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiableCredential {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub credential_types: Vec<String>,
    pub id: String,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Value,
    pub proof: Option<CredentialProof>,
}

/// W3C Credential Proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// Transform VDC mandate to W3C Verifiable Credential
///
/// Args:
/// - vdc: The VDC to transform
/// - gateway_did: Gateway's DID (used as issuer)
/// - subject_did: DID to use as credential subject (agent's DID or gateway's DID)
pub async fn transform_vdc_to_vc(
    vdc: &VDC,
    gateway_did: &str,
    subject_did: &str,
) -> Result<VerifiableCredential> {
    info!("Transforming VDC {} to W3C VC (subject: {})", vdc.id, subject_did);

    // Determine credential type based on mandate type
    let mandate_type = vdc.get_mandate_type()?;
    let credential_type = match mandate_type {
        MandateType::IntentMandate => "PurchaseIntentCredential",
        MandateType::CartMandate => "ShoppingCartCredential",
        MandateType::PaymentMandate => "PaymentAuthorizationCredential",
    };

    debug!("VDC mandate type: {} -> W3C type: {}", mandate_type, credential_type);

    // Validate authorization tokens if present
    validate_authorization_tokens(vdc).await?;

    // Extract credential data from VDC
    let credential_data = vdc.get_credential_data();

    // Build credential subject
    let mut subject = HashMap::new();
    subject.insert("id".to_string(), json!(subject_did));

    // Add all VDC credential subject data
    for (key, value) in credential_data {
        subject.insert(key, value);
    }

    // Add validation metadata
    subject.insert("validatedBy".to_string(), json!(gateway_did));
    subject.insert("validatedAt".to_string(), json!(chrono::Utc::now().to_rfc3339()));
    subject.insert("originalMandateId".to_string(), json!(vdc.id.clone()));
    subject.insert("originalIssuer".to_string(), json!(vdc.issuer.clone()));
    subject.insert("mandateType".to_string(), json!(vdc.mandate_type.clone()));

    // Add authorization token metadata if present
    if vdc
        .authorization_jwt
        .is_some()
    {
        subject.insert("authorizationType".to_string(), json!("JWT"));
    } else if vdc
        .authorization_sd_jwt_vc
        .is_some()
    {
        subject.insert("authorizationType".to_string(), json!("SD-JWT-VC"));
    }

    // Generate credential ID using subject DID
    let vc_id = format!("{}#vc-{}", subject_did, uuid::Uuid::new_v4());

    // Create W3C VC
    let vc = VerifiableCredential {
        context: vec![
            "https://www.w3.org/2018/credentials/v1".to_string(),
            "https://ap2-protocol.org/credentials/v1".to_string(),
        ],
        credential_types: vec!["VerifiableCredential".to_string(), credential_type.to_string()],
        id: vc_id.clone(),
        issuer: gateway_did.to_string(),
        issuance_date: chrono::Utc::now().to_rfc3339(),
        credential_subject: serde_json::to_value(subject)?,
        proof: None, // Will be added by sign_credential
    };

    // Sign the credential
    sign_credential(vc, gateway_did).await
}

/// Validate authorization tokens in VDC
async fn validate_authorization_tokens(vdc: &VDC) -> Result<()> {
    // Validate JWT authorization (for CartMandate)
    if let Some(jwt) = &vdc.authorization_jwt {
        debug!("Validating CartMandate JWT authorization");
        // TODO: Call gateway's /verify-jwt endpoint or implement JWT validation
        // For now, just check basic structure
        if jwt.split('.').count() != 3 {
            warn!("Invalid JWT format in CartMandate authorization");
            return Err(anyhow::anyhow!("Invalid JWT format"));
        }
        debug!("✓ JWT authorization structure valid");
    }

    // Validate SD-JWT-VC authorization (for PaymentMandate)
    if let Some(sd_jwt_vc) = &vdc.authorization_sd_jwt_vc {
        debug!("Validating PaymentMandate SD-JWT-VC authorization");
        // TODO: Call gateway's /verify-jwt endpoint with SD-JWT-VC
        // For now, just check basic structure (should have at least one tilde)
        if !sd_jwt_vc.contains('~') {
            warn!("Invalid SD-JWT-VC format in PaymentMandate authorization");
            return Err(anyhow::anyhow!("Invalid SD-JWT-VC format"));
        }
        debug!("✓ SD-JWT-VC authorization structure valid");
    }

    Ok(())
}

/// Sign a W3C Verifiable Credential.
///
/// Real signing (with the gateway's private key) is not implemented. Rather
/// than emit a credential carrying a fabricated `proofValue` that masquerades
/// as a genuine signature, this fails closed.
async fn sign_credential(
    _vc: VerifiableCredential,
    _gateway_did: &str,
) -> Result<VerifiableCredential> {
    Err(anyhow::anyhow!(
        "AP2 credential signing is not implemented; refusing to emit a credential with a fabricated proof"
    ))
}

/// Convert a Verifiable Credential to signed JWT form.
///
/// Real JWT signing is not implemented. The previous stub emitted a JWT with a
/// literal `unsigned` signature segment, which any lenient consumer could treat
/// as authentic, so this now fails closed instead of producing an unsigned JWT.
pub fn vc_to_jwt(_vc: &VerifiableCredential) -> Result<String> {
    Err(anyhow::anyhow!("AP2 VC-to-JWT signing is not implemented; refusing to emit an unsigned credential JWT"))
}

/// Extract credential type name for display/logging
#[allow(dead_code)]
pub fn get_credential_type_name(vc: &VerifiableCredential) -> String {
    vc.credential_types
        .iter()
        .find(|t| *t != "VerifiableCredential")
        .cloned()
        .unwrap_or_else(|| "UnknownCredential".to_string())
}

#[cfg(test)]
#[path = "credentials.test.rs"]
mod credentials_test;
