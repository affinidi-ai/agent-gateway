// AP2 Verifiable Presentation module
// Creates W3C Verifiable Presentations from Verifiable Credentials

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::info;

use super::credentials::VerifiableCredential;

/// W3C Verifiable Presentation structure
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiablePresentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub presentation_types: Vec<String>,
    pub id: String,
    pub holder: Option<String>,
    #[serde(rename = "verifiableCredential")]
    pub verifiable_credential: Vec<VerifiableCredential>,
    pub proof: Option<PresentationProof>,
}

/// W3C Presentation Proof structure
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresentationProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    pub challenge: Option<String>,
    pub domain: Option<String>,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// Create a Verifiable Presentation from one or more Verifiable Credentials
#[allow(dead_code)]
pub async fn create_presentation(
    credentials: Vec<VerifiableCredential>,
    gateway_did: &str,
    gateway_key_id: &str,
    holder_did: Option<String>,
) -> Result<VerifiablePresentation> {
    info!("Creating VP with {} credentials", credentials.len());

    let vp_id = format!("urn:uuid:{}", uuid::Uuid::new_v4());

    let mut vp = VerifiablePresentation {
        context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
        presentation_types: vec!["VerifiablePresentation".to_string()],
        id: vp_id.clone(),
        holder: holder_did,
        verifiable_credential: credentials,
        proof: None,
    };

    // Sign the presentation
    vp = sign_presentation(vp, gateway_did, gateway_key_id).await?;

    info!("✓ Successfully created VP: {}", vp_id);

    Ok(vp)
}

/// Sign a Verifiable Presentation.
///
/// Real signing is not implemented. Rather than attach a fabricated `proofValue`
/// that masquerades as a genuine signature, this fails closed.
#[allow(dead_code)]
async fn sign_presentation(
    _vp: VerifiablePresentation,
    _gateway_did: &str,
    _gateway_key_id: &str,
) -> Result<VerifiablePresentation> {
    Err(anyhow::anyhow!(
        "AP2 presentation signing is not implemented; refusing to emit a presentation with a fabricated proof"
    ))
}

/// Create a VP from a single VC (common case for AP2 mandates)
#[allow(dead_code)]
pub async fn create_single_credential_presentation(
    credential: VerifiableCredential,
    gateway_did: &str,
    gateway_key_id: &str,
    holder_did: Option<String>,
) -> Result<VerifiablePresentation> {
    create_presentation(vec![credential], gateway_did, gateway_key_id, holder_did).await
}

/// Convert VP to JSON value for injection into message metadata
#[allow(dead_code)]
pub fn vp_to_json(vp: &VerifiablePresentation) -> Result<Value> {
    serde_json::to_value(vp).map_err(Into::into)
}

#[cfg(test)]
#[path = "presentation.test.rs"]
mod presentation_test;
