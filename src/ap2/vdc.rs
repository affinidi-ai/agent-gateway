// AP2 VDC (Verifiable Digital Credential) validation module
// Handles signature validation for IntentMandate, CartMandate, and PaymentMandate

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, info, warn};

use super::mandates::{Ap2Mandate, parse_sd_jwt_vc};

/// AP2 Mandate types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
#[allow(clippy::enum_variant_names)]
pub enum MandateType {
    IntentMandate,
    CartMandate,
    PaymentMandate,
}

impl std::fmt::Display for MandateType {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            MandateType::IntentMandate => write!(f, "IntentMandate"),
            MandateType::CartMandate => write!(f, "CartMandate"),
            MandateType::PaymentMandate => write!(f, "PaymentMandate"),
        }
    }
}

/// VDC Proof structure (cryptographic signature)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VdcProof {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub created: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofValue")]
    pub proof_value: String,
}

/// Base VDC structure (all mandates follow this format)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub struct VDC {
    #[serde(rename = "@context")]
    pub context: String,
    #[serde(rename = "type")]
    pub mandate_type: String,
    pub id: String,
    pub issuer: String,
    #[serde(rename = "issuanceDate")]
    pub issuance_date: String,
    #[serde(rename = "credentialSubject")]
    pub credential_subject: Value,
    pub proof: VdcProof,

    /// JWT authorization token (for CartMandate merchant_authorization)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_jwt: Option<String>,

    /// SD-JWT-VC authorization token (for PaymentMandate user_authorization)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization_sd_jwt_vc: Option<String>,
}

/// Validation result with detailed information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub valid: bool,
    pub mandate_type: String,
    pub mandate_id: String,
    pub issuer_did: String,
    pub validated_at: String,
    pub errors: Vec<String>,
}

impl VDC {
    /// Parse VDC from JSON value
    /// Supports both W3C VC-wrapped format and official AP2 plain mandate format
    pub fn from_value(value: &Value) -> Result<Self> {
        // Try parsing as W3C VC-wrapped VDC first
        if let Ok(vdc) = serde_json::from_value::<VDC>(value.clone()) {
            return Ok(vdc);
        }

        // If that fails, try converting from plain AP2 mandate format
        Self::from_ap2_mandate(value)
    }

    /// Convert official AP2 mandate format to VDC structure
    /// AP2 mandates are structured objects from the Ap2Mandate enum
    fn from_ap2_mandate_enum(mandate: Ap2Mandate) -> Result<Self> {
        match mandate {
            Ap2Mandate::Intent(intent) => {
                // IntentMandate - no signature in human-present flow
                Ok(VDC {
                    context: "https://ap2-protocol.org/mandates/v1".to_string(),
                    mandate_type: "IntentMandate".to_string(),
                    id: format!("intent-{}", uuid::Uuid::new_v4()),
                    issuer: "did:ap2:shopping-agent".to_string(),
                    issuance_date: chrono::Utc::now().to_rfc3339(),
                    credential_subject: serde_json::to_value(&intent)?,
                    proof: VdcProof {
                        proof_type: "AP2IntentMandate".to_string(),
                        created: chrono::Utc::now().to_rfc3339(),
                        verification_method: "did:ap2:shopping-agent#key-1".to_string(),
                        proof_value: "unsigned-intent-mandate".to_string(),
                    },
                    authorization_jwt: None,
                    authorization_sd_jwt_vc: None,
                })
            }
            Ap2Mandate::Cart(cart) => {
                // CartMandate - extract merchant_authorization JWT
                let auth_jwt = cart
                    .merchant_authorization
                    .clone()
                    .ok_or_else(|| anyhow!("CartMandate missing merchant_authorization"))?;

                // Extract issuer from JWT if possible
                let issuer = extract_issuer_from_jwt(&auth_jwt).unwrap_or_else(|| "did:ap2:merchant-agent".to_string());

                Ok(VDC {
                    context: "https://ap2-protocol.org/mandates/v1".to_string(),
                    mandate_type: "CartMandate".to_string(),
                    id: cart.contents.id.clone(),
                    issuer: issuer.clone(),
                    issuance_date: chrono::Utc::now().to_rfc3339(),
                    credential_subject: serde_json::to_value(&cart.contents)?,
                    proof: VdcProof {
                        proof_type: "AP2JwtSignature".to_string(),
                        created: chrono::Utc::now().to_rfc3339(),
                        verification_method: format!("{}#key-1", issuer),
                        proof_value: auth_jwt.clone(),
                    },
                    authorization_jwt: Some(auth_jwt),
                    authorization_sd_jwt_vc: None,
                })
            }
            Ap2Mandate::Payment(payment) => {
                // PaymentMandate - extract user_authorization SD-JWT-VC
                let auth_sd_jwt_vc = payment
                    .user_authorization
                    .clone()
                    .ok_or_else(|| anyhow!("PaymentMandate missing user_authorization"))?;

                // Parse SD-JWT-VC to get issuer
                let (issuer_jwt, _kb_jwt) = parse_sd_jwt_vc(&auth_sd_jwt_vc)?;
                let issuer =
                    extract_issuer_from_jwt(&issuer_jwt).unwrap_or_else(|| "did:ap2:credentials-provider".to_string());

                Ok(VDC {
                    context: "https://ap2-protocol.org/mandates/v1".to_string(),
                    mandate_type: "PaymentMandate".to_string(),
                    id: format!("payment-{}", uuid::Uuid::new_v4()),
                    issuer: issuer.clone(),
                    issuance_date: chrono::Utc::now().to_rfc3339(),
                    credential_subject: serde_json::to_value(&payment.payment_mandate_contents)?,
                    proof: VdcProof {
                        proof_type: "AP2SdJwtVcSignature".to_string(),
                        created: chrono::Utc::now().to_rfc3339(),
                        verification_method: format!("{}#key-1", issuer),
                        proof_value: issuer_jwt.clone(),
                    },
                    authorization_jwt: None,
                    authorization_sd_jwt_vc: Some(auth_sd_jwt_vc),
                })
            }
        }
    }

    /// Convert from JSON Value (backward compatibility)
    fn from_ap2_mandate(value: &Value) -> Result<Self> {
        let mandate = Ap2Mandate::from_value(value)?;
        Self::from_ap2_mandate_enum(mandate)
    }

    /// Validate VDC structure and signature
    pub async fn validate(&self) -> Result<ValidationResult> {
        info!("Validating VDC mandate: {} (type: {})", self.id, self.mandate_type);

        let mut errors = Vec::new();
        let validated_at = chrono::Utc::now().to_rfc3339();

        // 1. Validate mandate type
        if !self.is_valid_mandate_type() {
            errors.push(format!("Invalid mandate type: {}", self.mandate_type));
        }

        // 2. Validate context
        if !self
            .context
            .starts_with("https://ap2-protocol.org")
        {
            errors.push(format!("Invalid context: {}", self.context));
        }

        // 3. Validate issuer DID format
        if !self
            .issuer
            .starts_with("did:")
        {
            errors.push(format!("Invalid issuer DID format: {}", self.issuer));
        }

        // 4. Validate issuance date
        if let Err(e) = chrono::DateTime::parse_from_rfc3339(&self.issuance_date) {
            errors.push(format!("Invalid issuance date: {}", e));
        }

        // 5. Validate proof structure
        if let Err(e) = self.validate_proof_structure() {
            errors.push(format!("Invalid proof structure: {}", e));
        }

        // 6. Validate signature (cryptographic verification)
        match self
            .validate_signature()
            .await
        {
            Ok(true) => debug!("Signature validation passed for {}", self.id),
            Ok(false) => errors.push("Signature validation failed".to_string()),
            Err(e) => errors.push(format!("Signature validation error: {}", e)),
        }

        // 7. Validate credential subject based on mandate type
        if let Err(e) = self.validate_credential_subject() {
            errors.push(format!("Invalid credential subject: {}", e));
        }

        let valid = errors.is_empty();

        if valid {
            info!("✓ VDC validation successful: {}", self.id);
        } else {
            warn!("✗ VDC validation failed: {} - {:?}", self.id, errors);
        }

        Ok(ValidationResult {
            valid,
            mandate_type: self.mandate_type.clone(),
            mandate_id: self.id.clone(),
            issuer_did: self.issuer.clone(),
            validated_at,
            errors,
        })
    }

    /// Check if mandate type is valid
    fn is_valid_mandate_type(&self) -> bool {
        matches!(self.mandate_type.as_str(), "IntentMandate" | "CartMandate" | "PaymentMandate")
    }

    /// Validate proof structure
    fn validate_proof_structure(&self) -> Result<()> {
        if self
            .proof
            .proof_type
            .is_empty()
        {
            return Err(anyhow!("Missing proof type"));
        }

        if !self
            .proof
            .verification_method
            .starts_with("did:")
        {
            return Err(anyhow!("Invalid verification method DID"));
        }

        if self
            .proof
            .proof_value
            .is_empty()
        {
            return Err(anyhow!("Missing proof value"));
        }

        if chrono::DateTime::parse_from_rfc3339(&self.proof.created).is_err() {
            return Err(anyhow!("Invalid proof creation date"));
        }

        Ok(())
    }

    /// Validate cryptographic signature.
    ///
    /// Real signature verification (resolve the issuer DID, obtain its public
    /// key, reconstruct the signed VDC, and verify `proof.proofValue`) is not
    /// yet implemented. Until it is, this **fails closed**: an unverifiable
    /// signature is never reported as valid, so the gateway will not accept a
    /// forged or unsigned AP2 mandate as authentic.
    async fn validate_signature(&self) -> Result<bool> {
        warn!("AP2 VDC signature verification is not implemented; rejecting {} as unverified", self.id);
        Ok(false)
    }

    /// Validate credential subject based on mandate type
    fn validate_credential_subject(&self) -> Result<()> {
        let subject = &self.credential_subject;

        match self.mandate_type.as_str() {
            "IntentMandate" => {
                // IntentMandate follows AP2 spec with natural_language_description
                // Required field: natural_language_description
                // Optional fields: intent_expiry, user_cart_confirmation_required, merchants, skus, requires_refundability
                if subject
                    .get("natural_language_description")
                    .is_none()
                {
                    return Err(anyhow!("IntentMandate missing 'natural_language_description' field"));
                }
                // Other fields are optional, so no further validation needed
            }
            "CartMandate" => {
                // CartMandate follows AP2 spec with contents field
                // Required field: contents (object containing cart details)
                if subject
                    .get("contents")
                    .is_none()
                {
                    return Err(anyhow!("CartMandate missing 'contents' field"));
                }
                // merchant_authorization is optional
            }
            "PaymentMandate" => {
                // PaymentMandate follows AP2 spec with payment_mandate_contents
                // Required field: payment_mandate_contents
                if subject
                    .get("payment_mandate_contents")
                    .is_none()
                {
                    return Err(anyhow!("PaymentMandate missing 'payment_mandate_contents' field"));
                }
            }
            _ => {
                return Err(anyhow!("Unknown mandate type: {}", self.mandate_type));
            }
        }

        Ok(())
    }

    /// Extract mandate type as enum
    pub fn get_mandate_type(&self) -> Result<MandateType> {
        match self.mandate_type.as_str() {
            "IntentMandate" => Ok(MandateType::IntentMandate),
            "CartMandate" => Ok(MandateType::CartMandate),
            "PaymentMandate" => Ok(MandateType::PaymentMandate),
            _ => Err(anyhow!("Unknown mandate type: {}", self.mandate_type)),
        }
    }

    /// Get credential subject data for transformation to W3C VC
    pub fn get_credential_data(&self) -> HashMap<String, Value> {
        let mut data = HashMap::new();

        // Add all credentialSubject fields
        if let Value::Object(subject_map) = &self.credential_subject {
            for (key, value) in subject_map {
                data.insert(key.clone(), value.clone());
            }
        }

        // Note: Metadata (originalMandateId, originalIssuer, mandateType) is added
        // by transform_vdc_to_vc() to avoid duplication

        data
    }
}

/// Extract issuer DID from JWT without full verification
/// This is a best-effort extraction for metadata purposes
fn extract_issuer_from_jwt(jwt: &str) -> Option<String> {
    // JWT format: header.payload.signature
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return None;
    }

    // Decode payload (base64url)
    let payload_bytes = base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, parts[1]).ok()?;

    // Parse JSON
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;

    // Extract iss claim
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract VDC from AP2 message payload
pub fn extract_vdc_from_message(message: &Value) -> Result<Option<VDC>> {
    // Use official AP2 mandate extraction
    let mandate = Ap2Mandate::extract_from_message(message)?;

    if let Some(m) = mandate {
        // Convert AP2 mandate to VDC structure directly
        let vdc = VDC::from_ap2_mandate_enum(m)?;
        return Ok(Some(vdc));
    }

    // Fallback: Check for W3C VC-wrapped VDC in extensions.payment.vdc (legacy path)
    if let Some(extensions) = message
        .get("params")
        .and_then(|p| p.get("extensions"))
        && let Some(payment) = extensions.get("payment")
        && let Some(vdc_value) = payment.get("vdc")
    {
        debug!("Found W3C VC in extensions.payment.vdc (legacy)");
        if let Ok(raw_json) = serde_json::to_string_pretty(vdc_value) {
            info!("📦 Raw VDC data from extensions.payment.vdc:\n{}", raw_json);
        }
        return VDC::from_value(vdc_value).map(Some);
    }

    // Fallback: Check for W3C VC in top-level mandate field (legacy)
    if let Some(mandate) = message.get("mandate") {
        debug!("Found W3C VC in top-level mandate field (legacy)");
        if let Ok(raw_json) = serde_json::to_string_pretty(mandate) {
            info!("📦 Raw VDC data from top-level mandate:\n{}", raw_json);
        }
        return VDC::from_value(mandate).map(Some);
    }

    // No VDC found
    Ok(None)
}

#[cfg(test)]
#[path = "vdc.test.rs"]
mod vdc_test;
