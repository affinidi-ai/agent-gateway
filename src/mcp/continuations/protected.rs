use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{ContinuationError, ContinuationRecord, MAX_ROUNDS, MAX_TTL_SECS};
use crate::encryption::aes_gcm::AesGcmEncryptor;
use crate::mcp::request_validation::ValidatedModernMessage;

const MAX_STATE_BYTES: usize = 32 * 1024;
const MAX_ENCODED_BYTES: usize = 64 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContinuationRoute {
    AccessPoint,
    TransitPoint { alias: String },
    Fabric { peer_did: String },
    FabricSend { peer_did: String },
    StandaloneProxy,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationBinding {
    pub deployment: String,
    pub principal: String,
    pub agent_did: String,
    pub user_identity_hash: String,
    pub authorization_digest: [u8; 32],
    pub tenant_id: Option<String>,
    pub surface_id: String,
    pub variant_id: Option<String>,
    pub route: ContinuationRoute,
    pub resource: String,
    pub provider_id: String,
    pub scopes: Vec<String>,
    pub method: String,
    pub arguments_digest: [u8; 32],
}

impl ContinuationBinding {
    pub fn digest(&self) -> Result<[u8; 32], ContinuationError> {
        let valid_text = |text: &str| {
            !text.is_empty()
                && text.len() <= 4096
                && !text
                    .chars()
                    .any(char::is_control)
        };
        if ![
            &self.deployment,
            &self.principal,
            &self.agent_did,
            &self.user_identity_hash,
            &self.surface_id,
            &self.provider_id,
            &self.resource,
        ]
        .into_iter()
        .all(|text| valid_text(text))
            || !self
                .agent_did
                .starts_with("did:")
            || self.scopes.len() > 128
            || self
                .scopes
                .iter()
                .any(|scope| {
                    scope.is_empty()
                        || scope.len() > 256
                        || scope
                            .bytes()
                            .any(|byte| !matches!(byte, 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
                })
            || self
                .tenant_id
                .as_deref()
                .is_some_and(|tenant| !valid_text(tenant))
            || self
                .variant_id
                .as_deref()
                .is_some_and(|variant| !valid_text(variant))
            || self.authorization_digest == [0; 32]
            || self.arguments_digest == [0; 32]
            || !valid_text(&self.method)
            || match &self.route {
                ContinuationRoute::TransitPoint { alias } => !valid_text(alias),
                ContinuationRoute::Fabric { peer_did } | ContinuationRoute::FabricSend { peer_did } => {
                    !valid_text(peer_did) || !peer_did.starts_with("did:")
                }
                _ => false,
            }
        {
            return Err(ContinuationError::InvalidRecord);
        }
        let resource = url::Url::parse(&self.resource).map_err(|_| ContinuationError::InvalidRecord)?;
        if !matches!(resource.scheme(), "http" | "https")
            || resource.host().is_none()
            || !resource.username().is_empty()
            || resource.password().is_some()
            || resource.fragment().is_some()
        {
            return Err(ContinuationError::InvalidRecord);
        }
        let canonical =
            Zeroizing::new(serde_json_canonicalizer::to_vec(self).map_err(|_| ContinuationError::InvalidRecord)?);
        Ok(Sha256::digest(canonical.as_slice()).into())
    }

    pub(super) fn matches_delegation(
        &self,
        token: &crate::delegation_vault::DelegationToken,
        now: u64,
    ) -> bool {
        token.agent_did == self.agent_did
            && token.user_identity_hash == self.user_identity_hash
            && token.credential_provider_id == self.provider_id
            && !token.access_token.is_empty()
            && token
                .expires_at
                .is_none_or(|expiry| u64::try_from(expiry.timestamp()).is_ok_and(|expiry| expiry > now))
            && self
                .scopes
                .iter()
                .all(|scope| token.scopes.contains(scope))
    }
}

pub fn request_arguments_digest(request: &ValidatedModernMessage) -> Result<[u8; 32], ContinuationError> {
    if request.method.is_empty()
        || request.method.len() > 4096
        || request
            .method
            .chars()
            .any(char::is_control)
    {
        return Err(ContinuationError::InvalidRecord);
    }
    let mut params = match request.params.as_ref() {
        Some(Value::Object(params)) => params.clone(),
        None => serde_json::Map::new(),
        _ => return Err(ContinuationError::InvalidRecord),
    };
    for field in ["_meta", "inputResponses", "requestState"] {
        params.remove(field);
    }
    let mut nodes = 0;
    validate_canonical_numbers(&Value::Object(params.clone()), 0, &mut nodes)?;
    let canonical = Zeroizing::new(
        serde_json_canonicalizer::to_vec(&json!({"method": request.method, "params": params}))
            .map_err(|_| ContinuationError::InvalidRecord)?,
    );
    if canonical.len() > 1024 * 1024 {
        return Err(ContinuationError::InvalidRecord);
    }
    Ok(Sha256::digest(canonical.as_slice()).into())
}

fn validate_canonical_numbers(
    value: &Value,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), ContinuationError> {
    *nodes += 1;
    if *nodes > 8192 || depth > 64 {
        return Err(ContinuationError::InvalidRecord);
    }
    match value {
        Value::Number(number) => {
            let number = number
                .as_f64()
                .ok_or(ContinuationError::InvalidRecord)?;
            if !number.is_finite() || number.fract() == 0.0 && number.abs() > 9_007_199_254_740_991.0 {
                return Err(ContinuationError::InvalidRecord);
            }
        }
        Value::Object(object) => {
            for value in object.values() {
                validate_canonical_numbers(value, depth + 1, nodes)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                validate_canonical_numbers(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamContinuation {
    pub request_state: Option<String>,
    pub input_responses: Option<Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub input_keys: Vec<String>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationKind {
    #[default]
    Consent,
    Forwarded,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContinuationPayment {
    X402 { receipt: Option<String>, verified_at: u64, expires_at: u64 },
    Mpp { receipt: Option<String>, verified_at: u64, expires_at: u64 },
}

impl ContinuationPayment {
    pub fn expires_at(&self) -> u64 {
        match self {
            Self::X402 { expires_at, .. } | Self::Mpp { expires_at, .. } => *expires_at,
        }
    }

    pub fn validate(
        &self,
        now: u64,
    ) -> Result<(), ContinuationError> {
        let (receipt, verified_at, expires_at) = match self {
            Self::X402 {
                receipt,
                verified_at,
                expires_at,
            }
            | Self::Mpp {
                receipt,
                verified_at,
                expires_at,
            } => (receipt, *verified_at, *expires_at),
        };
        if verified_at > now
            || expires_at <= now
            || expires_at
                .checked_sub(verified_at)
                .is_none_or(|ttl| ttl == 0 || ttl > MAX_TTL_SECS)
            || receipt
                .as_ref()
                .is_some_and(|receipt| {
                    receipt.is_empty()
                        || receipt.len() > 16 * 1024
                        || axum::http::HeaderValue::from_str(receipt).is_err()
                })
        {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationClaims {
    pub version: u8,
    pub id: Uuid,
    pub binding: ContinuationBinding,
    pub issued_at: u64,
    pub expires_at: u64,
    pub previous_request_id: Value,
    pub round: u8,
    #[serde(default)]
    pub kind: ContinuationKind,
    pub upstream: Option<UpstreamContinuation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment: Option<ContinuationPayment>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsentTicket {
    pub id: Uuid,
    pub continuation_id: Uuid,
    pub binding: ContinuationBinding,
    pub issued_at: u64,
    pub expires_at: u64,
    pub provider_digest: [u8; 32],
    pub surface_digest: [u8; 32],
    pub identity_strategy_digest: [u8; 32],
    pub callback_url: String,
    pub code_verifier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault_snapshot: Option<crate::delegation_vault::storage::ConsentSnapshot>,
}

impl ConsentTicket {
    pub fn validate(
        &self,
        callback: bool,
        now: u64,
    ) -> Result<(), ContinuationError> {
        ContinuationRecord {
            id: self.id,
            binding_digest: self.binding.digest()?,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revision: 0,
            round: 0,
            phase: super::ContinuationPhase::PendingConsent,
        }
        .check_access(&self.binding.digest()?, now)?;
        if self.continuation_id.is_nil()
            || !matches!(self.binding.method.as_str(), "tools/call" | "prompts/get" | "resources/read")
            || self.provider_digest == [0; 32]
            || self.surface_digest == [0; 32]
            || self.identity_strategy_digest == [0; 32]
            || crate::sts::mcp_profile::canonical_https_url(&self.callback_url).is_err()
            || match &self.code_verifier {
                Some(verifier) => {
                    !callback
                        || !(43..=128).contains(&verifier.len())
                        || !verifier
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
                }
                None => callback,
            }
        {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum StatePurpose {
    Retry,
    ConsentConnect,
    ConsentCallback,
}

impl StatePurpose {
    fn label(self) -> &'static str {
        match self {
            Self::Retry => "mcp-continuation",
            Self::ConsentConnect => "mcp-consent-connect",
            Self::ConsentCallback => "mcp-consent-callback",
        }
    }
}

impl ContinuationClaims {
    fn validate(
        &self,
        now: u64,
    ) -> Result<[u8; 32], ContinuationError> {
        let digest = self.binding.digest()?;
        if let Some(payment) = &self.payment {
            payment.validate(now)?;
            if self.expires_at > payment.expires_at() {
                return Err(ContinuationError::InvalidRecord);
            }
        }
        let record = ContinuationRecord {
            id: self.id,
            binding_digest: digest,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            revision: 0,
            round: self.round,
            phase: super::ContinuationPhase::PendingInput,
        };
        record.check_access(&digest, now)?;
        if self.version != 1
            || !matches!(self.binding.method.as_str(), "tools/call" | "prompts/get" | "resources/read")
            || self.round >= MAX_ROUNDS
            || !(self
                .previous_request_id
                .is_string()
                || self
                    .previous_request_id
                    .as_i64()
                    .is_some()
                || self
                    .previous_request_id
                    .as_u64()
                    .is_some())
            || self
                .previous_request_id
                .as_str()
                .is_some_and(|id| id.len() > 1024)
            || self
                .upstream
                .as_ref()
                .is_some_and(|upstream| {
                    upstream.input_keys.len() > 128
                        || upstream
                            .input_keys
                            .iter()
                            .any(|key| key.len() > 1024)
                        || upstream
                            .input_responses
                            .as_ref()
                            .is_some_and(|responses| !responses.is_object())
                })
            || (self.kind == ContinuationKind::Forwarded && self.upstream.is_none())
        {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(digest)
    }
}

pub struct ContinuationKey {
    id: String,
    material: Zeroizing<[u8; 32]>,
    not_before: u64,
    seal_until: u64,
    open_until: u64,
}

impl ContinuationKey {
    pub fn new(
        id: String,
        material: [u8; 32],
        not_before: u64,
        seal_until: u64,
        open_until: u64,
    ) -> Result<Self, ContinuationError> {
        if id.is_empty()
            || id.len() > 64
            || !id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            || material == [0; 32]
            || seal_until <= not_before
            || open_until < seal_until
            || open_until - seal_until > MAX_TTL_SECS
        {
            return Err(ContinuationError::KeyUnavailable);
        }
        Ok(Self {
            id,
            material: Zeroizing::new(material),
            not_before,
            seal_until,
            open_until,
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StateEnvelope {
    version: u8,
    key_id: String,
    ciphertext: String,
}

pub struct ContinuationCipher {
    deployment: String,
    active_key: String,
    keys: HashMap<String, ContinuationKey>,
    encryptor: AesGcmEncryptor,
}

impl ContinuationCipher {
    pub fn new(
        deployment: String,
        active_key: String,
        keys: Vec<ContinuationKey>,
    ) -> Result<Self, ContinuationError> {
        if deployment.is_empty()
            || deployment.len() > 128
            || deployment
                .chars()
                .any(char::is_control)
            || keys.is_empty()
            || keys.len() > 4
        {
            return Err(ContinuationError::KeyUnavailable);
        }
        let mut key_ring = HashMap::new();
        for key in keys {
            if key_ring
                .insert(key.id.clone(), key)
                .is_some()
            {
                return Err(ContinuationError::KeyUnavailable);
            }
        }
        if !key_ring.contains_key(&active_key) {
            return Err(ContinuationError::KeyUnavailable);
        }
        Ok(Self {
            deployment,
            active_key,
            keys: key_ring,
            encryptor: AesGcmEncryptor::new(),
        })
    }

    fn associated_data(
        &self,
        key_id: &str,
        purpose: StatePurpose,
    ) -> Result<Vec<u8>, ContinuationError> {
        serde_json_canonicalizer::to_vec(
            &json!({"purpose": purpose.label(), "version": 1, "deployment": self.deployment, "key_id": key_id}),
        )
        .map_err(|_| ContinuationError::InvalidState)
    }

    pub fn seal(
        &self,
        claims: &ContinuationClaims,
        now: u64,
    ) -> Result<String, ContinuationError> {
        claims.validate(now)?;
        if claims.binding.deployment != self.deployment {
            return Err(ContinuationError::BindingMismatch);
        }
        self.protect(claims, claims.issued_at, claims.expires_at, StatePurpose::Retry, now)
    }

    pub fn seal_consent(
        &self,
        ticket: &ConsentTicket,
        callback: bool,
        now: u64,
    ) -> Result<String, ContinuationError> {
        ticket.validate(callback, now)?;
        if ticket.binding.deployment != self.deployment {
            return Err(ContinuationError::BindingMismatch);
        }
        self.protect(
            ticket,
            ticket.issued_at,
            ticket.expires_at,
            if callback {
                StatePurpose::ConsentCallback
            } else {
                StatePurpose::ConsentConnect
            },
            now,
        )
    }

    fn protect<T: Serialize>(
        &self,
        value: &T,
        issued_at: u64,
        expires_at: u64,
        purpose: StatePurpose,
        now: u64,
    ) -> Result<String, ContinuationError> {
        let key = self
            .keys
            .get(&self.active_key)
            .ok_or(ContinuationError::KeyUnavailable)?;
        if now < key.not_before || now >= key.seal_until || issued_at < key.not_before || expires_at > key.open_until {
            return Err(ContinuationError::KeyUnavailable);
        }
        let plaintext = Zeroizing::new(serde_json::to_vec(value).map_err(|_| ContinuationError::InvalidState)?);
        if plaintext.len() > MAX_STATE_BYTES {
            return Err(ContinuationError::InvalidState);
        }
        let ciphertext = self
            .encryptor
            .encrypt_with_aad(&key.material, &plaintext, &self.associated_data(&key.id, purpose)?)
            .map_err(|_| ContinuationError::InvalidState)?;
        let envelope = StateEnvelope {
            version: 1,
            key_id: key.id.clone(),
            ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
        };
        let encoded =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).map_err(|_| ContinuationError::InvalidState)?);
        if encoded.len() > MAX_ENCODED_BYTES {
            return Err(ContinuationError::InvalidState);
        }
        Ok(encoded)
    }

    pub fn open(
        &self,
        encoded: &str,
        expected: &ContinuationBinding,
        request_id: &Value,
        now: u64,
    ) -> Result<ContinuationClaims, ContinuationError> {
        let claims = self.inspect(encoded, now)?;
        if claims.binding.digest()? != expected.digest()? {
            return Err(ContinuationError::BindingMismatch);
        }
        if claims.previous_request_id == *request_id {
            return Err(ContinuationError::RepeatedRequestId);
        }
        Ok(claims)
    }

    pub(super) fn inspect(
        &self,
        encoded: &str,
        now: u64,
    ) -> Result<ContinuationClaims, ContinuationError> {
        let (claims, key): (ContinuationClaims, _) = self.unprotect(encoded, StatePurpose::Retry, now)?;
        claims.validate(now)?;
        if claims.binding.deployment != self.deployment
            || claims.issued_at < key.not_before
            || claims.issued_at >= key.seal_until
            || claims.expires_at > key.open_until
        {
            return Err(ContinuationError::BindingMismatch);
        }
        Ok(claims)
    }

    pub fn open_consent(
        &self,
        encoded: &str,
        callback: bool,
        now: u64,
    ) -> Result<ConsentTicket, ContinuationError> {
        let (ticket, key): (ConsentTicket, _) = self.unprotect(
            encoded,
            if callback {
                StatePurpose::ConsentCallback
            } else {
                StatePurpose::ConsentConnect
            },
            now,
        )?;
        ticket.validate(callback, now)?;
        if ticket.binding.deployment != self.deployment
            || ticket.issued_at < key.not_before
            || ticket.issued_at >= key.seal_until
            || ticket.expires_at > key.open_until
        {
            return Err(ContinuationError::BindingMismatch);
        }
        Ok(ticket)
    }

    fn unprotect<T: serde::de::DeserializeOwned>(
        &self,
        encoded: &str,
        purpose: StatePurpose,
        now: u64,
    ) -> Result<(T, &ContinuationKey), ContinuationError> {
        if encoded.len() > MAX_ENCODED_BYTES || encoded.is_empty() {
            return Err(ContinuationError::InvalidState);
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|_| ContinuationError::InvalidState)?;
        let envelope: StateEnvelope = serde_json::from_slice(&bytes).map_err(|_| ContinuationError::InvalidState)?;
        if envelope.version != 1 {
            return Err(ContinuationError::InvalidState);
        }
        let key = self
            .keys
            .get(&envelope.key_id)
            .ok_or(ContinuationError::KeyUnavailable)?;
        if now < key.not_before || now >= key.open_until {
            return Err(ContinuationError::KeyUnavailable);
        }
        let ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .map_err(|_| ContinuationError::InvalidState)?;
        if ciphertext.len() > MAX_STATE_BYTES + 28 {
            return Err(ContinuationError::InvalidState);
        }
        let plaintext = Zeroizing::new(
            self.encryptor
                .decrypt_with_aad(&key.material, &ciphertext, &self.associated_data(&key.id, purpose)?)
                .map_err(|_| ContinuationError::InvalidState)?,
        );
        let value = serde_json::from_slice(&plaintext).map_err(|_| ContinuationError::InvalidState)?;
        Ok((value, key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::request_validation::McpMessageKind;

    #[test]
    fn consent_tickets_cannot_be_reused_as_retry_or_callback_state() {
        let cipher = ContinuationCipher::new("deployment".into(), "key".into(), vec![key("key", 7)]).unwrap();
        let claims = claims();
        let mut ticket = ConsentTicket {
            id: Uuid::new_v4(),
            continuation_id: claims.id,
            binding: claims.binding.clone(),
            issued_at: 10,
            expires_at: 100,
            provider_digest: [3; 32],
            surface_digest: [4; 32],
            identity_strategy_digest: [5; 32],
            callback_url: "https://gateway.example/consent/callback".into(),
            code_verifier: None,
            vault_snapshot: None,
        };
        let connect = cipher
            .seal_consent(&ticket, false, 10)
            .unwrap();
        assert_eq!(
            cipher
                .open_consent(&connect, false, 11)
                .unwrap()
                .id,
            ticket.id
        );
        assert!(
            cipher
                .open_consent(&connect, true, 11)
                .is_err()
        );
        assert!(
            cipher
                .open(&connect, &claims.binding, &json!(2), 11)
                .is_err()
        );
        let retry = cipher
            .seal(&claims, 10)
            .unwrap();
        assert!(
            cipher
                .open_consent(&retry, false, 11)
                .is_err()
        );
        ticket.code_verifier = Some("v".repeat(43));
        let callback = cipher
            .seal_consent(&ticket, true, 10)
            .unwrap();
        assert!(
            cipher
                .open_consent(&callback, false, 11)
                .is_err()
        );
        assert_eq!(
            cipher
                .open_consent(&callback, true, 11)
                .unwrap()
                .code_verifier,
            ticket.code_verifier
        );
        assert!(
            cipher
                .open_consent(&callback, true, 100)
                .is_err()
        );
        assert!(
            cipher
                .seal_consent(&ticket, false, 11)
                .is_err()
        );
    }

    fn request() -> ValidatedModernMessage {
        ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.to_string(),
            client_capabilities: Some(json!({})),
            client_info: None,
            method: "tools/call".into(),
            params: Some(json!({"name": "lookup", "arguments": {"city": "Paris", "count": 1}, "vendor": true})),
            id: Some(json!(1)),
            kind: McpMessageKind::Request,
        }
    }

    fn claims() -> ContinuationClaims {
        ContinuationClaims {
            version: 1,
            id: Uuid::new_v4(),
            issued_at: 10,
            expires_at: 100,
            previous_request_id: json!(1),
            round: 0,
            kind: ContinuationKind::Consent,
            binding: ContinuationBinding {
                deployment: "deployment".into(),
                principal: "principal-hash".into(),
                agent_did: "did:web:agent.example".into(),
                user_identity_hash: "user-hash".into(),
                authorization_digest: [2; 32],
                tenant_id: Some("tenant".into()),
                surface_id: Uuid::new_v4().to_string(),
                variant_id: Some("variant".into()),
                route: ContinuationRoute::AccessPoint,
                resource: "https://gateway.example/mcp".into(),
                provider_id: "provider".into(),
                scopes: vec!["read".into()],
                method: "tools/call".into(),
                arguments_digest: request_arguments_digest(&request()).unwrap(),
            },
            upstream: Some(UpstreamContinuation {
                request_state: Some("opaque upstream continuation".into()),
                input_responses: Some(json!({"upstream-key": {"action": "accept"}})),
                input_keys: Vec::new(),
            }),
            payment: None,
        }
    }

    fn key(
        id: &str,
        material: u8,
    ) -> ContinuationKey {
        ContinuationKey::new(id.to_string(), [material; 32], 1, 100, 1000).unwrap()
    }

    #[test]
    fn payment_evidence_is_encrypted_bounded_and_cannot_extend_its_validity() {
        let cipher = ContinuationCipher::new("deployment".into(), "key-1".into(), vec![key("key-1", 1)]).unwrap();
        let mut claims = claims();
        claims.payment = Some(ContinuationPayment::X402 {
            receipt: Some("private-receipt".into()),
            verified_at: 10,
            expires_at: 100,
        });
        let encoded = cipher
            .seal(&claims, 10)
            .unwrap();
        assert!(!encoded.contains("private-receipt"));
        let opened = cipher
            .open(&encoded, &claims.binding, &json!(2), 11)
            .unwrap();
        assert!(opened.payment == claims.payment);
        claims.expires_at = 101;
        assert!(matches!(cipher.seal(&claims, 10), Err(ContinuationError::InvalidRecord)));
        claims.expires_at = 100;
        for (verified_at, expires_at, receipt) in [
            (11, 100, Some("receipt".into())),
            (10, 10, None),
            (10, 911, None),
            (10, 100, Some("bad\r\nreceipt".into())),
            (10, 100, Some("x".repeat(16 * 1024 + 1))),
        ] {
            claims.payment = Some(ContinuationPayment::Mpp {
                receipt,
                verified_at,
                expires_at,
            });
            assert!(
                cipher
                    .seal(&claims, 10)
                    .is_err()
            );
        }
        let mut envelope: serde_json::Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&encoded)
                .unwrap(),
        )
        .unwrap();
        let mut ciphertext = URL_SAFE_NO_PAD
            .decode(
                envelope["ciphertext"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        ciphertext[20] ^= 1;
        envelope["ciphertext"] = json!(URL_SAFE_NO_PAD.encode(ciphertext));
        let tampered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap());
        assert!(
            cipher
                .open(&tampered, &claims.binding, &json!(2), 11)
                .is_err()
        );
    }

    #[test]
    fn protected_state_binds_context_and_preserves_opaque_upstream_state() {
        let cipher = ContinuationCipher::new("deployment".into(), "key-1".into(), vec![key("key-1", 1)]).unwrap();
        let claims = claims();
        let encoded = cipher
            .seal(&claims, 10)
            .unwrap();
        assert_ne!(
            encoded,
            cipher
                .seal(&claims, 10)
                .unwrap()
        );
        assert!(!encoded.contains("principal-hash"));
        let opened = cipher
            .open(&encoded, &claims.binding, &json!(2), 11)
            .unwrap();
        assert!(opened == claims);
        assert!(matches!(
            cipher.open(&encoded, &claims.binding, &json!(1), 11),
            Err(ContinuationError::RepeatedRequestId)
        ));
        assert!(matches!(cipher.open(&encoded, &claims.binding, &json!(2), 100), Err(ContinuationError::Expired)));
        for field in
            ["principal", "surface_id", "variant_id", "tenant_id", "resource", "provider_id", "deployment", "method"]
        {
            let mut changed = serde_json::to_value(&claims.binding).unwrap();
            changed[field] = match field {
                "resource" => json!("https://gateway.example/other"),
                "method" => json!("resources/read"),
                _ => json!("other"),
            };
            let changed: ContinuationBinding = serde_json::from_value(changed).unwrap();
            assert!(
                matches!(cipher.open(&encoded, &changed, &json!(2), 11), Err(ContinuationError::BindingMismatch)),
                "{field}"
            );
        }
        let mut changed = claims.binding.clone();
        changed.route = ContinuationRoute::Fabric {
            peer_did: "did:example:peer".into(),
        };
        assert!(matches!(cipher.open(&encoded, &changed, &json!(2), 11), Err(ContinuationError::BindingMismatch)));
        changed = claims.binding.clone();
        changed.authorization_digest = [3; 32];
        assert!(matches!(cipher.open(&encoded, &changed, &json!(2), 11), Err(ContinuationError::BindingMismatch)));
    }

    #[test]
    fn protected_state_rejects_tampering_unknown_keys_and_unbounded_rotation() {
        let cipher = ContinuationCipher::new("deployment".into(), "old".into(), vec![key("old", 1)]).unwrap();
        let claims = claims();
        let encoded = cipher
            .seal(&claims, 10)
            .unwrap();
        let mut envelope: StateEnvelope = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&encoded)
                .unwrap(),
        )
        .unwrap();
        let mut ciphertext = URL_SAFE_NO_PAD
            .decode(&envelope.ciphertext)
            .unwrap();
        ciphertext[12] ^= 1;
        envelope.ciphertext = URL_SAFE_NO_PAD.encode(ciphertext);
        let tampered = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&envelope).unwrap());
        assert!(matches!(cipher.open(&tampered, &claims.binding, &json!(2), 11), Err(ContinuationError::InvalidState)));
        let rotated =
            ContinuationCipher::new("deployment".into(), "new".into(), vec![key("old", 1), key("new", 2)]).unwrap();
        assert!(
            rotated
                .open(&encoded, &claims.binding, &json!(2), 11)
                .is_ok()
        );
        let retired = ContinuationCipher::new("deployment".into(), "new".into(), vec![key("new", 2)]).unwrap();
        assert!(matches!(
            retired.open(&encoded, &claims.binding, &json!(2), 11),
            Err(ContinuationError::KeyUnavailable)
        ));
        let other = ContinuationCipher::new("other".into(), "old".into(), vec![key("old", 1)]).unwrap();
        assert!(matches!(other.open(&encoded, &claims.binding, &json!(2), 11), Err(ContinuationError::InvalidState)));
        assert!(ContinuationKey::new("key".into(), [1; 32], 1, 100, 1001).is_err());
        assert!(ContinuationCipher::new("deployment".into(), "old".into(), vec![]).is_err());
        assert!(
            cipher
                .open(&"x".repeat(MAX_ENCODED_BYTES + 1), &claims.binding, &json!(2), 11)
                .is_err()
        );
        assert!(
            cipher
                .open("plaintext", &claims.binding, &json!(2), 11)
                .is_err()
        );
    }

    #[test]
    fn request_digest_is_canonical_and_ignores_only_root_retry_fields() {
        let original = request();
        let digest = request_arguments_digest(&original).unwrap();
        let mut retry = original.clone();
        retry.id = Some(json!(2));
        retry.params = Some(json!({"vendor": true, "arguments": {"count": 1.0, "city": "Paris"}, "name": "lookup",
            "_meta": {"progressToken": "new", "io.modelcontextprotocol/clientCapabilities": {"elicitation": {}}},
            "inputResponses": {"key": {"action": "accept"}}, "requestState": "opaque"}));
        assert_eq!(request_arguments_digest(&retry).unwrap(), digest);
        retry.params.as_mut().unwrap()["arguments"]["city"] = json!("Berlin");
        assert_ne!(request_arguments_digest(&retry).unwrap(), digest);
        retry = original.clone();
        retry.params.as_mut().unwrap()["arguments"]["_meta"] = json!({"business": true});
        assert_ne!(request_arguments_digest(&retry).unwrap(), digest);
        retry.params.as_mut().unwrap()["arguments"]["count"] = json!(9_007_199_254_740_992_u64);
        assert_eq!(request_arguments_digest(&retry), Err(ContinuationError::InvalidRecord));
        retry = original;
        retry.params.as_mut().unwrap()["vendor"] = json!(false);
        assert_ne!(request_arguments_digest(&retry).unwrap(), digest);
    }
}
