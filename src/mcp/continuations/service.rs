use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde_json::Value;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use super::consent::{ConsentResponse, parse_response};
use super::protected::{
    ConsentTicket, ContinuationBinding, ContinuationCipher, ContinuationClaims, ContinuationKind, ContinuationPayment,
    UpstreamContinuation, request_arguments_digest,
};
use super::{ContinuationError, ContinuationPhase, ContinuationRecord, ContinuationStore};
use crate::delegation_vault::{
    DelegationToken,
    storage::{DelegationVaultStorage, StagedConsent},
};
use crate::mcp::request_validation::{McpMessageKind, ValidatedModernMessage};

/// Continuations one principal may have issued and not yet expired, unless
/// configured otherwise.
pub const DEFAULT_MAX_PENDING_PER_PRINCIPAL: usize = 64;

/// Principals tracked before those with no live continuation are pruned.
const PRINCIPALS_BEFORE_PRUNE: usize = 4096;

pub struct ContinuationService {
    cipher: ContinuationCipher,
    store: Arc<dyn ContinuationStore>,
    pending: PrincipalQuota,
}

/// Counts the continuations each principal has issued until they expire, so
/// one caller cannot use up the store's capacity for everyone. Counted per
/// process: with a shared store, each process applies its own limit.
struct PrincipalQuota {
    max_per_principal: usize,
    /// Expiry of each continuation issued, by principal.
    issued: Mutex<HashMap<[u8; 32], Vec<u64>>>,
}

impl PrincipalQuota {
    /// The principal is the deployment, tenant and caller a binding names.
    fn owner(binding: &ContinuationBinding) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for part in [
            binding.deployment.as_str(),
            binding
                .tenant_id
                .as_deref()
                .unwrap_or_default(),
            binding.principal.as_str(),
        ] {
            hasher.update((part.len() as u64).to_be_bytes());
            hasher.update(part.as_bytes());
        }
        hasher.finalize().into()
    }

    /// Takes one of `owner`'s slots until `expires_at`.
    fn reserve(
        &self,
        owner: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<(), ContinuationError> {
        let mut issued = self
            .issued
            .lock()
            .map_err(|_| ContinuationError::Unavailable)?;
        if issued.len() > PRINCIPALS_BEFORE_PRUNE {
            issued.retain(|_, expiries| {
                expiries.retain(|expiry| *expiry > now);
                !expiries.is_empty()
            });
        }
        let expiries = issued
            .entry(owner)
            .or_default();
        expiries.retain(|expiry| *expiry > now);
        if expiries.len() >= self.max_per_principal {
            return Err(ContinuationError::PrincipalLimit);
        }
        expiries.push(expires_at);
        Ok(())
    }

    /// Gives back a slot whose continuation was never stored.
    fn release(
        &self,
        owner: [u8; 32],
        expires_at: u64,
    ) {
        if let Ok(mut issued) = self.issued.lock()
            && let Some(expiries) = issued.get_mut(&owner)
            && let Some(position) = expiries
                .iter()
                .position(|expiry| *expiry == expires_at)
        {
            expiries.swap_remove(position);
        }
    }
}

pub struct IssuedContinuation {
    pub state: String,
    pub id: Uuid,
    pub expires_at: u64,
}

pub struct ResumedContinuation {
    claims: ContinuationClaims,
    record: ContinuationRecord,
    request_id: Value,
    consent_response: ConsentResponse,
}

impl ResumedContinuation {
    pub fn phase(&self) -> ContinuationPhase {
        self.record.phase
    }

    #[cfg(test)]
    pub fn id(&self) -> Uuid {
        self.record.id
    }

    pub fn kind(&self) -> ContinuationKind {
        self.claims.kind
    }

    pub fn has_payment(&self) -> bool {
        self.claims.payment.is_some()
    }
}

pub struct ClaimedContinuation {
    claims: ContinuationClaims,
    record: ContinuationRecord,
}

pub struct ClaimedConsent {
    pub ticket: ConsentTicket,
    record: ContinuationRecord,
}

pub enum DelegationClaim {
    Pending(Box<ResumedContinuation>),
    Claimed { continuation: Box<ClaimedContinuation>, credential: Box<DelegationToken> },
}

impl ClaimedContinuation {
    pub fn payment(&self) -> Option<&ContinuationPayment> {
        self.claims.payment.as_ref()
    }

    pub fn expires_at(&self) -> u64 {
        self.record.expires_at
    }

    pub fn restore_upstream_request(
        &self,
        request: &ValidatedModernMessage,
    ) -> Result<ValidatedModernMessage, ContinuationError> {
        validate_request(request, &self.claims.binding)?;
        let mut restored = request.clone();
        let params = restored
            .params
            .as_mut()
            .and_then(Value::as_object_mut)
            .ok_or(ContinuationError::InvalidRecord)?;
        params.remove("requestState");
        params.remove("inputResponses");
        if let Some(upstream) = self.claims.upstream.as_ref() {
            if let Some(state) = upstream
                .request_state
                .as_ref()
            {
                params.insert("requestState".to_string(), Value::String(state.clone()));
            }
            let forwarded_responses = (self.claims.kind == ContinuationKind::Forwarded)
                .then(|| {
                    request
                        .params
                        .as_ref()
                        .and_then(|params| params.get("inputResponses"))
                        .and_then(Value::as_object)
                        .map(|responses| {
                            Value::Object(
                                responses
                                    .iter()
                                    .filter(|(key, _)| {
                                        upstream
                                            .input_keys
                                            .contains(key)
                                    })
                                    .map(|(key, value)| (key.clone(), value.clone()))
                                    .collect(),
                            )
                        })
                })
                .flatten();
            if let Some(responses) = forwarded_responses
                .as_ref()
                .or(upstream
                    .input_responses
                    .as_ref())
            {
                params.insert("inputResponses".to_string(), responses.clone());
            }
        }
        Ok(restored)
    }
}

impl ContinuationService {
    pub fn new(
        cipher: ContinuationCipher,
        store: Arc<dyn ContinuationStore>,
    ) -> Self {
        Self {
            cipher,
            store,
            pending: PrincipalQuota {
                max_per_principal: DEFAULT_MAX_PENDING_PER_PRINCIPAL,
                issued: Mutex::new(HashMap::new()),
            },
        }
    }

    /// Limits the continuations one principal may have pending at once.
    pub fn with_max_pending_per_principal(
        mut self,
        max: usize,
    ) -> Self {
        self.pending.max_per_principal = max;
        self
    }

    #[cfg(test)]
    pub async fn issue_consent(
        &self,
        request: &ValidatedModernMessage,
        binding: ContinuationBinding,
        provider_digest: [u8; 32],
        surface_digest: [u8; 32],
        identity_strategy_digest: [u8; 32],
        callback_url: String,
        ttl_secs: u64,
        now: u64,
    ) -> Result<(IssuedContinuation, String), ContinuationError> {
        self.issue_consent_with_payment(
            request,
            binding,
            provider_digest,
            surface_digest,
            identity_strategy_digest,
            callback_url,
            None,
            ttl_secs,
            now,
        )
        .await
    }

    pub async fn issue_consent_with_payment(
        &self,
        request: &ValidatedModernMessage,
        binding: ContinuationBinding,
        provider_digest: [u8; 32],
        surface_digest: [u8; 32],
        identity_strategy_digest: [u8; 32],
        callback_url: String,
        payment: Option<ContinuationPayment>,
        ttl_secs: u64,
        now: u64,
    ) -> Result<(IssuedContinuation, String), ContinuationError> {
        let ticket_id = Uuid::new_v4();
        let issued = self
            .issue_with_payment(request, binding.clone(), payment, ttl_secs, now)
            .await?;
        let ticket = ConsentTicket {
            id: ticket_id,
            continuation_id: issued.id,
            binding,
            issued_at: now,
            expires_at: issued.expires_at,
            provider_digest,
            surface_digest,
            identity_strategy_digest,
            callback_url,
            code_verifier: None,
            vault_snapshot: None,
        };
        let connect = self
            .cipher
            .seal_consent(&ticket, false, now)?;
        Ok((issued, connect))
    }

    pub async fn read_consent_ticket(
        &self,
        encoded: &str,
        callback: bool,
        now: u64,
    ) -> Result<ConsentTicket, ContinuationError> {
        let ticket = self
            .cipher
            .open_consent(encoded, callback, now)?;
        self.check_consent_parent(&ticket, now)
            .await?;
        Ok(ticket)
    }

    async fn check_consent_parent(
        &self,
        ticket: &ConsentTicket,
        now: u64,
    ) -> Result<(), ContinuationError> {
        let record = self
            .store
            .get(ticket.continuation_id, ticket.binding.digest()?, now)
            .await?;
        if record.issued_at != ticket.issued_at || record.expires_at != ticket.expires_at {
            return Err(ContinuationError::BindingMismatch);
        }
        match record.phase {
            ContinuationPhase::PendingConsent | ContinuationPhase::Ready => Ok(()),
            ContinuationPhase::Denied => Err(ContinuationError::Denied),
            _ => Err(ContinuationError::Conflict),
        }
    }

    pub async fn begin_consent_callback(
        &self,
        mut ticket: ConsentTicket,
        code_verifier: String,
        vault: &dyn DelegationVaultStorage,
        now: u64,
    ) -> Result<String, ContinuationError> {
        ticket.validate(false, now)?;
        self.check_consent_parent(&ticket, now)
            .await?;
        ticket.code_verifier = Some(code_verifier);
        ticket.vault_snapshot = Some(
            vault
                .consent_snapshot(
                    &ticket.binding.agent_did,
                    &ticket
                        .binding
                        .user_identity_hash,
                    &ticket.binding.provider_id,
                )
                .await
                .map_err(|_| ContinuationError::Unavailable)?,
        );
        let encoded = self
            .cipher
            .seal_consent(&ticket, true, now)?;
        self.store
            .create(
                ContinuationRecord {
                    id: ticket.id,
                    binding_digest: ticket.binding.digest()?,
                    issued_at: ticket.issued_at,
                    expires_at: ticket.expires_at,
                    revision: 0,
                    round: 0,
                    phase: ContinuationPhase::PendingConsent,
                },
                now,
            )
            .await?;
        Ok(encoded)
    }

    pub async fn claim_consent_callback(
        &self,
        ticket: ConsentTicket,
        now: u64,
    ) -> Result<ClaimedConsent, ContinuationError> {
        ticket.validate(true, now)?;
        if ticket
            .vault_snapshot
            .is_none()
        {
            return Err(ContinuationError::InvalidRecord);
        }
        self.check_consent_parent(&ticket, now)
            .await?;
        let record = self
            .store
            .get(ticket.id, ticket.binding.digest()?, now)
            .await?;
        if record.issued_at != ticket.issued_at
            || record.expires_at != ticket.expires_at
            || record.phase != ContinuationPhase::PendingConsent
        {
            return Err(ContinuationError::Conflict);
        }
        let ready = self
            .store
            .advance(record.id, record.expectation(), ContinuationPhase::Ready, now)
            .await?;
        let record = self
            .store
            .advance(ready.id, ready.expectation(), ContinuationPhase::Claimed, now)
            .await?;
        Ok(ClaimedConsent { ticket, record })
    }

    pub async fn deny_consent_callback(
        &self,
        ticket: &ConsentTicket,
        now: u64,
    ) -> Result<(), ContinuationError> {
        ticket.validate(true, now)?;
        self.check_consent_parent(ticket, now)
            .await?;
        let callback = self
            .store
            .get(ticket.id, ticket.binding.digest()?, now)
            .await?;
        if callback.issued_at != ticket.issued_at
            || callback.expires_at != ticket.expires_at
            || callback.phase != ContinuationPhase::PendingConsent
        {
            return Err(ContinuationError::Conflict);
        }
        self.store
            .advance(callback.id, callback.expectation(), ContinuationPhase::Denied, now)
            .await?;
        for _attempt in 0..=super::MAX_ROUNDS {
            let parent = self
                .store
                .get(ticket.continuation_id, ticket.binding.digest()?, now)
                .await?;
            match parent.phase {
                ContinuationPhase::Denied => return Ok(()),
                ContinuationPhase::PendingConsent | ContinuationPhase::Ready => {}
                _ => return Err(ContinuationError::Conflict),
            }
            match self
                .store
                .advance(parent.id, parent.expectation(), ContinuationPhase::Denied, now)
                .await
            {
                Err(ContinuationError::Conflict) => continue,
                result => return result.map(|_| ()),
            }
        }
        Err(ContinuationError::Conflict)
    }

    pub async fn complete_consent_callback(
        &self,
        consent: ClaimedConsent,
        vault: &dyn DelegationVaultStorage,
        credential: DelegationToken,
        now: u64,
    ) -> Result<(), ContinuationError> {
        consent
            .ticket
            .validate(true, now)?;
        if !consent
            .ticket
            .binding
            .matches_delegation(&credential, now)
        {
            return Err(ContinuationError::BindingMismatch);
        }
        self.check_consent_parent(&consent.ticket, now)
            .await?;
        let staged = StagedConsent {
            id: consent
                .ticket
                .continuation_id
                .to_string(),
            binding_digest: consent
                .ticket
                .binding
                .digest()?,
            issued_at: consent.ticket.issued_at,
            expires_at: consent.ticket.expires_at,
            snapshot: consent
                .ticket
                .vault_snapshot
                .clone()
                .ok_or(ContinuationError::InvalidRecord)?,
            credential,
        };
        vault
            .stage_consent(staged, now)
            .await
            .map_err(|_| ContinuationError::Unavailable)?;
        self.store
            .advance(consent.record.id, consent.record.expectation(), ContinuationPhase::Consumed, now)
            .await?;
        for _attempt in 0..=super::MAX_ROUNDS {
            self.check_consent_parent(&consent.ticket, now)
                .await?;
            let parent = self
                .store
                .get(
                    consent.ticket.continuation_id,
                    consent
                        .ticket
                        .binding
                        .digest()?,
                    now,
                )
                .await?;
            if parent.phase != ContinuationPhase::PendingConsent {
                return Err(if parent.phase == ContinuationPhase::Denied {
                    ContinuationError::Denied
                } else {
                    ContinuationError::Conflict
                });
            }
            match self
                .store
                .advance(parent.id, parent.expectation(), ContinuationPhase::Ready, now)
                .await
            {
                Err(ContinuationError::Conflict) => continue,
                result => return result.map(|_| ()),
            }
        }
        Err(ContinuationError::Conflict)
    }

    #[cfg(test)]
    pub async fn issue(
        &self,
        request: &ValidatedModernMessage,
        binding: ContinuationBinding,
        ttl_secs: u64,
        now: u64,
    ) -> Result<IssuedContinuation, ContinuationError> {
        self.issue_with_payment(request, binding, None, ttl_secs, now)
            .await
    }

    async fn issue_with_payment(
        &self,
        request: &ValidatedModernMessage,
        binding: ContinuationBinding,
        payment: Option<ContinuationPayment>,
        ttl_secs: u64,
        now: u64,
    ) -> Result<IssuedContinuation, ContinuationError> {
        let request_id = validate_request(request, &binding)?.clone();
        let params = request
            .params
            .as_ref()
            .and_then(Value::as_object)
            .ok_or(ContinuationError::InvalidRecord)?;
        let request_state = params
            .get("requestState")
            .map(|state| {
                state
                    .as_str()
                    .map(str::to_string)
                    .ok_or(ContinuationError::InvalidRecord)
            })
            .transpose()?;
        let input_responses = params
            .get("inputResponses")
            .map(|responses| {
                responses
                    .as_object()
                    .map(|_| responses.clone())
                    .ok_or(ContinuationError::InvalidRecord)
            })
            .transpose()?;
        let upstream = (request_state.is_some() || input_responses.is_some()).then_some(UpstreamContinuation {
            request_state,
            input_responses,
            input_keys: Vec::new(),
        });
        self.issue_record(request_id, binding, upstream, ContinuationKind::Consent, payment, ttl_secs, now)
            .await
    }

    #[cfg(test)]
    pub async fn wrap_upstream_response(
        &self,
        request: &ValidatedModernMessage,
        binding: ContinuationBinding,
        response: Value,
        ttl_secs: u64,
        now: u64,
    ) -> Result<Value, ContinuationError> {
        self.wrap_upstream_response_with_payment(request, binding, response, None, ttl_secs, now)
            .await
    }

    pub async fn wrap_upstream_response_with_payment(
        &self,
        request: &ValidatedModernMessage,
        binding: ContinuationBinding,
        mut response: Value,
        payment: Option<ContinuationPayment>,
        ttl_secs: u64,
        now: u64,
    ) -> Result<Value, ContinuationError> {
        let request_id = validate_request(request, &binding)?.clone();
        crate::mcp::modern::validate_response(request, &response, crate::mcp::modern::ResultSource::ModernServer)
            .map_err(|_| ContinuationError::InvalidRecord)?;
        let result = response
            .get_mut("result")
            .and_then(Value::as_object_mut)
            .filter(|result| {
                result
                    .get("resultType")
                    .and_then(Value::as_str)
                    == Some("input_required")
            })
            .ok_or(ContinuationError::InvalidRecord)?;
        let upstream = UpstreamContinuation {
            request_state: result
                .get("requestState")
                .and_then(Value::as_str)
                .map(str::to_string),
            input_responses: None,
            input_keys: result
                .get("inputRequests")
                .and_then(Value::as_object)
                .map(|requests| {
                    requests
                        .keys()
                        .cloned()
                        .collect()
                })
                .unwrap_or_default(),
        };
        let issued = self
            .issue_record(request_id, binding, Some(upstream), ContinuationKind::Forwarded, payment, ttl_secs, now)
            .await?;
        result.insert("requestState".into(), Value::String(issued.state));
        Ok(response)
    }

    async fn issue_record(
        &self,
        request_id: Value,
        binding: ContinuationBinding,
        upstream: Option<UpstreamContinuation>,
        kind: ContinuationKind,
        payment: Option<ContinuationPayment>,
        ttl_secs: u64,
        now: u64,
    ) -> Result<IssuedContinuation, ContinuationError> {
        let binding_digest = binding.digest()?;
        let owner = PrincipalQuota::owner(&binding);
        if !(1..=super::MAX_TTL_SECS).contains(&ttl_secs) {
            return Err(ContinuationError::InvalidRecord);
        }
        let mut expires_at = now
            .checked_add(ttl_secs)
            .ok_or(ContinuationError::InvalidRecord)?;
        if let Some(payment) = &payment {
            payment.validate(now)?;
            expires_at = expires_at.min(payment.expires_at());
        }
        let record = ContinuationRecord {
            id: Uuid::new_v4(),
            binding_digest,
            issued_at: now,
            expires_at,
            revision: 0,
            round: 0,
            phase: if kind == ContinuationKind::Consent {
                ContinuationPhase::PendingConsent
            } else {
                ContinuationPhase::PendingInput
            },
        };
        record.validate_new(now)?;
        let claims = ContinuationClaims {
            version: 1,
            id: record.id,
            binding,
            issued_at: now,
            expires_at: record.expires_at,
            previous_request_id: request_id,
            round: 0,
            kind,
            upstream,
            payment,
        };
        let state = self
            .cipher
            .seal(&claims, now)?;
        self.pending
            .reserve(owner, record.expires_at, now)?;
        if let Err(error) = self
            .store
            .create(record.clone(), now)
            .await
        {
            self.pending
                .release(owner, record.expires_at);
            return Err(error);
        }
        Ok(IssuedContinuation {
            state,
            id: record.id,
            expires_at: record.expires_at,
        })
    }

    pub fn request_binding(
        &self,
        encoded: &str,
        request: &ValidatedModernMessage,
        now: u64,
    ) -> Result<ContinuationBinding, ContinuationError> {
        let claims = self
            .cipher
            .inspect(encoded, now)?;
        let request_id = validate_request(request, &claims.binding)?;
        if request_id == &claims.previous_request_id {
            return Err(ContinuationError::RepeatedRequestId);
        }
        Ok(claims.binding)
    }

    pub async fn resume(
        &self,
        encoded: &str,
        binding: &ContinuationBinding,
        request: &ValidatedModernMessage,
        now: u64,
    ) -> Result<ResumedContinuation, ContinuationError> {
        let request_id = validate_request(request, binding)?;
        let claims = self
            .cipher
            .open(encoded, binding, request_id, now)?;
        let record = self
            .store
            .get(claims.id, binding.digest()?, now)
            .await?;
        if record.issued_at != claims.issued_at || record.expires_at != claims.expires_at {
            return Err(ContinuationError::BindingMismatch);
        }
        if record.round != claims.round {
            return Err(ContinuationError::Conflict);
        }
        match record.phase {
            ContinuationPhase::Claimed | ContinuationPhase::Consumed => return Err(ContinuationError::Conflict),
            ContinuationPhase::Denied => return Err(ContinuationError::Denied),
            _ => {}
        }
        let consent_response = if claims.kind == ContinuationKind::Consent {
            parse_response(request, claims.id)?
        } else {
            ConsentResponse::Missing
        };
        Ok(ResumedContinuation {
            claims,
            record,
            request_id: request_id.clone(),
            consent_response,
        })
    }

    pub async fn retry(
        &self,
        resumed: ResumedContinuation,
        now: u64,
    ) -> Result<IssuedContinuation, ContinuationError> {
        if !matches!(resumed.record.phase, ContinuationPhase::PendingInput | ContinuationPhase::PendingConsent) {
            return Err(ContinuationError::InvalidTransition);
        }
        let next = resumed
            .record
            .advance(&resumed.record.expectation(), resumed.record.phase, now)?;
        let claims = ContinuationClaims {
            previous_request_id: resumed.request_id,
            round: next.round,
            ..resumed.claims
        };
        let state = self
            .cipher
            .seal(&claims, now)?;
        self.store
            .advance(resumed.record.id, resumed.record.expectation(), resumed.record.phase, now)
            .await?;
        Ok(IssuedContinuation {
            state,
            id: next.id,
            expires_at: next.expires_at,
        })
    }

    pub async fn delegation_ready(
        &self,
        resumed: &ResumedContinuation,
        vault: &dyn DelegationVaultStorage,
        now: u64,
    ) -> Result<bool, ContinuationError> {
        if resumed.claims.kind != ContinuationKind::Consent
            || !matches!(resumed.record.phase, ContinuationPhase::PendingConsent | ContinuationPhase::Ready)
        {
            return Err(ContinuationError::InvalidTransition);
        }
        if matches!(resumed.consent_response, ConsentResponse::Decline | ConsentResponse::Cancel) {
            self.store
                .advance(resumed.record.id, resumed.record.expectation(), ContinuationPhase::Denied, now)
                .await?;
            return Err(ContinuationError::Denied);
        }
        if resumed.record.phase == ContinuationPhase::PendingConsent {
            return Ok(false);
        }
        let binding = &resumed.claims.binding;
        match vault
            .staged_consent(resumed.record.id, binding.digest()?, now)
            .await
            .map_err(|_| ContinuationError::Unavailable)?
        {
            Some(consent) if binding.matches_delegation(&consent.credential, now) => {}
            _ => {
                self.store
                    .advance(resumed.record.id, resumed.record.expectation(), ContinuationPhase::Denied, now)
                    .await?;
                return Err(ContinuationError::Denied);
            }
        };
        Ok(true)
    }

    pub async fn claim_delegation(
        &self,
        resumed: ResumedContinuation,
        vault: &dyn DelegationVaultStorage,
        now: u64,
    ) -> Result<DelegationClaim, ContinuationError> {
        if !self
            .delegation_ready(&resumed, vault, now)
            .await?
        {
            return Ok(DelegationClaim::Pending(Box::new(resumed)));
        }
        let continuation = self
            .claim(resumed, now)
            .await?;
        let credential = vault
            .activate_consent(
                continuation.record.id,
                continuation
                    .record
                    .binding_digest,
                now,
            )
            .await
            .map_err(|_| ContinuationError::Unavailable)?;
        if !continuation
            .claims
            .binding
            .matches_delegation(&credential, now)
        {
            return Err(ContinuationError::BindingMismatch);
        }
        Ok(DelegationClaim::Claimed {
            continuation: Box::new(continuation),
            credential: Box::new(credential),
        })
    }

    pub async fn claim_forwarded(
        &self,
        mut resumed: ResumedContinuation,
        now: u64,
    ) -> Result<ClaimedContinuation, ContinuationError> {
        if resumed.claims.kind != ContinuationKind::Forwarded
            || !matches!(resumed.record.phase, ContinuationPhase::PendingInput | ContinuationPhase::Ready)
        {
            return Err(ContinuationError::InvalidTransition);
        }
        if resumed.record.phase == ContinuationPhase::PendingInput {
            resumed.record = self
                .store
                .advance(resumed.record.id, resumed.record.expectation(), ContinuationPhase::Ready, now)
                .await?;
        }
        self.claim(resumed, now).await
    }

    async fn claim(
        &self,
        resumed: ResumedContinuation,
        now: u64,
    ) -> Result<ClaimedContinuation, ContinuationError> {
        if resumed.record.phase != ContinuationPhase::Ready {
            return Err(ContinuationError::InvalidTransition);
        }
        let record = self
            .store
            .advance(resumed.record.id, resumed.record.expectation(), ContinuationPhase::Claimed, now)
            .await?;
        Ok(ClaimedContinuation { claims: resumed.claims, record })
    }

    pub async fn complete(
        &self,
        claimed: ClaimedContinuation,
        now: u64,
    ) -> Result<(), ContinuationError> {
        self.store
            .advance(claimed.record.id, claimed.record.expectation(), ContinuationPhase::Consumed, now)
            .await?;
        Ok(())
    }
}

fn validate_request<'request>(
    request: &'request ValidatedModernMessage,
    binding: &ContinuationBinding,
) -> Result<&'request Value, ContinuationError> {
    let id = request
        .id
        .as_ref()
        .filter(|id| id.is_string() || id.as_i64().is_some() || id.as_u64().is_some())
        .ok_or(ContinuationError::InvalidRecord)?;
    if request.kind != McpMessageKind::Request
        || request.protocol_version != crate::mcp::MCP_MODERN_VERSION
        || !matches!(request.method.as_str(), "tools/call" | "prompts/get" | "resources/read")
        || binding.method != request.method
        || binding.arguments_digest != request_arguments_digest(request)?
    {
        return Err(ContinuationError::BindingMismatch);
    }
    binding.digest()?;
    Ok(id)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::super::embedded::EmbeddedContinuations;
    use super::super::protected::{ContinuationKey, ContinuationRoute};
    use super::*;

    #[tokio::test]
    async fn forwarded_continuations_preserve_opaque_state_and_isolate_input_keys() {
        let (service, _, request, binding) = setup();
        let collision = super::super::consent::input_key(Uuid::new_v4());
        let upstream = json!({"jsonrpc": "2.0", "id": request.id, "result": {
            "resultType": "input_required", "requestState": "not-gateway-state.opaque",
            "inputRequests": {&collision: {"method": "elicitation/create", "params": {
                "mode": "url", "url": "https://upstream.example/consent", "message": "Authorize"
            }}}
        }});
        let wrapped = service
            .wrap_upstream_response(&request, binding.clone(), upstream.clone(), 100, 10)
            .await
            .unwrap();
        assert_eq!(wrapped["result"]["inputRequests"], upstream["result"]["inputRequests"]);
        let encoded = wrapped["result"]["requestState"]
            .as_str()
            .unwrap();
        assert_ne!(encoded, "not-gateway-state.opaque");
        let mut retry = request.clone();
        retry.id = Some(json!(2));
        retry.params.as_mut().unwrap()["requestState"] = json!(encoded);
        retry.params.as_mut().unwrap()["inputResponses"] =
            json!({&collision: {"action": "decline"}, "unexpected": {"content": "ignored"}});
        let resumed = service
            .resume(encoded, &binding, &retry, 11)
            .await
            .unwrap();
        assert!(resumed.kind() == ContinuationKind::Forwarded);
        let other = service
            .resume(encoded, &binding, &retry, 11)
            .await
            .unwrap();
        let claimed = service
            .claim_forwarded(resumed, 11)
            .await
            .unwrap();
        assert!(matches!(
            service
                .claim_forwarded(other, 11)
                .await,
            Err(ContinuationError::Conflict)
        ));
        let restored = claimed
            .restore_upstream_request(&retry)
            .unwrap();
        assert_eq!(
            restored
                .params
                .as_ref()
                .unwrap()["requestState"],
            "not-gateway-state.opaque"
        );
        assert_eq!(
            restored
                .params
                .as_ref()
                .unwrap()["inputResponses"],
            json!({&collision: {"action": "decline"}})
        );
        let consent = service
            .issue(&restored, binding.clone(), 100, 11)
            .await
            .unwrap();
        let mut consent_retry = restored.clone();
        consent_retry.id = Some(json!(3));
        consent_retry
            .params
            .as_mut()
            .unwrap()["requestState"] = json!(consent.state);
        let pending = service
            .resume(&consent.state, &binding, &consent_retry, 12)
            .await
            .unwrap();
        assert!(pending.kind() == ContinuationKind::Consent);
        assert_eq!(
            pending
                .claims
                .upstream
                .as_ref()
                .unwrap()
                .request_state
                .as_deref(),
            Some("not-gateway-state.opaque")
        );
        service
            .complete(claimed, 12)
            .await
            .unwrap();
        assert!(matches!(
            service
                .resume(encoded, &binding, &retry, 12)
                .await,
            Err(ContinuationError::Conflict)
        ));
    }

    #[tokio::test]
    async fn successive_payment_rounds_keep_expiry_and_each_require_one_claim() {
        let (service, store, request, binding) = setup();
        let payment = ContinuationPayment::X402 {
            receipt: Some("receipt".into()),
            verified_at: 10,
            expires_at: 100,
        };
        let upstream = json!({"jsonrpc": "2.0", "id": request.id, "result": {
            "resultType": "input_required", "requestState": "upstream-state"
        }});
        let first = service
            .wrap_upstream_response_with_payment(
                &request,
                binding.clone(),
                upstream.clone(),
                Some(payment.clone()),
                100,
                10,
            )
            .await
            .unwrap();
        let encoded = first["result"]["requestState"]
            .as_str()
            .unwrap();
        let mut retry = request.clone();
        retry.id = Some(json!(2));
        retry.params.as_mut().unwrap()["requestState"] = json!(encoded);
        let resumed = service
            .resume(encoded, &binding, &retry, 11)
            .await
            .unwrap();
        assert!(resumed.has_payment());
        let competing = service
            .resume(encoded, &binding, &retry, 11)
            .await
            .unwrap();
        let claimed = service
            .claim_forwarded(resumed, 11)
            .await
            .unwrap();
        assert!(claimed.payment() == Some(&payment));
        assert_eq!(claimed.expires_at(), 100);
        assert!(matches!(
            service
                .claim_forwarded(competing, 11)
                .await,
            Err(ContinuationError::Conflict)
        ));
        let restored = claimed
            .restore_upstream_request(&retry)
            .unwrap();
        let mut next_response = upstream;
        next_response["id"] = json!(2);
        let next = service
            .wrap_upstream_response_with_payment(
                &restored,
                binding.clone(),
                next_response,
                claimed.payment().cloned(),
                100,
                50,
            )
            .await
            .unwrap();
        service
            .complete(claimed, 50)
            .await
            .unwrap();
        retry.id = Some(json!(3));
        let encoded = next["result"]["requestState"]
            .as_str()
            .unwrap();
        retry.params.as_mut().unwrap()["requestState"] = json!(encoded);
        let resumed = service
            .resume(encoded, &binding, &retry, 51)
            .await
            .unwrap();
        assert!(resumed.has_payment());
        assert_eq!(
            store
                .get(resumed.id(), binding.digest().unwrap(), 51)
                .await
                .unwrap()
                .expires_at,
            100
        );
        let claimed = service
            .claim_forwarded(resumed, 51)
            .await
            .unwrap();
        let (consent, connect) = service
            .issue_consent_with_payment(
                &restored,
                binding.clone(),
                [3; 32],
                [4; 32],
                [5; 32],
                "https://gateway.example/mcp-consent/callback/provider".into(),
                claimed.payment().cloned(),
                100,
                52,
            )
            .await
            .unwrap();
        assert_eq!(consent.expires_at, 100);
        assert_eq!(
            service
                .read_consent_ticket(&connect, false, 53)
                .await
                .unwrap()
                .expires_at,
            100
        );
        service
            .complete(claimed, 52)
            .await
            .unwrap();
        assert!(
            service
                .resume(encoded, &binding, &retry, 100)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn provider_denial_is_durable_and_cannot_rearm_consent() {
        let (service, store, request, binding) = setup();
        let directory = tempfile::tempdir().unwrap();
        let vault = crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let (issued, connect) = service
            .issue_consent(
                &request,
                binding.clone(),
                [3; 32],
                [4; 32],
                [5; 32],
                "https://gateway.example/consent/callback".into(),
                100,
                10,
            )
            .await
            .unwrap();
        let ticket = service
            .read_consent_ticket(&connect, false, 11)
            .await
            .unwrap();
        let callback = service
            .begin_consent_callback(ticket, "v".repeat(43), &vault, 11)
            .await
            .unwrap();
        let ticket = service
            .read_consent_ticket(&callback, true, 12)
            .await
            .unwrap();
        let mut altered = ticket.clone();
        altered.binding.principal = "another-caller".into();
        assert_eq!(
            service
                .deny_consent_callback(&altered, 12)
                .await,
            Err(ContinuationError::BindingMismatch)
        );
        service
            .deny_consent_callback(&ticket, 12)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(ticket.id, binding.digest().unwrap(), 12)
                .await
                .unwrap()
                .phase,
            ContinuationPhase::Denied
        );
        assert_eq!(
            store
                .get(issued.id, binding.digest().unwrap(), 12)
                .await
                .unwrap()
                .phase,
            ContinuationPhase::Denied
        );
        assert!(matches!(
            service
                .claim_consent_callback(ticket, 13)
                .await,
            Err(ContinuationError::Denied)
        ));
        assert!(matches!(
            service
                .read_consent_ticket(&callback, true, 13)
                .await,
            Err(ContinuationError::Denied)
        ));
        let mut retry = request;
        retry.id = Some(json!(2));
        assert!(matches!(
            service
                .resume(&issued.state, &binding, &retry, 13)
                .await,
            Err(ContinuationError::Denied)
        ));
    }

    #[tokio::test]
    async fn consent_callbacks_are_single_use_and_stop_after_parent_denial() {
        let (service, store, request, binding) = setup();
        let directory = tempfile::tempdir().unwrap();
        let vault = crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let (issued, connect) = service
            .issue_consent(
                &request,
                binding.clone(),
                [3; 32],
                [4; 32],
                [5; 32],
                "https://gateway.example/consent/callback".into(),
                100,
                10,
            )
            .await
            .unwrap();
        let ticket = service
            .read_consent_ticket(&connect, false, 11)
            .await
            .unwrap();
        let callback = service
            .begin_consent_callback(ticket.clone(), "v".repeat(43), &vault, 11)
            .await
            .unwrap();
        assert!(matches!(
            service
                .begin_consent_callback(ticket, "w".repeat(43), &vault, 11)
                .await,
            Err(ContinuationError::Conflict)
        ));
        let ticket = service
            .read_consent_ticket(&callback, true, 12)
            .await
            .unwrap();
        let (first, second) = tokio::join!(
            service.claim_consent_callback(ticket.clone(), 12),
            service.claim_consent_callback(ticket, 12)
        );
        let claimed = match (first, second) {
            (Ok(consent), Err(ContinuationError::Conflict)) | (Err(ContinuationError::Conflict), Ok(consent)) => {
                consent
            }
            _ => panic!("a consent callback must be claimed only once"),
        };
        service
            .complete_consent_callback(claimed, &vault, delegation_token(&binding), 12)
            .await
            .unwrap();
        let ticket = service
            .read_consent_ticket(&callback, true, 12)
            .await
            .unwrap();
        assert!(matches!(
            service
                .claim_consent_callback(ticket, 12)
                .await,
            Err(ContinuationError::Conflict)
        ));
        let parent = store
            .get(issued.id, binding.digest().unwrap(), 12)
            .await
            .unwrap();
        store
            .advance(parent.id, parent.expectation(), ContinuationPhase::Denied, 12)
            .await
            .unwrap();
        assert!(matches!(
            service
                .read_consent_ticket(&connect, false, 13)
                .await,
            Err(ContinuationError::Denied)
        ));
        assert!(
            vault
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn pending_retries_rotate_state_atomically_without_extending_expiry() {
        let (service, store, request, binding) = setup();
        let issued = service
            .issue(&request, binding.clone(), 100, 10)
            .await
            .unwrap();
        let mut retry = request.clone();
        retry.id = Some(json!(2));
        let first = service
            .resume(&issued.state, &binding, &retry, 11)
            .await
            .unwrap();
        let second = service
            .resume(&issued.state, &binding, &retry, 11)
            .await
            .unwrap();
        let fresh = service
            .retry(first, 11)
            .await
            .unwrap();
        assert!(matches!(
            service
                .retry(second, 11)
                .await,
            Err(ContinuationError::Conflict)
        ));
        assert!(matches!(
            service
                .resume(&issued.state, &binding, &retry, 12)
                .await,
            Err(ContinuationError::Conflict)
        ));
        assert!(matches!(
            service
                .resume(&fresh.state, &binding, &retry, 12)
                .await,
            Err(ContinuationError::RepeatedRequestId)
        ));
        let mut state = fresh.state;
        for round in 2..super::super::MAX_ROUNDS {
            retry.id = Some(json!(u64::from(round) + 1));
            let resumed = service
                .resume(&state, &binding, &retry, 12)
                .await
                .unwrap();
            state = service
                .retry(resumed, 12)
                .await
                .unwrap()
                .state;
        }
        retry.id = Some(json!(99));
        let resumed = service
            .resume(&state, &binding, &retry, 12)
            .await
            .unwrap();
        assert!(matches!(
            service
                .retry(resumed, 12)
                .await,
            Err(ContinuationError::RoundLimit)
        ));
        let stored = store
            .get(issued.id, binding.digest().unwrap(), 12)
            .await
            .unwrap();
        assert_eq!(stored.expires_at, 110);
        assert_eq!(stored.round, super::super::MAX_ROUNDS - 1);
        assert_eq!(stored.phase, ContinuationPhase::PendingConsent);
    }

    fn setup() -> (ContinuationService, Arc<EmbeddedContinuations>, ValidatedModernMessage, ContinuationBinding) {
        let store = Arc::new(EmbeddedContinuations::new(16).unwrap());
        let cipher = ContinuationCipher::new(
            "deployment".into(),
            "key".into(),
            vec![ContinuationKey::new("key".into(), [1; 32], 1, 1000, 1900).unwrap()],
        )
        .unwrap();
        let request = ValidatedModernMessage {
            protocol_version: crate::mcp::MCP_MODERN_VERSION.into(),
            client_capabilities: Some(json!({"elicitation": {"url": {}}})),
            client_info: None,
            method: "tools/call".into(),
            id: Some(json!(1)),
            kind: McpMessageKind::Request,
            params: Some(
                json!({"name": "write", "arguments": {"value": 1}, "requestState": "upstream opaque state", "inputResponses": {"upstream": {"action": "accept"}}}),
            ),
        };
        let binding = ContinuationBinding {
            deployment: "deployment".into(),
            principal: "principal".into(),
            agent_did: "did:web:agent.example".into(),
            user_identity_hash: "user-hash".into(),
            authorization_digest: [2; 32],
            tenant_id: None,
            surface_id: Uuid::new_v4().to_string(),
            variant_id: None,
            route: ContinuationRoute::AccessPoint,
            resource: "https://gateway.example/mcp".into(),
            provider_id: "provider".into(),
            scopes: vec!["write".into()],
            method: request.method.clone(),
            arguments_digest: request_arguments_digest(&request).unwrap(),
        };
        (ContinuationService::new(cipher, store.clone()), store, request, binding)
    }

    #[tokio::test]
    async fn one_principal_cannot_use_up_the_store_for_others() {
        let (service, _, request, binding) = setup();
        let service = service.with_max_pending_per_principal(3);
        for _ in 0..3 {
            service
                .issue(&request, binding.clone(), 100, 10)
                .await
                .unwrap();
        }

        assert!(matches!(
            service
                .issue(&request, binding.clone(), 100, 10)
                .await,
            Err(ContinuationError::PrincipalLimit)
        ));
        let other = ContinuationBinding {
            principal: "other-principal".into(),
            ..binding.clone()
        };
        assert!(
            service
                .issue(&request, other, 100, 10)
                .await
                .is_ok()
        );
        let other_tenant = ContinuationBinding {
            tenant_id: Some("tenant".into()),
            ..binding.clone()
        };
        assert!(
            service
                .issue(&request, other_tenant, 100, 10)
                .await
                .is_ok()
        );
        // Slots come back as the principal's continuations expire.
        assert!(
            service
                .issue(&request, binding, 100, 110)
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_continuation_the_store_refuses_does_not_take_a_slot() {
        let (_, _, request, binding) = setup();
        let cipher = ContinuationCipher::new(
            "deployment".into(),
            "key".into(),
            vec![ContinuationKey::new("key".into(), [1; 32], 1, 1000, 1900).unwrap()],
        )
        .unwrap();
        let service = ContinuationService::new(cipher, Arc::new(EmbeddedContinuations::new(1).unwrap()))
            .with_max_pending_per_principal(2);
        let other = ContinuationBinding {
            principal: "other-principal".into(),
            ..binding.clone()
        };
        service
            .issue(&request, other, 100, 10)
            .await
            .unwrap();
        for _ in 0..3 {
            assert!(matches!(
                service
                    .issue(&request, binding.clone(), 100, 10)
                    .await,
                Err(ContinuationError::Capacity)
            ));
        }
    }

    #[test]
    fn consent_credential_must_match_the_bound_identity_provider_and_scopes() {
        let (_, _, _, binding) = setup();
        let token = delegation_token(&binding);
        assert!(binding.matches_delegation(&token, 11));
        assert!(!binding.matches_delegation(&token, 100));
        for field in ["agent", "user", "provider", "scopes", "credential"] {
            let mut changed = token.clone();
            match field {
                "agent" => changed.agent_did = "did:web:other.example".into(),
                "user" => changed.user_identity_hash = "other-user".into(),
                "provider" => changed.credential_provider_id = "other-provider".into(),
                "scopes" => changed.scopes = vec!["read".into()],
                "credential" => changed.access_token.clear(),
                _ => unreachable!(),
            }
            assert!(!binding.matches_delegation(&changed, 11), "{field}");
        }
        let mut changed = binding.clone();
        changed
            .scopes
            .push("admin".into());
        assert_ne!(binding.digest().unwrap(), changed.digest().unwrap());
        changed.scopes = vec!["two scopes".into()];
        assert!(matches!(changed.digest(), Err(ContinuationError::InvalidRecord)));
    }

    fn delegation_token(binding: &ContinuationBinding) -> DelegationToken {
        let created_at = chrono::DateTime::from_timestamp(10, 0).unwrap();
        DelegationToken {
            id: Uuid::new_v4().to_string(),
            agent_did: binding.agent_did.clone(),
            user_identity_hash: binding
                .user_identity_hash
                .clone(),
            credential_provider_id: binding.provider_id.clone(),
            provider_id: "provider-name".into(),
            access_token: "test-credential".into(),
            refresh_token: None,
            token_type: "Bearer".into(),
            scopes: binding.scopes.clone(),
            expires_at: chrono::DateTime::from_timestamp(100, 0),
            delegation_vc: None,
            consent_identity: None,
            consent_granted_at: created_at,
            last_used_at: None,
            created_at,
            updated_at: created_at,
        }
    }

    #[tokio::test]
    async fn pending_consent_cannot_be_satisfied_by_an_unverified_vault_record() {
        use crate::delegation_vault::storage::FileSystemDelegationVaultStore;

        let (service, store, request, binding) = setup();
        let directory = tempfile::tempdir().unwrap();
        let vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let mut token = delegation_token(&binding);
        token.expires_at = None;
        vault
            .store(token)
            .await
            .unwrap();
        let issued = service
            .issue(&request, binding.clone(), 100, 10)
            .await
            .unwrap();
        let mut retry = request;
        retry.id = Some(json!(2));
        let resumed = service
            .resume(&issued.state, &binding, &retry, 11)
            .await
            .unwrap();
        assert!(matches!(
            service
                .claim_delegation(resumed, &vault, 11)
                .await
                .unwrap(),
            DelegationClaim::Pending(_)
        ));
        assert_eq!(
            store
                .get(issued.id, binding.digest().unwrap(), 11)
                .await
                .unwrap()
                .phase,
            ContinuationPhase::PendingConsent
        );
    }

    #[tokio::test]
    async fn consent_claim_reads_the_vault_and_only_one_retry_can_dispatch() {
        use crate::delegation_vault::storage::FileSystemDelegationVaultStore;

        let (service, store, request, binding) = setup();
        let directory = tempfile::tempdir().unwrap();
        let callback_vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let request_vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let (issued, connect) = service
            .issue_consent(
                &request,
                binding.clone(),
                [3; 32],
                [4; 32],
                [5; 32],
                "https://gateway.example/consent/callback".into(),
                100,
                10,
            )
            .await
            .unwrap();
        let mut retry = request.clone();
        retry.id = Some(json!(2));
        retry.params.as_mut().unwrap()["inputResponses"] = json!({"gateway": {"action": "accept"}});
        let resumed = service
            .resume(&issued.state, &binding, &retry, 11)
            .await
            .unwrap();
        assert!(
            !service
                .delegation_ready(&resumed, &request_vault, 11)
                .await
                .unwrap()
        );
        let DelegationClaim::Pending(resumed) = service
            .claim_delegation(resumed, &request_vault, 11)
            .await
            .unwrap()
        else {
            panic!("client acceptance must not create credentials");
        };
        assert_eq!(resumed.phase(), ContinuationPhase::PendingConsent);
        let mut token = delegation_token(&binding);
        token.expires_at = None;
        token.scopes = vec!["read".into()];
        token = callback_vault
            .store(token.clone())
            .await
            .unwrap();
        let DelegationClaim::Pending(resumed) = service
            .claim_delegation(*resumed, &request_vault, 11)
            .await
            .unwrap()
        else {
            panic!("insufficient scopes must not authorize dispatch");
        };
        token.scopes = binding.scopes.clone();
        token.expires_at = chrono::DateTime::from_timestamp(10, 0);
        token = callback_vault
            .update(token.clone())
            .await
            .unwrap();
        let DelegationClaim::Pending(resumed) = service
            .claim_delegation(*resumed, &request_vault, 11)
            .await
            .unwrap()
        else {
            panic!("expired credentials must not authorize dispatch");
        };
        assert_eq!(resumed.phase(), ContinuationPhase::PendingConsent);
        token.expires_at = None;
        token = callback_vault
            .update(token.clone())
            .await
            .unwrap();
        let ticket = service
            .read_consent_ticket(&connect, false, 11)
            .await
            .unwrap();
        let callback = service
            .begin_consent_callback(ticket, "v".repeat(43), &callback_vault, 11)
            .await
            .unwrap();
        let ticket = service
            .read_consent_ticket(&callback, true, 11)
            .await
            .unwrap();
        let claimed = service
            .claim_consent_callback(ticket, 11)
            .await
            .unwrap();
        let mut verified = token.clone();
        verified.access_token = "verified-consent-credential".into();
        service
            .complete_consent_callback(claimed, &callback_vault, verified, 11)
            .await
            .unwrap();
        assert_eq!(
            request_vault
                .get(&token.id)
                .await
                .unwrap()
                .unwrap()
                .access_token,
            token.access_token
        );
        let resumed = service
            .resume(&issued.state, &binding, &retry, 11)
            .await
            .unwrap();
        let other = service
            .resume(&issued.state, &binding, &retry, 11)
            .await
            .unwrap();
        for pending in [&resumed, &other] {
            assert!(
                service
                    .delegation_ready(pending, &request_vault, 11)
                    .await
                    .unwrap()
            );
        }
        assert_eq!(
            store
                .get(issued.id, binding.digest().unwrap(), 11)
                .await
                .unwrap()
                .phase,
            ContinuationPhase::Ready
        );
        assert_eq!(
            request_vault
                .get(&token.id)
                .await
                .unwrap()
                .unwrap()
                .access_token,
            token.access_token
        );
        let (first, second) = tokio::join!(
            service.claim_delegation(resumed, &request_vault, 11),
            service.claim_delegation(other, &request_vault, 11)
        );
        let claimed = match (first, second) {
            (Ok(claimed), Err(ContinuationError::Conflict)) | (Err(ContinuationError::Conflict), Ok(claimed)) => {
                claimed
            }
            _ => panic!("exactly one vault-backed retry must claim dispatch"),
        };
        let DelegationClaim::Claimed { continuation, credential } = claimed else {
            panic!("valid persisted credentials must authorize dispatch");
        };
        assert_eq!(credential.id, token.id);
        assert_eq!(credential.access_token, "verified-consent-credential");
        let restored = continuation
            .restore_upstream_request(&retry)
            .unwrap();
        assert_eq!(restored.params.unwrap()["requestState"], "upstream opaque state");
        service
            .complete(*continuation, 12)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(issued.id, binding.digest().unwrap(), 12)
                .await
                .unwrap()
                .phase,
            ContinuationPhase::Consumed
        );
    }

    #[tokio::test]
    async fn continuation_service_never_treats_client_acceptance_as_ready_consent() {
        let (service, store, request, binding) = setup();
        let issued = service
            .issue(&request, binding.clone(), 100, 10)
            .await
            .unwrap();
        let mut retry = request.clone();
        retry.id = Some(json!(2));
        retry.params.as_mut().unwrap()["requestState"] = json!(issued.state);
        retry.params.as_mut().unwrap()["inputResponses"] = json!({
            super::super::consent::input_key(issued.id): {"action": "accept"},
            "unexpected": {"action": "accept"}
        });
        let resumed = service
            .resume(&issued.state, &binding, &retry, 11)
            .await
            .unwrap();
        assert_eq!(resumed.phase(), ContinuationPhase::PendingConsent);
        assert!(matches!(
            service
                .claim(resumed, 11)
                .await,
            Err(ContinuationError::InvalidTransition)
        ));
        let pending = store
            .get(issued.id, binding.digest().unwrap(), 11)
            .await
            .unwrap();
        store
            .advance(issued.id, pending.expectation(), ContinuationPhase::Ready, 11)
            .await
            .unwrap();
        let resumed = service
            .resume(&issued.state, &binding, &retry, 12)
            .await
            .unwrap();
        let claimed = service
            .claim(resumed, 12)
            .await
            .unwrap();
        let restored = claimed
            .restore_upstream_request(&retry)
            .unwrap();
        assert_eq!(restored.id, retry.id);
        assert_eq!(
            restored
                .params
                .as_ref()
                .unwrap()["requestState"],
            "upstream opaque state"
        );
        assert_eq!(
            restored
                .params
                .as_ref()
                .unwrap()["inputResponses"],
            json!({"upstream": {"action": "accept"}})
        );
        assert!(matches!(
            service
                .resume(&issued.state, &binding, &retry, 12)
                .await,
            Err(ContinuationError::Conflict)
        ));
        service
            .complete(claimed, 13)
            .await
            .unwrap();
        assert!(matches!(
            service
                .resume(&issued.state, &binding, &retry, 13)
                .await,
            Err(ContinuationError::Conflict)
        ));
    }

    #[tokio::test]
    async fn declined_cancelled_and_revoked_consent_cannot_claim_dispatch() {
        use crate::delegation_vault::storage::FileSystemDelegationVaultStore;

        let (service, store, request, binding) = setup();
        let directory = tempfile::tempdir().unwrap();
        let vault = FileSystemDelegationVaultStore::new(directory.path().into())
            .await
            .unwrap();
        let mut token = delegation_token(&binding);
        token.expires_at = None;
        for action in ["decline", "cancel", "revoked"] {
            vault
                .store(token.clone())
                .await
                .unwrap();
            let (issued, connect) = service
                .issue_consent(
                    &request,
                    binding.clone(),
                    [3; 32],
                    [4; 32],
                    [5; 32],
                    "https://gateway.example/consent/callback".into(),
                    100,
                    10,
                )
                .await
                .unwrap();
            let ticket = service
                .read_consent_ticket(&connect, false, 11)
                .await
                .unwrap();
            let callback = service
                .begin_consent_callback(ticket, "v".repeat(43), &vault, 11)
                .await
                .unwrap();
            let ticket = service
                .read_consent_ticket(&callback, true, 11)
                .await
                .unwrap();
            let claimed = service
                .claim_consent_callback(ticket, 11)
                .await
                .unwrap();
            let mut verified = token.clone();
            verified.access_token = "must-remain-staged".into();
            service
                .complete_consent_callback(claimed, &vault, verified, 11)
                .await
                .unwrap();
            let mut retry = request.clone();
            retry.id = Some(json!(2));
            retry.params.as_mut().unwrap()["inputResponses"] = json!({
                super::super::consent::input_key(issued.id): {
                    "action": if action == "revoked" { "accept" } else { action }
                }
            });
            if action == "revoked" {
                vault
                    .delete(&token.id)
                    .await
                    .unwrap();
            }
            let resumed = service
                .resume(&issued.state, &binding, &retry, 11)
                .await
                .unwrap();
            assert!(
                matches!(
                    service
                        .claim_delegation(resumed, &vault, 11)
                        .await,
                    Err(ContinuationError::Denied)
                ),
                "{action}"
            );
            let stored = store
                .get(issued.id, binding.digest().unwrap(), 12)
                .await
                .unwrap();
            assert_eq!(stored.phase, ContinuationPhase::Denied, "{action}");
            assert!(
                vault
                    .get(&token.id)
                    .await
                    .unwrap()
                    .is_none_or(|stored| stored.access_token == token.access_token)
            );
            assert!(
                matches!(
                    service
                        .resume(&issued.state, &binding, &retry, 12)
                        .await,
                    Err(ContinuationError::Denied)
                ),
                "{action}"
            );
        }
    }

    #[tokio::test]
    async fn continuation_service_serializes_claims_and_rejects_altered_requests() {
        let (service, store, request, binding) = setup();
        let issued = service
            .issue(&request, binding.clone(), 100, 10)
            .await
            .unwrap();
        assert!(matches!(
            service
                .resume(&issued.state, &binding, &request, 11)
                .await,
            Err(ContinuationError::RepeatedRequestId)
        ));
        let mut retry = request.clone();
        retry.id = Some(json!(2));
        assert_eq!(
            service
                .request_binding(&issued.state, &retry, 11)
                .unwrap()
                .digest()
                .unwrap(),
            binding.digest().unwrap()
        );
        assert!(matches!(
            service.request_binding("opaque upstream state", &retry, 11),
            Err(ContinuationError::InvalidState)
        ));
        assert!(matches!(
            service.request_binding(&issued.state, &request, 11),
            Err(ContinuationError::RepeatedRequestId)
        ));
        assert!(matches!(service.request_binding(&issued.state, &retry, 110), Err(ContinuationError::Expired)));
        retry.params.as_mut().unwrap()["arguments"]["value"] = json!(2);
        assert!(matches!(service.request_binding(&issued.state, &retry, 11), Err(ContinuationError::BindingMismatch)));
        assert!(matches!(
            service
                .resume(&issued.state, &binding, &retry, 11)
                .await,
            Err(ContinuationError::BindingMismatch)
        ));
        retry.params.as_mut().unwrap()["arguments"]["value"] = json!(1);
        let pending = store
            .get(issued.id, binding.digest().unwrap(), 11)
            .await
            .unwrap();
        store
            .advance(issued.id, pending.expectation(), ContinuationPhase::Ready, 11)
            .await
            .unwrap();
        let first = service
            .resume(&issued.state, &binding, &retry, 12)
            .await
            .unwrap();
        let second = service
            .resume(&issued.state, &binding, &retry, 12)
            .await
            .unwrap();
        let (first, second) = tokio::join!(service.claim(first, 12), service.claim(second, 12));
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert!(
            matches!(first, Err(ContinuationError::Conflict)) || matches!(second, Err(ContinuationError::Conflict))
        );
        let changed_binding = ContinuationBinding {
            authorization_digest: [3; 32],
            ..binding
        };
        assert!(matches!(
            service
                .resume(&issued.state, &changed_binding, &retry, 12)
                .await,
            Err(ContinuationError::BindingMismatch)
        ));
    }
}
