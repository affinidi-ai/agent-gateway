pub mod config;
pub mod consent;
pub mod delegation;
pub mod dynamodb;
pub mod embedded;
pub mod protected;
pub mod service;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const MAX_TTL_SECS: u64 = 900;
pub const MAX_ROUNDS: u8 = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContinuationPhase {
    PendingInput,
    PendingConsent,
    Ready,
    Claimed,
    Consumed,
    Denied,
}

impl ContinuationPhase {
    fn permits(
        self,
        next: Self,
    ) -> bool {
        matches!(
            (self, next),
            (Self::PendingInput, Self::PendingConsent | Self::Ready | Self::Denied)
                | (Self::PendingConsent, Self::Ready | Self::Denied)
                | (Self::Ready, Self::Claimed | Self::Denied)
                | (Self::Claimed, Self::Consumed)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContinuationRecord {
    pub id: Uuid,
    pub binding_digest: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub revision: u64,
    pub round: u8,
    pub phase: ContinuationPhase,
}

impl ContinuationRecord {
    pub fn validate(&self) -> Result<(), ContinuationError> {
        if self.id.is_nil()
            || self.binding_digest == [0; 32]
            || self.round >= MAX_ROUNDS
            || self
                .expires_at
                .checked_sub(self.issued_at)
                .is_none_or(|ttl| ttl == 0 || ttl > MAX_TTL_SECS)
        {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(())
    }

    pub fn validate_new(
        &self,
        now: u64,
    ) -> Result<(), ContinuationError> {
        self.validate()?;
        if self.issued_at > now
            || self.revision != 0
            || self.round != 0
            || !matches!(self.phase, ContinuationPhase::PendingInput | ContinuationPhase::PendingConsent)
        {
            return Err(ContinuationError::InvalidRecord);
        }
        self.check_access(&self.binding_digest, now)
    }

    pub fn check_access(
        &self,
        binding_digest: &[u8; 32],
        now: u64,
    ) -> Result<(), ContinuationError> {
        self.validate()?;
        if self.binding_digest != *binding_digest {
            return Err(ContinuationError::BindingMismatch);
        }
        if now >= self.expires_at {
            return Err(ContinuationError::Expired);
        }
        if now < self.issued_at {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(())
    }

    pub fn advance(
        &self,
        expected: &ContinuationExpectation,
        next: ContinuationPhase,
        now: u64,
    ) -> Result<Self, ContinuationError> {
        self.check_access(&expected.binding_digest, now)?;
        if self.revision != expected.revision || self.phase != expected.phase || self.round != expected.round {
            return Err(ContinuationError::Conflict);
        }
        let retry = self.phase == next
            && matches!(self.phase, ContinuationPhase::PendingInput | ContinuationPhase::PendingConsent);
        if !retry && !self.phase.permits(next) {
            return Err(ContinuationError::InvalidTransition);
        }
        let round = if retry {
            self.round
                .checked_add(1)
                .filter(|round| *round < MAX_ROUNDS)
                .ok_or(ContinuationError::RoundLimit)?
        } else {
            self.round
        };
        Ok(Self {
            revision: self
                .revision
                .checked_add(1)
                .ok_or(ContinuationError::InvalidRecord)?,
            round,
            phase: next,
            ..self.clone()
        })
    }

    pub fn expectation(&self) -> ContinuationExpectation {
        ContinuationExpectation {
            binding_digest: self.binding_digest,
            revision: self.revision,
            round: self.round,
            phase: self.phase,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContinuationExpectation {
    pub binding_digest: [u8; 32],
    pub revision: u64,
    pub round: u8,
    pub phase: ContinuationPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContinuationError {
    #[error("Continuation storage is unavailable")]
    Unavailable,
    #[error("Continuation was not found")]
    NotFound,
    #[error("Continuation has expired")]
    Expired,
    #[error("Continuation belongs to another authorization or request context")]
    BindingMismatch,
    #[error("Continuation changed or was already claimed")]
    Conflict,
    #[error("Invalid continuation record")]
    InvalidRecord,
    #[error("Invalid continuation state transition")]
    InvalidTransition,
    #[error("Continuation capacity reached")]
    Capacity,
    #[error("Too many pending continuations for this caller")]
    PrincipalLimit,
    #[error("Continuation state authentication failed")]
    InvalidState,
    #[error("Continuation encryption key is unavailable")]
    KeyUnavailable,
    #[error("Continuation retry must use a new request identifier")]
    RepeatedRequestId,
    #[error("Continuation consent was denied")]
    Denied,
    #[error("Continuation retry limit reached")]
    RoundLimit,
    #[error("Invalid continuation input response")]
    InvalidInputResponse,
}

#[async_trait]
pub trait ContinuationStore: Send + Sync {
    async fn create(
        &self,
        record: ContinuationRecord,
        now: u64,
    ) -> Result<(), ContinuationError>;
    async fn get(
        &self,
        id: Uuid,
        binding_digest: [u8; 32],
        now: u64,
    ) -> Result<ContinuationRecord, ContinuationError>;
    async fn advance(
        &self,
        id: Uuid,
        expected: ContinuationExpectation,
        next: ContinuationPhase,
        now: u64,
    ) -> Result<ContinuationRecord, ContinuationError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn record() -> ContinuationRecord {
        ContinuationRecord {
            id: Uuid::new_v4(),
            binding_digest: [1; 32],
            issued_at: 10,
            expires_at: 110,
            revision: 0,
            round: 0,
            phase: ContinuationPhase::PendingInput,
        }
    }

    #[test]
    fn continuation_transitions_never_rearm_a_claimed_or_consumed_operation() {
        let mut record = record();
        assert_eq!(
            record.advance(&record.expectation(), ContinuationPhase::Claimed, 10),
            Err(ContinuationError::InvalidTransition)
        );
        for phase in [
            ContinuationPhase::PendingConsent,
            ContinuationPhase::Ready,
            ContinuationPhase::Claimed,
            ContinuationPhase::Consumed,
        ] {
            let previous = record.clone();
            record = record
                .advance(&record.expectation(), phase, 11)
                .unwrap();
            assert_eq!(record.revision, previous.revision + 1);
            assert_eq!(record.id, previous.id);
            assert_eq!(record.binding_digest, previous.binding_digest);
            assert_eq!(record.expires_at, previous.expires_at);
            assert_eq!(record.advance(&previous.expectation(), phase, 11), Err(ContinuationError::Conflict));
        }
        for phase in [
            ContinuationPhase::PendingInput,
            ContinuationPhase::PendingConsent,
            ContinuationPhase::Ready,
            ContinuationPhase::Claimed,
            ContinuationPhase::Consumed,
        ] {
            assert_eq!(record.advance(&record.expectation(), phase, 11), Err(ContinuationError::InvalidTransition));
        }
    }

    #[test]
    fn continuation_checks_binding_expiry_and_creation_invariants() {
        let record = record();
        assert_eq!(record.validate_new(10), Ok(()));
        assert_eq!(record.validate_new(9), Err(ContinuationError::InvalidRecord));
        assert_eq!(record.check_access(&[2; 32], 111), Err(ContinuationError::BindingMismatch));
        assert_eq!(record.check_access(&record.binding_digest, 110), Err(ContinuationError::Expired));
        assert!(
            ContinuationRecord {
                expires_at: u64::MAX,
                ..record.clone()
            }
            .validate_new(10)
            .is_err()
        );
        assert!(
            ContinuationRecord {
                id: Uuid::nil(),
                ..record.clone()
            }
            .validate_new(10)
            .is_err()
        );
        assert!(
            ContinuationRecord {
                phase: ContinuationPhase::Ready,
                ..record.clone()
            }
            .validate_new(10)
            .is_err()
        );
        assert!(
            ContinuationRecord { revision: 1, ..record.clone() }
                .validate_new(10)
                .is_err()
        );
        let denied = record
            .advance(&record.expectation(), ContinuationPhase::Denied, 10)
            .unwrap();
        assert_eq!(
            denied.advance(&denied.expectation(), ContinuationPhase::Ready, 11),
            Err(ContinuationError::InvalidTransition)
        );
    }
}
