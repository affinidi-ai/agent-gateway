use std::collections::HashMap;
use std::sync::Mutex;

use async_trait::async_trait;
use uuid::Uuid;

use super::{ContinuationError, ContinuationExpectation, ContinuationPhase, ContinuationRecord, ContinuationStore};

pub struct EmbeddedContinuations {
    records: Mutex<HashMap<Uuid, ContinuationRecord>>,
    capacity: usize,
}

impl EmbeddedContinuations {
    pub fn new(capacity: usize) -> Result<Self, ContinuationError> {
        if capacity == 0 || capacity > 100_000 {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(Self {
            records: Mutex::new(HashMap::new()),
            capacity,
        })
    }
}

#[async_trait]
impl ContinuationStore for EmbeddedContinuations {
    async fn create(
        &self,
        record: ContinuationRecord,
        now: u64,
    ) -> Result<(), ContinuationError> {
        record.validate_new(now)?;
        let mut records = self
            .records
            .lock()
            .map_err(|_| ContinuationError::Unavailable)?;
        records.retain(|_, record| record.expires_at > now);
        if records.contains_key(&record.id) {
            return Err(ContinuationError::Conflict);
        }
        if records.len() >= self.capacity {
            return Err(ContinuationError::Capacity);
        }
        records.insert(record.id, record);
        Ok(())
    }

    async fn get(
        &self,
        id: Uuid,
        binding_digest: [u8; 32],
        now: u64,
    ) -> Result<ContinuationRecord, ContinuationError> {
        let records = self
            .records
            .lock()
            .map_err(|_| ContinuationError::Unavailable)?;
        let record = records
            .get(&id)
            .ok_or(ContinuationError::NotFound)?;
        record.check_access(&binding_digest, now)?;
        Ok(record.clone())
    }

    async fn advance(
        &self,
        id: Uuid,
        expected: ContinuationExpectation,
        next: ContinuationPhase,
        now: u64,
    ) -> Result<ContinuationRecord, ContinuationError> {
        let mut records = self
            .records
            .lock()
            .map_err(|_| ContinuationError::Unavailable)?;
        let record = records
            .get_mut(&id)
            .ok_or(ContinuationError::NotFound)?;
        let advanced = record.advance(&expected, next, now)?;
        *record = advanced.clone();
        Ok(advanced)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::tests::record;
    use super::*;

    #[tokio::test]
    async fn concurrent_claims_authorize_exactly_one_dispatch() {
        let store = Arc::new(EmbeddedContinuations::new(8).unwrap());
        let record = record();
        store
            .create(record.clone(), 10)
            .await
            .unwrap();
        let ready = store
            .advance(record.id, record.expectation(), ContinuationPhase::Ready, 10)
            .await
            .unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(16));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..16 {
            let store = store.clone();
            let barrier = barrier.clone();
            let ready = ready.clone();
            tasks.spawn(async move {
                barrier.wait().await;
                store
                    .advance(ready.id, ready.expectation(), ContinuationPhase::Claimed, 11)
                    .await
            });
        }
        let mut claims = Vec::new();
        while let Some(result) = tasks.join_next().await {
            match result.unwrap() {
                Ok(record) => claims.push(record),
                Err(error) => assert_eq!(error, ContinuationError::Conflict),
            }
        }
        assert_eq!(claims.len(), 1);
        assert_eq!(claims[0].revision, 2);
        assert_eq!(
            store
                .advance(record.id, claims[0].expectation(), ContinuationPhase::Ready, 11)
                .await,
            Err(ContinuationError::InvalidTransition)
        );
        let consumed = store
            .advance(record.id, claims[0].expectation(), ContinuationPhase::Consumed, 11)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(record.id, record.binding_digest, 11)
                .await
                .unwrap(),
            consumed
        );
        assert_eq!(
            store
                .advance(record.id, ready.expectation(), ContinuationPhase::Claimed, 11)
                .await,
            Err(ContinuationError::Conflict)
        );
    }

    #[tokio::test]
    async fn capacity_expiry_restart_and_wrong_bindings_fail_closed() {
        let store = EmbeddedContinuations::new(1).unwrap();
        let record = record();
        store
            .create(record.clone(), 10)
            .await
            .unwrap();
        assert_eq!(
            store
                .create(record.clone(), 10)
                .await,
            Err(ContinuationError::Conflict)
        );
        let other = ContinuationRecord {
            id: Uuid::new_v4(),
            ..record.clone()
        };
        assert_eq!(
            store
                .create(other.clone(), 10)
                .await,
            Err(ContinuationError::Capacity)
        );
        let forged = ContinuationExpectation {
            binding_digest: [2; 32],
            ..record.expectation()
        };
        assert_eq!(
            store
                .advance(record.id, forged, ContinuationPhase::Ready, 11)
                .await,
            Err(ContinuationError::BindingMismatch)
        );
        assert_eq!(
            store
                .get(record.id, record.binding_digest, 11)
                .await
                .unwrap(),
            record
        );
        assert_eq!(
            store
                .get(record.id, record.binding_digest, 110)
                .await,
            Err(ContinuationError::Expired)
        );
        let replacement = ContinuationRecord {
            issued_at: 110,
            expires_at: 210,
            ..other
        };
        store
            .create(replacement.clone(), 110)
            .await
            .unwrap();
        assert_eq!(
            store
                .get(record.id, record.binding_digest, 110)
                .await,
            Err(ContinuationError::NotFound)
        );
        let restarted = EmbeddedContinuations::new(1).unwrap();
        assert_eq!(
            restarted
                .get(replacement.id, replacement.binding_digest, 111)
                .await,
            Err(ContinuationError::NotFound)
        );
    }
}
