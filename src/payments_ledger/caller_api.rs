//! What a caller may learn about its own held payment: the outcome, the live
//! review state and the receipt reference of the paid request it made, found by
//! case id and shown only to the caller that made it.

use std::sync::{Arc, OnceLock};

use serde_json::{Value, json};

use super::{CaseStatusLookup, DelegatedPaymentStore, LedgerOutcome, PaymentLedgerRow};

static CASE_STATUS: OnceLock<Arc<CaseStatusLookup>> = OnceLock::new();

/// The review state lookup a caller's poll uses, shared with the admin API.
pub fn init_case_status(lookup: Arc<CaseStatusLookup>) {
    let _ = CASE_STATUS.set(lookup);
}

/// The case `case_id` of a payment on `surface_id` made by `caller_principal`.
/// `None` when there is no such case, it is another caller's, or the caller is
/// not authenticated.
pub async fn caller_case(
    surface_id: &str,
    case_id: &str,
    caller_principal: Option<&str>,
) -> Option<Value> {
    let store = super::global()?;
    caller_case_in(
        &store,
        CASE_STATUS
            .get()
            .map(Arc::as_ref),
        surface_id,
        case_id,
        caller_principal?,
    )
    .await
}

async fn caller_case_in(
    store: &DelegatedPaymentStore,
    lookup: Option<&CaseStatusLookup>,
    surface_id: &str,
    case_id: &str,
    caller_principal: &str,
) -> Option<Value> {
    let is_callers = |row: &PaymentLedgerRow| {
        row.surface_id == surface_id
            && row
                .caller_principal
                .as_deref()
                == Some(caller_principal)
    };
    let row = match store
        .rows_where(|row| is_callers(row) && row.case_id.as_deref() == Some(case_id))
        .pop()
    {
        Some((row, _)) => row,
        None => store
            .row_for_case(case_id)
            .await
            .map(|(row, _)| row)
            .filter(is_callers)?,
    };
    let case_status = match (lookup, row.outcome) {
        (Some(lookup), LedgerOutcome::Held) => {
            lookup
                .check(&row.payment_gateway_id, case_id)
                .await
        }
        _ => None,
    };
    Some(json!({
        "status": row.outcome,
        "case_status": case_status.map(|status| status.status),
        "receipt": row.receipt_reference,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments_ledger::store::Limits;
    use crate::payments_ledger::tests::{row, row_in_one_segment, store};

    #[tokio::test]
    async fn a_caller_sees_only_its_own_case_on_its_surface() {
        let (store, dir) = store().await;
        let mut held = row("s-1", LedgerOutcome::Held, chrono::Duration::zero());
        held.case_id = Some("case-1".to_string());
        held.caller_principal = Some("caller-a".to_string());
        held.receipt_reference = Some("pi_1".to_string());
        store
            .record_durable(held, None)
            .await
            .unwrap();

        assert_eq!(
            caller_case_in(&store, None, "s-1", "case-1", "caller-a").await,
            Some(json!({"status": "held", "case_status": null, "receipt": "pi_1"}))
        );
        assert_eq!(caller_case_in(&store, None, "s-1", "case-1", "caller-b").await, None, "another caller");
        assert_eq!(caller_case_in(&store, None, "s-2", "case-1", "caller-a").await, None, "another surface");
        assert_eq!(caller_case_in(&store, None, "s-1", "case-2", "caller-a").await, None, "another case");
        let _ = std::fs::remove_dir_all(dir);
    }

    fn held_case(seconds: i64) -> PaymentLedgerRow {
        let mut held = row_in_one_segment("s-1", LedgerOutcome::Held, seconds);
        held.case_id = Some("case-1".to_string());
        held.caller_principal = Some("caller-a".to_string());
        held.receipt_reference = Some("pi_1".to_string());
        held
    }

    async fn one_row_window(dir: &std::path::Path) -> DelegatedPaymentStore {
        DelegatedPaymentStore::with_limits(
            dir.to_path_buf(),
            Limits {
                window_rows: 1,
                ..Limits::default()
            },
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn a_case_that_left_the_window_is_found_through_the_case_index() {
        let dir = std::env::temp_dir().join(format!("payments-ledger-test-{}", uuid::Uuid::new_v4()));
        let store = one_row_window(&dir).await;
        store
            .record_durable(held_case(0), None)
            .await
            .unwrap();
        store
            .record_durable(row_in_one_segment("s-1", LedgerOutcome::Paid, 1), None)
            .await
            .unwrap();
        assert!(
            store
                .rows_where(|row| row.case_id.is_some())
                .is_empty(),
            "the case left the window"
        );

        let found = Some(json!({"status": "held", "case_status": null, "receipt": "pi_1"}));
        assert_eq!(caller_case_in(&store, None, "s-1", "case-1", "caller-a").await, found);
        assert_eq!(caller_case_in(&store, None, "s-1", "case-1", "caller-b").await, None, "another caller");
        assert_eq!(caller_case_in(&store, None, "s-2", "case-1", "caller-a").await, None, "another surface");
        assert_eq!(caller_case_in(&store, None, "s-1", "case-2", "caller-a").await, None, "another case");

        drop(store);
        let index = dir.join("case-index.jsonl");
        std::fs::remove_file(&index).unwrap();
        let store = one_row_window(&dir).await;
        assert!(index.is_file(), "the index is rebuilt at startup");
        assert_eq!(caller_case_in(&store, None, "s-1", "case-1", "caller-a").await, found);
        assert_eq!(caller_case_in(&store, None, "s-1", "case-1", "caller-b").await, None, "another caller");

        drop(store);
        std::fs::remove_file(&index).unwrap();
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path
                .extension()
                .is_some_and(|extension| extension == "jsonl")
            {
                std::fs::remove_file(path).unwrap();
            }
        }
        let store = one_row_window(&dir).await;
        assert_eq!(caller_case_in(&store, None, "s-1", "case-1", "caller-a").await, None, "the row is gone");
        let _ = std::fs::remove_dir_all(dir);
    }
}
