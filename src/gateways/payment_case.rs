//! The review state of a payment a connected agent-pay gateway holds, as it
//! answers a `payment-case-status` query.
//!
//! The reply body is `{"case_id", "status", "receipt"?, "receipt_vc_fingerprint"?}`,
//! or `{"error": "case_not_found"}` for a case the peer does not know. Only the
//! status is read.

use serde::{Deserialize, Serialize};

/// Where a held payment stands. `capture_failed` means the capture failed or its
/// outcome is unknown: the payer must not be asked to pay again before it is
/// reconciled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentCaseState {
    Held,
    Approved,
    Captured,
    Rejected,
    Voided,
    CaptureFailed,
}

/// Why a case status could not be had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaseStatusError {
    /// The peer could not be reached or did not answer in time.
    Unavailable(String),
    /// The peer answered but refused the query or sent something unusable.
    Rejected(String),
}

impl std::fmt::Display for CaseStatusError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "payment gateway unavailable: {reason}"),
            Self::Rejected(reason) => write!(f, "payment gateway rejected the case status query: {reason}"),
        }
    }
}

/// Parses a `payment-case-status-response` body for `case_id`. `Ok(None)` is a
/// case the peer does not know.
pub fn parse_case_status_response(
    body: &serde_json::Value,
    case_id: &str,
) -> Result<Option<PaymentCaseState>, CaseStatusError> {
    if let Some(error) = body
        .get("error")
        .filter(|error| !error.is_null())
    {
        return match error.as_str() {
            Some("case_not_found") => Ok(None),
            Some(reason) => Err(CaseStatusError::Rejected(crate::a2a::clip_for_log(reason).to_string())),
            None => Err(CaseStatusError::Rejected("unspecified error".to_string())),
        };
    }
    if body
        .get("case_id")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|answered| answered != case_id)
    {
        return Err(CaseStatusError::Rejected("the answer is for another case".to_string()));
    }
    body.get("status")
        .and_then(|status| serde_json::from_value(status.clone()).ok())
        .map(Some)
        .ok_or_else(|| CaseStatusError::Rejected("the answer has no known status".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn every_status_the_peer_reports_is_read() {
        for (status, expected) in [
            ("held", PaymentCaseState::Held),
            ("approved", PaymentCaseState::Approved),
            ("captured", PaymentCaseState::Captured),
            ("rejected", PaymentCaseState::Rejected),
            ("voided", PaymentCaseState::Voided),
            ("capture_failed", PaymentCaseState::CaptureFailed),
        ] {
            let body =
                json!({"case_id": "case-1", "status": status, "receipt": {"id": "r"}, "receipt_vc_fingerprint": "f"});
            assert_eq!(parse_case_status_response(&body, "case-1"), Ok(Some(expected)), "{status}");
            assert_eq!(serde_json::to_value(expected).unwrap(), json!(status));
        }
    }

    #[test]
    fn a_case_the_peer_does_not_know_is_none_and_any_other_error_is_a_refusal() {
        assert_eq!(parse_case_status_response(&json!({"error": "case_not_found"}), "case-1"), Ok(None));
        assert_eq!(
            parse_case_status_response(&json!({"error": "not_allowed"}), "case-1"),
            Err(CaseStatusError::Rejected("not_allowed".to_string()))
        );
        assert_eq!(
            parse_case_status_response(&json!({"error": {"code": 1}}), "case-1"),
            Err(CaseStatusError::Rejected("unspecified error".to_string()))
        );
    }

    #[test]
    fn an_answer_without_a_known_status_or_for_another_case_is_refused() {
        for body in [
            json!({"case_id": "case-1"}),
            json!({"case_id": "case-1", "status": "settled"}),
            json!({"case_id": "case-1", "status": 7}),
            json!({}),
        ] {
            assert_eq!(
                parse_case_status_response(&body, "case-1"),
                Err(CaseStatusError::Rejected("the answer has no known status".to_string())),
                "{body}"
            );
        }
        assert_eq!(
            parse_case_status_response(&json!({"case_id": "case-2", "status": "held"}), "case-1"),
            Err(CaseStatusError::Rejected("the answer is for another case".to_string()))
        );
        assert_eq!(parse_case_status_response(&json!({"status": "held"}), "case-1"), Ok(Some(PaymentCaseState::Held)));
    }
}
