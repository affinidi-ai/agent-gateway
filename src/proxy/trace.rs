//! Trace-id propagation and the per-surface trace-id termination (egress
//! firewall) helpers.
//!
//! One `trace_id` correlates a request across every hop (metrics, audit, the
//! "This request" filter, and the injected VPs' `traceId`). Two pure helpers
//! govern how it flows:
//!
//! * [`continue_or_mint_trace_id`] — at a gateway's **inbound**, continue a
//!   trusted upstream trace carried in `X-Gateway-Trace-Id` (only when it parses
//!   as a UUID, so a spoofed value can't inject or poison correlation), else mint
//!   a fresh one.
//! * [`egress_trace_id`] — at a gateway's **egress**, forward the request's own
//!   trace downstream unless the surface opts into termination, in which case a
//!   fresh id crosses the boundary while this gateway keeps the incoming trace for
//!   its own VP + audit.

/// Continue a trusted upstream trace or mint a fresh one.
///
/// `incoming` is the `X-Gateway-Trace-Id` header (or fabric message `trace_id`)
/// from the previous hop. It is reused **only** when it parses as a UUID — an
/// external caller could set the header, but the UUID check blocks log/field
/// injection and a spoofed value can at worst pollute correlation (never an
/// authorization decision). Any missing or malformed value mints a fresh id, so
/// the external entry hop always starts a new trace.
pub fn continue_or_mint_trace_id(incoming: Option<&str>) -> String {
    incoming
        .and_then(|s| {
            uuid::Uuid::parse_str(s)
                .ok()
                .map(|_| s.to_string())
        })
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
}

/// Egress-firewall trace id for the onward hop.
///
/// Returns `own` (this request's trace) unchanged unless `terminate` is set, in
/// which case a **fresh** id is minted so the trace never crosses this boundary
/// to the next gateway/agent — while the gateway keeps `own` for its own VP +
/// audit (the `caller → … → here` past stays traceable).
pub fn egress_trace_id(
    terminate: bool,
    own: &str,
) -> String {
    if terminate {
        uuid::Uuid::new_v4().to_string()
    } else {
        own.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn continue_reuses_a_valid_uuid() {
        let id = uuid::Uuid::new_v4().to_string();
        assert_eq!(continue_or_mint_trace_id(Some(&id)), id);
    }

    #[test]
    fn continue_mints_for_non_uuid() {
        // A non-UUID header value is rejected (injection guard) and a fresh
        // UUID is minted instead of being echoed back.
        let out = continue_or_mint_trace_id(Some("not-a-uuid; DROP TABLE"));
        assert_ne!(out, "not-a-uuid; DROP TABLE");
        assert!(uuid::Uuid::parse_str(&out).is_ok());
    }

    #[test]
    fn continue_mints_for_missing_or_empty() {
        let a = continue_or_mint_trace_id(None);
        let b = continue_or_mint_trace_id(Some(""));
        assert!(uuid::Uuid::parse_str(&a).is_ok());
        assert!(uuid::Uuid::parse_str(&b).is_ok());
        // Two independent mints must differ.
        assert_ne!(a, b);
    }

    #[test]
    fn egress_passes_through_when_not_terminating() {
        let own = uuid::Uuid::new_v4().to_string();
        assert_eq!(egress_trace_id(false, &own), own);
    }

    #[test]
    fn egress_mints_a_fresh_id_when_terminating() {
        let own = uuid::Uuid::new_v4().to_string();
        let out = egress_trace_id(true, &own);
        assert_ne!(out, own, "termination must not forward the incoming trace");
        assert!(uuid::Uuid::parse_str(&out).is_ok());
    }
}
