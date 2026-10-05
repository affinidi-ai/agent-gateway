//! Canonical A2A JSON-RPC method table (v0.3 slash-form and v1.0 PascalCase).
//!
//! A2A v1.0 renamed the JSON-RPC wire method names from the v0.3 slash-form
//! (e.g. `message/send`) to PascalCase (e.g. `SendMessage`), and restructured the
//! push-notification-config methods (`tasks/pushNotificationConfig/set` becomes
//! `CreateTaskPushNotificationConfig`, etc.). The gateway is a proxy sitting
//! between callers and upstream agents that may each be on either version, so it
//! must **recognise both eras**.
//!
//! Policy exposure (`input.a2a.method`) and request forwarding keep the method
//! **exactly as the caller sent it** — the gateway does not rewrite it. Policy
//! also receives `input.a2a.method_canonical`, the slash-form from
//! [`recognised_canonical`] (absent for an unrecognised method), so one deny
//! rule covers both spellings. The gateway's own method-dependent logic (request-shape validation, payment
//! gating, A2A-proxy dispatch, onboarding) compares the canonical (v0.3
//! slash-form) name from [`canonical_method`], and protocol detection and UCP
//! extraction recognise both eras via [`is_a2a_method`], so that internal
//! behaviour is version-independent without changing what customer policies
//! observe.

/// `(canonical v0.3 slash-form, v1.0 PascalCase)` for every A2A JSON-RPC method
/// the gateway recognises. The canonical form is the v0.3 slash-form.
///
/// The legacy pre-0.2 `tasks/send` alias is intentionally absent (dropped).
const METHOD_TABLE: &[(&str, &str)] = &[
    ("message/send", "SendMessage"),
    ("message/stream", "SendStreamingMessage"),
    ("tasks/get", "GetTask"),
    ("tasks/list", "ListTasks"),
    ("tasks/cancel", "CancelTask"),
    ("tasks/resubscribe", "SubscribeToTask"),
    ("tasks/pushNotificationConfig/set", "CreateTaskPushNotificationConfig"),
    ("tasks/pushNotificationConfig/get", "GetTaskPushNotificationConfig"),
    ("tasks/pushNotificationConfig/list", "ListTaskPushNotificationConfigs"),
    ("tasks/pushNotificationConfig/delete", "DeleteTaskPushNotificationConfig"),
    ("agent/getAuthenticatedExtendedCard", "GetExtendedAgentCard"),
];

/// Return the canonical v0.3 slash-form name for a recognised A2A method in
/// either era, or `None` when `method` is not in the method table.
pub fn recognised_canonical(method: &str) -> Option<&'static str> {
    METHOD_TABLE
        .iter()
        .find(|(canonical, pascal)| method == *canonical || method == *pascal)
        .map(|(canonical, _)| *canonical)
}

/// Return the canonical v0.3 slash-form name for an A2A method, accepting either
/// the v0.3 slash-form or the v1.0 PascalCase spelling. Unrecognised methods are
/// returned unchanged.
///
/// Use this for the gateway's own internal method gating. `input.a2a.method` and
/// the forwarded request body keep the caller's original spelling; the canonical
/// form reaches policy only as the separate `input.a2a.method_canonical`.
pub fn canonical_method(method: &str) -> &str {
    recognised_canonical(method).unwrap_or(method)
}

/// Which A2A era a wire method name belongs to, as a metric label:
/// `"0.3"` (slash-form), `"1.0"` (PascalCase), or `"unknown"`.
///
/// Note this is independent of the version a caller negotiated via `A2A-Version`:
/// the gateway accepts either era regardless, so a caller can legitimately send a
/// v1.0 method name while negotiating 0.3 (for example by omitting the header).
/// Surfacing that skew is the point of tracking it.
pub fn method_era(method: &str) -> &'static str {
    for (canonical, pascal) in METHOD_TABLE {
        if method == *canonical {
            return "0.3";
        }
        if method == *pascal {
            return "1.0";
        }
    }
    "unknown"
}

/// True when `method` is a recognised A2A JSON-RPC method in either era
/// (v0.3 slash-form or v1.0 PascalCase).
pub fn is_a2a_method(method: &str) -> bool {
    recognised_canonical(method).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalises_both_eras_to_slash_form() {
        // v1.0 PascalCase -> canonical v0.3 slash-form
        assert_eq!(canonical_method("SendMessage"), "message/send");
        assert_eq!(canonical_method("SendStreamingMessage"), "message/stream");
        assert_eq!(canonical_method("GetTask"), "tasks/get");
        assert_eq!(canonical_method("ListTasks"), "tasks/list");
        assert_eq!(canonical_method("CancelTask"), "tasks/cancel");
        assert_eq!(canonical_method("SubscribeToTask"), "tasks/resubscribe");
        assert_eq!(canonical_method("CreateTaskPushNotificationConfig"), "tasks/pushNotificationConfig/set");
        assert_eq!(canonical_method("DeleteTaskPushNotificationConfig"), "tasks/pushNotificationConfig/delete");
        assert_eq!(canonical_method("GetExtendedAgentCard"), "agent/getAuthenticatedExtendedCard");

        // v0.3 slash-form is already canonical
        assert_eq!(canonical_method("message/send"), "message/send");
        assert_eq!(canonical_method("tasks/list"), "tasks/list");
    }

    #[test]
    fn unknown_methods_pass_through_unchanged() {
        assert_eq!(canonical_method("tools/call"), "tools/call");
        assert_eq!(canonical_method("tasks/send"), "tasks/send"); // dropped alias, not canonicalised
        assert_eq!(canonical_method("whatever"), "whatever");
    }

    #[test]
    fn recognised_canonical_maps_both_eras_and_rejects_unknown() {
        assert_eq!(recognised_canonical("SendMessage"), Some("message/send"));
        assert_eq!(recognised_canonical("message/send"), Some("message/send"));
        assert_eq!(recognised_canonical("GetTask"), Some("tasks/get"));
        assert_eq!(recognised_canonical("custom/thing"), None);
        assert_eq!(recognised_canonical("FooBar"), None);
        assert_eq!(recognised_canonical("tasks/send"), None);
        assert_eq!(recognised_canonical(""), None);
    }

    #[test]
    fn recognises_both_eras() {
        // v0.3 slash-form
        assert!(is_a2a_method("message/send"));
        assert!(is_a2a_method("tasks/pushNotificationConfig/list"));
        assert!(is_a2a_method("agent/getAuthenticatedExtendedCard"));
        // v1.0 PascalCase
        assert!(is_a2a_method("SendMessage"));
        assert!(is_a2a_method("ListTasks"));
        assert!(is_a2a_method("GetExtendedAgentCard"));
    }

    #[test]
    fn labels_the_era_of_a_method_name() {
        assert_eq!(method_era("message/send"), "0.3");
        assert_eq!(method_era("tasks/pushNotificationConfig/set"), "0.3");
        assert_eq!(method_era("SendMessage"), "1.0");
        assert_eq!(method_era("CreateTaskPushNotificationConfig"), "1.0");
        assert_eq!(method_era("GetExtendedAgentCard"), "1.0");
        // Not an A2A method at all (MCP, UCP, the dropped alias, junk).
        assert_eq!(method_era("tools/call"), "unknown");
        assert_eq!(method_era("tasks/send"), "unknown");
        assert_eq!(method_era(""), "unknown");
    }

    #[test]
    fn rejects_non_a2a_and_dropped_alias() {
        assert!(!is_a2a_method("tools/call")); // MCP
        assert!(!is_a2a_method("initialize")); // MCP
        assert!(!is_a2a_method("tasks/send")); // dropped pre-0.2 alias
        assert!(!is_a2a_method("create_checkout")); // UCP
        assert!(!is_a2a_method(""));
    }
}
