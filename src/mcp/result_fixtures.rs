//! The pinned result-preservation fixtures, with the
//! requests that produce them, so each transport path can show an upstream
//! result carrying every preservation field reaches the caller intact.

use serde_json::{Value, json};

pub(crate) struct ResultFixture {
    pub method: String,
    pub result: Value,
}

pub(crate) fn result_fixtures() -> Vec<ResultFixture> {
    let fixtures: Value = serde_json::from_str(include_str!("../../tests/fixtures/mcp/2026-07-28.json")).unwrap();
    fixtures["results"]
        .as_array()
        .unwrap()
        .iter()
        .map(|fixture| ResultFixture {
            method: fixture["method"]
                .as_str()
                .unwrap()
                .to_string(),
            result: fixture["result"].clone(),
        })
        .collect()
}

impl ResultFixture {
    /// A modern request the fixture answers, and its mirrored headers.
    pub fn request(
        &self,
        id: &str,
    ) -> (Value, Vec<(&'static str, String)>) {
        let (mut params, name) = match self.method.as_str() {
            "tools/call" => (json!({"name": "echo", "arguments": {}}), Some("echo")),
            "resources/read" => (json!({"uri": "https://example.org/resource"}), Some("https://example.org/resource")),
            "tasks/get" => (json!({"taskId": "task-1"}), None),
            _ => (json!({}), None),
        };
        params["_meta"] = json!({
            "io.modelcontextprotocol/protocolVersion": super::MCP_MODERN_VERSION,
            "io.modelcontextprotocol/clientCapabilities": {"elicitation": {"url": {}}}
        });
        let mut headers = vec![
            ("content-type", "application/json".to_string()),
            ("accept", "application/json, text/event-stream".to_string()),
            ("mcp-protocol-version", super::MCP_MODERN_VERSION.to_string()),
            ("mcp-method", self.method.clone()),
        ];
        if let Some(name) = name {
            headers.push(("mcp-name", name.to_string()));
        }
        (json!({"jsonrpc": "2.0", "id": id, "method": self.method, "params": params}), headers)
    }

    /// The upstream's JSON-RPC response carrying the fixture.
    pub fn response(
        &self,
        id: &str,
    ) -> Value {
        json!({"jsonrpc": "2.0", "id": id, "result": self.result})
    }

    /// Asserts a delivered result against the fixture. A path may change only
    /// what it documents: its own gateway metadata keys, a caller-scoped
    /// `cacheScope: private` with `ttlMs: 0`, and a `requestState` it wraps.
    pub fn assert_preserved(
        &self,
        delivered: &Value,
        path: &str,
    ) {
        let method = &self.method;
        let mut expected = self.result.clone();
        let mut actual = delivered.clone();
        if let Some(meta) = actual
            .get_mut("_meta")
            .and_then(Value::as_object_mut)
        {
            meta.retain(|key, _| !super::meta::is_gateway_key(key));
            if meta.is_empty()
                && expected
                    .get("_meta")
                    .is_none()
            {
                actual
                    .as_object_mut()
                    .unwrap()
                    .remove("_meta");
            }
        }
        // A path holding continuations wraps the upstream `requestState`;
        // without them it forwards the state opaquely.
        if expected["resultType"] == "input_required" && actual["requestState"] != expected["requestState"] {
            assert!(
                actual["requestState"].is_string(),
                "{path} {method}: the wrapped requestState must stay a string: {actual}"
            );
            for result in [&mut expected, &mut actual] {
                result
                    .as_object_mut()
                    .unwrap()
                    .remove("requestState");
            }
        }
        if expected["resultType"] == "complete" && actual["cacheScope"] == "private" && actual["ttlMs"] == 0 {
            expected["cacheScope"] = json!("private");
            expected["ttlMs"] = json!(0);
        }
        assert_eq!(actual, expected, "{path} altered the {method} result");
    }
}
