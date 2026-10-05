//! MCP capability validation

use serde_json::Value as JsonValue;
use tracing::{debug, warn};

/// Validate client capabilities against server capabilities
#[allow(dead_code)]
pub fn validate_capabilities(
    client_caps: &JsonValue,
    server_caps: &JsonValue,
) -> Result<(), String> {
    debug!("Validating MCP capabilities");

    // Check if client requires capabilities that server doesn't support
    if let Some(client_obj) = client_caps.as_object()
        && let Some(server_obj) = server_caps.as_object()
    {
        for (capability, _) in client_obj {
            if !server_obj.contains_key(capability) {
                warn!("Client requires capability '{}' which server doesn't support", capability);
            }
        }
    }

    Ok(())
}

/// Check if a capability is supported
#[allow(dead_code)]
pub fn has_capability(
    capabilities: &JsonValue,
    capability: &str,
) -> bool {
    capabilities
        .get(capability)
        .is_some()
}
