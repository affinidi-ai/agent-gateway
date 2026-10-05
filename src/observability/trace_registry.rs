//! Dynamic registry of paths that should be traced
//!
//! This registry is populated when channels and MCP proxies are created,
//! allowing the tracing middleware to dynamically determine which paths represent
//! agent traffic vs dashboard/UX traffic.

use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// Global registry of path prefixes that should be traced
static TRACE_REGISTRY: once_cell::sync::Lazy<Arc<RwLock<TraceRegistry>>> =
    once_cell::sync::Lazy::new(|| Arc::new(RwLock::new(TraceRegistry::new())));

/// Registry of path prefixes that should be traced for agent traffic
#[derive(Debug, Clone)]
pub struct TraceRegistry {
    /// Channel prefixes mapped to their human-readable names
    /// e.g., {"/agents": "agents", "/payments": "payments"}
    channel_prefixes: HashMap<String, String>,

    /// MCP proxy prefixes mapped to their human-readable names
    /// e.g., {"/mcp/filesystem": "filesystem", "/mcp/github": "github"}
    mcp_prefixes: HashMap<String, String>,
}

impl TraceRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            channel_prefixes: HashMap::new(),
            mcp_prefixes: HashMap::new(),
        }
    }

    /// Register a channel prefix for tracing
    /// Overwrites existing registration for the same prefix to allow updates
    pub fn register_channel_prefix(
        &mut self,
        prefix: String,
        name: String,
    ) {
        tracing::info!("Registering channel '{}' at prefix '{}' for tracing", name, prefix);
        self.channel_prefixes
            .insert(prefix, name);
    }

    /// Register an MCP proxy prefix for tracing
    /// Overwrites existing registration for the same prefix to allow updates
    pub fn register_mcp_prefix(
        &mut self,
        prefix: String,
        name: String,
    ) {
        tracing::info!("Registering MCP proxy '{}' at prefix '{}' for tracing", name, prefix);
        self.mcp_prefixes
            .insert(prefix, name);
    }

    /// Check if a path should be traced based on registered prefixes
    pub fn should_trace(
        &self,
        path: &str,
    ) -> bool {
        self.get_trace_info(path)
            .is_some()
    }

    /// Get trace information (name and type) for a path
    /// Returns (name, type) where type is "channel", "mcp", or "well-known"
    ///
    /// Note: Prefixes are checked in order of length (longest first) to ensure
    /// more specific paths match before more general ones (e.g., "/agents/a2a" before "/agents")
    pub fn get_trace_info(
        &self,
        path: &str,
    ) -> Option<(String, String)> {
        // Collect all channel prefixes and sort by length (longest first)
        let mut channel_prefixes: Vec<_> = self
            .channel_prefixes
            .iter()
            .collect();
        channel_prefixes.sort_by_key(|b| std::cmp::Reverse(b.0.len()));

        // Check channel prefixes (longest first for specificity)
        for (prefix, name) in channel_prefixes {
            if path.starts_with(prefix.as_str()) {
                return Some((name.clone(), "channel".to_string()));
            }
        }

        // Collect all MCP prefixes and sort by length (longest first)
        let mut mcp_prefixes: Vec<_> = self
            .mcp_prefixes
            .iter()
            .collect();
        mcp_prefixes.sort_by_key(|b| std::cmp::Reverse(b.0.len()));

        // Check MCP prefixes (longest first for specificity)
        for (prefix, name) in mcp_prefixes {
            if path.starts_with(prefix.as_str()) {
                return Some((name.clone(), "mcp".to_string()));
            }
        }

        // Also trace well-known endpoints
        if path == "/.well-known/agent-card.json" {
            return Some(("agent-card".to_string(), "well-known".to_string()));
        }

        None
    }

    /// Clear all registered prefixes (useful for testing)
    #[allow(dead_code)]
    pub fn clear(&mut self) {
        self.channel_prefixes.clear();
        self.mcp_prefixes.clear();
    }
}

/// Get the global trace registry
#[allow(dead_code)]
pub fn get_trace_registry() -> Arc<RwLock<TraceRegistry>> {
    TRACE_REGISTRY.clone()
}

/// Register a channel prefix for tracing
pub fn register_channel_prefix(
    prefix: impl Into<String>,
    name: impl Into<String>,
) {
    let mut registry = TRACE_REGISTRY.write();
    registry.register_channel_prefix(prefix.into(), name.into());
}

/// Register an MCP proxy prefix for tracing
pub fn register_mcp_prefix(
    prefix: impl Into<String>,
    name: impl Into<String>,
) {
    let mut registry = TRACE_REGISTRY.write();
    registry.register_mcp_prefix(prefix.into(), name.into());
}

/// Check if a path should be traced
#[allow(dead_code)]
pub fn should_trace_path(path: &str) -> bool {
    let registry = TRACE_REGISTRY.read();
    registry.should_trace(path)
}

/// Get trace information for a path (name and type)
/// Returns (name, type) where type is "channel", "mcp", or "well-known"
pub fn get_trace_info(path: &str) -> Option<(String, String)> {
    let registry = TRACE_REGISTRY.read();
    registry.get_trace_info(path)
}
