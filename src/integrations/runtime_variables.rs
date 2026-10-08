use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::RwLock;

/// Global storage for variable patterns from config
static VARIABLE_PATTERN: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(r"\$\{([^:}]+)(?::[^}]+)?\}".to_string()));

static CUSTOM_VARIABLE_PREFIX: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new("_".to_string()));

/// Cached compiled regex for variable substitution
static VAR_REGEX: Lazy<RwLock<Regex>> = Lazy::new(|| RwLock::new(Regex::new(r"\$\{([^:}]+)(?::[^}]+)?\}").unwrap()));

/// Update the variable patterns from config (called during startup)
pub fn set_variable_patterns(
    variable_pattern: String,
    custom_prefix: String,
) {
    if let Ok(mut p) = VARIABLE_PATTERN.write() {
        *p = variable_pattern.clone();
    }
    if let Ok(mut p) = CUSTOM_VARIABLE_PREFIX.write() {
        *p = custom_prefix;
    }
    // Update the cached regex when pattern changes
    if let Ok(new_regex) = Regex::new(&variable_pattern)
        && let Ok(mut regex) = VAR_REGEX.write()
    {
        *regex = new_regex;
    }
}

/// The prefix that marks a template variable as custom (operator-supplied) rather than runtime.
pub fn custom_variable_prefix() -> String {
    CUSTOM_VARIABLE_PREFIX
        .read()
        .map(|prefix| prefix.clone())
        .unwrap_or_else(|_| "_".to_string())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVariable {
    pub name: String,
    pub label: String,
    pub description: String,
    pub example: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVariableCategory {
    pub category: String,
    pub label: String,
    pub description: String,
    pub variables: Vec<RuntimeVariable>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeVariablesResponse {
    pub categories: Vec<RuntimeVariableCategory>,
}

/// Variables whose value is JSON text. When one fills an entire JSON string
/// value of a template (`"record": "${AUDIT_RECORD}"`), the JSON is embedded as
/// structured data instead of an escaped string.
const JSON_VALUED_VARIABLES: &[&str] = &["AUDIT_RECORD"];

static RUNTIME_VARIABLES: Lazy<RuntimeVariablesResponse> = Lazy::new(|| RuntimeVariablesResponse {
    categories: vec![
        get_general_variables(),
        get_connection_point_variables(),
        get_user_variables(),
        get_gateway_variables(),
        get_surface_variables(),
        get_identity_variables(),
        get_mcp_proxy_variables(),
        get_mediator_variables(),
        get_trust_registry_variables(),
        get_secrets_variables(),
        get_audit_variables(),
    ],
});

/// Get all runtime variable definitions
pub fn get_runtime_variables() -> RuntimeVariablesResponse {
    RUNTIME_VARIABLES.clone()
}

fn get_general_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "general".to_string(),
        label: "General".to_string(),
        description: "Variables available to all integrations regardless of context".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "OLD_STATE".to_string(),
                label: "Old State".to_string(),
                description: "JSON representation of the entity's state before the event. Empty for CREATE events. Contains the entity object (Gateway, User, etc.) for UPDATE and DELETE events; a user carries only user_id, role, status, is_primary, created_at and updated_at.".to_string(),
                example: r#"${OLD_STATE}"#.to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "NEW_STATE".to_string(),
                label: "New State".to_string(),
                description: "JSON representation of the entity's state after the event. Empty for DELETE events. Contains the entity object (Gateway, User, etc.) for CREATE and UPDATE events; a user carries only user_id, role, status, is_primary, created_at and updated_at.".to_string(),
                example: r#"${NEW_STATE}"#.to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "The type of event that triggered the integration (e.g., 'gateway.created', 'user.updated', etc.)".to_string(),
                example: "${EVENT_TYPE}".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "TIMESTAMP".to_string(),
                label: "Timestamp".to_string(),
                description: "ISO 8601 timestamp when the event occurred".to_string(),
                example: "$TIMESTAMP".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "SERVER_NAME".to_string(),
                label: "Server Name".to_string(),
                description: "Name of the Agent Gateway server".to_string(),
                example: "$SERVER_NAME".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "SERVER_DOMAIN".to_string(),
                label: "Server Domain".to_string(),
                description: "Domain name of the server".to_string(),
                example: "$SERVER_DOMAIN".to_string(),
                category: "general".to_string(),
            },
            RuntimeVariable {
                name: "MESSAGE_ID".to_string(),
                label: "Message ID".to_string(),
                description: "Unique identifier for the message/event".to_string(),
                example: "$MESSAGE_ID".to_string(),
                category: "general".to_string(),
            },
        ],
    }
}

fn get_connection_point_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "connection_point".to_string(),
        label: "Connection Point".to_string(),
        description: "Variables available when notifications are triggered from connection point events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "CP_ID".to_string(),
                label: "Connection Point ID".to_string(),
                description: "Unique identifier of the connection point".to_string(),
                example: "$CP_ID".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "CP_NAME".to_string(),
                label: "Connection Point Name".to_string(),
                description: "Display name of the connection point".to_string(),
                example: "$CP_NAME".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "CP_DESCRIPTION".to_string(),
                label: "Connection Point Description".to_string(),
                description: "Description of the connection point".to_string(),
                example: "$CP_DESCRIPTION".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY".to_string(),
                label: "Gateway Name".to_string(),
                description: "Name of the associated gateway".to_string(),
                example: "$GATEWAY".to_string(),
                category: "connection_point".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_ID".to_string(),
                label: "Gateway ID".to_string(),
                description: "Unique identifier of the gateway".to_string(),
                example: "$GATEWAY_ID".to_string(),
                category: "connection_point".to_string(),
            },
        ],
    }
}

fn get_user_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "user".to_string(),
        label: "User Management".to_string(),
        description: "Variables available when notifications are triggered from user management events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "USER_ID".to_string(),
                label: "User ID".to_string(),
                description: "Unique identifier of the user".to_string(),
                example: "$USER_ID".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USERNAME".to_string(),
                label: "Username".to_string(),
                description: "Username of the user".to_string(),
                example: "$USERNAME".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USER_EMAIL".to_string(),
                label: "User Email".to_string(),
                description: "Email address of the user".to_string(),
                example: "$USER_EMAIL".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USER_ROLE".to_string(),
                label: "User Role".to_string(),
                description: "Role assigned to the user (administrator, poweruser, user)".to_string(),
                example: "$USER_ROLE".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "USER_STATUS".to_string(),
                label: "User Status".to_string(),
                description: "Current status of the user (new, approved, disabled)".to_string(),
                example: "$USER_STATUS".to_string(),
                category: "user".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of user event (user.created, user.approved, user.updated, user.deleted, user.login)"
                    .to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "user".to_string(),
            },
        ],
    }
}

fn get_gateway_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "gateway".to_string(),
        label: "Gateway".to_string(),
        description: "Variables available when notifications are triggered from gateway events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "GATEWAY_ID".to_string(),
                label: "Gateway ID".to_string(),
                description: "Unique identifier of the gateway".to_string(),
                example: "$GATEWAY_ID".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_NAME".to_string(),
                label: "Gateway Name".to_string(),
                description: "Display name of the gateway".to_string(),
                example: "$GATEWAY_NAME".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_DESCRIPTION".to_string(),
                label: "Gateway Description".to_string(),
                description: "Description of the gateway".to_string(),
                example: "$GATEWAY_DESCRIPTION".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_DID".to_string(),
                label: "Gateway DID".to_string(),
                description: "Decentralized Identifier of the gateway".to_string(),
                example: "$GATEWAY_DID".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_TYPE".to_string(),
                label: "Gateway Type".to_string(),
                description: "Type of gateway (SelfGateway or Remote)".to_string(),
                example: "$GATEWAY_TYPE".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_STATUS".to_string(),
                label: "Gateway Status".to_string(),
                description: "Current status of the gateway (Active, Disabled, etc.)".to_string(),
                example: "$GATEWAY_STATUS".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "GATEWAY_OLD_STATUS".to_string(),
                label: "Gateway Old Status".to_string(),
                description: "Previous status of the gateway (available in status_changed events)".to_string(),
                example: "$GATEWAY_OLD_STATUS".to_string(),
                category: "gateway".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description:
                    "Type of gateway event (gateway.created, gateway.updated, gateway.deleted, gateway.status_changed)"
                        .to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "gateway".to_string(),
            },
        ],
    }
}

fn get_surface_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "surface".to_string(),
        label: "Surface".to_string(),
        description: "Variables available when notifications are triggered from Agent Surface events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "SURFACE_ID".to_string(),
                label: "Surface ID".to_string(),
                description: "Unique identifier of the Agent Surface".to_string(),
                example: "$SURFACE_ID".to_string(),
                category: "surface".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_NAME".to_string(),
                label: "Surface Name".to_string(),
                description: "Display name of the Agent Surface".to_string(),
                example: "$SURFACE_NAME".to_string(),
                category: "surface".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_PROTOCOL".to_string(),
                label: "Surface Protocol".to_string(),
                description: "Protocol type (a2a, mcp)".to_string(),
                example: "$SURFACE_PROTOCOL".to_string(),
                category: "surface".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of Agent Surface event".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "surface".to_string(),
            },
        ],
    }
}

fn get_identity_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "identity".to_string(),
        label: "Identity".to_string(),
        description: "Variables available when notifications are triggered from DID identity events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "IDENTITY_DID".to_string(),
                label: "Identity DID".to_string(),
                description: "Decentralized Identifier of the identity".to_string(),
                example: "$IDENTITY_DID".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "IDENTITY_TYPE".to_string(),
                label: "Identity Type".to_string(),
                description: "Type of DID (did:web, did:key, etc.)".to_string(),
                example: "$IDENTITY_TYPE".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "IDENTITY_CONTROLLER".to_string(),
                label: "Identity Controller".to_string(),
                description: "DID of the identity controller".to_string(),
                example: "$IDENTITY_CONTROLLER".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "SURFACE_ID".to_string(),
                label: "Surface ID".to_string(),
                description: "Agent Surface where the identity appeared (for identity.appeared events)".to_string(),
                example: "$SURFACE_ID".to_string(),
                category: "identity".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of identity event (identity.created, identity.updated, identity.deleted, identity.appeared, identity.accessed)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "identity".to_string(),
            },
        ],
    }
}

fn get_mcp_proxy_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "mcp_proxy".to_string(),
        label: "MCP Proxy".to_string(),
        description: "Variables available when notifications are triggered from MCP Proxy events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "MCP_PROXY_ID".to_string(),
                label: "MCP Proxy ID".to_string(),
                description: "Unique identifier of the MCP proxy".to_string(),
                example: "$MCP_PROXY_ID".to_string(),
                category: "mcp_proxy".to_string(),
            },
            RuntimeVariable {
                name: "MCP_PROXY_NAME".to_string(),
                label: "MCP Proxy Name".to_string(),
                description: "Name of the MCP proxy".to_string(),
                example: "$MCP_PROXY_NAME".to_string(),
                category: "mcp_proxy".to_string(),
            },
            RuntimeVariable {
                name: "MCP_PROXY_DESCRIPTION".to_string(),
                label: "MCP Proxy Description".to_string(),
                description: "Description of the MCP proxy".to_string(),
                example: "$MCP_PROXY_DESCRIPTION".to_string(),
                category: "mcp_proxy".to_string(),
            },
            RuntimeVariable {
                name: "MCP_PROXY_TARGET_URL".to_string(),
                label: "Target URL".to_string(),
                description: "Backend target URL of the MCP proxy".to_string(),
                example: "$MCP_PROXY_TARGET_URL".to_string(),
                category: "mcp_proxy".to_string(),
            },
            RuntimeVariable {
                name: "MCP_PROXY_STATUS".to_string(),
                label: "MCP Proxy Status".to_string(),
                description: "Current status of the MCP proxy (Active, Disabled)".to_string(),
                example: "$MCP_PROXY_STATUS".to_string(),
                category: "mcp_proxy".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of MCP proxy event (mcp_proxy.created, mcp_proxy.updated, mcp_proxy.deleted, mcp_proxy.status_changed)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "mcp_proxy".to_string(),
            },
        ],
    }
}

fn get_mediator_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "mediator".to_string(),
        label: "Mediator".to_string(),
        description: "Variables available when notifications are triggered from Mediator events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "MEDIATOR_ID".to_string(),
                label: "Mediator ID".to_string(),
                description: "Unique identifier of the mediator".to_string(),
                example: "$MEDIATOR_ID".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_NAME".to_string(),
                label: "Mediator Name".to_string(),
                description: "Name of the mediator".to_string(),
                example: "$MEDIATOR_NAME".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_DESCRIPTION".to_string(),
                label: "Mediator Description".to_string(),
                description: "Description of the mediator".to_string(),
                example: "$MEDIATOR_DESCRIPTION".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_ENDPOINT".to_string(),
                label: "Mediator Endpoint".to_string(),
                description: "Endpoint URL of the mediator".to_string(),
                example: "$MEDIATOR_ENDPOINT".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_DID".to_string(),
                label: "Mediator DID".to_string(),
                description: "Decentralized Identifier of the mediator".to_string(),
                example: "$MEDIATOR_DID".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "MEDIATOR_STATUS".to_string(),
                label: "Mediator Status".to_string(),
                description: "Current status of the mediator (Active, Disabled)".to_string(),
                example: "$MEDIATOR_STATUS".to_string(),
                category: "mediator".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of mediator event (mediator.created, mediator.updated, mediator.deleted, mediator.status_changed)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "mediator".to_string(),
            },
        ],
    }
}

fn get_trust_registry_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "trust_registry".to_string(),
        label: "Trust Registry".to_string(),
        description: "Variables available when notifications are triggered from Trust Registry events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "TRUST_REGISTRY_ID".to_string(),
                label: "Trust Registry ID".to_string(),
                description: "Unique identifier of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_ID".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_NAME".to_string(),
                label: "Trust Registry Name".to_string(),
                description: "Name of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_NAME".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_DESCRIPTION".to_string(),
                label: "Trust Registry Description".to_string(),
                description: "Description of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_DESCRIPTION".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_DID".to_string(),
                label: "Trust Registry DID".to_string(),
                description: "Decentralized Identifier of the trust registry".to_string(),
                example: "$TRUST_REGISTRY_DID".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "TRUST_REGISTRY_STATUS".to_string(),
                label: "Trust Registry Status".to_string(),
                description: "Current status of the trust registry (Active, Disabled)".to_string(),
                example: "$TRUST_REGISTRY_STATUS".to_string(),
                category: "trust_registry".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of trust registry event (trust_registry.created, trust_registry.updated, trust_registry.deleted, trust_registry.status_changed)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "trust_registry".to_string(),
            },
        ],
    }
}

fn get_secrets_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "secrets".to_string(),
        label: "Secrets".to_string(),
        description: "Variables available when notifications are triggered from Secrets vault events".to_string(),
        variables: vec![
            RuntimeVariable {
                name: "SECRET_ID".to_string(),
                label: "Secret ID".to_string(),
                description: "Unique identifier of the secret".to_string(),
                example: "$SECRET_ID".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "SECRET_NAME".to_string(),
                label: "Secret Name".to_string(),
                description: "Name of the secret".to_string(),
                example: "$SECRET_NAME".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "SECRET_DESCRIPTION".to_string(),
                label: "Secret Description".to_string(),
                description: "Description of the secret".to_string(),
                example: "$SECRET_DESCRIPTION".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "SECRET_TAGS".to_string(),
                label: "Secret Tags".to_string(),
                description: "Comma-separated tags associated with the secret".to_string(),
                example: "$SECRET_TAGS".to_string(),
                category: "secrets".to_string(),
            },
            RuntimeVariable {
                name: "EVENT_TYPE".to_string(),
                label: "Event Type".to_string(),
                description: "Type of secret event (secret.created, secret.updated, secret.deleted)".to_string(),
                example: "$EVENT_TYPE".to_string(),
                category: "secrets".to_string(),
            },
        ],
    }
}

fn audit_variable(
    name: &str,
    label: &str,
    description: &str,
) -> RuntimeVariable {
    RuntimeVariable {
        name: name.to_string(),
        label: label.to_string(),
        description: description.to_string(),
        example: format!("${{{}}}", name),
        category: "audit".to_string(),
    }
}

fn get_audit_variables() -> RuntimeVariableCategory {
    RuntimeVariableCategory {
        category: "audit".to_string(),
        label: "Governance Audit".to_string(),
        description: "Variables available when a governance audit record is written to the VP Audit Log".to_string(),
        variables: vec![
            audit_variable(
                "AUDIT_RECORD",
                "Audit Record",
                "The complete audit record as JSON, in the same shape as a VP Audit Log entry, including the signed VP. Used as an entire JSON string value (\"record\": \"${AUDIT_RECORD}\") it is embedded as a JSON object; inside other text it is inserted as JSON text.",
            ),
            audit_variable(
                "AUDIT_CATEGORY",
                "Audit Category",
                "Category of the audit record (policy_decision, trust_check, trace_terminated, vp_injected, token_injected, consent_granted, payment, …). EVENT_TYPE carries the same value as audit.<category>.",
            ),
            audit_variable(
                "AUDIT_TRACE_ID",
                "Trace ID",
                "Request trace ID that correlates every audit record written for the same request",
            ),
            audit_variable("AUDIT_SURFACE_ID", "Surface ID", "ID of the Agent Surface the record belongs to"),
            audit_variable("AUDIT_SURFACE_NAME", "Surface Name", "Name of the Agent Surface the record belongs to"),
            audit_variable("AUDIT_PROTOCOL", "Protocol", "Protocol of the surface (a2a, mcp, …)"),
            audit_variable("AUDIT_AGENT_DID", "Agent DID", "DID of the agent the record was written for"),
            audit_variable(
                "AUDIT_VIA_FABRIC",
                "Via Fabric",
                "true when the request traversed the gateway-to-gateway fabric, otherwise false",
            ),
            audit_variable(
                "AUDIT_PRINCIPAL",
                "Principal",
                "The authenticated caller the record was written for: their email, else display name, else the authenticated subject (JWT sub, API key name, DID or mTLS principal). Empty when the request had no authenticated caller.",
            ),
            audit_variable(
                "AUDIT_PRINCIPAL_EMAIL",
                "Principal Email",
                "Email of the authenticated caller, when their credential carries one",
            ),
            audit_variable(
                "AUDIT_PRINCIPAL_NAME",
                "Principal Name",
                "Display name of the authenticated caller, when their credential carries one",
            ),
            audit_variable(
                "AUDIT_AUTH_METHOD",
                "Auth Method",
                "How the caller authenticated (jwt_bearer, api_key, did_auth, mtls, session, access_token); empty without an authenticated caller",
            ),
            audit_variable(
                "AUDIT_DECISION",
                "Policy Decision",
                "Policy decision (allow or deny) for policy_decision records; empty for other categories",
            ),
            audit_variable(
                "AUDIT_DENY_REASON",
                "Deny Reason",
                "Deny reason reported by the policy for denied policy_decision records; empty otherwise",
            ),
            audit_variable(
                "AUDIT_POLICY_NAME",
                "Policy Name",
                "Name of the policy that made the decision (its policy definition name, else its Rego package) for policy_decision records; empty otherwise",
            ),
            audit_variable(
                "AUDIT_POLICY_VERSION",
                "Policy Version",
                "Version of the enforced policy revision for policy_decision records, when the policy is versioned",
            ),
            audit_variable(
                "AUDIT_POLICY_CONTENT_HASH",
                "Policy Content Hash",
                "sha256:<hex> hash of the exact Rego enforced for policy_decision records, when known",
            ),
            audit_variable("AUDIT_VP_JWT", "Signed VP", "Signed Verifiable Presentation (JWT) attached to the record"),
            audit_variable(
                "AUDIT_VP_FINGERPRINT",
                "VP Fingerprint",
                "sha256:<hex> fingerprint of the signed VP attached to the record",
            ),
        ],
    }
}

/// Get list of variable names for a specific category (for validation)
pub fn get_variable_names_for_category(category: &str) -> Vec<String> {
    let all_vars = &*RUNTIME_VARIABLES;

    // For 'general' category, only return general variables
    // For other categories, return general + category-specific variables
    let mut variable_names = Vec::new();

    // Add general variables
    if let Some(general_category) = all_vars
        .categories
        .iter()
        .find(|c| c.category == "general")
    {
        variable_names.extend(
            general_category
                .variables
                .iter()
                .map(|v| v.name.clone()),
        );
    }

    // Add category-specific variables (unless category is 'general')
    if category != "general"
        && let Some(specific_category) = all_vars
            .categories
            .iter()
            .find(|c| c.category == category)
    {
        variable_names.extend(
            specific_category
                .variables
                .iter()
                .map(|v| v.name.clone()),
        );
    }

    variable_names
}

/// Validate that all runtime variables in a template are valid for the given category
/// Returns a list of invalid variable names (runtime vars that don't exist for this category)
/// Custom variables (starting with _) are always considered valid
pub fn validate_template_variables(
    template: &str,
    category: &str,
) -> Vec<String> {
    let allowed_variables = get_variable_names_for_category(category);

    // Get patterns from global config
    let var_pattern = VARIABLE_PATTERN
        .read()
        .unwrap()
        .clone();
    let custom_prefix = CUSTOM_VARIABLE_PREFIX
        .read()
        .unwrap()
        .clone();

    let re = regex::Regex::new(&var_pattern).unwrap();

    let mut invalid_vars = Vec::new();

    for cap in re.captures_iter(template) {
        let var_name = cap
            .get(1)
            .unwrap()
            .as_str()
            .trim();

        // Custom variables (start with custom prefix) are always valid
        if var_name.starts_with(&custom_prefix) {
            continue;
        }

        // Check if runtime variable is in allowed list
        if !allowed_variables.contains(&var_name.to_string()) && !invalid_vars.contains(&var_name.to_string()) {
            invalid_vars.push(var_name.to_string());
        }
    }

    invalid_vars
}

/// Substitute runtime variables in a template string
///
/// This function replaces ${VARIABLE_NAME} placeholders with actual values
/// from the provided HashMap. Also supports ${VARIABLE:Label} format where :Label is ignored.
///
/// Variables are categorized as:
/// - Runtime variables: Validated against category allowed list
/// - Custom variables: Start with underscore (${_MY_VAR}) - always allowed, not validated
///
/// If category is None, all variables from the HashMap will be substituted regardless of category.
pub fn substitute_variables(
    template: &str,
    category: Option<&str>,
    values: &HashMap<String, String>,
) -> String {
    let allowed_variables: Option<Vec<String>> = category.map(get_variable_names_for_category);
    let custom_prefix = custom_variable_prefix();
    let Ok(re) = VAR_REGEX.read() else {
        return template.to_string();
    };

    // One pass over the template: a substituted value is never scanned for placeholders again.
    re.replace_all(template, |cap: &regex::Captures| {
        let var_name = cap[1].trim();
        match values.get(var_name) {
            Some(value) if is_variable_allowed(var_name, allowed_variables.as_deref(), &custom_prefix) => {
                Cow::Borrowed(value.as_str())
            }
            _ => Cow::Owned(cap[0].to_string()),
        }
    })
    .into_owned()
}

/// Custom variables are always allowed; runtime variables must belong to the
/// category, and every variable is allowed when no category is given.
fn is_variable_allowed(
    var_name: &str,
    allowed_variables: Option<&[String]>,
    custom_prefix: &str,
) -> bool {
    var_name.starts_with(custom_prefix)
        || allowed_variables.is_none_or(|vars| {
            vars.iter()
                .any(|v| v == var_name)
        })
}

/// The structured value for a template string that consists of exactly one
/// JSON-valued variable placeholder, or `None` when the string should be
/// substituted as text.
fn embedded_json_value(
    template: &str,
    category: Option<&str>,
    values: &HashMap<String, String>,
) -> Option<serde_json::Value> {
    let var_name = {
        let re = VAR_REGEX.read().ok()?;
        let cap = re.captures(template)?;
        if cap.get(0)?.as_str() != template {
            return None;
        }
        cap.get(1)?
            .as_str()
            .trim()
            .to_string()
    };
    if !JSON_VALUED_VARIABLES.contains(&var_name.as_str()) {
        return None;
    }
    let allowed_variables = category.map(get_variable_names_for_category);
    let custom_prefix = CUSTOM_VARIABLE_PREFIX
        .read()
        .ok()?
        .clone();
    if !is_variable_allowed(&var_name, allowed_variables.as_deref(), &custom_prefix) {
        return None;
    }
    serde_json::from_str(values.get(&var_name)?).ok()
}

/// Substitute variables in a JSON value structure (recursive, JSON-safe)
/// This preserves the JSON structure and properly handles special characters
pub fn substitute_variables_in_json(
    value: &serde_json::Value,
    category: Option<&str>,
    variables: &HashMap<String, String>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => embedded_json_value(s, category, variables)
            .unwrap_or_else(|| serde_json::Value::String(substitute_variables(s, category, variables))),
        serde_json::Value::Array(arr) => {
            // Recursively process array elements
            serde_json::Value::Array(
                arr.iter()
                    .map(|item| substitute_variables_in_json(item, category, variables))
                    .collect(),
            )
        }
        serde_json::Value::Object(obj) => {
            // Recursively process object values
            serde_json::Value::Object(
                obj.iter()
                    .map(|(k, v)| (k.clone(), substitute_variables_in_json(v, category, variables)))
                    .collect(),
            )
        }
        // Numbers, booleans, and null are returned as-is
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_runtime_variables() {
        let vars = get_runtime_variables();
        assert!(!vars.categories.is_empty());

        // Check that connection_point category exists
        let cp_category = vars
            .categories
            .iter()
            .find(|c| c.category == "connection_point");
        assert!(cp_category.is_some());

        // Check that it has variables
        let cp_category = cp_category.unwrap();
        assert!(
            !cp_category
                .variables
                .is_empty()
        );
    }

    #[test]
    fn test_get_variable_names_for_category() {
        let names = get_variable_names_for_category("user");
        assert!(names.contains(&"USER_ID".to_string()));
        assert!(names.contains(&"USERNAME".to_string()));
        assert!(names.contains(&"USER_EMAIL".to_string()));
    }

    #[test]
    fn test_substitute_variables() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_123".to_string());
        values.insert("USERNAME".to_string(), "john.doe".to_string());
        values.insert("USER_EMAIL".to_string(), "john@example.com".to_string());

        let template = "User ${USER_ID} (${USERNAME}) has email ${USER_EMAIL}";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "User user_123 (john.doe) has email john@example.com");
    }

    #[test]
    fn test_substitute_variables_with_labels() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_456".to_string());

        let template = "User ID: ${USER_ID:User Identifier}";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "User ID: user_456");
    }

    #[test]
    #[ignore] // FIXME: failing test
    fn test_substitute_variables_dollar_format() {
        let mut values = HashMap::new();
        values.insert("USERNAME".to_string(), "jane".to_string());

        let template = "Welcome $USERNAME!";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "Welcome jane!");
    }

    #[test]
    #[ignore] // FIXME: failing test
    fn test_substitute_variables_in_json() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_123".to_string());
        values.insert("USERNAME".to_string(), "John \"The Boss\" Doe".to_string()); // Contains quotes
        values.insert("MESSAGE".to_string(), "Hello\nWorld".to_string()); // Contains newline

        let json_template = serde_json::json!({
            "user_id": "${USER_ID}",
            "username": "${USERNAME}",
            "message": "${MESSAGE}",
            "nested": {
                "value": "${USER_ID}"
            },
            "array": ["${USERNAME}", "static"]
        });

        let result = substitute_variables_in_json(&json_template, Some("user"), &values);

        assert_eq!(result["user_id"], "user_123");
        assert_eq!(result["username"], "John \"The Boss\" Doe");
        assert_eq!(result["message"], "Hello\nWorld");
        assert_eq!(result["nested"]["value"], "user_123");
        assert_eq!(result["array"][0], "John \"The Boss\" Doe");
        assert_eq!(result["array"][1], "static");
    }

    #[test]
    #[ignore] // FIXME: failing test
    fn test_substitute_variables_in_dollar_format() {
        let mut values = HashMap::new();
        values.insert("USERNAME".to_string(), "jane".to_string());

        let template = "Welcome $USERNAME!";
        let result = substitute_variables(template, Some("user"), &values);

        assert_eq!(result, "Welcome jane!");
    }

    #[test]
    fn test_substitute_variables_missing_value() {
        let mut values = HashMap::new();
        values.insert("USER_ID".to_string(), "user_123".to_string());

        let template = "User ${USER_ID} (${USERNAME})";
        let result = substitute_variables(template, Some("user"), &values);

        // Variables without values should remain unchanged
        assert_eq!(result, "User user_123 (${USERNAME})");
    }

    #[test]
    fn test_substitute_variables_no_category_restriction() {
        let mut values = HashMap::new();
        values.insert("CUSTOM_VAR".to_string(), "custom_value".to_string());

        let template = "Value: ${CUSTOM_VAR}";
        let result = substitute_variables(template, None, &values);

        assert_eq!(result, "Value: custom_value");
    }

    fn audit_values() -> HashMap<String, String> {
        HashMap::from([
            ("EVENT_TYPE".to_string(), "audit.policy_decision".to_string()),
            ("AUDIT_TRACE_ID".to_string(), "trace-1".to_string()),
            (
                "AUDIT_RECORD".to_string(),
                r#"{"event":{"policy_decision":{"decision":"deny"}},"trace_id":"trace-1"}"#.to_string(),
            ),
            ("OLD_STATE".to_string(), r#"{"id":"gw-1"}"#.to_string()),
        ])
    }

    #[test]
    fn test_audit_category_variables_are_valid_for_audit_templates() {
        let template = r#"{"type": "${EVENT_TYPE}", "trace": "${AUDIT_TRACE_ID}", "record": "${AUDIT_RECORD}"}"#;
        assert!(validate_template_variables(template, "audit").is_empty());
        assert_eq!(validate_template_variables(template, "gateway"), vec!["AUDIT_TRACE_ID", "AUDIT_RECORD"]);
        assert_eq!(validate_template_variables("${GATEWAY_ID}", "audit"), vec!["GATEWAY_ID"]);
    }

    #[test]
    fn test_json_valued_variable_is_embedded_as_structured_json() {
        let template = serde_json::json!({
            "event_type": "${EVENT_TYPE}",
            "record": "${AUDIT_RECORD}",
            "labelled": "${AUDIT_RECORD:Audit record}",
            "nested": ["${AUDIT_RECORD}"],
        });
        let result = substitute_variables_in_json(&template, Some("audit"), &audit_values());

        let record = serde_json::json!({"event": {"policy_decision": {"decision": "deny"}}, "trace_id": "trace-1"});
        assert_eq!(result["event_type"], "audit.policy_decision");
        assert_eq!(result["record"], record);
        assert_eq!(result["labelled"], record);
        assert_eq!(result["nested"][0], record);
    }

    #[test]
    fn test_json_valued_variable_inside_text_stays_text() {
        let template = serde_json::json!({"summary": "Record: ${AUDIT_RECORD}", "padded": " ${AUDIT_RECORD}"});
        let result = substitute_variables_in_json(&template, Some("audit"), &audit_values());

        let raw = r#"{"event":{"policy_decision":{"decision":"deny"}},"trace_id":"trace-1"}"#;
        assert_eq!(result["summary"], format!("Record: {raw}"));
        assert_eq!(result["padded"], format!(" {raw}"));
    }

    #[test]
    fn test_text_valued_variables_are_never_embedded() {
        let template = serde_json::json!({"old": "${OLD_STATE}"});
        let result = substitute_variables_in_json(&template, Some("gateway"), &audit_values());
        assert_eq!(result["old"], r#"{"id":"gw-1"}"#, "OLD_STATE keeps its string form");
    }

    #[test]
    fn test_json_valued_variable_outside_its_category_is_left_alone() {
        let template = serde_json::json!({"record": "${AUDIT_RECORD}"});
        let result = substitute_variables_in_json(&template, Some("gateway"), &audit_values());
        assert_eq!(result["record"], "${AUDIT_RECORD}");
    }

    #[test]
    fn test_invalid_json_value_falls_back_to_text() {
        let mut values = audit_values();
        values.insert("AUDIT_RECORD".to_string(), "not json".to_string());
        let template = serde_json::json!({"record": "${AUDIT_RECORD}"});
        let result = substitute_variables_in_json(&template, Some("audit"), &values);
        assert_eq!(result["record"], "not json");
    }

    #[test]
    fn test_a_substituted_value_is_never_expanded_again() {
        let values = HashMap::from([
            ("USERNAME".to_string(), "${_TOKEN}".to_string()),
            ("_TOKEN".to_string(), "operator-secret".to_string()),
        ]);

        let result = substitute_variables("user=${USERNAME} token=${_TOKEN}", Some("user"), &values);

        assert_eq!(result, "user=${_TOKEN} token=operator-secret");
    }

    #[test]
    fn test_a_repeated_placeholder_is_filled_everywhere() {
        let values = HashMap::from([("USER_ID".to_string(), "u-1".to_string())]);

        let result = substitute_variables("${USER_ID}/${USER_ID}", Some("user"), &values);

        assert_eq!(result, "u-1/u-1");
    }
}
