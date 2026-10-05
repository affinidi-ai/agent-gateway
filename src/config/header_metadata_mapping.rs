use std::collections::{BTreeMap, HashSet};

use axum::http::{HeaderMap, HeaderName};
use serde::{Deserialize, Serialize};

use super::agent_surface::{SurfaceProtocol, TransitProtocol};

pub const DEFAULT_HEADER_METADATA_EXTENSION_URI: &str = "https://fabric.affinidi.io/extensions/header-metadata/v1";

#[cfg(test)]
pub const COPILOT_HEADER_METADATA_PRESET_MAPPINGS: &[(&str, &str)] = &[
    ("x-ms-entra-agent-id", "entra_agent_id"),
    ("x-ms-client-tenant-id", "client_tenant_id"),
    ("x-ms-client-session-id", "session_id"),
    ("x-ms-correlation-id", "correlation_id"),
    ("x-ms-coreframework-caller-activity-id", "activity_id"),
    ("x-ms-apim-referrer", "referrer"),
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderMetadataMappingConfig {
    #[serde(default = "default_header_metadata_extension_uri")]
    pub extension_uri: String,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<HeaderMetadataFieldMapping>,

    #[serde(default = "default_strip_mapped_headers")]
    pub strip_mapped_headers: bool,
}

impl Default for HeaderMetadataMappingConfig {
    fn default() -> Self {
        Self {
            extension_uri: default_header_metadata_extension_uri(),
            headers: Vec::new(),
            strip_mapped_headers: default_strip_mapped_headers(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HeaderMetadataFieldMapping {
    pub header: String,
    pub field: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderMetadataMappingDiagnostics {
    pub extension_uri: String,
    pub configured_fields: Vec<String>,
    pub mapped_fields: Vec<String>,
    pub missing_headers: Vec<String>,
    pub strip_mapped_headers: bool,
}

impl HeaderMetadataMappingConfig {
    pub fn validate(
        &self,
        protocol: &SurfaceProtocol,
    ) -> Result<(), HeaderMetadataMappingValidationError> {
        self.validate_for_protocol(
            matches!(protocol, SurfaceProtocol::A2a | SurfaceProtocol::Ap2),
            &protocol.to_string(),
        )
    }

    pub fn validate_transit(
        &self,
        protocol: &TransitProtocol,
    ) -> Result<(), HeaderMetadataMappingValidationError> {
        self.validate_for_protocol(
            matches!(protocol, TransitProtocol::A2a | TransitProtocol::Ap2),
            &protocol.to_string(),
        )
    }

    fn validate_for_protocol(
        &self,
        supported: bool,
        protocol: &str,
    ) -> Result<(), HeaderMetadataMappingValidationError> {
        if !supported {
            return Err(HeaderMetadataMappingValidationError::UnsupportedProtocol { protocol: protocol.to_string() });
        }

        let extension_uri = self.extension_uri.trim();
        if extension_uri.is_empty() {
            return Err(HeaderMetadataMappingValidationError::BlankExtensionUri);
        }
        let parsed = url::Url::parse(extension_uri)
            .map_err(|_| HeaderMetadataMappingValidationError::InvalidExtensionUri(extension_uri.to_string()))?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(HeaderMetadataMappingValidationError::InvalidExtensionUri(extension_uri.to_string()));
        }

        let mut fields = HashSet::with_capacity(self.headers.len());
        for mapping in &self.headers {
            mapping.validate()?;
            let field = mapping.field.trim();
            if !fields.insert(field.to_string()) {
                return Err(HeaderMetadataMappingValidationError::DuplicateField(field.to_string()));
            }
        }
        Ok(())
    }

    pub fn map_headers(
        &self,
        headers: &HeaderMap,
    ) -> BTreeMap<String, String> {
        let mut mapped = BTreeMap::new();
        for mapping in &self.headers {
            let header_name = mapping.header.trim();
            let field = mapping.field.trim();
            let Ok(header_name) = HeaderName::from_bytes(header_name.as_bytes()) else {
                continue;
            };
            let Some(value) = headers.get(header_name) else {
                continue;
            };
            let Ok(value) = value.to_str() else {
                continue;
            };
            mapped.insert(field.to_string(), value.to_string());
        }
        mapped
    }

    pub fn diagnostics(
        &self,
        headers: &HeaderMap,
    ) -> HeaderMetadataMappingDiagnostics {
        let mut configured_fields = Vec::with_capacity(self.headers.len());
        let mut mapped_fields = Vec::new();
        let mut missing_headers = Vec::new();

        for mapping in &self.headers {
            let header = mapping
                .header
                .trim()
                .to_string();
            let field = mapping
                .field
                .trim()
                .to_string();
            configured_fields.push(field.clone());

            let Ok(header_name) = HeaderName::from_bytes(header.as_bytes()) else {
                missing_headers.push(header);
                continue;
            };
            match headers.get(header_name) {
                Some(value) if value.to_str().is_ok() => mapped_fields.push(field),
                _ => missing_headers.push(header),
            }
        }

        HeaderMetadataMappingDiagnostics {
            extension_uri: self.extension_uri.clone(),
            configured_fields,
            mapped_fields,
            missing_headers,
            strip_mapped_headers: self.strip_mapped_headers,
        }
    }
}

impl HeaderMetadataFieldMapping {
    pub fn validate(&self) -> Result<(), HeaderMetadataMappingValidationError> {
        let header = self.header.trim();
        if header.is_empty() {
            return Err(HeaderMetadataMappingValidationError::BlankHeader);
        }
        HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| HeaderMetadataMappingValidationError::InvalidHeader(header.to_string()))?;
        if is_sensitive_header(header) {
            return Err(HeaderMetadataMappingValidationError::SensitiveHeader(header.to_string()));
        }
        if self.field.trim().is_empty() {
            return Err(HeaderMetadataMappingValidationError::BlankField);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HeaderMetadataMappingValidationError {
    #[error("header metadata mapping is only supported for A2A/AP2 surfaces, got {protocol}")]
    UnsupportedProtocol { protocol: String },
    #[error("header metadata mapping extension_uri must not be blank")]
    BlankExtensionUri,
    #[error("header metadata mapping extension_uri must be an absolute http(s) URI: {0}")]
    InvalidExtensionUri(String),
    #[error("header metadata mapping header must not be blank")]
    BlankHeader,
    #[error("header metadata mapping header is invalid: {0}")]
    InvalidHeader(String),
    #[error("header metadata mapping cannot copy sensitive header '{0}'")]
    SensitiveHeader(String),
    #[error("header metadata mapping destination field must not be blank")]
    BlankField,
    #[error("header metadata mapping contains duplicate destination field '{0}'")]
    DuplicateField(String),
}

pub fn default_header_metadata_extension_uri() -> String {
    DEFAULT_HEADER_METADATA_EXTENSION_URI.to_string()
}

pub fn default_strip_mapped_headers() -> bool {
    true
}

#[cfg(test)]
pub fn copilot_header_metadata_identity_schema() -> serde_json::Value {
    let identity_fields = ["entra_agent_id", "client_tenant_id"];
    let properties = COPILOT_HEADER_METADATA_PRESET_MAPPINGS
        .iter()
        .map(|(_, field)| {
            let schema = if identity_fields.contains(field) {
                serde_json::json!({ "type": "string", "x-identity": true })
            } else {
                serde_json::json!({ "type": "string" })
            };
            ((*field).to_string(), schema)
        })
        .collect::<serde_json::Map<_, _>>();

    serde_json::json!({
        "type": "object",
        "properties": properties,
        "required": identity_fields,
    })
}

pub fn is_sensitive_header(header: &str) -> bool {
    let normalized = header
        .trim()
        .to_ascii_lowercase();
    normalized == "authorization"
        || normalized == "proxy-authorization"
        || normalized == "cookie"
        || normalized == "set-cookie"
        || normalized.contains("token")
        || normalized.contains("secret")
        || normalized.contains("credential")
        || normalized.contains("api-key")
        || normalized.contains("apikey")
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn mapping(
        header: &str,
        field: &str,
    ) -> HeaderMetadataFieldMapping {
        HeaderMetadataFieldMapping {
            header: header.to_string(),
            field: field.to_string(),
        }
    }

    #[test]
    fn header_lookup_is_case_insensitive() {
        let config = HeaderMetadataMappingConfig {
            headers: vec![mapping("x-agent-id", "agent_id")],
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("X-Agent-Id", HeaderValue::from_static("agent-123"));

        let mapped = config.map_headers(&headers);

        assert_eq!(mapped.get("agent_id"), Some(&"agent-123".to_string()));
    }

    #[test]
    fn missing_headers_are_skipped() {
        let config = HeaderMetadataMappingConfig {
            headers: vec![mapping("x-agent-session-id", "session_id")],
            ..Default::default()
        };

        let mapped = config.map_headers(&HeaderMap::new());

        assert!(mapped.is_empty());
    }

    #[test]
    fn diagnostics_report_field_names_without_header_values() {
        let config = HeaderMetadataMappingConfig {
            headers: vec![mapping("x-agent-id", "agent_id"), mapping("x-session", "session_id")],
            ..Default::default()
        };
        let mut headers = HeaderMap::new();
        headers.insert("x-agent-id", HeaderValue::from_static("secret-agent-value"));

        let diagnostics = config.diagnostics(&headers);

        assert_eq!(diagnostics.extension_uri, DEFAULT_HEADER_METADATA_EXTENSION_URI);
        assert_eq!(diagnostics.configured_fields, vec!["agent_id".to_string(), "session_id".to_string()]);
        assert_eq!(diagnostics.mapped_fields, vec!["agent_id".to_string()]);
        assert_eq!(diagnostics.missing_headers, vec!["x-session".to_string()]);
        assert!(diagnostics.strip_mapped_headers);
        assert!(!format!("{diagnostics:?}").contains("secret-agent-value"));
    }

    #[test]
    fn blank_destination_fields_are_rejected() {
        let config = HeaderMetadataMappingConfig {
            headers: vec![mapping("x-agent-id", "   ")],
            ..Default::default()
        };

        let err = config
            .validate(&SurfaceProtocol::A2a)
            .expect_err("blank destination must fail validation");

        assert_eq!(err, HeaderMetadataMappingValidationError::BlankField);
    }

    #[test]
    fn duplicate_destination_fields_are_rejected() {
        let config = HeaderMetadataMappingConfig {
            headers: vec![mapping("x-agent-id", "agent_id"), mapping("x-other-agent-id", "agent_id")],
            ..Default::default()
        };

        let err = config
            .validate(&SurfaceProtocol::A2a)
            .expect_err("duplicate destination must fail validation");

        assert_eq!(err, HeaderMetadataMappingValidationError::DuplicateField("agent_id".to_string()));
    }

    #[test]
    fn sensitive_headers_are_rejected() {
        for header in ["authorization", "Cookie", "x-agent-token", "x-api-key", "x-client-secret"] {
            let config = HeaderMetadataMappingConfig {
                headers: vec![mapping(header, "blocked")],
                ..Default::default()
            };

            let err = config
                .validate(&SurfaceProtocol::A2a)
                .expect_err("sensitive header must fail validation");

            assert!(matches!(err, HeaderMetadataMappingValidationError::SensitiveHeader(_)));
        }
    }

    #[test]
    fn mapping_is_rejected_for_non_a2a_protocols() {
        let config = HeaderMetadataMappingConfig {
            headers: vec![mapping("x-agent-id", "agent_id")],
            ..Default::default()
        };

        let err = config
            .validate(&SurfaceProtocol::Mcp)
            .expect_err("MCP must not support A2A header metadata mapping");

        assert_eq!(err, HeaderMetadataMappingValidationError::UnsupportedProtocol { protocol: "mcp".to_string() });
    }

    #[test]
    fn strip_mapped_headers_defaults_to_enabled() {
        let config: HeaderMetadataMappingConfig = serde_json::from_value(serde_json::json!({
            "headers": [{ "header": "x-agent-id", "field": "agent_id" }]
        }))
        .expect("config should deserialize");

        assert!(config.strip_mapped_headers);
    }

    #[test]
    fn serialization_round_trips() {
        let config = HeaderMetadataMappingConfig {
            extension_uri: "https://example.test/extensions/headers/v1".to_string(),
            headers: vec![mapping("x-agent-id", "agent_id")],
            strip_mapped_headers: false,
        };

        let value = serde_json::to_value(&config).expect("serialize config");
        let round_trip: HeaderMetadataMappingConfig = serde_json::from_value(value).expect("deserialize config");

        assert_eq!(round_trip, config);
    }
}
