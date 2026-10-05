use std::path::Path;

use chrono::Utc;
use serde_json::json;

const DEFAULT_PING_OPENAPI_SPEC: &str = "openapi: 3.0.0\n\
info:\n\
\x20 title: g2g BDD REST API\n\
\x20 version: 1.0.0\n\
paths:\n\
\x20 /ping:\n\
\x20\x20\x20 get:\n\
\x20\x20\x20\x20\x20 operationId: ping\n\
\x20\x20\x20\x20\x20 summary: Ping the REST API\n\
\x20\x20\x20\x20\x20 responses:\n\
\x20\x20\x20\x20\x20\x20\x20 '200':\n\
\x20\x20\x20\x20\x20\x20\x20\x20\x20 description: OK\n";

pub const WEATHER_OPENAPI_SPEC: &str = include_str!("../fixtures/weather-openapi.yaml");

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct McpProxyFixture {
    pub proxy_id: String,
    pub target_url: String,
    pub openapi_spec: Option<String>,
    pub disabled: bool,
}

impl McpProxyFixture {
    pub fn new(
        proxy_id: impl Into<String>,
        target_url: impl Into<String>,
    ) -> Self {
        Self {
            proxy_id: proxy_id.into(),
            target_url: target_url.into(),
            openapi_spec: None,
            disabled: false,
        }
    }

    pub fn with_openapi_spec(
        mut self,
        spec: impl Into<String>,
    ) -> Self {
        self.openapi_spec = Some(spec.into());
        self
    }

    pub fn with_disabled(mut self) -> Self {
        self.disabled = true;
        self
    }
}

pub fn write_mcp_proxy_fixture(
    proxies_dir: &Path,
    proxy: &McpProxyFixture,
) {
    let now = Utc::now().to_rfc3339();
    let openapi_spec = proxy
        .openapi_spec
        .as_deref()
        .unwrap_or(DEFAULT_PING_OPENAPI_SPEC);
    let status = if proxy.disabled {
        "disabled"
    } else {
        "active"
    };
    let proxy_json = json!({
        "id": proxy.proxy_id,
        "name": proxy.proxy_id,
        "description": "g2g BDD MCP proxy",
        "base_url": proxy.target_url,
        "openapi_spec": openapi_spec,
        "status": status,
        "channel_prefix": "/mcp",
        "endpoint_path": format!("/{}", proxy.proxy_id),
        "flatten_post_params": false,
        "created_at": now,
        "updated_at": now,
    });
    std::fs::write(
        proxies_dir.join(format!("{}.json", proxy.proxy_id)),
        serde_json::to_string_pretty(&proxy_json).unwrap(),
    )
    .unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn mcp_proxy_fixture_writer_creates_expected_storage_record() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let proxies_dir = temp_dir
            .path()
            .join("mcp_proxies");
        std::fs::create_dir_all(&proxies_dir).unwrap();

        super::write_mcp_proxy_fixture(&proxies_dir, &super::McpProxyFixture::new("rest-api", "http://127.0.0.1:9"));

        let proxy_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(proxies_dir.join("rest-api.json")).unwrap()).unwrap();
        assert_eq!(proxy_json["id"], "rest-api");
        assert_eq!(proxy_json["base_url"], "http://127.0.0.1:9");
        assert_eq!(proxy_json["endpoint_path"], "/rest-api");
        assert!(
            proxy_json["openapi_spec"]
                .as_str()
                .unwrap()
                .contains("operationId: ping")
        );
    }

    #[test]
    fn mcp_proxy_fixture_writer_uses_custom_openapi_spec_when_provided() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let proxies_dir = temp_dir
            .path()
            .join("mcp_proxies");
        std::fs::create_dir_all(&proxies_dir).unwrap();

        let fixture =
            super::McpProxyFixture::new("weather", "http://127.0.0.1:9").with_openapi_spec(super::WEATHER_OPENAPI_SPEC);
        super::write_mcp_proxy_fixture(&proxies_dir, &fixture);

        let proxy_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(proxies_dir.join("weather.json")).unwrap()).unwrap();
        let spec = proxy_json["openapi_spec"]
            .as_str()
            .unwrap();
        assert!(spec.contains("operationId: get_weather"));
        assert!(spec.contains("operationId: get_forecast"));
        assert!(!spec.contains("operationId: ping"));
    }

    #[test]
    fn mcp_proxy_fixture_writer_serializes_disabled_status() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let proxies_dir = temp_dir
            .path()
            .join("mcp_proxies");
        std::fs::create_dir_all(&proxies_dir).unwrap();

        let fixture = super::McpProxyFixture::new("rest-api", "http://127.0.0.1:9").with_disabled();
        super::write_mcp_proxy_fixture(&proxies_dir, &fixture);

        let proxy_json: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(proxies_dir.join("rest-api.json")).unwrap()).unwrap();
        assert_eq!(proxy_json["status"], "disabled");
    }
}
