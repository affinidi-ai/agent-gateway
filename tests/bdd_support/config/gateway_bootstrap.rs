use std::path::Path;

use serde_json::json;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GatewayBootstrapSurface {
    pub id: String,
    pub name: String,
    pub prefix: String,
}

impl GatewayBootstrapSurface {
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        prefix: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            prefix: prefix.into(),
        }
    }
}

pub fn write_gateway_bootstrap_json(
    config_dir: &Path,
    gateway_port: u16,
    bootstrap_surfaces: &[GatewayBootstrapSurface],
    identity_route_key: &str,
) {
    write_gateway_bootstrap_json_inner(config_dir, gateway_port, None, bootstrap_surfaces, identity_route_key, None);
}

pub fn write_gateway_bootstrap_json_with_terms(
    config_dir: &Path,
    gateway_port: u16,
    bootstrap_surfaces: &[GatewayBootstrapSurface],
    identity_route_key: &str,
    affinidi_terms_url: &str,
) {
    write_gateway_bootstrap_json_inner(
        config_dir,
        gateway_port,
        None,
        bootstrap_surfaces,
        identity_route_key,
        Some(affinidi_terms_url),
    );
}

pub fn write_gateway_bootstrap_json_with_outbound_listener(
    config_dir: &Path,
    gateway_port: u16,
    outbound_port: u16,
    bootstrap_surfaces: &[GatewayBootstrapSurface],
    identity_route_key: &str,
) {
    write_gateway_bootstrap_json_inner(
        config_dir,
        gateway_port,
        Some(outbound_port),
        bootstrap_surfaces,
        identity_route_key,
        None,
    );
}

fn write_gateway_bootstrap_json_inner(
    config_dir: &Path,
    gateway_port: u16,
    outbound_port: Option<u16>,
    bootstrap_surfaces: &[GatewayBootstrapSurface],
    identity_route_key: &str,
    affinidi_terms_url: Option<&str>,
) {
    let listen_address = format!("http://localhost:{gateway_port}");
    let mut listeners = vec![json!({
        "id": "bdd-test",
        "name": "BDD Test",
        "bind_address": "0.0.0.0",
        "port": gateway_port,
        "protocol": "http",
        "external_urls": [listen_address],
        "listener_type": "inbound",
    })];
    if let Some(outbound_port) = outbound_port {
        listeners.push(json!({
            "id": "bdd-outbound",
            "name": "BDD Outbound",
            "bind_address": "0.0.0.0",
            "port": outbound_port,
            "protocol": "http",
            "external_urls": [format!("http://localhost:{outbound_port}")],
            "listener_type": "outbound",
        }));
    }
    let gateway_json = json!({
        "did": { "domain": "localhost" },
        "webauthn": {
            "rp_id": "localhost",
            "external_origin": listen_address,
        },
        "integration": { "types": [], "categories": [] },
        "terms": affinidi_terms_url.is_some(),
        "affinidi_terms_url": affinidi_terms_url,
        "listeners": listeners,
        "channels": bootstrap_surfaces
            .iter()
            .map(|surface| json!({
                "id": surface.id,
                "name": surface.name,
                "prefix": surface.prefix,
            }))
            .collect::<Vec<_>>(),
        "routes": {
            identity_route_key: {
                "type": "identity_api",
                "prefix": "/api",
            }
        },
    });

    std::fs::write(config_dir.join("gateway.json"), serde_json::to_string_pretty(&gateway_json).unwrap()).unwrap();
}

#[cfg(test)]
mod tests {
    #[test]
    fn write_gateway_bootstrap_json_with_surfaces_and_identity_route() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let bootstrap_surfaces = vec![
            super::GatewayBootstrapSurface::new("alpha", "Alpha", "/alpha"),
            super::GatewayBootstrapSurface::new("bravo", "Bravo", "/bravo"),
        ];

        super::write_gateway_bootstrap_json(temp_dir.path(), 32001, &bootstrap_surfaces, "identity");

        let gateway_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("gateway.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(gateway_json["webauthn"]["external_origin"], "http://localhost:32001");
        assert_eq!(gateway_json["listeners"][0]["port"], 32001);
        assert_eq!(gateway_json["listeners"][0]["external_urls"][0], "http://localhost:32001");
        assert_eq!(gateway_json["listeners"][0]["listener_type"], "inbound");
        assert_eq!(gateway_json["channels"][0]["id"], "alpha");
        assert_eq!(gateway_json["channels"][0]["name"], "Alpha");
        assert_eq!(gateway_json["channels"][0]["prefix"], "/alpha");
        assert_eq!(gateway_json["channels"][1]["id"], "bravo");
        assert_eq!(gateway_json["routes"]["identity"]["type"], "identity_api");
        assert_eq!(gateway_json["routes"]["identity"]["prefix"], "/api");
        assert_eq!(gateway_json["terms"], false);
    }

    #[test]
    fn write_gateway_bootstrap_json_can_enable_terms() {
        let temp_dir = tempfile::TempDir::new().unwrap();

        super::write_gateway_bootstrap_json_with_terms(
            temp_dir.path(),
            32001,
            &[],
            "identity",
            "http://127.0.0.1:32002/terms/v1/current.json",
        );

        let gateway_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("gateway.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(gateway_json["terms"], true);
        assert_eq!(gateway_json["affinidi_terms_url"], "http://127.0.0.1:32002/terms/v1/current.json");
    }

    #[test]
    fn write_gateway_bootstrap_json_can_include_outbound_listener() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let bootstrap_surfaces = vec![super::GatewayBootstrapSurface::new("alpha", "Alpha", "/alpha")];

        super::write_gateway_bootstrap_json_with_outbound_listener(
            temp_dir.path(),
            32001,
            32002,
            &bootstrap_surfaces,
            "identity",
        );

        let gateway_json: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(
                temp_dir
                    .path()
                    .join("gateway.json"),
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(
            gateway_json["listeners"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert_eq!(gateway_json["listeners"][0]["listener_type"], "inbound");
        assert_eq!(gateway_json["listeners"][1]["port"], 32002);
        assert_eq!(gateway_json["listeners"][1]["external_urls"][0], "http://localhost:32002");
        assert_eq!(gateway_json["listeners"][1]["listener_type"], "outbound");
    }
}
