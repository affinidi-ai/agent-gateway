use cucumber::{then, when};
use reqwest::Method;
use serde_json::json;

use crate::steps::credential_save::send;
use crate::world::SurfaceWorld;

const SASL_PASSWORD: &str = "bdd-kafka-password";

#[when(
    expr = "the operator creates a Kafka stream endpoint with security protocol {string} and SASL mechanism {string}"
)]
async fn operator_creates_kafka_stream_endpoint(
    world: &mut SurfaceWorld,
    security_protocol: String,
    sasl_mechanism: String,
) {
    let body = json!({
        "name": "Kafka events",
        "type": "stream",
        "configuration": {
            "platform": "kafka",
            "topic": "gw1.audit",
            "brokers": "127.0.0.1:9",
            "security_protocol": security_protocol,
            "sasl_mechanism": sasl_mechanism,
            "sasl_username": "gw1",
            "sasl_password": SASL_PASSWORD
        }
    });
    let response = send(world, Method::POST, "/v1/integrations/endpoints", Some(&body)).await;
    world.admin_response = Some(response);
}

#[then(
    expr = "the endpoint in the admin API response connects with security protocol {string} and SASL mechanism {string}"
)]
fn endpoint_connects_with(
    world: &mut SurfaceWorld,
    security_protocol: String,
    sasl_mechanism: String,
) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("admin API response")
        .body;
    assert_eq!(body["configuration"]["security_protocol"], security_protocol.as_str(), "{body}");
    assert_eq!(body["configuration"]["sasl_mechanism"], sasl_mechanism.as_str(), "{body}");
}

#[then("the endpoint in the admin API response does not show its SASL password")]
fn endpoint_hides_sasl_password(world: &mut SurfaceWorld) {
    let body = &world
        .admin_response
        .as_ref()
        .expect("admin API response")
        .body;
    assert_eq!(body["secrets"], json!(["sasl_password"]), "{body}");
    assert!(!body.to_string().contains(SASL_PASSWORD), "{body}");
}
