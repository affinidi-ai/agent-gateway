//! Promotion to Active re-reads credential providers from disk: an edit made to a
//! provider file while the gateway was running is served once the node is promoted.

use serde_json::{Value, json};

use super::helpers::{self, GatewayHarness};

async fn call(request: reqwest::RequestBuilder) -> (u16, Value) {
    let response = request
        .send()
        .await
        .expect("admin API request");
    let status = response.status().as_u16();
    (
        status,
        response
            .json()
            .await
            .unwrap_or(Value::Null),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn promotion_to_active_serves_provider_edits_made_on_disk() {
    if crate::gateways::test_helpers::rerun_in_isolated_process() {
        return;
    }
    let mut client = None;
    let mut providers_dir = None;
    let h = GatewayHarness::start(|dir, _, bootstrap| {
        client = Some(helpers::configure_admin_api(bootstrap));
        providers_dir = Some(dir.join("credential_providers"));
    })
    .await;
    let client = client.expect("client");
    let providers_dir = providers_dir.expect("providers dir");

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    while call(client.get(format!("{}/api/v1/health", h.gateway_base)))
        .await
        .0
        != 200
    {
        assert!(tokio::time::Instant::now() < deadline, "gateway never became ready");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let (status, body) = call(
        client
            .post(format!("{}/api/v1/secrets/new", h.gateway_base))
            .json(&json!({"name": "UPSTREAM_KEY", "secret_id": "UPSTREAM_KEY", "value": "upstream-secret"})),
    )
    .await;
    assert_eq!(status, 201, "{body}");
    let (status, created) = call(
        client
            .post(format!("{}/api/v1/credential-providers", h.gateway_base))
            .json(&json!({"name": "before", "provider_id": "upstream", "provider_type": "api_key",
                "api_key_secret_ref": "UPSTREAM_KEY"})),
    )
    .await;
    assert_eq!(status, 201, "{created}");
    let provider_url = format!(
        "{}/api/v1/credential-providers/{}",
        h.gateway_base,
        created["id"]
            .as_str()
            .expect("provider id")
    );

    let file = std::fs::read_dir(&providers_dir)
        .expect("providers dir")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.extension()
                .is_some_and(|ext| ext == "json")
        })
        .expect("stored provider file");
    let mut stored: Value = serde_json::from_slice(&std::fs::read(&file).expect("read provider")).expect("JSON");
    stored["name"] = "after".into();
    std::fs::write(&file, serde_json::to_vec(&stored).expect("serialize")).expect("write provider");

    let (status, served) = call(client.get(&provider_url)).await;
    assert_eq!(status, 200, "{served}");
    assert_eq!(served["name"], "before", "an on-disk edit is not served before activation");

    crate::server::mode::set_server_mode(crate::server::mode::ServerMode::Active);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    let mut last = Value::Null;
    loop {
        if let Ok(response) = client
            .get(&provider_url)
            .send()
            .await
        {
            last = response
                .json()
                .await
                .unwrap_or(Value::Null);
            if last["name"] == "after" {
                break;
            }
        }
        assert!(tokio::time::Instant::now() < deadline, "activation never served the edited provider: {last}");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if let Ok(response) = client
            .get(format!("{}/api/v1/health", h.gateway_base))
            .send()
            .await
            && response.status() == 200
        {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "the node never became ready after activation");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}
