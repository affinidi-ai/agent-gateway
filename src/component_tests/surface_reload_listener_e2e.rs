//! Surface saves that reload the whole gateway configuration keep every port
//! listener bound: the inbound port, which also serves the management API, and
//! the shared outbound port answer every request made during the saves, and
//! the routes the saves add or remove take effect on the same listeners.

use super::helpers::{GatewayHarness, configure_admin_api, configure_gateway_route_prefixes};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Requests every few milliseconds, each on a new connection, to the inbound
/// management API and the outbound liveness route, recording those not answered
/// `200`.
struct Prober {
    running: Arc<AtomicBool>,
    failures: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<usize>,
}

impl Prober {
    fn start(urls: Vec<String>) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let failures = Arc::new(Mutex::new(Vec::new()));
        let client = reqwest::Client::builder()
            .no_proxy()
            .pool_max_idle_per_host(0)
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let task = tokio::spawn({
            let (running, failures) = (running.clone(), failures.clone());
            async move {
                let mut probes = 0;
                while running.load(Ordering::Relaxed) {
                    for url in &urls {
                        let failure = match client.get(url).send().await {
                            Ok(response) if response.status() == 200 => None,
                            Ok(response) => Some(format!("{url}: {}", response.status())),
                            Err(error) => Some(format!("{url}: {error}")),
                        };
                        if let Some(failure) = failure {
                            failures
                                .lock()
                                .unwrap()
                                .push(failure);
                        }
                        probes += 1;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                probes
            }
        });
        Self { running, failures, task }
    }

    /// Stop probing and return how many requests were made and the failed ones.
    async fn stop(self) -> (usize, Vec<String>) {
        self.running
            .store(false, Ordering::Relaxed);
        let probes = self.task.await.unwrap();
        let failures = std::mem::take(&mut *self.failures.lock().unwrap());
        (probes, failures)
    }
}

fn port_of(url: &str) -> u16 {
    url.rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

async fn send(request: reqwest::RequestBuilder) -> (u16, Value) {
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

async fn call(
    h: &GatewayHarness,
    path: &str,
) -> u16 {
    reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .post(format!("{}{path}", h.gateway_base))
        .json(&json!({"jsonrpc": "2.0", "method": "test", "id": 1}))
        .send()
        .await
        .unwrap()
        .status()
        .as_u16()
}

/// Creating, deactivating and deleting surfaces with Transit Points and
/// variants, which the gateway applies by reloading its whole configuration,
/// refuses no request on the inbound port, its management API, or the shared
/// outbound port; a variant's alias route answers once it is saved and stops
/// once its surface is deleted.
#[tokio::test(flavor = "multi_thread")]
async fn surface_saves_that_reload_the_gateway_refuse_no_connection() {
    let mut admin = None;
    let h = GatewayHarness::start_with_outbound(|_, _, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        configure_gateway_route_prefixes(
            bootstrap,
            &[("transit", "transit", "/transit"), ("aliased", "aliased", "/aliased")],
        );
    })
    .await;
    let admin = admin.unwrap();
    let surfaces = format!("{}/api/v1/surfaces", h.gateway_base);
    let listen_address = format!("http://localhost:{}", port_of(&h.gateway_base));
    let outbound_listen_address = format!(
        "http://localhost:{}",
        port_of(
            h.outbound_url
                .as_deref()
                .unwrap()
        )
    );
    assert_eq!(call(&h, "/aliased$beta").await, 404, "no surface serves the alias before it is saved");

    let prober = Prober::start(vec![
        format!("{}/api/v1/alive", h.gateway_base),
        format!(
            "{}/alive",
            h.outbound_url
                .as_deref()
                .unwrap()
        ),
    ]);

    let (status, transit) = send(admin.post(&surfaces).json(&json!({
        "name": "transit",
        "access_point": {"listen_address": listen_address, "route": "/transit", "protocol": "a2a", "public": true},
        "target": {"endpoint": h.mock.url()},
        "transit": {"outbound_listen_address": outbound_listen_address, "points": [{
            "alias": "partner", "target_endpoint": h.mock.url(),
            "require_transit_token": false, "allow_unauthenticated_callers": true
        }]}
    })))
    .await;
    assert_eq!(status, 201, "a surface with a Transit Point: {transit}");

    let (status, aliased) = send(admin.post(&surfaces).json(&json!({
        "name": "aliased",
        "access_point": {"listen_address": listen_address, "route": "/aliased", "protocol": "a2a", "public": true},
        "target": {"endpoint": h.mock.url()},
        "variants": [{"id": "beta", "alias": "beta", "name": "Beta", "enabled": true, "overrides": {}}]
    })))
    .await;
    assert_eq!(status, 201, "a surface with a variant: {aliased}");
    assert_eq!(call(&h, "/aliased$beta").await, 200, "the saved variant's alias route answers");

    let transit_url = format!(
        "{surfaces}/{}",
        transit["surface_id"]
            .as_str()
            .unwrap()
    );
    let (status, disabled) = send(
        admin
            .patch(&transit_url)
            .header("content-type", "application/merge-patch+json")
            .body(json!({"status": "disabled"}).to_string()),
    )
    .await;
    assert_eq!(status, 200, "an inactive surface: {disabled}");

    let (status, deleted) = send(admin.delete(format!(
        "{surfaces}/{}",
        aliased["surface_id"]
            .as_str()
            .unwrap()
    )))
    .await;
    assert_eq!(status, 200, "deleting the surface with a variant: {deleted}");

    let (probes, failures) = prober.stop().await;
    assert!(probes > 0, "the ports were probed during the saves");
    assert!(
        failures.is_empty(),
        "{} of {probes} requests during the saves were not answered, first: {:?}",
        failures.len(),
        &failures[..failures.len().min(5)]
    );
    assert_eq!(call(&h, "/aliased$beta").await, 404, "the deleted surface's alias route stops answering");
}
