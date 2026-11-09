use cucumber::{given, then, when};
use reqwest::Method;

use crate::bdd_support::admin_client::RecordedResponse;
use crate::bdd_support::config::single_surface_fixture::GatewayPrefixFixture;
use crate::bdd_support::config::single_surface_writer::{DASHBOARD_PAGE_MARKER, add_gateway_prefixes};
use crate::bdd_support::http::collect_headers;
use crate::steps::when::{ensure_admin_session, ensure_gateway_running};
use crate::world::SurfaceWorld;

#[given("the gateway serves its dashboard")]
fn gateway_serves_its_dashboard(world: &mut SurfaceWorld) {
    world
        .surface_config
        .serves_dashboard = true;
}

#[given(expr = "the gateway configuration offers the Surface Prefix {string}")]
fn gateway_configuration_offers_surface_prefix(
    world: &mut SurfaceWorld,
    prefix: String,
) {
    world
        .surface_config
        .gateway_prefixes
        .push(GatewayPrefixFixture::Channel(prefix));
}

#[given(expr = "the gateway configuration has an MCP proxy at {string}")]
fn gateway_configuration_has_mcp_proxy(
    world: &mut SurfaceWorld,
    prefix: String,
) {
    world
        .surface_config
        .gateway_prefixes
        .push(GatewayPrefixFixture::McpProxy(prefix));
}

#[given(expr = "the gateway configuration redirects {string} to {string}")]
fn gateway_configuration_redirects(
    world: &mut SurfaceWorld,
    prefix: String,
    target: String,
) {
    world
        .surface_config
        .gateway_prefixes
        .push(GatewayPrefixFixture::Redirect { prefix, target });
}

#[when(expr = "a browser opens {string}")]
async fn browser_opens(
    world: &mut SurfaceWorld,
    path: String,
) {
    ensure_gateway_running(world).await;
    let port = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        .gateway_port;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("build browser client")
        .get(format!("http://127.0.0.1:{port}{path}"))
        .send()
        .await
        .unwrap_or_else(|error| panic!("GET {path}: {error}"));
    let status = response.status().as_u16();
    let headers = collect_headers(response.headers());
    let page = response
        .text()
        .await
        .unwrap_or_else(|error| panic!("read {path}: {error}"));
    world.caller_response = Some(RecordedResponse {
        status,
        headers,
        body: serde_json::Value::String(page),
    });
}

#[when(expr = "the operator adds a redirect from {string} to {string} and reloads the configuration")]
async fn operator_adds_redirect_and_reloads(
    world: &mut SurfaceWorld,
    prefix: String,
    target: String,
) {
    add_redirect_and_reload(world, prefix, target).await;
}

#[given(expr = "the operator has added a redirect from {string} to {string} and reloaded the configuration")]
async fn operator_has_added_redirect_and_reloaded(
    world: &mut SurfaceWorld,
    prefix: String,
    target: String,
) {
    add_redirect_and_reload(world, prefix, target).await;
}

async fn add_redirect_and_reload(
    world: &mut SurfaceWorld,
    prefix: String,
    target: String,
) {
    ensure_admin_session(world).await;
    let base_dir = world
        .infra
        .as_ref()
        .expect("the gateway must be running")
        ._temp_dir
        .path()
        .to_path_buf();
    add_gateway_prefixes(&base_dir, &[GatewayPrefixFixture::Redirect { prefix, target }]);
    let reload = world
        .admin_client
        .as_ref()
        .expect("the operator must be signed in")
        .send_recorded_json::<()>(Method::POST, "/v1/config/reload", None)
        .await
        .expect("reload the configuration");
    world.admin_response = Some(reload);
}

fn page_response(world: &SurfaceWorld) -> &RecordedResponse {
    world
        .caller_response
        .as_ref()
        .expect("a browser must have opened a page")
}

#[then("the dashboard page is served")]
fn dashboard_page_is_served(world: &mut SurfaceWorld) {
    let response = page_response(world);
    assert_eq!(response.status, 200, "{response:?}");
    assert!(
        response
            .body
            .as_str()
            .is_some_and(|page| page.contains(DASHBOARD_PAGE_MARKER)),
        "not the dashboard page: {response:?}"
    );
}

#[then(expr = "the browser is redirected to {string}")]
fn browser_is_redirected(
    world: &mut SurfaceWorld,
    target: String,
) {
    let response = page_response(world);
    assert_eq!(response.status, 308, "{response:?}");
    assert_eq!(
        response
            .headers
            .get("location")
            .map(String::as_str),
        Some(target.as_str()),
        "{response:?}"
    );
}

#[then(expr = "the reload succeeds and reports {string}")]
fn reload_succeeds_and_reports(
    world: &mut SurfaceWorld,
    text: String,
) {
    let reload = world
        .admin_response
        .as_ref()
        .expect("the operator must have reloaded the configuration");
    assert_eq!(reload.status, 200, "{reload:?}");
    assert!(
        reload.body["warning"]
            .as_str()
            .is_some_and(|warning| warning.contains(&text)),
        "the reload reports no {text:?}: {reload:?}"
    );
}
