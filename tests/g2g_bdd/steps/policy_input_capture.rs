use cucumber::{given, then};
use serde_json::Value;

use crate::bdd_support::dashboard_socket::DashboardSocket;
use crate::world::G2gWorld;

#[given(expr = "policy input capture is turned on on gateway {int}")]
pub async fn capture_turned_on(
    world: &mut G2gWorld,
    gw_index: usize,
) {
    world.start().await;
    world
        .harness()
        .gw(gw_index)
        .admin
        .set_feature_flags(&[("policy_input_capture", true)])
        .await
        .expect("turn policy input capture on");
}

#[given(expr = "the operator listens to the policy input of gateway {int} surface {string}")]
pub async fn operator_listens(
    world: &mut G2gWorld,
    gw_index: usize,
    surface_name: String,
) {
    world.start().await;
    let (surface_gw, surface_id) = world.surface(&surface_name);
    assert_eq!(surface_gw, gw_index, "surface '{surface_name}' is on gateway {surface_gw}");
    if !world
        .dashboard_sockets
        .contains_key(&gw_index)
    {
        let admin = &world
            .harness()
            .gw(gw_index)
            .admin;
        let token = admin
            .session_token()
            .expect("the operator must have a dashboard session");
        let socket = DashboardSocket::connect(&admin.dashboard_socket_url(), &token).await;
        world
            .dashboard_sockets
            .insert(gw_index, socket);
    }
    let answer = world.dashboard_sockets[&gw_index]
        .ask_to_listen(&surface_id, true)
        .await;
    assert_eq!(answer["listening"], true, "listening to policy input: {answer}");
}

#[then(
    expr = "the Capture view on gateway {int} shows the {string} policy of surface {string} deciding {string} on an input showing {string}"
)]
pub async fn capture_view_shows(
    world: &mut G2gWorld,
    gw_index: usize,
    slot: String,
    surface_name: String,
    decision: String,
    text: String,
) {
    let (_, surface_id) = world.surface(&surface_name);
    let matches = |capture: &Value| {
        capture["config_id"] == surface_id.as_str()
            && capture["slot"] == slot.as_str()
            && capture["decision"] == decision.as_str()
            && capture["input"]
                .to_string()
                .contains(&text)
    };
    let missing = format!(
        "no {slot} policy capture of surface '{surface_name}' on gateway {gw_index} deciding {decision:?} on an input showing {text:?}"
    );
    socket(world, gw_index)
        .wait_for_capture(matches, &missing)
        .await;
}

#[then(expr = "no captured policy input of surface {string} on gateway {int} contains {string}")]
pub async fn no_capture_contains(
    world: &mut G2gWorld,
    surface_name: String,
    gw_index: usize,
    text: String,
) {
    let (_, surface_id) = world.surface(&surface_name);
    socket(world, gw_index).assert_no_capture_contains(&surface_id, &text);
}

fn socket(
    world: &G2gWorld,
    gw_index: usize,
) -> &DashboardSocket {
    world
        .dashboard_sockets
        .get(&gw_index)
        .unwrap_or_else(|| panic!("the operator must be listening on gateway {gw_index}"))
}
