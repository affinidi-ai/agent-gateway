//! Transit Point lifecycle E2E: a Transit Point that is deleted, disabled or
//! removed stops answering at once, for a managed agent opening a new
//! connection and for one still holding a connection it kept alive across the
//! change, on a TLS outbound listener, whose connections outlive a rebuild; a
//! Transit Point that stays keeps answering on that connection, and deleting
//! one surface leaves the outbound listener other surfaces share bound.

use super::helpers::{GatewayHarness, configure_admin_api, configure_gateway_route_prefixes};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};

/// Send one HTTP/1.1 request for `path` on `connection` and return its status,
/// or `None` when the gateway closed the connection instead of answering.
async fn send_on<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut BufReader<S>,
    host: &str,
    path: &str,
) -> Option<u16> {
    let body = r#"{"jsonrpc":"2.0","method":"test","id":1}"#;
    let request = format!(
        "POST {path} HTTP/1.1\r\nhost: {host}\r\ncontent-type: application/json\r\n\
         content-length: {}\r\nconnection: keep-alive\r\n\r\n{body}",
        body.len()
    );
    connection
        .get_mut()
        .write_all(request.as_bytes())
        .await
        .ok()?;
    let mut status_line = String::new();
    if connection
        .read_line(&mut status_line)
        .await
        .ok()?
        == 0
    {
        return None;
    }
    let status = status_line
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    let mut content_length = 0;
    loop {
        let mut header = String::new();
        connection
            .read_line(&mut header)
            .await
            .ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().ok()?;
        }
    }
    let mut response_body = vec![0; content_length];
    connection
        .read_exact(&mut response_body)
        .await
        .ok()?;
    Some(status)
}

/// A certificate authority and the `localhost` server certificate it signs,
/// written to `directory` for the gateway, with a TLS client that trusts it.
fn test_pki(directory: &std::path::Path) -> tokio_rustls::TlsConnector {
    use rcgen::{BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose};

    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Transit Point lifecycle CA");
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params
        .clone()
        .self_signed(&ca_key)
        .unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let mut server_params = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()]).unwrap();
    server_params.distinguished_name = DistinguishedName::new();
    server_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    let server_key = KeyPair::generate().unwrap();
    let server_cert = server_params
        .signed_by(&server_key, &issuer)
        .unwrap();
    std::fs::write(directory.join("lifecycle-cert.pem"), server_cert.pem()).unwrap();
    std::fs::write(directory.join("lifecycle-key.pem"), server_key.serialize_pem()).unwrap();

    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(ca_cert.der().clone())
        .unwrap();
    tokio_rustls::TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    ))
}

/// A gateway whose outbound listener speaks TLS, with a client for its admin
/// API and a TLS client that trusts the outbound listener.
async fn gateway_with_tls_outbound_listener(
    route_prefixes: &[(&str, &str, &str)]
) -> (GatewayHarness, reqwest::Client, tokio_rustls::TlsConnector) {
    let mut admin = None;
    let mut connector = None;
    let h = GatewayHarness::start_with_outbound(|directory, gateway, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        configure_gateway_route_prefixes(bootstrap, route_prefixes);
        connector = Some(test_pki(directory));
        for tls in [&mut bootstrap.tls, &mut gateway.tls] {
            tls.cert_path = directory.join("lifecycle-cert.pem");
            tls.key_path = directory.join("lifecycle-key.pem");
        }
        let path = &bootstrap.config_files.gateway;
        let mut network: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let outbound = &mut network["listeners"][1];
        outbound["protocol"] = json!("https");
        let url = outbound["external_urls"][0]
            .as_str()
            .unwrap()
            .replace("http://", "https://");
        outbound["external_urls"] = json!([url]);
        std::fs::write(path, serde_json::to_vec(&network).unwrap()).unwrap();
    })
    .await;
    (h, admin.unwrap(), connector.unwrap())
}

fn outbound_port(h: &GatewayHarness) -> u16 {
    h.outbound_url
        .as_deref()
        .unwrap()
        .rsplit(':')
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

/// Create a surface on `route` whose Transit Points, one per alias, forward to
/// the harness's mock target over the outbound listener at `outbound_scheme`.
/// Returns the stored surface.
async fn create_surface(
    h: &GatewayHarness,
    admin: &reqwest::Client,
    route: &str,
    outbound_scheme: &str,
    aliases: &[&str],
) -> serde_json::Value {
    let points: Vec<serde_json::Value> = aliases
        .iter()
        .map(|alias| json!({ "alias": alias, "target_endpoint": h.mock.url(), "require_transit_token": false }))
        .collect();
    let created = admin
        .post(format!("{}/api/v1/surfaces", h.gateway_base))
        .json(&json!({
            "name": route.trim_start_matches('/'),
            "access_point": { "listen_address": h.gateway_base, "route": route, "protocol": "a2a" },
            "target": { "endpoint": h.mock.url() },
            "transit": {
                "outbound_listen_address": format!("{outbound_scheme}://localhost:{}", outbound_port(h)),
                "points": points
            }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);
    created.json().await.unwrap()
}

fn surface_url(
    h: &GatewayHarness,
    surface: &serde_json::Value,
) -> String {
    format!(
        "{}/api/v1/surfaces/{}",
        h.gateway_base,
        surface["surface_id"]
            .as_str()
            .unwrap()
    )
}

async fn tls_connection(
    h: &GatewayHarness,
    connector: &tokio_rustls::TlsConnector,
) -> Option<BufReader<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", outbound_port(h)))
        .await
        .ok()?;
    let stream = connector
        .connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), stream)
        .await
        .ok()?;
    Some(BufReader::new(stream))
}

/// A TLS connection to the outbound listener, kept alive after a call to
/// `path` that reached its target.
async fn kept_alive_tls_connection(
    h: &GatewayHarness,
    connector: &tokio_rustls::TlsConnector,
    path: &str,
) -> BufReader<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    for _ in 0..100 {
        if let Some(mut connection) = tls_connection(h, connector).await
            && send_on(&mut connection, "localhost", path).await == Some(200)
        {
            return connection;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the Transit Point at {path} must answer over TLS before the change");
}

/// A deleted surface's Transit Point refuses the next call at once, with
/// `404`, on a new connection and on a TLS connection kept alive across the
/// delete, and never reaches its target again.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_surface_takes_its_transit_point_out_of_service_at_once() {
    let (h, admin, connector) = gateway_with_tls_outbound_listener(&[("doomed", "doomed", "/doomed")]).await;
    let surface = create_surface(&h, &admin, "/doomed", "https", &["partner"]).await;
    let path = "/outbound/doomed/partner";
    let mut kept_alive = kept_alive_tls_connection(&h, &connector, path).await;

    let deleted = admin
        .delete(surface_url(&h, &surface))
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 200);
    let calls_at_delete = h
        .mock
        .request_count
        .load(Ordering::SeqCst);

    assert_eq!(send_on(&mut kept_alive, "localhost", path).await, Some(404), "on the kept-alive connection");
    let mut fresh = tls_connection(&h, &connector)
        .await
        .expect("the outbound listener stays bound");
    assert_eq!(send_on(&mut fresh, "localhost", path).await, Some(404), "on a new connection");
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        calls_at_delete,
        "no call after the delete may reach the target"
    );
}

/// Disabling a surface, or removing all of its Transit Points, refuses the
/// next call on a TLS connection kept alive across the change with `404`.
#[tokio::test(flavor = "multi_thread")]
async fn disabling_a_surface_or_emptying_its_transit_points_refuses_a_kept_alive_connection() {
    for (case, change) in [
        ("disable", json!({ "status": "disabled" })),
        ("remove every Transit Point", json!({ "transit": { "points": [] } })),
    ] {
        let (h, admin, connector) = gateway_with_tls_outbound_listener(&[("closing", "closing", "/closing")]).await;
        let surface = create_surface(&h, &admin, "/closing", "https", &["partner"]).await;
        let path = "/outbound/closing/partner";
        let mut kept_alive = kept_alive_tls_connection(&h, &connector, path).await;

        let updated = admin
            .patch(surface_url(&h, &surface))
            .header("content-type", "application/merge-patch+json")
            .body(change.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(updated.status(), 200, "{case}");
        let calls_at_change = h
            .mock
            .request_count
            .load(Ordering::SeqCst);

        assert_eq!(send_on(&mut kept_alive, "localhost", path).await, Some(404), "{case}");
        assert_eq!(
            h.mock
                .request_count
                .load(Ordering::SeqCst),
            calls_at_change,
            "{case}: no call after the change may reach the target"
        );
    }
}

/// Removing one of a surface's Transit Points refuses it on a TLS connection
/// kept alive across the change, while the Transit Point that stays keeps
/// answering on that connection.
#[tokio::test(flavor = "multi_thread")]
async fn removing_one_transit_point_refuses_it_on_a_kept_alive_connection_and_keeps_the_other() {
    let (h, admin, connector) = gateway_with_tls_outbound_listener(&[("links", "links", "/links")]).await;
    let surface = create_surface(&h, &admin, "/links", "https", &["unlinked", "kept"]).await;
    let mut kept_alive = kept_alive_tls_connection(&h, &connector, "/outbound/links/unlinked").await;
    assert_eq!(send_on(&mut kept_alive, "localhost", "/outbound/links/kept").await, Some(200));

    let mut updated = surface.clone();
    updated["transit"]["points"] = json!(
        surface["transit"]["points"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|point| point["alias"] == "kept")
            .cloned()
            .collect::<Vec<_>>()
    );
    let put = admin
        .put(surface_url(&h, &surface))
        .json(&updated)
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), 200);
    let calls_at_unlink = h
        .mock
        .request_count
        .load(Ordering::SeqCst);

    assert_eq!(send_on(&mut kept_alive, "localhost", "/outbound/links/unlinked").await, Some(404));
    assert_eq!(
        h.mock
            .request_count
            .load(Ordering::SeqCst),
        calls_at_unlink,
        "the removed Transit Point must not reach its target"
    );
    assert_eq!(send_on(&mut kept_alive, "localhost", "/outbound/links/kept").await, Some(200));
}

/// Deleting one surface leaves the outbound listener it shares with another
/// surface bound: a connection kept alive to the other surface's Transit
/// Point, which a rebind would close, keeps answering.
#[tokio::test(flavor = "multi_thread")]
async fn deleting_a_surface_keeps_the_outbound_listener_other_surfaces_share() {
    let mut admin = None;
    let h = GatewayHarness::start_with_outbound(|_, _, bootstrap| {
        admin = Some(configure_admin_api(bootstrap));
        configure_gateway_route_prefixes(bootstrap, &[("deleted", "deleted", "/deleted"), ("kept", "kept", "/kept")]);
    })
    .await;
    let admin = admin.unwrap();
    let deleted = create_surface(&h, &admin, "/deleted", "http", &["partner"]).await;
    create_surface(&h, &admin, "/kept", "http", &["partner"]).await;
    let outbound_host = format!("127.0.0.1:{}", outbound_port(&h));
    let mut kept_alive = None;
    for _ in 0..100 {
        if let Ok(stream) = tokio::net::TcpStream::connect(&outbound_host).await {
            let mut connection = BufReader::new(stream);
            if send_on(&mut connection, &outbound_host, "/outbound/kept/partner").await == Some(200) {
                kept_alive = Some(connection);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let mut kept_alive = kept_alive.expect("the kept surface's Transit Point must answer before the delete");

    let response = admin
        .delete(surface_url(&h, &deleted))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);

    assert_eq!(
        send_on(&mut kept_alive, &outbound_host, "/outbound/kept/partner").await,
        Some(200),
        "the shared outbound listener must stay bound"
    );
    assert_eq!(send_on(&mut kept_alive, &outbound_host, "/outbound/deleted/partner").await, Some(404));
    let alive = reqwest::Client::builder()
        .no_proxy()
        .build()
        .unwrap()
        .get(format!("http://{outbound_host}/alive"))
        .send()
        .await
        .unwrap();
    assert_eq!(alive.status(), 200, "the outbound listener keeps answering its liveness route");
}
