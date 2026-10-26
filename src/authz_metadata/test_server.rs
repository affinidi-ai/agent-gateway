use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub(super) struct Reply {
    status: u16,
    body: String,
    location: Option<String>,
    delay: Duration,
}

impl Reply {
    pub(super) fn json(body: &str) -> Self {
        Self {
            status: 200,
            body: body.to_string(),
            location: None,
            delay: Duration::ZERO,
        }
    }

    pub(super) fn status(status: u16) -> Self {
        Self { status, ..Self::json("") }
    }

    pub(super) fn redirect(location: &str) -> Self {
        Self {
            location: Some(location.to_string()),
            ..Self::status(302)
        }
    }

    pub(super) fn delayed(
        self,
        delay: Duration,
    ) -> Self {
        Self { delay, ..self }
    }
}

#[derive(Default)]
struct Routes {
    replies: HashMap<String, Reply>,
    hits: Vec<String>,
}

type Shared = Arc<Mutex<Routes>>;

pub(super) struct TestServer {
    base: String,
    routes: Shared,
    task: tokio::task::JoinHandle<()>,
}

impl TestServer {
    pub(super) async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let addr = listener
            .local_addr()
            .expect("local address");
        let routes = Shared::default();
        let app = Router::new()
            .fallback(serve)
            .with_state(routes.clone());
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self {
            base: format!("http://{addr}"),
            routes,
            task,
        }
    }

    pub(super) fn base(&self) -> &str {
        &self.base
    }

    pub(super) fn url(
        &self,
        path: &str,
    ) -> String {
        format!("{}{path}", self.base)
    }

    pub(super) fn reply(
        &self,
        path: &str,
        reply: Reply,
    ) {
        self.routes
            .lock()
            .unwrap()
            .replies
            .insert(path.to_string(), reply);
    }

    pub(super) fn requests(&self) -> Vec<String> {
        self.routes
            .lock()
            .unwrap()
            .hits
            .clone()
    }

    pub(super) fn hits(
        &self,
        path: &str,
    ) -> usize {
        self.requests()
            .iter()
            .filter(|hit| *hit == path)
            .count()
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    State(routes): State<Shared>,
    uri: Uri,
) -> Response {
    let path = uri.path().to_string();
    let reply = {
        let mut routes = routes.lock().unwrap();
        routes.hits.push(path.clone());
        routes
            .replies
            .get(&path)
            .cloned()
    };
    let Some(reply) = reply else {
        return StatusCode::NOT_FOUND.into_response();
    };
    tokio::time::sleep(reply.delay).await;
    let status = StatusCode::from_u16(reply.status).expect("a valid status");
    let mut response = (status, [(header::CONTENT_TYPE, "application/json")], reply.body).into_response();
    if let Some(location) = reply.location {
        response.headers_mut().insert(
            header::LOCATION,
            location
                .parse()
                .expect("a valid location"),
        );
    }
    response
}
