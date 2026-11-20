use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

/// The update a dashboard connection receives for each captured policy evaluation.
pub const POLICY_INPUT_CAPTURED: &str = "policy_input_captured";
/// The gateway's answer to a request to start or stop listening to policy input.
pub const POLICY_INPUT_LISTEN_ANSWER: &str = "policy_input_capture";

fn text_of(message: Message) -> Option<Value> {
    match message {
        Message::Text(text) => serde_json::from_str(&text).ok(),
        _ => None,
    }
}

/// An operator's open dashboard WebSocket: the policy input captures and listen answers
/// it received, and a way to send. Dropping it closes the connection.
#[derive(Debug)]
pub struct DashboardSocket {
    received: Arc<Mutex<Vec<Value>>>,
    outgoing: tokio::sync::mpsc::UnboundedSender<String>,
    reader: tokio::task::JoinHandle<()>,
    writer: tokio::task::JoinHandle<()>,
}

impl DashboardSocket {
    /// Open the dashboard WebSocket at `url` with the session `token`, and collect what
    /// it receives from the moment the gateway confirms the connection.
    pub async fn connect(
        url: &str,
        token: &str,
    ) -> Self {
        let mut request = url
            .into_client_request()
            .expect("a dashboard WebSocket request");
        request.headers_mut().insert(
            "Authorization",
            format!("Bearer {token}")
                .parse()
                .expect("a bearer header"),
        );
        let (socket, _) = tokio_tungstenite::connect_async(request)
            .await
            .expect("open the dashboard WebSocket");
        let (mut write, mut read) = socket.split();
        loop {
            let message = tokio::time::timeout(Duration::from_secs(5), read.next())
                .await
                .expect("the dashboard WebSocket confirms the connection")
                .expect("the dashboard WebSocket stays open")
                .expect("a dashboard WebSocket message");
            if text_of(message).is_some_and(|update| update["type"] == "connected") {
                break;
            }
        }
        let received = Arc::new(Mutex::new(Vec::new()));
        let collected = Arc::clone(&received);
        let reader = tokio::spawn(async move {
            while let Some(Ok(message)) = read.next().await {
                if let Some(update) = text_of(message).filter(|update| {
                    update["type"] == POLICY_INPUT_CAPTURED || update["type"] == POLICY_INPUT_LISTEN_ANSWER
                }) {
                    collected
                        .lock()
                        .expect("dashboard messages lock")
                        .push(update);
                }
            }
        });
        let (outgoing, mut to_send) = tokio::sync::mpsc::unbounded_channel::<String>();
        let writer = tokio::spawn(async move {
            while let Some(text) = to_send.recv().await {
                if write
                    .send(Message::Text(text.into()))
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            received,
            outgoing,
            reader,
            writer,
        }
    }

    pub fn received(&self) -> Vec<Value> {
        self.received
            .lock()
            .expect("dashboard messages lock")
            .clone()
    }

    /// What it received of `message_type`.
    pub fn received_of(
        &self,
        message_type: &str,
    ) -> Vec<Value> {
        self.received()
            .into_iter()
            .filter(|message| message["type"] == message_type)
            .collect()
    }

    pub fn send(
        &self,
        text: String,
    ) {
        self.outgoing
            .send(text)
            .expect("the dashboard WebSocket is open");
    }

    /// Ask to start or stop listening to the policy input of `surface_id`, and return
    /// the gateway's answer.
    pub async fn ask_to_listen(
        &self,
        surface_id: &str,
        start: bool,
    ) -> Value {
        let answered = self
            .received_of(POLICY_INPUT_LISTEN_ANSWER)
            .len();
        let message_type = if start {
            "capture_policy_input"
        } else {
            "stop_capturing_policy_input"
        };
        self.send(serde_json::json!({ "type": message_type, "surface_id": surface_id }).to_string());
        for _ in 0..100 {
            if let Some(answer) = self
                .received_of(POLICY_INPUT_LISTEN_ANSWER)
                .into_iter()
                .nth(answered)
            {
                assert_eq!(answer["surface_id"], surface_id, "listen answer: {answer}");
                return answer;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("the gateway did not answer the request to listen to the policy input of surface '{surface_id}'");
    }

    /// Wait until a capture `matches` accepts has arrived, panicking with `missing` and
    /// every capture received when none does.
    pub async fn wait_for_capture(
        &self,
        matches: impl Fn(&Value) -> bool,
        missing: &str,
    ) {
        for _ in 0..100 {
            if self
                .received_of(POLICY_INPUT_CAPTURED)
                .iter()
                .any(&matches)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("{missing}: {:#?}", self.received_of(POLICY_INPUT_CAPTURED));
    }

    /// Assert that at least one capture of `surface_id` arrived and that none of their
    /// inputs contains `text`.
    pub fn assert_no_capture_contains(
        &self,
        surface_id: &str,
        text: &str,
    ) {
        let captures: Vec<Value> = self
            .received_of(POLICY_INPUT_CAPTURED)
            .into_iter()
            .filter(|capture| capture["config_id"] == surface_id)
            .collect();
        assert!(!captures.is_empty(), "no policy input of surface '{surface_id}' was captured");
        for capture in &captures {
            assert!(
                !capture["input"]
                    .to_string()
                    .contains(text),
                "a captured input contains {text:?}: {capture:#}"
            );
        }
    }
}

impl Drop for DashboardSocket {
    fn drop(&mut self) {
        self.reader.abort();
        self.writer.abort();
    }
}
