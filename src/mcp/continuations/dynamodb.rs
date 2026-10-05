use std::collections::HashMap;

use async_trait::async_trait;
use aws_sdk_dynamodb::{Client, types::AttributeValue};
use uuid::Uuid;

use super::{ContinuationError, ContinuationExpectation, ContinuationPhase, ContinuationRecord, ContinuationStore};
use crate::storage::dynamodb_generic_repository::{PK, SK, object_key};

pub struct DynamoContinuations {
    client: Client,
    table: String,
    namespace: String,
}

impl DynamoContinuations {
    pub fn new(
        client: Client,
        table: String,
        namespace: String,
    ) -> Result<Self, ContinuationError> {
        if table.trim().is_empty()
            || table.len() > 2048
            || namespace.is_empty()
            || namespace.len() > 128
            || !namespace
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(Self { client, table, namespace })
    }

    fn key(
        &self,
        id: Uuid,
    ) -> HashMap<String, AttributeValue> {
        let (partition, sort) = object_key("McpContinuation", &format!("{}:{id}", self.namespace));
        HashMap::from([(PK.to_string(), AttributeValue::S(partition)), (SK.to_string(), AttributeValue::S(sort))])
    }

    fn item(
        &self,
        record: &ContinuationRecord,
    ) -> Result<HashMap<String, AttributeValue>, ContinuationError> {
        let mut item: HashMap<String, AttributeValue> =
            serde_dynamo::to_item(record).map_err(|_| ContinuationError::InvalidRecord)?;
        item.extend(self.key(record.id));
        Ok(item)
    }

    fn decode(
        &self,
        id: Uuid,
        mut item: HashMap<String, AttributeValue>,
    ) -> Result<ContinuationRecord, ContinuationError> {
        for (name, value) in self.key(id) {
            if item.remove(&name) != Some(value) {
                return Err(ContinuationError::InvalidRecord);
            }
        }
        let record: ContinuationRecord = serde_dynamo::from_item(item).map_err(|_| ContinuationError::InvalidRecord)?;
        record.validate()?;
        if record.id != id {
            return Err(ContinuationError::InvalidRecord);
        }
        Ok(record)
    }
}

#[async_trait]
impl ContinuationStore for DynamoContinuations {
    async fn create(
        &self,
        record: ContinuationRecord,
        now: u64,
    ) -> Result<(), ContinuationError> {
        record.validate_new(now)?;
        self.client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(self.item(&record)?))
            .condition_expression("attribute_not_exists(#pk)")
            .expression_attribute_names("#pk", PK)
            .send()
            .await
            .map_err(|error| {
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_conditional_check_failed_exception())
                {
                    ContinuationError::Conflict
                } else {
                    ContinuationError::Unavailable
                }
            })?;
        Ok(())
    }

    async fn get(
        &self,
        id: Uuid,
        binding_digest: [u8; 32],
        now: u64,
    ) -> Result<ContinuationRecord, ContinuationError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.table)
            .set_key(Some(self.key(id)))
            .consistent_read(true)
            .send()
            .await
            .map_err(|_| ContinuationError::Unavailable)?;
        let record = self.decode(
            id,
            response
                .item
                .ok_or(ContinuationError::NotFound)?,
        )?;
        record.check_access(&binding_digest, now)?;
        Ok(record)
    }

    async fn advance(
        &self,
        id: Uuid,
        expected: ContinuationExpectation,
        next: ContinuationPhase,
        now: u64,
    ) -> Result<ContinuationRecord, ContinuationError> {
        let current = self
            .get(id, expected.binding_digest, now)
            .await?;
        let advanced = current.advance(&expected, next, now)?;
        let item = self.item(&current)?;
        let updated = self.item(&advanced)?;
        let values = HashMap::from([
            (":binding".to_string(), item["binding_digest"].clone()),
            (":revision".to_string(), item["revision"].clone()),
            (":round".to_string(), item["round"].clone()),
            (":phase".to_string(), item["phase"].clone()),
            (":expires".to_string(), item["expires_at"].clone()),
            (":issued".to_string(), item["issued_at"].clone()),
            (":next_revision".to_string(), updated["revision"].clone()),
            (":next_round".to_string(), updated["round"].clone()),
            (":next_phase".to_string(), updated["phase"].clone()),
            (":now".to_string(), AttributeValue::N(now.to_string())),
        ]);
        self.client.update_item().table_name(&self.table).set_key(Some(self.key(id)))
            .update_expression("SET #phase = :next_phase, #revision = :next_revision, #round = :next_round")
            .condition_expression("#binding = :binding AND #revision = :revision AND #round = :round AND #phase = :phase AND #expires = :expires AND #issued = :issued AND #expires > :now AND #issued <= :now")
            .set_expression_attribute_names(Some(HashMap::from([
                ("#binding".to_string(), "binding_digest".to_string()), ("#revision".to_string(), "revision".to_string()),
                ("#phase".to_string(), "phase".to_string()), ("#expires".to_string(), "expires_at".to_string()),
                ("#issued".to_string(), "issued_at".to_string()),
                ("#round".to_string(), "round".to_string()),
            ])))
            .set_expression_attribute_values(Some(values)).send().await.map_err(|error| {
                if error.as_service_error().is_some_and(|error| error.is_conditional_check_failed_exception()) {
                    ContinuationError::Conflict
                } else { ContinuationError::Unavailable }
            })?;
        Ok(advanced)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::post,
    };
    use serde_json::{Value, json};

    use super::super::tests::record;
    use super::*;

    struct Fixture {
        requests: tokio::sync::mpsc::Sender<(String, Value)>,
        responses: tokio::sync::Mutex<std::collections::VecDeque<(StatusCode, Value)>>,
    }

    async fn reply(
        State(fixture): State<Arc<Fixture>>,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> (StatusCode, Json<Value>) {
        assert_eq!(headers["content-type"], "application/x-amz-json-1.0");
        let body: Value = serde_json::from_slice(&body).unwrap();
        let action = headers["x-amz-target"]
            .to_str()
            .unwrap()
            .to_string();
        fixture
            .requests
            .send((action, body))
            .await
            .unwrap();
        let (status, response) = fixture
            .responses
            .lock()
            .await
            .pop_front()
            .expect("unexpected DynamoDB call");
        (status, Json(response))
    }

    fn client(endpoint: String) -> Client {
        Client::from_conf(
            aws_sdk_dynamodb::config::Builder::new()
                .behavior_version_latest()
                .region(aws_sdk_dynamodb::config::Region::new("us-east-1"))
                .credentials_provider(aws_sdk_dynamodb::config::Credentials::new(
                    "fixture", "fixture", None, None, "fixture",
                ))
                .endpoint_url(endpoint)
                .retry_config(aws_sdk_dynamodb::config::retry::RetryConfig::disabled())
                .sleep_impl(Arc::new(aws_smithy_async::rt::sleep::TokioSleep::new()))
                .build(),
        )
    }

    #[tokio::test]
    async fn dynamodb_continuations_use_consistent_reads_and_conditional_state_transitions() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let store = DynamoContinuations::new(
            client(format!("http://{}", listener.local_addr().unwrap())),
            "continuations".into(),
            "deployment".into(),
        )
        .unwrap();
        let record = record();
        let mut fixture_item: HashMap<String, serde_dynamo::AttributeValue> = serde_dynamo::to_item(&record).unwrap();
        let (partition, sort) = object_key("McpContinuation", &format!("deployment:{}", record.id));
        fixture_item.insert(PK.to_string(), serde_dynamo::AttributeValue::S(partition));
        fixture_item.insert(SK.to_string(), serde_dynamo::AttributeValue::S(sort));
        let item = serde_json::to_value(fixture_item).unwrap();
        let (requests_tx, mut requests_rx) = tokio::sync::mpsc::channel(16);
        let fixture = Arc::new(Fixture {
            requests: requests_tx,
            responses: tokio::sync::Mutex::new(std::collections::VecDeque::from([
                (StatusCode::OK, json!({})),
                (StatusCode::OK, json!({"Item": item})),
                (StatusCode::OK, json!({"Item": item})),
                (StatusCode::OK, json!({})),
                (
                    StatusCode::BAD_REQUEST,
                    json!({"__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException", "message": "conditional fixture"}),
                ),
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    json!({"__type": "InternalServerError", "message": "private backend detail"}),
                ),
            ])),
        });
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            axum::serve(
                listener,
                Router::new()
                    .route("/", post(reply))
                    .with_state(fixture),
            )
            .await
            .unwrap();
        });
        store
            .create(record.clone(), 10)
            .await
            .unwrap();
        let (action, request) = requests_rx
            .recv()
            .await
            .unwrap();
        assert!(action.ends_with("PutItem"));
        assert_eq!(request["ConditionExpression"], "attribute_not_exists(#pk)");
        assert_eq!(request["Item"]["expires_at"]["N"], "110");
        assert_eq!(request["Item"][PK], request["Item"][SK]);
        assert!(
            request["Item"][PK]["S"]
                .as_str()
                .unwrap()
                .starts_with("McpContinuation#deployment:")
        );
        assert_eq!(
            store
                .get(record.id, record.binding_digest, 10)
                .await
                .unwrap(),
            record
        );
        let (action, request) = requests_rx
            .recv()
            .await
            .unwrap();
        assert!(action.ends_with("GetItem"));
        assert_eq!(request["ConsistentRead"], true);
        let ready = store
            .advance(record.id, record.expectation(), ContinuationPhase::Ready, 11)
            .await
            .unwrap();
        assert_eq!(ready.phase, ContinuationPhase::Ready);
        assert_eq!(ready.revision, 1);
        assert!(
            requests_rx
                .recv()
                .await
                .unwrap()
                .0
                .ends_with("GetItem")
        );
        let (action, request) = requests_rx
            .recv()
            .await
            .unwrap();
        assert!(action.ends_with("UpdateItem"));
        assert_eq!(
            request["UpdateExpression"],
            "SET #phase = :next_phase, #revision = :next_revision, #round = :next_round"
        );
        assert_eq!(request["ExpressionAttributeValues"][":round"]["N"], "0");
        assert_eq!(request["ExpressionAttributeValues"][":next_round"]["N"], "0");
        assert_eq!(request["ExpressionAttributeValues"][":phase"]["S"], "pending_input");
        assert_eq!(request["ExpressionAttributeValues"][":next_phase"]["S"], "ready");
        assert_eq!(request["ExpressionAttributeValues"][":revision"]["N"], "0");
        assert_eq!(request["ExpressionAttributeValues"][":now"]["N"], "11");
        assert!(
            request["ConditionExpression"]
                .as_str()
                .unwrap()
                .contains("#expires > :now")
        );
        assert_eq!(
            store
                .create(record.clone(), 10)
                .await,
            Err(ContinuationError::Conflict)
        );
        assert_eq!(
            store
                .get(record.id, record.binding_digest, 10)
                .await,
            Err(ContinuationError::Unavailable)
        );
        tasks.shutdown().await;
    }

    #[test]
    fn dynamodb_continuation_rows_reject_cross_namespace_and_malformed_records() {
        let store = DynamoContinuations::new(client("http://127.0.0.1:1".into()), "continuations".into(), "one".into())
            .unwrap();
        let record = record();
        let item = store.item(&record).unwrap();
        assert_eq!(
            store
                .decode(record.id, item.clone())
                .unwrap(),
            record
        );
        let other = DynamoContinuations::new(client("http://127.0.0.1:1".into()), "continuations".into(), "two".into())
            .unwrap();
        assert_eq!(other.decode(record.id, item.clone()), Err(ContinuationError::InvalidRecord));
        let mut missing = item;
        missing.remove("binding_digest");
        assert_eq!(store.decode(record.id, missing), Err(ContinuationError::InvalidRecord));
        assert!(
            DynamoContinuations::new(
                client("http://127.0.0.1:1".into()),
                "continuations".into(),
                "invalid#namespace".into()
            )
            .is_err()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an explicit loopback DynamoDB-compatible service"]
    async fn dynamodb_continuations_enforce_claims_across_processes() {
        use std::time::Duration;

        use aws_sdk_dynamodb::types::{
            AttributeDefinition, BillingMode, KeySchemaElement, KeyType, ScalarAttributeType,
        };
        use futures::FutureExt;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let endpoint =
            std::env::var("ATG_MCP_DYNAMO_ENDPOINT").expect("set ATG_MCP_DYNAMO_ENDPOINT to a local test service");
        let url = url::Url::parse(&endpoint).unwrap();
        assert_eq!(url.scheme(), "http");
        assert!(url.username().is_empty() && url.password().is_none());
        assert!(
            match url.host() {
                Some(url::Host::Ipv4(address)) => address.is_loopback(),
                Some(url::Host::Ipv6(address)) => address.is_loopback(),
                _ => false,
            },
            "conformance tests must never contact a remote DynamoDB endpoint"
        );
        let client = client(endpoint.clone());
        if let Ok(table) = std::env::var("ATG_MCP_DYNAMO_CHILD_TABLE") {
            assert!(table.starts_with("mcp-conformance-"));
            let replay = crate::sts::replay::McpReplay::new(
                &crate::sts::replay::McpReplayConfig::Dynamodb { table: table.clone() },
                Some(client.clone()),
            )
            .unwrap();
            let store = DynamoContinuations::new(client, table, "conformance".into()).unwrap();
            let ready: ContinuationRecord =
                serde_json::from_str(&std::env::var("ATG_MCP_DYNAMO_RECORD").unwrap()).unwrap();
            let barrier: std::net::SocketAddr = std::env::var("ATG_MCP_DYNAMO_BARRIER")
                .unwrap()
                .parse()
                .unwrap();
            assert!(barrier.ip().is_loopback());
            tokio::time::timeout(Duration::from_secs(30), async {
                assert_eq!(
                    store
                        .get(ready.id, ready.binding_digest, 11)
                        .await
                        .unwrap(),
                    ready
                );
                let mut stream = tokio::net::TcpStream::connect(barrier)
                    .await
                    .unwrap();
                stream
                    .write_all(&[1])
                    .await
                    .unwrap();
                stream
                    .read_u8()
                    .await
                    .unwrap();
                let won = match store
                    .advance(ready.id, ready.expectation(), ContinuationPhase::Claimed, 11)
                    .await
                {
                    Ok(claimed) => {
                        assert_eq!(claimed.phase, ContinuationPhase::Claimed);
                        assert_eq!(claimed.revision, ready.revision + 1);
                        true
                    }
                    Err(ContinuationError::Conflict) => false,
                    other => panic!("unexpected process claim result: {other:?}"),
                };
                let redeemed = replay
                    .record_unique(
                        "https://gateway.example/oauth2/mcp",
                        "https://issuer.example",
                        "same-grant",
                        100,
                        11,
                    )
                    .await
                    .unwrap();
                stream
                    .write_all(&[u8::from(won), u8::from(redeemed)])
                    .await
                    .unwrap();
            })
            .await
            .expect("child claim timed out");
            return;
        }

        let table = format!("mcp-conformance-{}", Uuid::new_v4());
        client
            .create_table()
            .table_name(&table)
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(PK)
                    .attribute_type(ScalarAttributeType::S)
                    .build()
                    .unwrap(),
            )
            .attribute_definitions(
                AttributeDefinition::builder()
                    .attribute_name(SK)
                    .attribute_type(ScalarAttributeType::S)
                    .build()
                    .unwrap(),
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(PK)
                    .key_type(KeyType::Hash)
                    .build()
                    .unwrap(),
            )
            .key_schema(
                KeySchemaElement::builder()
                    .attribute_name(SK)
                    .key_type(KeyType::Range)
                    .build()
                    .unwrap(),
            )
            .billing_mode(BillingMode::PayPerRequest)
            .send()
            .await
            .unwrap();
        let store = DynamoContinuations::new(client.clone(), table.clone(), "conformance".into()).unwrap();
        let initial = record();
        let result = std::panic::AssertUnwindSafe(tokio::time::timeout(Duration::from_secs(45), async {
            store
                .create(initial.clone(), 10)
                .await
                .unwrap();
            assert_eq!(
                store
                    .create(initial.clone(), 10)
                    .await,
                Err(ContinuationError::Conflict)
            );
            let ready = store
                .advance(initial.id, initial.expectation(), ContinuationPhase::Ready, 11)
                .await
                .unwrap();
            let barrier = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let test_name = std::thread::current()
                .name()
                .unwrap()
                .to_string();
            let mut children = Vec::new();
            for _process in 0..4 {
                children.push(
                    tokio::process::Command::new(std::env::current_exe().unwrap())
                        .args(["--exact", &test_name, "--ignored", "--nocapture"])
                        .env("ATG_MCP_DYNAMO_ENDPOINT", &endpoint)
                        .env("ATG_MCP_DYNAMO_CHILD_TABLE", &table)
                        .env("ATG_MCP_DYNAMO_RECORD", serde_json::to_string(&ready).unwrap())
                        .env(
                            "ATG_MCP_DYNAMO_BARRIER",
                            barrier
                                .local_addr()
                                .unwrap()
                                .to_string(),
                        )
                        .stdout(std::process::Stdio::piped())
                        .stderr(std::process::Stdio::piped())
                        .kill_on_drop(true)
                        .spawn()
                        .unwrap(),
                );
            }
            let mut streams = Vec::new();
            for _process in 0..4 {
                let (mut stream, _) = barrier
                    .accept()
                    .await
                    .unwrap();
                assert_eq!(
                    stream
                        .read_u8()
                        .await
                        .unwrap(),
                    1
                );
                streams.push(stream);
            }
            for stream in &mut streams {
                stream
                    .write_all(&[1])
                    .await
                    .unwrap();
            }
            let mut winners = 0;
            let mut redemptions = 0;
            for stream in &mut streams {
                winners += stream
                    .read_u8()
                    .await
                    .unwrap();
                redemptions += stream
                    .read_u8()
                    .await
                    .unwrap();
            }
            for child in children {
                let output = child
                    .wait_with_output()
                    .await
                    .unwrap();
                assert!(output.status.success(), "child failed: {}", String::from_utf8_lossy(&output.stderr));
            }
            assert_eq!(winners, 1);
            assert_eq!(redemptions, 1);
            let replay = crate::sts::replay::McpReplay::new(
                &crate::sts::replay::McpReplayConfig::Dynamodb { table: table.clone() },
                Some(client.clone()),
            )
            .unwrap();
            assert!(
                !replay
                    .record_unique(
                        "https://gateway.example/oauth2/mcp",
                        "https://issuer.example",
                        "same-grant",
                        100,
                        12
                    )
                    .await
                    .unwrap()
            );
            assert!(
                replay
                    .record_unique("https://other.example/oauth2/mcp", "https://issuer.example", "same-grant", 100, 12)
                    .await
                    .unwrap()
            );
            assert!(
                replay
                    .record_unique(
                        "https://gateway.example/oauth2/mcp",
                        "https://other-issuer.example",
                        "same-grant",
                        100,
                        12
                    )
                    .await
                    .unwrap()
            );
            assert!(
                replay
                    .record_unique(
                        "https://gateway.example/oauth2/mcp",
                        "https://issuer.example",
                        "same-grant",
                        200,
                        100
                    )
                    .await
                    .unwrap()
            );
            assert!(
                replay
                    .record_unique(
                        "https://gateway.example/oauth2/mcp",
                        "https://issuer.example",
                        "bad-expiry",
                        100,
                        100
                    )
                    .await
                    .is_err()
            );
            let restarted = DynamoContinuations::new(client.clone(), table.clone(), "conformance".into()).unwrap();
            let claimed = restarted
                .get(initial.id, initial.binding_digest, 12)
                .await
                .unwrap();
            assert_eq!(claimed.phase, ContinuationPhase::Claimed);
            assert_eq!(
                restarted
                    .advance(initial.id, ready.expectation(), ContinuationPhase::Claimed, 12)
                    .await,
                Err(ContinuationError::Conflict)
            );
            assert_eq!(
                restarted
                    .advance(initial.id, claimed.expectation(), ContinuationPhase::Ready, 12)
                    .await,
                Err(ContinuationError::InvalidTransition)
            );
            let consumed = restarted
                .advance(initial.id, claimed.expectation(), ContinuationPhase::Consumed, 12)
                .await
                .unwrap();
            assert_eq!(
                store
                    .get(initial.id, initial.binding_digest, 12)
                    .await
                    .unwrap(),
                consumed
            );
            assert_eq!(
                store
                    .get(initial.id, [2; 32], 12)
                    .await,
                Err(ContinuationError::BindingMismatch)
            );
            assert_eq!(
                store
                    .get(initial.id, initial.binding_digest, initial.expires_at)
                    .await,
                Err(ContinuationError::Expired)
            );
            let other = DynamoContinuations::new(client.clone(), table.clone(), "other".into()).unwrap();
            assert_eq!(
                other
                    .get(initial.id, initial.binding_digest, 12)
                    .await,
                Err(ContinuationError::NotFound)
            );
        }))
        .catch_unwind()
        .await;
        let cleanup = client
            .delete_table()
            .table_name(&table)
            .send()
            .await;
        match result {
            Ok(result) => result.expect("multi-process conformance timed out"),
            Err(panic) => std::panic::resume_unwind(panic),
        }
        cleanup.unwrap();
        assert_eq!(
            store
                .get(initial.id, initial.binding_digest, 12)
                .await,
            Err(ContinuationError::Unavailable)
        );
        let replay =
            crate::sts::replay::McpReplay::new(&crate::sts::replay::McpReplayConfig::Dynamodb { table }, Some(client))
                .unwrap();
        assert!(
            replay
                .record_unique("https://gateway.example/oauth2/mcp", "https://issuer.example", "unavailable", 100, 12)
                .await
                .is_err()
        );
    }
}
