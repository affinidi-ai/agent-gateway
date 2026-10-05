//! Shared DynamoDB client construction and single-table key helpers.

use anyhow::Result;
use aws_sdk_dynamodb::Client as DynamoDbClient;

pub const PK: &str = "PK";
pub const SK: &str = "SK";
pub const ID_SEPARATOR: &str = "#";

pub async fn build_dynamodb_client(
    region: Option<&str>,
    profile: Option<&str>,
) -> Result<DynamoDbClient> {
    let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .sleep_impl(std::sync::Arc::new(aws_smithy_async::rt::sleep::TokioSleep::new()));

    if let Some(profile_name) = profile {
        config_loader = config_loader.profile_name(profile_name);
    }

    if let Some(region_str) = region {
        config_loader = config_loader.region(aws_config::Region::new(region_str.to_string()));
    }

    let config = config_loader.load().await;
    Ok(DynamoDbClient::new(&config))
}

pub fn object_key(
    class_name: &str,
    id: &str,
) -> (String, String) {
    let value = format!("{class_name}{ID_SEPARATOR}{id}");
    (value.clone(), value)
}
