pub mod communication;
pub mod did_manager;
pub mod filesystem;
pub mod handlers;
pub mod q3_resource_config;
pub mod reader;
pub mod reference_fields;
pub mod store;
pub mod types;
pub mod worker;

pub use communication::TrustRegistryListenerManager;
pub use filesystem::FileSystemTrustRegistryStore;
pub use store::TrustRegistryStore;
pub use worker::TrustRegistryWorker;

#[cfg(test)]
mod tests {
    use super::types::{TrAdminListRecordsResponse, TrustRegistryListRecordsResponse};

    #[test]
    fn list_records_response_includes_round_trip_time() {
        let response = TrustRegistryListRecordsResponse::from_list_records(
            TrAdminListRecordsResponse { count: 0, records: Vec::new() },
            17,
        );

        let json = serde_json::to_value(response).expect("response should serialize");

        assert_eq!(json["count"], 0);
        assert_eq!(json["records"], serde_json::json!([]));
        assert_eq!(json["round_trip_ms"], 17);
    }
}
