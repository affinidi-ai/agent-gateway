//! Endpoints, event sets and the integrations that join them.

pub mod endpoint;
pub mod event_set;
pub mod integration;
pub mod store;

pub use endpoint::{Endpoint, EndpointType};
pub use event_set::{EventSet, EventSetError};
pub use integration::Integration;
pub use store::{Definition, DefinitionStore};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    #[default]
    Active,
    Disabled,
}

fn now() -> String {
    chrono::Utc::now().to_rfc3339()
}
