//! A one-time move of the live version's integrations (`2470747`) onto endpoints, event sets
//! and integrations. See `.plans/integrations-endpoints-event-sets.md`, stage 5.

pub mod apply;
pub mod cleanup;
pub mod legacy;
pub mod plan;
pub mod received;
pub mod run;
