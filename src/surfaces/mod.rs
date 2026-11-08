//! Agent Surface storage module

pub mod filesystem;
pub mod resolved_cache;
pub mod store;

pub use filesystem::FileSystemAgentSurfaceStore;
pub use resolved_cache::ResolvedSurfaceCache;
pub use store::{
    AgentSurfaceStore, RetiredA2aSwitches, carry_over_a2a_settings, clear_dangling_default_variants,
    fall_back_to_first_source_auth_methods, strip_unsupported_header_metadata_mappings,
};
