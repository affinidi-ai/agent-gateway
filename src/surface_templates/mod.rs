//! Surface Templates — reusable bundles of pre-configured surface items.
//!
//! Templates carry one or more items (palette elements, edges, policies)
//! that the frontend places onto an agent surface. Builtin templates ship
//! out of the box; users can also create, import and export their own.

pub mod filesystem;
pub mod handlers;
pub mod types;

pub use filesystem::FileSystemSurfaceTemplateStore;
