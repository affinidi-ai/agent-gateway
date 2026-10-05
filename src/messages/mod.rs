//! DIDComm Message Types and Dispatcher
//!
//! This module contains the message type system and central dispatcher
//! for all DIDComm messages processed by the application.

pub mod dispatcher;
pub mod message_types;

pub use dispatcher::{DispatchContext, dispatch_message};
pub use message_types::MessageType;
