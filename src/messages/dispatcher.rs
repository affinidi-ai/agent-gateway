//! Message Dispatcher
//!
//! Central dispatcher for all incoming DIDComm messages.
//! Provides hooks for middleware, logging, metrics, and routing to appropriate handlers.

use std::time::Instant;
use tracing::{debug, error, info, warn};

use super::message_types::{MessageType, ProtocolFamily};
use crate::gateways::connection_points::message_processor::{ProcessingResult, process_message_internal};
use crate::gateways::connection_points::messages::ReceivedMessage;

/// Message dispatcher statistics
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct DispatcherStats {
    pub total_messages: u64,
    pub by_protocol: std::collections::HashMap<ProtocolFamily, u64>,
    pub processing_errors: u64,
}

/// Dispatch context for middleware and augmentation
#[derive(Debug, Clone)]
pub struct DispatchContext {
    /// When the message was received
    #[allow(dead_code)]
    pub received_at: chrono::DateTime<chrono::Utc>,
    /// Parsed message type
    pub message_type: MessageType,
    /// Protocol family
    pub protocol_family: ProtocolFamily,
    /// Connection point ID that received this message
    pub connection_point_id: Option<String>,
}

impl DispatchContext {
    pub fn new(message: &ReceivedMessage) -> Self {
        let message_type = MessageType::from_str(&message.message_type);
        let protocol_family = message_type.protocol_family();

        Self {
            received_at: chrono::Utc::now(),
            message_type,
            protocol_family,
            connection_point_id: None,
        }
    }

    pub fn with_connection_point(
        mut self,
        cp_id: String,
    ) -> Self {
        self.connection_point_id = Some(cp_id);
        self
    }
}

/// Main message dispatcher
///
/// This is the central entry point for all incoming DIDComm messages.
/// It provides:
/// - Message type parsing and validation
/// - Protocol family identification
/// - Middleware hooks (pre/post processing)
/// - Metrics collection
/// - Error handling and logging
/// - Routing to appropriate protocol handlers
pub async fn dispatch_message(
    message: &ReceivedMessage,
    context: DispatchContext,
) -> ProcessingResult {
    let start_time = Instant::now();

    // Log incoming message with context
    info!(
        "📨 Dispatching message: type={} ({}), from={:?}, id={}",
        context.message_type, context.protocol_family, message.from_did, message.id
    );

    // Pre-processing hook - can be extended for middleware
    if let Err(e) = pre_process_hook(message, &context).await {
        warn!("Pre-processing hook failed: {}", e);
        // Continue processing anyway unless critical
    }

    // Route to appropriate handler based on message type
    let result = match &context.message_type {
        MessageType::Unknown(type_str) => {
            info!("❓ Unknown message type: {}", type_str);
            ProcessingResult::Stored
        }
        _ => {
            // Delegate to the internal processor
            process_message_internal(message, &context.message_type).await
        }
    };

    // Post-processing hook
    let elapsed = start_time.elapsed();
    if let Err(e) = post_process_hook(message, &context, &result, elapsed) {
        warn!("Post-processing hook failed: {}", e);
    }

    debug!("✓ Message dispatched successfully in {:?}: {:?}", elapsed, result);

    result
}

/// Pre-processing hook for middleware
///
/// This is called BEFORE message processing and can be used for:
/// - Authentication/authorization checks
/// - Rate limiting
/// - Message validation
/// - Custom logging
/// - Metrics collection
async fn pre_process_hook(
    message: &ReceivedMessage,
    context: &DispatchContext,
) -> Result<(), String> {
    debug!("Pre-processing message: {}", message.id);

    // Example: Log protocol family metrics
    debug!("Protocol family: {}", context.protocol_family);

    // Add custom pre-processing logic here
    // For example:
    // - Check if sender is authorized
    // - Validate message format
    // - Apply rate limiting
    // - Update metrics

    Ok(())
}

/// Post-processing hook for middleware
///
/// This is called AFTER message processing and can be used for:
/// - Logging results
/// - Metrics collection
/// - Cleanup operations
/// - Notifications
fn post_process_hook(
    message: &ReceivedMessage,
    _context: &DispatchContext,
    result: &ProcessingResult,
    elapsed: std::time::Duration,
) -> Result<(), String> {
    debug!("Post-processing message: {} (took {:?})", message.id, elapsed);

    // Log based on result type
    match result {
        ProcessingResult::RequiresResponse { response_type, .. } => {
            info!("💬 Message requires response: {}", response_type);
        }
        ProcessingResult::StreamingResponse { .. } => {
            debug!("Message produced an owned streaming response");
        }
        ProcessingResult::ProcessedNoResponse => {
            debug!("✓ Message processed successfully");
        }
        ProcessingResult::Failed { reason } => {
            error!("❌ Message processing failed: {}", reason);
        }
        ProcessingResult::Stored => {
            debug!("📥 Message stored for later processing");
        }
        ProcessingResult::OOBConnectionAccepted(_) => {
            info!("🎉 OOB connection accepted");
        }
        ProcessingResult::OOBConnectionSetup(_) => {
            info!("🔗 OOB connection setup received");
        }
        ProcessingResult::OOBConnectionRejected { reason } => {
            error!("❌ OOB connection rejected: {}", reason);
        }
    }

    // Add custom post-processing logic here
    // For example:
    // - Update processing time metrics
    // - Send notifications
    // - Trigger webhooks
    // - Update dashboard stats

    Ok(())
}

/// Convenience function to dispatch with minimal context
#[allow(dead_code)]
pub async fn dispatch_message_simple(message: &ReceivedMessage) -> ProcessingResult {
    let context = DispatchContext::new(message);
    dispatch_message(message, context).await
}
