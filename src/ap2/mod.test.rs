#[cfg(test)]
mod tests {
    use super::super::*;
    use serde_json::json;

    #[tokio::test]
    #[ignore] // FIXME: failing test
    async fn test_process_ap2_message() {
        let mut message = json!({
            "jsonrpc": "2.0",
            "method": "agent.invoke",
            "params": {
                "extensions": {
                    "payment": {
                        "vdc": {
                            "@context": "https://ap2-protocol.org/mandates/v1",
                            "type": "IntentMandate",
                            "id": "intent-test-123",
                            "issuer": "did:example:shopping-agent",
                            "issuanceDate": "2024-01-15T10:00:00Z",
                            "credentialSubject": {
                                "user_cart_confirmation_required": true,
                                "natural_language_description": "Purchase laptop under $1500 with fast shipping",
                                "requires_refundability": true,
                                "intent_expiry": "2026-01-15T00:00:00Z"
                            },
                            "proof": {
                                "type": "Ed25519Signature2020",
                                "created": "2024-01-15T10:00:00Z",
                                "verificationMethod": "did:example:shopping-agent#key-1",
                                "proofValue": "z3FXQ1234567890abcdef"
                            }
                        }
                    }
                }
            }
        });

        // Test without VCIssuer and without agent identity
        let result = process_ap2_message(&mut message, "did:example:gateway", &None, &None).await;

        // Should fail because VCIssuer is required
        assert!(result.is_err(), "Should fail without VCIssuer");

        // Check error message
        let err_msg = result
            .unwrap_err()
            .to_string();
        assert!(err_msg.contains("VCIssuer required"), "Error should mention VCIssuer requirement");
    }

    #[tokio::test]
    async fn test_process_message_without_vdc() {
        let mut message = json!({
            "jsonrpc": "2.0",
            "method": "agent.invoke",
            "params": {}
        });

        let result = process_ap2_message(&mut message, "did:example:gateway", &None, &None).await;

        assert!(result.is_ok(), "Should succeed even without VDC");

        // Metadata should not be added if no VDC present
        assert!(
            message
                .get("metadata")
                .is_none()
                || !message["metadata"]["ap2_payment_vp"].is_string()
        );
    }
}
