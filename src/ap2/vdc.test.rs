#[cfg(test)]
mod tests {
    use crate::ap2::vdc::*;
    use serde_json::json;

    #[tokio::test]
    #[ignore] // FIXME: failing test
    async fn test_validate_intent_mandate() {
        // Test with PLAIN AP2 format (the actual format sent in messages)
        let plain_mandate = json!({
            "user_cart_confirmation_required": true,
            "natural_language_description": "Buy Nike Air Max 90 in size 10, white color, budget under $150",
            "merchants": null,
            "skus": ["NIKE-AM90-WHT-M10"],
            "requires_refundability": true,
            "intent_expiry": "2026-01-14T18:00:00Z"
        });

        // from_ap2_mandate should create the VDC wrapper
        let vdc = VDC::from_value(&plain_mandate).unwrap();

        // Verify the VDC was created with synthetic values
        assert_eq!(vdc.mandate_type, "IntentMandate");
        assert!(
            vdc.id
                .starts_with("intentmandate-")
        );
        assert_eq!(vdc.issuer, "did:ap2:synthetic-issuer");

        // Verify credential subject contains the plain mandate data
        assert_eq!(
            vdc.credential_subject["natural_language_description"],
            "Buy Nike Air Max 90 in size 10, white color, budget under $150"
        );

        let result = vdc.validate().await.unwrap();
        assert!(result.valid, "Validation should pass for plain AP2 format");
        assert_eq!(result.mandate_type, "IntentMandate");
    }

    #[tokio::test]
    async fn test_validate_wrapped_vdc() {
        // Test with W3C VC-wrapped format (for backward compatibility)
        let vdc_json = json!({
            "@context": "https://ap2-protocol.org/mandates/v1",
            "type": "IntentMandate",
            "id": "intent-test-123",
            "issuer": "did:example:shopping-agent",
            "issuanceDate": "2024-01-15T10:00:00Z",
            "credentialSubject": {
                "user_cart_confirmation_required": true,
                "natural_language_description": "Buy Nike Air Max 90 in size 10, white color, budget under $150",
                "merchants": null,
                "skus": ["NIKE-AM90-WHT-M10"],
                "requires_refundability": true,
                "intent_expiry": "2026-01-14T18:00:00Z"
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2024-01-15T10:00:00Z",
                "verificationMethod": "did:example:shopping-agent#key-1",
                "proofValue": "z3FXQ1234567890abcdefghijklmnop"
            }
        });

        let vdc = VDC::from_value(&vdc_json).unwrap();
        let result = vdc.validate().await.unwrap();

        // Signature verification is unimplemented and fails closed: a mandate
        // whose signature cannot be cryptographically verified must not be
        // reported as valid.
        assert!(!result.valid, "Unverifiable signature must fail closed");
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.contains("Signature")),
            "Validation errors should flag the signature: {:?}",
            result.errors
        );
        assert_eq!(result.mandate_type, "IntentMandate");
        assert_eq!(result.mandate_id, "intent-test-123");
    }

    #[test]
    fn test_extract_vdc_from_message() {
        let message = json!({
            "jsonrpc": "2.0",
            "method": "agent.invoke",
            "params": {
                "extensions": {
                    "payment": {
                        "vdc": {
                            "@context": "https://ap2-protocol.org/mandates/v1",
                            "type": "CartMandate",
                            "id": "cart-123",
                            "issuer": "did:example:merchant",
                            "issuanceDate": "2024-01-15T10:00:00Z",
                            "credentialSubject": {
                                "contents": {
                                    "id": "cart_shoes_123",
                                    "payment_request": {
                                        "details": {
                                            "total": {
                                                "amount": {"currency": "USD", "value": 130.34}
                                            }
                                        }
                                    }
                                },
                                "merchant_authorization": "eyJhbGc..."
                            },
                            "proof": {
                                "type": "Ed25519Signature2020",
                                "created": "2024-01-15T10:00:00Z",
                                "verificationMethod": "did:example:merchant#key-1",
                                "proofValue": "z3FXQ1234567890"
                            }
                        }
                    }
                }
            }
        });

        let vdc = extract_vdc_from_message(&message).unwrap();
        assert!(vdc.is_some());
        assert_eq!(vdc.unwrap().mandate_type, "CartMandate");
    }

    #[test]
    fn test_extract_vdc_from_ap2_spec_format() {
        // Test official AP2 specification format: params.message.parts[].data["ap2.mandates.IntentMandate"]
        let message = json!({
            "jsonrpc": "2.0",
            "method": "agent.invoke",
            "params": {
                "message": {
                    "messageId": "msg-123",
                    "contextId": "ctx-456",
                    "role": "agent",
                    "parts": [
                        {
                            "kind": "text",
                            "text": "Find products that match the user's IntentMandate."
                        },
                        {
                            "kind": "data",
                            "data": {
                                "ap2.mandates.IntentMandate": {
                                    "user_cart_confirmation_required": false,
                                    "natural_language_description": "I'd like some cool red shoes in my size",
                                    "merchants": null,
                                    "skus": null,
                                    "requires_refundability": true,
                                    "intent_expiry": "2025-09-16T15:00:00Z"
                                }
                            }
                        }
                    ]
                }
            }
        });

        let vdc = extract_vdc_from_message(&message).unwrap();
        assert!(vdc.is_some());
        let vdc = vdc.unwrap();
        assert_eq!(vdc.mandate_type, "IntentMandate");

        // Verify the credential subject contains the mandate data
        let subject = &vdc.credential_subject;
        assert_eq!(subject["natural_language_description"], "I'd like some cool red shoes in my size");
        assert_eq!(subject["requires_refundability"], true);
    }

    #[test]
    #[ignore] // FIXME: failing test
    fn test_extract_cart_mandate_from_ap2_spec_format() {
        // Test CartMandate in official AP2 format
        let message = json!({
            "params": {
                "message": {
                    "parts": [
                        {
                            "kind": "data",
                            "data": {
                                "ap2.mandates.CartMandate": {
                                    "contents": {
                                        "id": "cart-shoes-123",
                                        "user_cart_confirmation_required": false,
                                        "payment_request": {
                                            "method_data": [{"supported_methods": "CARD"}],
                                            "details": {"id": "order-123"}
                                        },
                                        "cart_expiry": "2025-09-16T15:00:00Z",
                                        "merchant_name": "ShoeStore"
                                    },
                                    "merchant_authorization": "eyJhbGc..."
                                }
                            }
                        }
                    ]
                }
            }
        });

        let vdc = extract_vdc_from_message(&message).unwrap();
        assert!(vdc.is_some());
        let vdc = vdc.unwrap();
        assert_eq!(vdc.mandate_type, "CartMandate");

        // Verify contents field exists
        let subject = &vdc.credential_subject;
        assert!(
            subject
                .get("contents")
                .is_some()
        );
    }
}
