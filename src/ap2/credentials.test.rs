#[cfg(test)]
mod tests {
    use crate::ap2::credentials::*;
    use crate::ap2::vdc::VDC;
    use serde_json::json;

    #[tokio::test]
    async fn test_transform_intent_mandate_to_vc() {
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
                "proofValue": "z3FXQ1234567890"
            }
        });

        let vdc = VDC::from_value(&vdc_json).unwrap();
        let result = transform_vdc_to_vc(&vdc, "did:example:gateway", "did:example:shopping-agent").await;

        // Credential signing is unimplemented and fails closed, so no credential
        // (and therefore no fabricated proof) can be produced.
        assert!(result.is_err(), "Transform must fail closed without real signing");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("signing is not implemented")
        );
    }

    #[tokio::test]
    async fn test_transform_cart_mandate_to_vc() {
        let vdc_json = json!({
            "@context": "https://ap2-protocol.org/mandates/v1",
            "type": "CartMandate",
            "id": "cart-test-456",
            "issuer": "did:example:merchant",
            "issuanceDate": "2024-01-15T11:00:00Z",
            "credentialSubject": {
                "contents": {
                    "id": "cart_shoes_123",
                    "payment_request": {
                        "details": {
                            "total": {
                                "amount": {"currency": "USD", "value": 130.34}
                            },
                            "displayItems": [
                                {"label": "Nike Air Max 90", "amount": {"currency": "USD", "value": 119.99}}
                            ]
                        }
                    },
                    "cart_expiry": "2026-01-14T16:00:00Z",
                    "merchant_name": "Nike, Inc."
                },
                "merchant_authorization": "eyJhbGc..."
            },
            "proof": {
                "type": "Ed25519Signature2020",
                "created": "2024-01-15T11:00:00Z",
                "verificationMethod": "did:example:merchant#key-1",
                "proofValue": "z3FXQ9876543210"
            }
        });

        let vdc = VDC::from_value(&vdc_json).unwrap();
        let result = transform_vdc_to_vc(&vdc, "did:example:gateway", "did:example:merchant").await;

        // Fails closed: no signed credential is produced.
        assert!(result.is_err(), "Transform must fail closed without real signing");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("signing is not implemented")
        );
    }
}
