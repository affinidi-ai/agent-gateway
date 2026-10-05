#[cfg(test)]
mod tests {
    use crate::ap2::credentials::VerifiableCredential;
    use crate::ap2::presentation::*;
    use serde_json::json;

    #[tokio::test]
    async fn test_create_presentation() {
        let vc = VerifiableCredential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            credential_types: vec!["VerifiableCredential".to_string(), "PurchaseIntentCredential".to_string()],
            id: "urn:uuid:test-vc-123".to_string(),
            issuer: "did:example:gateway".to_string(),
            issuance_date: chrono::Utc::now().to_rfc3339(),
            credential_subject: json!({
                "id": "did:example:shopping-agent",
                "intent": "Purchase laptop",
                "maxPrice": 1500
            }),
            proof: None,
        };

        let result = create_single_credential_presentation(
            vc,
            "did:example:gateway",
            "key-1",
            Some("did:example:shopping-agent".to_string()),
        )
        .await;

        // Presentation signing is unimplemented and fails closed, so no
        // presentation carrying a fabricated proof can be produced.
        assert!(result.is_err(), "Presentation creation must fail closed without real signing");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("signing is not implemented")
        );
    }

    #[tokio::test]
    async fn test_vp_to_json() {
        let vc = VerifiableCredential {
            context: vec!["https://www.w3.org/2018/credentials/v1".to_string()],
            credential_types: vec!["VerifiableCredential".to_string()],
            id: "urn:uuid:test-vc".to_string(),
            issuer: "did:example:gateway".to_string(),
            issuance_date: chrono::Utc::now().to_rfc3339(),
            credential_subject: json!({"id": "did:example:agent"}),
            proof: None,
        };

        let result = create_single_credential_presentation(vc, "did:example:gateway", "key-1", None).await;

        // Fails closed: no presentation is produced, so there is nothing to serialize.
        assert!(result.is_err(), "Presentation creation must fail closed without real signing");
    }
}
