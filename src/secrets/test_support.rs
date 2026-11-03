use std::sync::Arc;

use super::{CreateSecretRequest, FilesystemSecretsStore, SecretsStore};

/// A secrets store holding `own` for `tenant-a`, the appliance-wide `wide` and `other` for
/// `tenant-b`, each with the value `<secret_id>-value`.
pub(crate) async fn tenant_secrets() -> (tempfile::TempDir, Option<Arc<dyn SecretsStore>>) {
    let dir = tempfile::tempdir().unwrap();
    let store = FilesystemSecretsStore::new_async(dir.path().to_str().unwrap())
        .await
        .unwrap();
    for (secret_id, tenant_id) in [("own", Some("tenant-a")), ("wide", None), ("other", Some("tenant-b"))] {
        store
            .create(CreateSecretRequest {
                tenant_id: tenant_id.map(String::from),
                name: secret_id.into(),
                secret_id: secret_id.into(),
                description: None,
                value: format!("{secret_id}-value"),
                secret_type: "General".into(),
                tags: vec![],
            })
            .await
            .unwrap();
    }
    (dir, Some(Arc::new(store)))
}
