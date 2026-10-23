use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, SecretsStore, UpdateSecretRequest};

/// A secrets store holding `(secret_id, tenant_id, value)` entries, readable by secret id only.
pub struct Secrets(pub Vec<(&'static str, Option<&'static str>, &'static str)>);

#[async_trait::async_trait]
impl SecretsStore for Secrets {
    async fn create(
        &self,
        _request: CreateSecretRequest,
    ) -> anyhow::Result<Secret> {
        unimplemented!()
    }

    async fn get(
        &self,
        _id: &str,
    ) -> anyhow::Result<Option<Secret>> {
        unimplemented!()
    }

    async fn get_by_secret_id(
        &self,
        secret_id: &str,
    ) -> anyhow::Result<Option<Secret>> {
        let now = chrono::Utc::now();
        Ok(self
            .0
            .iter()
            .find(|(id, _, _)| *id == secret_id)
            .map(|(id, tenant, value)| Secret {
                id: format!("internal-{id}"),
                tenant_id: tenant.map(str::to_string),
                name: id.to_string(),
                secret_id: id.to_string(),
                description: None,
                value: value.to_string(),
                secret_type: "General".to_string(),
                tags: Vec::new(),
                created_at: now,
                updated_at: now,
            }))
    }

    async fn list_all(&self) -> anyhow::Result<Vec<SecretListItem>> {
        unimplemented!()
    }

    async fn update(
        &self,
        _id: &str,
        _request: UpdateSecretRequest,
    ) -> anyhow::Result<Secret> {
        unimplemented!()
    }

    async fn delete(
        &self,
        _id: &str,
    ) -> anyhow::Result<()> {
        unimplemented!()
    }

    async fn find_by_tag(
        &self,
        _tag: &str,
    ) -> anyhow::Result<Vec<SecretListItem>> {
        unimplemented!()
    }
}
