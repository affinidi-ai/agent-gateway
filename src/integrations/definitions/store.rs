use std::path::PathBuf;

use anyhow::Result;

use crate::storage::filesystem::{StorableEntity, StorageBackend, uncached_storage};

pub trait Definition: StorableEntity {
    fn created_at(&self) -> &str;
}

/// One JSON file per definition.
pub struct DefinitionStore<T: Definition> {
    storage: Box<dyn StorageBackend<T>>,
}

impl<T: Definition> DefinitionStore<T> {
    pub async fn new(
        path: PathBuf,
        entity_name: &'static str,
    ) -> Result<Self> {
        Ok(Self {
            storage: uncached_storage(path, entity_name).await?,
        })
    }

    /// The definition with `id`, or `None` when there is none. An error means the store could
    /// not answer: an invalid id, or a record it failed to read, decrypt or parse.
    pub async fn find(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        self.storage.get(id).await
    }

    /// Every definition, newest first.
    pub async fn list(&self) -> Result<Vec<T>> {
        let mut definitions = self
            .storage
            .list_all()
            .await?;
        definitions.sort_by(|a, b| {
            b.created_at()
                .cmp(a.created_at())
        });
        Ok(definitions)
    }

    pub async fn save(
        &self,
        definition: &T,
    ) -> Result<()> {
        self.storage
            .save(definition)
            .await
    }

    /// Whether a definition with `id` existed and was removed.
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<bool> {
        if !self
            .storage
            .exists(id)
            .await?
        {
            return Ok(false);
        }
        self.storage
            .delete(id)
            .await?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::definitions::{Endpoint, EndpointType};
    use serde_json::json;
    use tempfile::tempdir;

    fn endpoint(
        name: &str,
        created_at: &str,
    ) -> Endpoint {
        let mut endpoint = Endpoint::new(name.to_string(), String::new(), EndpointType::Slack, json!({}));
        endpoint.created_at = created_at.to_string();
        endpoint
    }

    #[tokio::test]
    async fn finds_what_it_saved_and_lists_newest_first() {
        let dir = tempdir().expect("temp dir");
        let store = DefinitionStore::<Endpoint>::new(dir.path().to_path_buf(), "endpoint")
            .await
            .expect("store");
        let older = endpoint("older", "2026-01-01T00:00:00+00:00");
        let newer = endpoint("newer", "2026-02-01T00:00:00+00:00");
        store
            .save(&older)
            .await
            .expect("save older");
        store
            .save(&newer)
            .await
            .expect("save newer");

        assert_eq!(
            store
                .find(&older.id)
                .await
                .expect("find"),
            Some(older.clone())
        );
        let names: Vec<String> = store
            .list()
            .await
            .expect("list")
            .into_iter()
            .map(|endpoint| endpoint.name)
            .collect();
        assert_eq!(names, ["newer", "older"]);
    }

    #[tokio::test]
    async fn finds_nothing_for_an_unknown_id() {
        let dir = tempdir().expect("temp dir");
        let store = DefinitionStore::<Endpoint>::new(dir.path().to_path_buf(), "endpoint")
            .await
            .expect("store");

        assert_eq!(
            store
                .find(&uuid::Uuid::new_v4().to_string())
                .await
                .expect("find"),
            None
        );
    }

    #[tokio::test]
    async fn delete_reports_whether_it_removed_a_definition() {
        let dir = tempdir().expect("temp dir");
        let store = DefinitionStore::<Endpoint>::new(dir.path().to_path_buf(), "endpoint")
            .await
            .expect("store");
        let saved = endpoint("saved", "2026-01-01T00:00:00+00:00");
        store
            .save(&saved)
            .await
            .expect("save");

        assert!(
            store
                .delete(&saved.id)
                .await
                .expect("delete")
        );
        assert!(
            !store
                .delete(&saved.id)
                .await
                .expect("delete again")
        );
        assert_eq!(
            store
                .find(&saved.id)
                .await
                .expect("find"),
            None
        );
    }

    #[tokio::test]
    async fn save_leaves_only_the_record_file_and_it_parses() {
        let dir = tempdir().expect("temp dir");
        let store = DefinitionStore::<Endpoint>::new(dir.path().to_path_buf(), "endpoint")
            .await
            .expect("store");
        let saved = endpoint("saved", "2026-01-01T00:00:00+00:00");
        store
            .save(&saved)
            .await
            .expect("save");
        store
            .save(&saved)
            .await
            .expect("save again");

        let files: Vec<String> = std::fs::read_dir(dir.path())
            .expect("read dir")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert_eq!(files, [format!("{}.json", saved.id)]);
        assert_eq!(
            store
                .find(&saved.id)
                .await
                .expect("find"),
            Some(saved)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_list_never_fails_while_a_definition_is_being_saved() {
        let dir = tempdir().expect("temp dir");
        let store = std::sync::Arc::new(
            DefinitionStore::<Endpoint>::new(dir.path().to_path_buf(), "endpoint")
                .await
                .expect("store"),
        );
        let mut big = endpoint("big", "2026-01-01T00:00:00+00:00");
        big.configuration = json!({ "padding": "x".repeat(256 * 1024) });
        store
            .save(&big)
            .await
            .expect("first save");

        let writer = {
            let store = store.clone();
            let big = big.clone();
            tokio::spawn(async move {
                for _ in 0..200 {
                    store
                        .save(&big)
                        .await
                        .expect("save");
                }
            })
        };
        let readers: Vec<_> = (0..3)
            .map(|_| {
                let store = store.clone();
                let id = big.id.clone();
                tokio::spawn(async move {
                    for _ in 0..200 {
                        let listed = store
                            .list()
                            .await
                            .expect("list while saving");
                        assert_eq!(listed.len(), 1);
                        assert!(
                            store
                                .find(&id)
                                .await
                                .expect("find while saving")
                                .is_some()
                        );
                    }
                })
            })
            .collect();

        writer
            .await
            .expect("writer");
        for reader in readers {
            reader
                .await
                .expect("reader");
        }
    }
}
