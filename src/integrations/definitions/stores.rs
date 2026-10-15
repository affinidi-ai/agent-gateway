use std::path::Path;
use std::sync::{Arc, OnceLock};

use anyhow::Result;

use super::{DefinitionStore, Endpoint, EventSet, Integration};
use crate::config::StoragePaths;

/// The endpoint, event set and integration stores the API and event delivery share.
pub struct DefinitionStores {
    pub endpoints: DefinitionStore<Endpoint>,
    pub event_sets: DefinitionStore<EventSet>,
    pub integrations: DefinitionStore<Integration>,
}

impl DefinitionStores {
    pub async fn open(
        endpoints: &Path,
        event_sets: &Path,
        integrations: &Path,
    ) -> Result<Self> {
        Ok(Self {
            endpoints: DefinitionStore::new(endpoints.to_path_buf(), "integration endpoint").await?,
            event_sets: DefinitionStore::new(event_sets.to_path_buf(), "integration event set").await?,
            integrations: DefinitionStore::new(integrations.to_path_buf(), "integration").await?,
        })
    }

    pub async fn open_configured(paths: &StoragePaths) -> Result<Self> {
        Self::open(
            Path::new(&paths.integration_endpoints),
            Path::new(&paths.integration_event_sets),
            Path::new(&paths.integration_definitions),
        )
        .await
    }
}

static DEFINITION_STORES: OnceLock<Arc<DefinitionStores>> = OnceLock::new();

/// Sets the stores the API and event delivery share. Only the first call takes effect.
pub fn init_definition_stores(stores: Arc<DefinitionStores>) {
    let _ = DEFINITION_STORES.set(stores);
}

pub fn definition_stores() -> Option<Arc<DefinitionStores>> {
    DEFINITION_STORES
        .get()
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn stores_in(dir: &Path) -> Arc<DefinitionStores> {
        Arc::new(
            DefinitionStores::open(&dir.join("endpoints"), &dir.join("event_sets"), &dir.join("integrations"))
                .await
                .expect("stores"),
        )
    }

    #[tokio::test]
    async fn opens_each_store_in_its_configured_folder() {
        let dir = tempfile::tempdir().expect("temp dir");
        let folder = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let paths = StoragePaths {
            integration_endpoints: folder("endpoints"),
            integration_event_sets: folder("event_sets"),
            integration_definitions: folder("integrations"),
            ..StoragePaths::default()
        };
        let stores = DefinitionStores::open_configured(&paths)
            .await
            .expect("stores");
        let event_set = EventSet::new("Set".to_string(), String::new(), vec!["user.login".to_string()]).expect("set");

        stores
            .event_sets
            .save(&event_set)
            .await
            .expect("save");

        assert!(
            dir.path()
                .join("event_sets")
                .join(format!("{}.json", event_set.id))
                .exists()
        );
    }

    #[tokio::test]
    async fn stores_set_later_do_not_replace_the_shared_ones() {
        let dir = tempfile::tempdir().expect("temp dir");
        init_definition_stores(stores_in(&dir.path().join("first")).await);
        let shared = definition_stores().expect("set");

        init_definition_stores(stores_in(&dir.path().join("second")).await);

        assert!(Arc::ptr_eq(&definition_stores().expect("set"), &shared));
    }
}
