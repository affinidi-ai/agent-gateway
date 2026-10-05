//! Filesystem-backed storage for surface templates with builtin seeding.
//!
//! On first start the templates dir is created and every `*.json` file
//! discovered under the optional seed source directory (typically
//! `<config_dir>/agent_surface_templates/`) is parsed, stamped with
//! `builtin: true`, and written to the storage dir. On subsequent
//! restarts a builtin file is overwritten in place when its on-disk
//! content differs from the source AND the file still has
//! `builtin: true` — this lets us ship corrected builtins without
//! leaving stale copies on every dev box. Admins who want to hand-edit
//! a builtin must flip `builtin: false` (which also takes the file out
//! of REST-API immutability), at which point the seeder leaves it
//! alone.

use anyhow::{Context, Result};
use async_trait::async_trait;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

use super::types::SurfaceTemplate;
use crate::storage::filesystem::{StorageBackend, StorageConfig, cached_storage_with_config};

/// Filename extension used by source seed templates. Only `*.json`
/// files in the seed dir are considered; anything else is ignored so
/// the folder can also hold READMEs and other supporting docs.
const SEED_FILE_EXTENSION: &str = "json";

/// Public store API. Keeping a trait makes the handler layer testable
/// with a memory store later; for now the only implementation is the
/// filesystem one.
#[async_trait]
pub trait SurfaceTemplateStore: Send + Sync {
    async fn list_all(&self) -> Result<Vec<SurfaceTemplate>>;
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<SurfaceTemplate>>;
    async fn save(
        &self,
        template: &SurfaceTemplate,
    ) -> Result<()>;
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}

/// Filesystem-based surface template store with in-memory cache.
pub struct FileSystemSurfaceTemplateStore {
    storage: Box<dyn StorageBackend<SurfaceTemplate>>,
}

impl FileSystemSurfaceTemplateStore {
    /// Create a new store.
    ///
    /// * `storage_dir` — runtime persistence directory (one file per
    ///   template id).
    /// * `seed_source_dir` — optional directory scanned for `*.json`
    ///   files at boot. Each discovered file is parsed and seeded as a
    ///   builtin. Pass `None` to skip seeding (e.g. dev gateways with
    ///   no shipped builtins).
    pub async fn new(
        storage_dir: PathBuf,
        seed_source_dir: Option<PathBuf>,
    ) -> Result<Self> {
        info!("Loading surface templates from: {}", storage_dir.display());
        tokio::fs::create_dir_all(&storage_dir)
            .await
            .with_context(|| format!("creating surface_templates dir {}", storage_dir.display()))?;

        if let Some(seed_dir) = seed_source_dir {
            Self::seed_builtins(&storage_dir, &seed_dir).await?;
        } else {
            info!("No seed source directory provided; skipping builtin surface template seeding");
        }

        // Surface templates are non-secret, shareable presets and are always
        // stored as plaintext `.json`. They deliberately bypass the global
        // encryption-at-rest config (an unconditional `StorageConfig::default()`)
        // so enabling encryption never migrates them to `.json.enc` — which would
        // otherwise make them unreadable after a KEK change and surface as an
        // empty `/v1/surface-templates` list.
        let storage = Box::new(
            cached_storage_with_config::<SurfaceTemplate>(storage_dir, "surface_template", StorageConfig::default())
                .await?,
        );
        let count = storage
            .list_all()
            .await?
            .len();
        info!("Loaded {} surface template(s)", count);
        Ok(Self { storage })
    }

    /// Scan `seed_source_dir` for `*.json` files and write each one to
    /// the runtime storage dir as a builtin. Files whose on-disk copy
    /// matches the source byte-for-byte are skipped; files that differ
    /// are overwritten only when the on-disk copy still has
    /// `builtin: true` (admin ownership flips that flag to `false` and
    /// opts the file out of seeder updates).
    ///
    /// The seed dir is allowed to not exist (logged + treated as
    /// empty) so a gateway can boot without any pre-bundled templates.
    async fn seed_builtins(
        storage_dir: &Path,
        seed_source_dir: &Path,
    ) -> Result<()> {
        if !seed_source_dir.exists() {
            info!(
                "Seed source dir {} does not exist; skipping builtin surface template seeding",
                seed_source_dir.display()
            );
            return Ok(());
        }

        let mut entries = tokio::fs::read_dir(seed_source_dir)
            .await
            .with_context(|| format!("reading seed source dir {}", seed_source_dir.display()))?;

        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("iterating seed source dir {}", seed_source_dir.display()))?
        {
            let source_path = entry.path();
            if !source_path.is_file() {
                continue;
            }
            if source_path
                .extension()
                .and_then(|s| s.to_str())
                != Some(SEED_FILE_EXTENSION)
            {
                continue;
            }

            if let Err(e) = Self::seed_one(storage_dir, &source_path).await {
                // One bad template should not block the rest from
                // seeding — log and continue.
                warn!("Failed to seed builtin surface template from {}: {:#}", source_path.display(), e);
            }
        }

        Ok(())
    }

    async fn seed_one(
        storage_dir: &Path,
        source_path: &Path,
    ) -> Result<()> {
        let body = tokio::fs::read_to_string(source_path)
            .await
            .with_context(|| format!("reading {}", source_path.display()))?;

        let mut tpl: SurfaceTemplate = serde_json::from_str(&body)
            .with_context(|| format!("parsing surface template at {}", source_path.display()))?;

        // The template's own `id` field is authoritative for the
        // on-disk filename so save/load round-trips line up with the
        // REST API's `/v1/surface-templates/{id}` paths.
        if tpl.id.is_empty() {
            anyhow::bail!("seed template {} has an empty `id` field", source_path.display());
        }
        tpl.tenant_id = None;
        tpl.builtin = true;
        if tpl.author.is_empty() {
            tpl.author = "system".to_string();
        }

        let pretty =
            serde_json::to_string_pretty(&tpl).with_context(|| format!("serializing seed template '{}'", tpl.id))?;

        let target_path = storage_dir.join(format!("{}.json", tpl.id));

        if target_path.exists() {
            let on_disk = tokio::fs::read_to_string(&target_path)
                .await
                .with_context(|| format!("reading existing builtin {}", target_path.display()))?;
            if on_disk == pretty {
                return Ok(());
            }
            // Drift detected. Only overwrite when the on-disk file
            // still claims `builtin: true` — admin-owned forks
            // (builtin: false) are preserved.
            match serde_json::from_str::<SurfaceTemplate>(&on_disk) {
                Ok(existing) if !existing.builtin => {
                    info!("Builtin '{}' has been adopted (builtin: false); leaving on-disk copy", tpl.id);
                    return Ok(());
                }
                Ok(_) => {
                    info!("Re-seeding stale builtin surface template: {}", tpl.id);
                }
                Err(e) => {
                    warn!("Existing builtin '{}' could not be parsed ({}); overwriting with seed source", tpl.id, e);
                }
            }
        } else {
            info!("Seeded builtin surface template: {} (from {})", tpl.id, source_path.display());
        }

        tokio::fs::write(&target_path, pretty)
            .await
            .with_context(|| format!("writing builtin template to {}", target_path.display()))?;
        Ok(())
    }
}

#[async_trait]
impl SurfaceTemplateStore for FileSystemSurfaceTemplateStore {
    async fn list_all(&self) -> Result<Vec<SurfaceTemplate>> {
        self.storage.list_all().await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<SurfaceTemplate>> {
        self.storage.get(id).await
    }

    async fn save(
        &self,
        template: &SurfaceTemplate,
    ) -> Result<()> {
        if template.id.is_empty() {
            warn!("Refusing to save surface template with empty id");
            return Err(anyhow::anyhow!("surface template id must not be empty"));
        }
        self.storage
            .save(template)
            .await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Write `count` minimal `.json` files into `seed_dir` and return
    /// the list of template ids that were written.
    async fn write_seed_files(
        seed_dir: &Path,
        count: usize,
    ) -> Vec<String> {
        tokio::fs::create_dir_all(seed_dir)
            .await
            .unwrap();
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let id = format!("builtin-seed-{}", i);
            let body = serde_json::json!({
                "id": id,
                "name": format!("Seed {}", i),
                "description": "",
                "tags": [],
                "author": "system",
                "builtin": true,
                "items": []
            });
            let path = seed_dir.join(format!("seed_{}.json", i));
            tokio::fs::write(&path, serde_json::to_string_pretty(&body).unwrap())
                .await
                .unwrap();
            ids.push(id);
        }
        ids
    }

    #[tokio::test]
    async fn seeds_all_json_files_on_first_start() {
        let storage = TempDir::new().unwrap();
        let seed = TempDir::new().unwrap();
        let ids = write_seed_files(seed.path(), 3).await;

        let store = FileSystemSurfaceTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .expect("store init");

        let templates = store
            .list_all()
            .await
            .unwrap();
        assert_eq!(templates.len(), ids.len(), "all seed files should be seeded on first start");
        for id in &ids {
            let found = templates
                .iter()
                .find(|t| &t.id == id)
                .unwrap_or_else(|| panic!("missing seeded builtin: {}", id));
            assert!(found.builtin, "{} should be flagged builtin", id);
            assert_eq!(found.author, "system");
        }
    }

    #[tokio::test]
    async fn ignores_non_json_files_in_seed_dir() {
        let storage = TempDir::new().unwrap();
        let seed = TempDir::new().unwrap();
        write_seed_files(seed.path(), 1).await;
        // Drop a sibling file with a different extension that should
        // be skipped by the glob.
        tokio::fs::write(seed.path().join("notes.txt"), "ignored")
            .await
            .unwrap();

        let store = FileSystemSurfaceTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .unwrap();

        let templates = store
            .list_all()
            .await
            .unwrap();
        assert_eq!(templates.len(), 1);
    }

    #[tokio::test]
    async fn missing_seed_dir_is_not_an_error() {
        let storage = TempDir::new().unwrap();
        let missing_seed = storage
            .path()
            .join("does-not-exist");

        let store = FileSystemSurfaceTemplateStore::new(storage.path().to_path_buf(), Some(missing_seed))
            .await
            .expect("missing seed dir should be tolerated");

        let templates = store
            .list_all()
            .await
            .unwrap();
        assert!(templates.is_empty());
    }

    #[tokio::test]
    async fn preserves_admin_owned_builtin_when_builtin_flag_cleared() {
        let storage = TempDir::new().unwrap();
        let seed = TempDir::new().unwrap();
        let ids = write_seed_files(seed.path(), 1).await;
        let id = &ids[0];

        // First boot — seed.
        FileSystemSurfaceTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .unwrap();

        // Admin adopts the builtin: rename + clear the builtin flag.
        let path = storage
            .path()
            .join(format!("{}.json", id));
        let mut tpl: SurfaceTemplate = serde_json::from_str(
            &tokio::fs::read_to_string(&path)
                .await
                .unwrap(),
        )
        .unwrap();
        tpl.name = "Edited Name".to_string();
        tpl.builtin = false;
        tokio::fs::write(&path, serde_json::to_string_pretty(&tpl).unwrap())
            .await
            .unwrap();

        // Second boot — admin-owned file (builtin: false) must survive.
        let store = FileSystemSurfaceTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .unwrap();
        let reloaded = store
            .get(id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.name, "Edited Name");
        assert!(!reloaded.builtin);
    }

    #[tokio::test]
    async fn reseeds_stale_builtin_still_flagged_builtin() {
        let storage = TempDir::new().unwrap();
        let seed = TempDir::new().unwrap();
        let ids = write_seed_files(seed.path(), 1).await;
        let id = &ids[0];

        // First boot — seed.
        FileSystemSurfaceTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .unwrap();

        // Simulate an out-of-date seeded builtin: keep `builtin: true`
        // but mutate the name. The seeder must overwrite it on next
        // boot because the file still claims to be a builtin.
        let path = storage
            .path()
            .join(format!("{}.json", id));
        let mut tpl: SurfaceTemplate = serde_json::from_str(
            &tokio::fs::read_to_string(&path)
                .await
                .unwrap(),
        )
        .unwrap();
        let canonical_name = tpl.name.clone();
        tpl.name = "Stale Drift".to_string();
        assert!(tpl.builtin);
        tokio::fs::write(&path, serde_json::to_string_pretty(&tpl).unwrap())
            .await
            .unwrap();

        // Second boot — stale builtin should be replaced.
        let store = FileSystemSurfaceTemplateStore::new(storage.path().to_path_buf(), Some(seed.path().to_path_buf()))
            .await
            .unwrap();
        let reloaded = store
            .get(id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.name, canonical_name);
        assert!(reloaded.builtin);
    }

    #[tokio::test]
    async fn save_and_delete_user_template() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemSurfaceTemplateStore::new(dir.path().to_path_buf(), None)
            .await
            .unwrap();

        let user_tpl = SurfaceTemplate {
            schema: None,
            id: "user-my-template".to_string(),
            tenant_id: None,
            name: "My Template".to_string(),
            kind: crate::surface_templates::types::TemplateKind::Partial,
            description: String::new(),
            details: None,
            starter_hint: None,
            icon: None,
            tags: vec![],
            author: "did:example:alice".to_string(),
            created_at: None,
            updated_at: None,
            builtin: false,
            sort_priority: i32::MAX,
            items: vec![],
            surface: None,
        };
        store
            .save(&user_tpl)
            .await
            .unwrap();
        assert!(
            store
                .get("user-my-template")
                .await
                .unwrap()
                .is_some()
        );

        store
            .delete("user-my-template")
            .await
            .unwrap();
        assert!(
            store
                .get("user-my-template")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_empty_id_on_save() {
        let dir = TempDir::new().unwrap();
        let store = FileSystemSurfaceTemplateStore::new(dir.path().to_path_buf(), None)
            .await
            .unwrap();
        let bad = SurfaceTemplate {
            schema: None,
            id: String::new(),
            tenant_id: None,
            name: "x".to_string(),
            kind: crate::surface_templates::types::TemplateKind::Partial,
            description: String::new(),
            details: None,
            starter_hint: None,
            icon: None,
            tags: vec![],
            author: String::new(),
            created_at: None,
            updated_at: None,
            builtin: false,
            sort_priority: i32::MAX,
            items: vec![],
            surface: None,
        };
        assert!(
            store
                .save(&bad)
                .await
                .is_err()
        );
    }
}
