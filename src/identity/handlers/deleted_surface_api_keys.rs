//! Revokes the API keys of surfaces that no longer exist: at a surface's delete, and when the
//! gateway becomes Active for the keys of surfaces deleted before deletes revoked them.

use std::collections::{BTreeMap, HashSet};
use std::path::Path;

use anyhow::Context as _;
use tracing::{debug, error, info, warn};

use crate::api_keys::ApiKeyStatus;
use crate::api_keys::store::ApiKeyStore;
use crate::config::agent_surface::AgentSurface;
use crate::identity::state::IdentityApiState;
use crate::tenancy::ResourceKind;

/// The actor a deleted surface's API keys are revoked under.
const SURFACE_DELETE_ACTOR: &str = "surface-delete";

/// Revokes every active API key of the surface `owner`, read from its key folder on disk so keys
/// another node created are revoked too, and returns how many it revoked. The keys are kept, so
/// the surface id still owns them and cannot be taken by a new surface. A key record in the folder
/// naming another owner is left alone, and a key revoked meanwhile is not counted. A folder that
/// cannot be read, or a key that cannot be revoked, is logged.
pub(crate) async fn revoke_api_keys_of(
    api_keys: &dyn ApiKeyStore,
    owner: &str,
) -> usize {
    let keys = match api_keys
        .list_from_disk(owner)
        .await
    {
        Ok(keys) => keys,
        Err(error) => {
            error!(surface = %owner, %error, "Could not read the API keys of a deleted surface to revoke them");
            return 0;
        }
    };
    let mut revoked = 0;
    for key in keys
        .into_iter()
        .filter(|key| key.agent_id == owner && key.status == ApiKeyStatus::Active)
    {
        match api_keys
            .revoke(owner, &key.key_id, SURFACE_DELETE_ACTOR)
            .await
        {
            Ok(()) => {
                crate::identity::provider_key_gate::gate().key_changed(&key.key_id);
                revoked += 1;
            }
            Err(crate::api_keys::ApiKeyError::AlreadyRevoked { .. }) => {
                debug!(surface = %owner, key_id = %key.key_id, "An API key of a deleted surface was revoked meanwhile")
            }
            Err(error) => {
                error!(surface = %owner, key_id = %key.key_id, %error, "Could not revoke an API key of a deleted surface")
            }
        }
    }
    revoked
}

/// Revokes every active API key whose owner is neither a surface of any source the gateway
/// serves nor named by an API Key Provider of one; see [`revoke_api_keys_of_unknown_owners`].
pub(crate) async fn revoke_api_keys_of_deleted_surfaces(state: &IdentityApiState) -> Option<usize> {
    let api_keys = state
        .api_key_store
        .as_deref()?;
    let recent = chrono::TimeDelta::from_std(crate::identity::provider_key_gate::missing_key_recheck())
        .unwrap_or(chrono::TimeDelta::MAX);
    revoke_api_keys_of_unknown_owners(crate::server::mode::current_mode, api_keys, recent, known_api_key_owners(state))
        .await
}

/// Revokes every active API key whose owner is not in `known_owners`, which is read after the
/// keys so a surface created meanwhile, whose keys can only follow it, is in it. An owner whose
/// newest key was created within `recent` is left alone, since its surface may exist on another
/// node and not be visible here yet. Revokes nothing and returns `None` when `mode` is `Standby`,
/// or when the keys or the owners cannot all be read; stops at the owner before which `mode` is
/// no longer `Active`. Returns how many it revoked; a key already revoked is not counted, so a
/// second run revokes none.
async fn revoke_api_keys_of_unknown_owners(
    mode: impl Fn() -> crate::server::mode::ServerMode,
    api_keys: &dyn ApiKeyStore,
    recent: chrono::TimeDelta,
    known_owners: impl std::future::Future<Output = anyhow::Result<HashSet<String>>>,
) -> Option<usize> {
    use crate::server::mode::ServerMode::Active;
    if mode() != Active {
        debug!("Not revoking the API keys of deleted surfaces on a Standby node");
        return None;
    }
    let mut owners: BTreeMap<String, (bool, chrono::DateTime<chrono::Utc>)> = BTreeMap::new();
    match api_keys
        .list_all_complete()
        .await
    {
        Ok(keys) => {
            for key in keys {
                let (active, newest) = owners
                    .entry(key.agent_id)
                    .or_insert((false, key.created_at));
                *active |= key.status == ApiKeyStatus::Active;
                *newest = (*newest).max(key.created_at);
            }
        }
        Err(error) => {
            warn!(%error, "Skipped revoking the API keys of deleted surfaces: the API keys could not all be read");
            return None;
        }
    }
    owners.retain(|_, (active, _)| *active);
    let known = if owners.is_empty() {
        HashSet::new()
    } else {
        match known_owners.await {
            Ok(known) => known,
            Err(error) => {
                warn!(
                    "Skipped revoking the API keys of deleted surfaces: the surfaces could not all be read: {error:#}"
                );
                return None;
            }
        }
    };
    let created_before = chrono::Utc::now()
        .checked_sub_signed(recent)
        .unwrap_or(chrono::DateTime::<chrono::Utc>::MIN_UTC);
    let mut revoked = 0;
    let mut deferred = 0;
    for (owner, (_, newest)) in owners
        .iter()
        .filter(|(owner, _)| !known.contains(owner.as_str()))
    {
        if *newest > created_before {
            debug!(surface = %owner, "Not revoking the API keys of a surface whose newest key was just created");
            deferred += 1;
            continue;
        }
        if mode() != Active {
            warn!(revoked, "Stopped revoking the API keys of deleted surfaces: the node is no longer Active");
            return Some(revoked);
        }
        revoked += revoke_api_keys_of(api_keys, owner).await;
    }
    info!(revoked, deferred, "Revoked the API keys of surfaces that no longer exist");
    Some(revoked)
}

/// [`known_owners`] of the agent surface folder, the agent surface store, the static gateway
/// configuration and the configured source.
async fn known_api_key_owners(state: &IdentityApiState) -> anyhow::Result<HashSet<String>> {
    let store = state
        .agent_surface_store
        .as_deref()
        .context("the agent surface store is not configured")?;
    let stored = crate::surfaces::AgentSurfaceStore::list_all(store).await?;
    known_owners(
        Path::new(
            &state
                .bootstrap_config
                .storage_paths
                .agent_surfaces,
        ),
        &[&stored, &state.config.surfaces],
        &state
            .bootstrap_config
            .channel_config_source,
        super::config::load_dynamodb_config(&state.bootstrap_config),
    )
    .await
}

/// Every id that may own API keys: each surface in `surface_folder`, by file name so a file that
/// cannot be read counts, each surface of `served` and, for the `dynamodb` `source`, of the
/// configuration `dynamodb` reads, and each key owner an API Key Provider of one of those surfaces
/// names. An error when any of them cannot be read, when `source` is neither `local` nor
/// `dynamodb`, or when no surface is found at all, as when the folder is not the one the surfaces
/// are stored in.
async fn known_owners(
    surface_folder: &Path,
    served: &[&[AgentSurface]],
    source: &str,
    dynamodb: impl std::future::Future<Output = anyhow::Result<crate::config::GatewayConfig>>,
) -> anyhow::Result<HashSet<String>> {
    let mut surfaces = stored_surface_ids(surface_folder)
        .await
        .with_context(|| format!("the agent surface folder {} could not be read", surface_folder.display()))?;
    let loaded;
    let mut lists = served.to_vec();
    match source {
        "local" => {}
        "dynamodb" => {
            loaded = dynamodb.await?;
            lists.push(&loaded.surfaces);
        }
        other => anyhow::bail!("the '{other}' configuration source cannot be read"),
    }
    let mut known = HashSet::new();
    for list in lists {
        surfaces.extend(
            list.iter()
                .map(|surface| surface.surface_id.clone()),
        );
        add_provider_owners(&mut known, list)?;
    }
    surfaces.remove("");
    if surfaces.is_empty() {
        anyhow::bail!(
            "no surface was found in the agent surface folder {}, the surface store, the static configuration \
             or the configuration source",
            surface_folder.display()
        );
    }
    known.extend(surfaces);
    Ok(known)
}

/// The ids of the surface files in `directory`, readable or not.
async fn stored_surface_ids(directory: &Path) -> std::io::Result<HashSet<String>> {
    let mut ids = HashSet::new();
    let mut entries = tokio::fs::read_dir(directory).await?;
    while let Some(entry) = entries.next_entry().await? {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(id) = name
            .strip_suffix(".json.enc")
            .or_else(|| name.strip_suffix(".json"))
        {
            ids.insert(id.to_string());
        }
    }
    Ok(ids)
}

/// Adds every key owner the API Key Providers of `surfaces` name, in the base and every variant;
/// an error when a surface's variants cannot be resolved.
fn add_provider_owners(
    known: &mut HashSet<String>,
    surfaces: &[AgentSurface],
) -> anyhow::Result<()> {
    for surface in surfaces {
        let references = super::surface_tenancy::collect_surface_reference_keys(surface).map_err(|error| {
            anyhow::anyhow!("the references of surface '{}' could not be read: {error:?}", surface.surface_id)
        })?;
        known.extend(
            references
                .into_iter()
                .filter(|reference| reference.kind == ResourceKind::ApiKeys)
                .map(|reference| reference.id),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_keys::FileSystemApiKeyStore;
    use crate::server::mode::ServerMode::{Active, Standby};

    async fn store(directory: &tempfile::TempDir) -> FileSystemApiKeyStore {
        FileSystemApiKeyStore::new(
            directory
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap()
    }

    async fn create(
        store: &FileSystemApiKeyStore,
        owner: &str,
    ) -> String {
        store
            .create(owner, "client", None, "test")
            .await
            .unwrap()
            .key_id
    }

    async fn status(
        store: &FileSystemApiKeyStore,
        owner: &str,
        key_id: &str,
    ) -> (ApiKeyStatus, Option<chrono::DateTime<chrono::Utc>>) {
        let record = store
            .get_record(owner, key_id)
            .await
            .unwrap()
            .unwrap();
        (record.status, record.revoked_at)
    }

    /// No key counts as just created.
    const NOW: chrono::TimeDelta = chrono::TimeDelta::zero();

    fn known(ids: &[&str]) -> impl std::future::Future<Output = anyhow::Result<HashSet<String>>> {
        let ids = ids
            .iter()
            .map(|id| id.to_string())
            .collect();
        async move { Ok(ids) }
    }

    #[derive(Clone, Default)]
    struct Logs(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Logs {
        fn write(
            &mut self,
            buf: &[u8],
        ) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap()
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
        type Writer = Logs;

        fn make_writer(&'a self) -> Logs {
            self.clone()
        }
    }

    #[tokio::test]
    async fn only_the_active_keys_of_unknown_owners_are_revoked_under_the_surface_delete_actor() {
        let directory = tempfile::TempDir::new().unwrap();
        let keys = store(&directory).await;
        let orphan = create(&keys, "gone-surface").await;
        let live = create(&keys, "live-surface").await;
        let earlier = create(&keys, "gone-earlier").await;
        keys.revoke("gone-earlier", &earlier, "test")
            .await
            .unwrap();
        let earlier_before = status(&keys, "gone-earlier", &earlier).await;
        let logs = Logs::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let _logging = tracing::subscriber::set_default(subscriber);

        let first = revoke_api_keys_of_unknown_owners(|| Active, &keys, NOW, known(&["live-surface"])).await;
        let second = revoke_api_keys_of_unknown_owners(|| Active, &keys, NOW, known(&["live-surface"])).await;

        assert_eq!(first, Some(1));
        assert_eq!(second, Some(0), "a second run revokes nothing");
        assert_eq!(
            status(&keys, "gone-surface", &orphan)
                .await
                .0,
            ApiKeyStatus::Revoked
        );
        assert_eq!(status(&keys, "live-surface", &live).await, (ApiKeyStatus::Active, None));
        assert_eq!(
            status(&keys, "gone-earlier", &earlier).await,
            earlier_before,
            "an already revoked key is untouched"
        );
        let logged = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
        let revocations: Vec<&str> = logged
            .lines()
            .filter(|line| line.contains("Revoked API key"))
            .collect();
        assert_eq!(revocations.len(), 1, "{logged}");
        assert!(revocations[0].contains(&format!("key_id={orphan}")), "{logged}");
        assert!(revocations[0].contains("actor=surface-delete"), "{logged}");
        assert!(logged.contains("revoked=1"), "{logged}");
    }

    #[tokio::test]
    async fn nothing_is_revoked_when_the_owners_cannot_all_be_read() {
        let directory = tempfile::TempDir::new().unwrap();
        let keys = store(&directory).await;
        let key = create(&keys, "unknown-surface").await;

        let swept = revoke_api_keys_of_unknown_owners(|| Active, &keys, NOW, async {
            anyhow::bail!("the surface folder could not be read")
        })
        .await;

        assert_eq!(swept, None);
        assert_eq!(status(&keys, "unknown-surface", &key).await, (ApiKeyStatus::Active, None));
    }

    #[tokio::test]
    async fn nothing_is_revoked_when_a_key_folder_cannot_be_read() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::TempDir::new().unwrap();
        let readable = create(&store(&directory).await, "readable-orphan").await;
        create(&store(&directory).await, "locked-orphan").await;
        let locked = directory
            .path()
            .join("locked-orphan");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            // Running as root: no read fails.
            return;
        }
        let keys = store(&directory).await;

        let swept = revoke_api_keys_of_unknown_owners(|| Active, &keys, NOW, known(&[])).await;

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(swept, None);
        assert_eq!(status(&keys, "readable-orphan", &readable).await, (ApiKeyStatus::Active, None));
    }

    #[tokio::test]
    async fn a_deleted_surfaces_keys_are_revoked_from_disk_including_one_another_node_created() {
        let directory = tempfile::TempDir::new().unwrap();
        let keys = store(&directory).await;
        let own = create(&keys, "deleted-surface").await;
        let other_node = create(&store(&directory).await, "deleted-surface").await;
        let neighbour = create(&keys, "live-surface").await;

        let revoked = revoke_api_keys_of(&keys, "deleted-surface").await;

        assert_eq!(revoked, 2);
        let fresh = store(&directory).await;
        for key_id in [&own, &other_node] {
            assert_eq!(
                status(&fresh, "deleted-surface", key_id)
                    .await
                    .0,
                ApiKeyStatus::Revoked,
                "{key_id}"
            );
        }
        assert_eq!(status(&fresh, "live-surface", &neighbour).await, (ApiKeyStatus::Active, None));
        assert_eq!(revoke_api_keys_of(&keys, "deleted-surface").await, 0, "a second delete revokes nothing");
    }

    #[tokio::test]
    async fn a_deleted_surface_whose_key_folder_cannot_be_read_revokes_nothing() {
        use std::os::unix::fs::PermissionsExt as _;
        let directory = tempfile::TempDir::new().unwrap();
        let keys = store(&directory).await;
        let key = create(&keys, "locked-surface").await;
        let locked = directory
            .path()
            .join("locked-surface");
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        if std::fs::read_dir(&locked).is_ok() {
            // Running as root: no read fails.
            return;
        }

        let revoked = revoke_api_keys_of(&keys, "locked-surface").await;

        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(revoked, 0);
        assert_eq!(status(&store(&directory).await, "locked-surface", &key).await, (ApiKeyStatus::Active, None));
    }

    #[tokio::test]
    async fn a_standby_node_revokes_nothing_until_it_becomes_active() {
        let directory = tempfile::TempDir::new().unwrap();
        let keys = store(&directory).await;
        let key = create(&keys, "gone-surface").await;

        let on_standby = revoke_api_keys_of_unknown_owners(|| Standby, &keys, NOW, known(&[])).await;
        let standby_status = status(&keys, "gone-surface", &key).await;
        let on_activation = revoke_api_keys_of_unknown_owners(|| Active, &keys, NOW, known(&[])).await;

        assert_eq!(on_standby, None);
        assert_eq!(standby_status, (ApiKeyStatus::Active, None));
        assert_eq!(on_activation, Some(1));
        assert_eq!(
            status(&keys, "gone-surface", &key)
                .await
                .0,
            ApiKeyStatus::Revoked
        );
    }

    #[tokio::test]
    async fn every_surface_file_counts_whether_or_not_it_can_be_read() {
        let directory = tempfile::TempDir::new().unwrap();
        for (name, content) in [
            ("readable.json", "{}"),
            ("unparseable.json", "{\"surface_id\": }"),
            ("undecryptable.json.enc", "not an envelope"),
            ("notes.txt", ""),
        ] {
            std::fs::write(directory.path().join(name), content).unwrap();
        }

        let mut ids: Vec<String> = stored_surface_ids(directory.path())
            .await
            .unwrap()
            .into_iter()
            .collect();
        ids.sort();

        assert_eq!(ids, ["readable", "undecryptable", "unparseable"]);
        assert!(
            stored_surface_ids(
                &directory
                    .path()
                    .join("missing")
            )
            .await
            .is_err(),
            "a folder that cannot be read is an error"
        );
    }

    #[tokio::test]
    async fn the_keys_of_an_owner_whose_newest_key_was_just_created_are_kept() {
        let directory = tempfile::TempDir::new().unwrap();
        let keys = store(&directory).await;
        let fresh = create(&keys, "created-on-another-node").await;

        let swept =
            revoke_api_keys_of_unknown_owners(|| Active, &keys, chrono::TimeDelta::seconds(30), known(&[])).await;

        assert_eq!(swept, Some(0));
        assert_eq!(status(&keys, "created-on-another-node", &fresh).await, (ApiKeyStatus::Active, None));
    }

    #[tokio::test]
    async fn the_sweep_stops_once_the_node_is_no_longer_active() {
        let directory = tempfile::TempDir::new().unwrap();
        let keys = store(&directory).await;
        let first = create(&keys, "gone-a").await;
        let second = create(&keys, "gone-b").await;
        let checks = std::cell::Cell::new(0);
        let mode = || {
            checks.set(checks.get() + 1);
            if checks.get() <= 2 {
                Active
            } else {
                Standby
            }
        };

        let swept = revoke_api_keys_of_unknown_owners(mode, &keys, NOW, known(&[])).await;

        assert_eq!(swept, Some(1));
        assert_eq!(
            status(&keys, "gone-a", &first)
                .await
                .0,
            ApiKeyStatus::Revoked
        );
        assert_eq!(status(&keys, "gone-b", &second).await, (ApiKeyStatus::Active, None));
    }

    fn surface(
        surface_id: &str,
        provider_owner: &str,
    ) -> AgentSurface {
        let provider = |agent_id: &str| {
            serde_json::json!({"type": "api_key_provider", "agent_id": agent_id,
                               "extraction": {"source": "http_header", "field": "x-api-key"}})
        };
        serde_json::from_value(serde_json::json!({
            "surface_id": surface_id,
            "name": "served-surface",
            "access_point": {"listen_address": "http://localhost:1", "route": "/r", "protocol": "a2a",
                             "caller_authentication": {"methods": [provider(provider_owner)]}},
            "target": {"endpoint": "http://127.0.0.1:9/"},
            "transit": {"points": [{"alias": "p", "target_endpoint": "https://partner.example/a2a",
                                    "protocol": "a2a", "source_auth": provider("transit-point-owner")}]}
        }))
        .unwrap()
    }

    async fn unread() -> anyhow::Result<crate::config::GatewayConfig> {
        panic!("the DynamoDB source is read only for the dynamodb source")
    }

    fn sorted(known: HashSet<String>) -> Vec<String> {
        let mut known: Vec<String> = known.into_iter().collect();
        known.sort();
        known
    }

    #[tokio::test]
    async fn surface_files_static_config_surfaces_and_the_key_owners_their_providers_name_are_known() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::write(
            directory
                .path()
                .join("stored-surface.json"),
            "{}",
        )
        .unwrap();
        let configured = [surface("configured-surface", "access-point-owner")];

        let known = known_owners(directory.path(), &[&[], &configured], "local", unread())
            .await
            .unwrap();

        assert_eq!(
            sorted(known),
            ["access-point-owner", "configured-surface", "stored-surface", "transit-point-owner"]
        );
    }

    #[tokio::test]
    async fn no_owner_is_known_when_no_surface_is_found_anywhere() {
        let directory = tempfile::TempDir::new().unwrap();
        let unnamed = [surface("", "access-point-owner")];

        let error = known_owners(directory.path(), &[&[], &unnamed], "local", unread())
            .await
            .unwrap_err()
            .to_string();

        assert!(error.contains("no surface was found"), "{error}");
        assert!(
            error.contains(
                &directory
                    .path()
                    .display()
                    .to_string()
            ),
            "{error}"
        );
    }

    #[tokio::test]
    async fn no_owner_is_known_for_a_source_that_cannot_be_read() {
        let directory = tempfile::TempDir::new().unwrap();
        std::fs::write(
            directory
                .path()
                .join("stored-surface.json"),
            "{}",
        )
        .unwrap();

        let error = known_owners(directory.path(), &[], "file", unread())
            .await
            .unwrap_err()
            .to_string();
        let dynamodb = known_owners(directory.path(), &[], "dynamodb", async {
            anyhow::bail!("DynamoDB table name not specified")
        })
        .await;

        assert_eq!(error, "the 'file' configuration source cannot be read");
        assert!(dynamodb.is_err());
    }
}
