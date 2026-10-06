use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use tokio::fs;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::auth_manager::pat::{PatAuthenticator, PatPrincipal};
use crate::auth_manager::resource_scope::{self, CompiledResourceScope, RequiredHeader};

use super::{AccessToken, MAX_DELEGATION_DEPTH, TOKEN_PREFIX};

pub(crate) fn hash_secret(token: &str) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

fn constant_time_eq(
    left: &str,
    right: &str,
) -> bool {
    use subtle::ConstantTimeEq;

    left.len() == right.len()
        && bool::from(
            left.as_bytes()
                .ct_eq(right.as_bytes()),
        )
}

const LAST_USED_PERSIST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// `Inactive` covers the token and every ancestor; `Stale` means another
/// rotation committed after the caller read `expected_generation`.
#[derive(Debug)]
pub enum RotateOutcome {
    Rotated(Box<AccessToken>),
    NotFound,
    Inactive,
    Stale,
}

pub struct FsAccessTokenStore {
    dir: PathBuf,
    cache: Arc<DashMap<String, AccessToken>>,
    hash_index: Arc<DashMap<String, String>>,
    compiled_scopes: Arc<DashMap<String, Arc<CompiledResourceScope>>>,
    last_persist: Arc<DashMap<String, std::time::Instant>>,
    mutation_locks: Arc<DashMap<String, Arc<Mutex<()>>>>,
    delegation_lock: Arc<Mutex<()>>,
}

impl FsAccessTokenStore {
    pub async fn new(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).await?;
        let cache = Arc::new(DashMap::new());
        let hash_index = Arc::new(DashMap::new());

        let mut entries = fs::read_dir(&dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("json")
            {
                continue;
            }
            match fs::read(&path).await {
                Ok(bytes) => match serde_json::from_slice::<AccessToken>(&bytes) {
                    Ok(token) => {
                        if token.is_active(Utc::now()) {
                            hash_index.insert(token.token_hash.clone(), token.id.clone());
                        }
                        cache.insert(token.id.clone(), token);
                    }
                    Err(error) => warn!(?path, %error, "Skipping unreadable access-token record"),
                },
                Err(error) => warn!(?path, %error, "Failed to read access-token record"),
            }
        }

        Ok(Self {
            dir,
            cache,
            hash_index,
            compiled_scopes: Arc::new(DashMap::new()),
            last_persist: Arc::new(DashMap::new()),
            mutation_locks: Arc::new(DashMap::new()),
            delegation_lock: Arc::new(Mutex::new(())),
        })
    }

    fn mutation_lock(
        &self,
        id: &str,
    ) -> Arc<Mutex<()>> {
        self.mutation_locks
            .entry(id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn path_for(
        &self,
        id: &str,
    ) -> PathBuf {
        self.dir
            .join(format!("{id}.json"))
    }

    async fn persist(
        &self,
        token: &AccessToken,
    ) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(token)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        let target = self.path_for(&token.id);
        let temporary = target.with_extension(format!("{}.tmp", uuid::Uuid::new_v4().as_simple()));
        let written = Self::write_private_file(&temporary, &bytes).await;
        let renamed = match written {
            Ok(()) => fs::rename(&temporary, &target).await,
            Err(error) => Err(error),
        };
        if renamed.is_err() {
            let _ = fs::remove_file(&temporary).await;
        }
        renamed
    }

    /// Writes `bytes` to `path` readable only by the owner (mode 0o600 on unix)
    /// and flushed to disk, so a rename over the target never exposes a partial file.
    async fn write_private_file(
        path: &Path,
        bytes: &[u8],
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        let mut options = fs::OpenOptions::new();
        options
            .write(true)
            .create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(path).await?;
        file.write_all(bytes).await?;
        file.sync_all().await
    }

    pub async fn create(
        &self,
        token: AccessToken,
    ) -> std::io::Result<()> {
        let _delegation_guard = self
            .delegation_lock
            .lock()
            .await;
        if token.delegation_depth > MAX_DELEGATION_DEPTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "access-token delegation depth exceeds the configured maximum",
            ));
        }
        match token
            .parent_token_id
            .as_deref()
        {
            Some(parent_id) => {
                let parent = self
                    .get(parent_id)
                    .filter(|parent| {
                        let now = Utc::now();
                        parent.is_active(now) && self.lineage_is_active(parent, now)
                    })
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "parent access token is no longer active",
                        )
                    })?;
                if token.delegation_depth
                    != parent
                        .delegation_depth
                        .saturating_add(1)
                    || (!parent.scopes.is_empty()
                        && (token.scopes.is_empty()
                            || token
                                .scopes
                                .iter()
                                .any(|scope| !parent.scopes.contains(scope))))
                {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "access-token delegation does not match its parent authority",
                    ));
                }
            }
            None if token.delegation_depth != 0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "root access token must have delegation depth zero",
                ));
            }
            None => {}
        }
        self.persist(&token).await?;
        self.hash_index
            .insert(token.token_hash.clone(), token.id.clone());
        self.cache
            .insert(token.id.clone(), token);
        Ok(())
    }

    pub fn list(&self) -> Vec<AccessToken> {
        self.cache
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get(
        &self,
        id: &str,
    ) -> Option<AccessToken> {
        self.cache
            .get(id)
            .map(|entry| entry.value().clone())
    }

    pub async fn revoke(
        &self,
        id: &str,
    ) -> std::io::Result<Option<AccessToken>> {
        let _delegation_guard = self
            .delegation_lock
            .lock()
            .await;
        let Some(root) = self.get(id) else {
            return Ok(None);
        };
        let token_ids = self.descendants_including(id);
        for token_id in token_ids {
            self.revoke_one(&token_id)
                .await?;
        }
        Ok(Some(self.get(id).unwrap_or(root)))
    }

    fn descendants_including(
        &self,
        root_id: &str,
    ) -> Vec<String> {
        let mut token_ids = vec![root_id.to_string()];
        let mut index = 0;
        while index < token_ids.len() {
            let parent_id = token_ids[index].clone();
            for entry in self.cache.iter() {
                if entry
                    .parent_token_id
                    .as_deref()
                    == Some(parent_id.as_str())
                    && !token_ids.contains(entry.key())
                {
                    token_ids.push(entry.key().clone());
                }
            }
            index += 1;
        }
        token_ids
    }

    pub fn controls(
        &self,
        controller_id: &str,
        target_id: &str,
    ) -> bool {
        let mut current_id = target_id.to_string();
        let mut visited = std::collections::HashSet::new();
        loop {
            if current_id == controller_id {
                return true;
            }
            if !visited.insert(current_id.clone()) {
                return false;
            }
            let Some(current) = self.get(&current_id) else {
                return false;
            };
            let Some(parent_id) = current.parent_token_id else {
                return false;
            };
            current_id = parent_id;
        }
    }

    async fn revoke_one(
        &self,
        id: &str,
    ) -> std::io::Result<()> {
        let mutation_lock = self.mutation_lock(id);
        let _guard = mutation_lock.lock().await;
        let Some(mut token) = self.get(id) else {
            return Ok(());
        };
        if token.revoked_at.is_none() {
            token.revoked_at = Some(Utc::now());
            self.persist(&token).await?;
            self.cache
                .insert(token.id.clone(), token.clone());
            self.compiled_scopes
                .remove(id);
            self.hash_index
                .remove(&token.token_hash);
            self.last_persist.remove(id);
        }
        Ok(())
    }

    pub async fn update(
        &self,
        id: &str,
        name: String,
        description: String,
        scopes: Vec<String>,
        resource_pattern: Option<String>,
        required_headers: Vec<RequiredHeader>,
    ) -> std::io::Result<Option<AccessToken>> {
        let _delegation_guard = self
            .delegation_lock
            .lock()
            .await;
        let mutation_lock = self.mutation_lock(id);
        let _guard = mutation_lock.lock().await;
        let Some(mut token) = self.get(id) else {
            return Ok(None);
        };
        token.name = name;
        token.description = description;
        token.scopes = scopes;
        token.resource_pattern = resource_pattern;
        token.required_headers = required_headers;
        self.persist(&token).await?;
        self.cache
            .insert(token.id.clone(), token.clone());
        self.compiled_scopes
            .remove(id);
        Ok(Some(token))
    }

    /// Holds the delegation lock so the lineage check cannot race an ancestor revoke.
    pub async fn rotate(
        &self,
        id: &str,
        actor: &str,
        expected_generation: u32,
        new_hash: String,
    ) -> std::io::Result<RotateOutcome> {
        let _delegation_guard = self
            .delegation_lock
            .lock()
            .await;
        let mutation_lock = self.mutation_lock(id);
        let _guard = mutation_lock.lock().await;
        let Some(mut token) = self.get(id) else {
            return Ok(RotateOutcome::NotFound);
        };
        let now = Utc::now();
        if !token.is_active(now) || !self.lineage_is_active(&token, now) {
            return Ok(RotateOutcome::Inactive);
        }
        if token.rotation_generation != expected_generation {
            return Ok(RotateOutcome::Stale);
        }
        let old_hash = std::mem::replace(&mut token.token_hash, new_hash);
        token.rotation_generation = token
            .rotation_generation
            .saturating_add(1);
        token.rotated_at = Some(now);
        token.rotated_by = Some(actor.to_string());
        token.last_used_at = None;
        self.persist(&token).await?;
        self.cache
            .insert(token.id.clone(), token.clone());
        self.hash_index
            .remove(&old_hash);
        self.hash_index
            .insert(token.token_hash.clone(), token.id.clone());
        self.last_persist.remove(id);
        Ok(RotateOutcome::Rotated(Box::new(token)))
    }

    async fn touch_last_used(
        &self,
        id: &str,
    ) {
        let mutation_lock = self.mutation_lock(id);
        let _guard = mutation_lock.lock().await;
        let now = std::time::Instant::now();
        if let Some(previous) = self.last_persist.get(id)
            && now.duration_since(*previous.value()) < LAST_USED_PERSIST_INTERVAL
        {
            return;
        }
        self.last_persist
            .insert(id.to_string(), now);
        if let Some(mut token) = self.get(id) {
            if !token.is_active(Utc::now()) {
                return;
            }
            token.last_used_at = Some(Utc::now());
            if let Err(error) = self.persist(&token).await {
                debug!(token_id = id, %error, "Failed to persist access-token usage time");
            }
            self.cache
                .insert(token.id.clone(), token);
        }
    }

    fn find_by_secret(
        &self,
        token: &str,
    ) -> Option<AccessToken> {
        let presented = hash_secret(token);
        let id = self
            .hash_index
            .get(&presented)
            .map(|entry| entry.value().clone())?;
        let record = self.get(&id)?;
        constant_time_eq(&record.token_hash, &presented).then_some(record)
    }

    fn lineage_is_active(
        &self,
        record: &AccessToken,
        now: chrono::DateTime<Utc>,
    ) -> bool {
        if record.delegation_depth > MAX_DELEGATION_DEPTH {
            return false;
        }
        let mut current = record.clone();
        let mut visited = std::collections::HashSet::new();
        visited.insert(current.id.clone());
        loop {
            match current
                .parent_token_id
                .as_deref()
            {
                None => return current.delegation_depth == 0,
                Some(parent_id) => {
                    if !visited.insert(parent_id.to_string()) {
                        return false;
                    }
                    let Some(parent) = self.get(parent_id) else {
                        return false;
                    };
                    if !parent.is_active(now)
                        || current.delegation_depth
                            != parent
                                .delegation_depth
                                .saturating_add(1)
                        || (!parent.scopes.is_empty()
                            && (current.scopes.is_empty()
                                || current
                                    .scopes
                                    .iter()
                                    .any(|scope| !parent.scopes.contains(scope))))
                    {
                        return false;
                    }
                    current = parent;
                }
            }
        }
    }

    fn compiled_scope_for(
        &self,
        record: &AccessToken,
    ) -> Result<Option<Arc<CompiledResourceScope>>, ()> {
        if record
            .resource_pattern
            .is_none()
            && record
                .required_headers
                .is_empty()
        {
            return Ok(None);
        }
        if let Some(existing) = self
            .compiled_scopes
            .get(&record.id)
        {
            return Ok(Some(existing.value().clone()));
        }
        match resource_scope::compile(
            record
                .resource_pattern
                .as_deref(),
            &record.required_headers,
        ) {
            Ok(compiled) => {
                let compiled = Arc::new(compiled);
                self.compiled_scopes
                    .insert(record.id.clone(), compiled.clone());
                Ok(Some(compiled))
            }
            Err(error) => {
                warn!(token_id = %record.id, %error, "Rejecting access token with invalid resource scope");
                Err(())
            }
        }
    }
}

#[async_trait]
impl PatAuthenticator for FsAccessTokenStore {
    async fn authenticate(
        &self,
        token: &str,
    ) -> Option<PatPrincipal> {
        if !token.starts_with(TOKEN_PREFIX) {
            return None;
        }
        let record = self.find_by_secret(token)?;
        let now = Utc::now();
        if !record.is_active(now) || !self.lineage_is_active(&record, now) {
            return None;
        }
        let resource_scope = self
            .compiled_scope_for(&record)
            .ok()?;
        self.touch_last_used(&record.id)
            .await;
        Some(PatPrincipal {
            user_id: record.user_id,
            scopes: (!record.scopes.is_empty()).then_some(record.scopes),
            token_id: record.id,
            delegation_depth: record.delegation_depth,
            resource_scope,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::Duration;

    use super::*;

    async fn store() -> FsAccessTokenStore {
        let dir = std::env::temp_dir().join(format!("ag-access-tokens-{}", uuid::Uuid::new_v4()));
        FsAccessTokenStore::new(dir)
            .await
            .unwrap()
    }

    fn record(
        hash: &str,
        scopes: Vec<String>,
    ) -> AccessToken {
        AccessToken {
            id: format!("agat_{}", uuid::Uuid::new_v4().as_simple()),
            name: "test".into(),
            description: String::new(),
            token_hash: hash.into(),
            user_id: "user-1".into(),
            scopes,
            resource_pattern: None,
            required_headers: Vec::new(),
            created_by: "user-1".into(),
            parent_token_id: None,
            delegation_depth: 0,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
            rotation_generation: 0,
            rotated_at: None,
            rotated_by: None,
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn persisted_record_is_owner_only_and_leaves_no_temporary_files() {
        use std::os::unix::fs::PermissionsExt;

        let store = store().await;
        let token = record(&hash_secret("agpat_mode"), Vec::new());
        let id = token.id.clone();
        store
            .create(token)
            .await
            .unwrap();

        let path = store.path_for(&id);
        let mode = std::fs::metadata(&path)
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let leftovers = std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension == "tmp")
            })
            .count();
        assert_eq!(leftovers, 0);
    }

    #[tokio::test]
    async fn authenticates_live_token_and_maps_scopes() {
        let store = store().await;
        let secret = "agpat_secret-value";
        let mut token = record(&hash_secret(secret), vec!["surfaces.edit".into()]);
        token.user_id = "admin-9".into();
        store
            .create(token)
            .await
            .unwrap();

        let principal = store
            .authenticate(secret)
            .await
            .unwrap();
        assert_eq!(principal.user_id, "admin-9");
        assert_eq!(principal.scopes, Some(vec!["surfaces.edit".to_string()]));
    }

    #[tokio::test]
    async fn authenticates_freshly_minted_canonical_secret() {
        // A freshly minted token uses the new `agpat_` secret / `agat_` id and
        // authenticates end to end.
        let store = store().await;
        let (id, secret) = crate::access_tokens::generate_token();
        assert!(id.starts_with("agat_"));
        assert!(secret.starts_with(TOKEN_PREFIX));
        let mut token = record(&hash_secret(&secret), vec!["gateways.view".into()]);
        token.id = id;
        store
            .create(token)
            .await
            .unwrap();

        let principal = store
            .authenticate(&secret)
            .await
            .expect("freshly minted agpat_ secret should authenticate");
        assert_eq!(principal.scopes, Some(vec!["gateways.view".to_string()]));
    }

    #[tokio::test]
    async fn rejects_unknown_revoked_and_expired_tokens() {
        let store = store().await;
        let secret = "agpat_live";
        store
            .create(record(&hash_secret(secret), vec![]))
            .await
            .unwrap();
        assert!(
            store
                .authenticate("agpat_unknown")
                .await
                .is_none()
        );

        let id = store.list()[0].id.clone();
        store
            .revoke(&id)
            .await
            .unwrap();
        assert!(
            !store
                .hash_index
                .contains_key(&hash_secret(secret))
        );
        assert!(
            store
                .authenticate(secret)
                .await
                .is_none()
        );

        let expired_secret = "agpat_expired";
        let mut expired = record(&hash_secret(expired_secret), vec![]);
        expired.expires_at = Some(Utc::now() - Duration::minutes(1));
        store
            .create(expired)
            .await
            .unwrap();
        assert!(
            store
                .authenticate(expired_secret)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn survives_reload_and_fails_closed_on_invalid_scope() {
        let dir = std::env::temp_dir().join(format!("ag-access-tokens-{}", uuid::Uuid::new_v4()));
        let secret = "agpat_persisted";
        let store = FsAccessTokenStore::new(&dir)
            .await
            .unwrap();
        store
            .create(record(&hash_secret(secret), vec![]))
            .await
            .unwrap();
        drop(store);
        let reloaded = FsAccessTokenStore::new(&dir)
            .await
            .unwrap();
        assert!(
            reloaded
                .authenticate(secret)
                .await
                .is_some()
        );

        let broken_secret = "agpat_broken";
        let mut broken = record(&hash_secret(broken_secret), vec![]);
        broken.resource_pattern = Some("TENANT:(:.*".into());
        reloaded
            .create(broken)
            .await
            .unwrap();
        assert!(
            reloaded
                .authenticate(broken_secret)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn usage_touch_cannot_overwrite_concurrent_revocation() {
        let store = Arc::new(store().await);
        let secret = "agpat_concurrent";
        let token = record(&hash_secret(secret), vec![]);
        let id = token.id.clone();
        store
            .create(token)
            .await
            .unwrap();

        let mutation_lock = store.mutation_lock(&id);
        let guard = mutation_lock.lock().await;

        let revoke_store = store.clone();
        let revoke_id = id.clone();
        let revoke = tokio::spawn(async move {
            revoke_store
                .revoke(&revoke_id)
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;

        let touch_store = store.clone();
        let touch_id = id.clone();
        let touch = tokio::spawn(async move {
            touch_store
                .touch_last_used(&touch_id)
                .await
        });
        tokio::task::yield_now().await;

        drop(guard);
        revoke.await.unwrap();
        touch.await.unwrap();

        assert!(
            store
                .get(&id)
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            store
                .authenticate(secret)
                .await
                .is_none()
        );

        let reloaded = FsAccessTokenStore::new(&store.dir)
            .await
            .unwrap();
        assert!(
            reloaded
                .get(&id)
                .unwrap()
                .revoked_at
                .is_some()
        );
        assert!(
            reloaded
                .authenticate(secret)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn revoking_parent_cascades_to_all_descendants_and_survives_reload() {
        let store = store().await;
        let root_secret = "agpat_root";
        let child_secret = "agpat_child";
        let grandchild_secret = "agpat_grandchild";

        let root = record(&hash_secret(root_secret), vec!["access_tokens.edit".into()]);
        let root_id = root.id.clone();
        store
            .create(root)
            .await
            .unwrap();

        let mut child = record(&hash_secret(child_secret), vec!["access_tokens.edit".into()]);
        child.parent_token_id = Some(root_id.clone());
        child.delegation_depth = 1;
        let child_id = child.id.clone();
        store
            .create(child)
            .await
            .unwrap();

        let mut grandchild = record(&hash_secret(grandchild_secret), vec!["access_tokens.edit".into()]);
        grandchild.parent_token_id = Some(child_id);
        grandchild.delegation_depth = 2;
        let grandchild_id = grandchild.id.clone();
        store
            .create(grandchild)
            .await
            .unwrap();

        for secret in [root_secret, child_secret, grandchild_secret] {
            assert!(
                store
                    .authenticate(secret)
                    .await
                    .is_some()
            );
        }

        store
            .revoke(&root_id)
            .await
            .unwrap();

        for secret in [root_secret, child_secret, grandchild_secret] {
            assert!(
                store
                    .authenticate(secret)
                    .await
                    .is_none()
            );
        }
        for id in [&root_id, &grandchild_id] {
            assert!(
                store
                    .get(id)
                    .unwrap()
                    .revoked_at
                    .is_some()
            );
        }

        let reloaded = FsAccessTokenStore::new(&store.dir)
            .await
            .unwrap();
        for secret in [root_secret, child_secret, grandchild_secret] {
            assert!(
                reloaded
                    .authenticate(secret)
                    .await
                    .is_none()
            );
        }
    }

    #[tokio::test]
    async fn rotation_swaps_secret_in_place_and_survives_reload() {
        let store = store().await;
        let old_secret = "agpat_rotate_old";
        let new_secret = "agpat_rotate_new";
        let child_secret = "agpat_rotate_child";

        let mut root = record(&hash_secret(old_secret), vec!["access_tokens.edit".into()]);
        root.name = "ci".into();
        root.last_used_at = Some(Utc::now());
        let root_id = root.id.clone();
        store
            .create(root)
            .await
            .unwrap();
        let mut child = record(&hash_secret(child_secret), vec!["access_tokens.edit".into()]);
        child.parent_token_id = Some(root_id.clone());
        child.delegation_depth = 1;
        store
            .create(child)
            .await
            .unwrap();

        let RotateOutcome::Rotated(rotated) = store
            .rotate(&root_id, "admin-1", 0, hash_secret(new_secret))
            .await
            .unwrap()
        else {
            panic!("rotation of an active token should succeed");
        };
        assert_eq!(rotated.id, root_id);
        assert_eq!(rotated.rotation_generation, 1);
        assert_eq!(rotated.rotated_by.as_deref(), Some("admin-1"));
        assert!(rotated.rotated_at.is_some());
        assert_eq!(rotated.name, "ci");
        assert_eq!(rotated.scopes, vec!["access_tokens.edit".to_string()]);
        assert_eq!(rotated.token_hash, hash_secret(new_secret));
        assert!(rotated.last_used_at.is_none());

        assert!(
            store
                .authenticate(old_secret)
                .await
                .is_none()
        );
        let principal = store
            .authenticate(new_secret)
            .await
            .unwrap();
        assert_eq!(principal.token_id, root_id);
        assert!(
            store
                .authenticate(child_secret)
                .await
                .is_some()
        );

        let reloaded = FsAccessTokenStore::new(&store.dir)
            .await
            .unwrap();
        assert!(
            reloaded
                .authenticate(old_secret)
                .await
                .is_none()
        );
        assert_eq!(
            reloaded
                .authenticate(new_secret)
                .await
                .unwrap()
                .token_id,
            root_id
        );
        assert_eq!(
            reloaded
                .get(&root_id)
                .unwrap()
                .rotation_generation,
            1
        );
    }

    #[tokio::test]
    async fn rotation_rejects_missing_revoked_and_expired_tokens() {
        let store = store().await;
        assert!(matches!(
            store
                .rotate("agat_missing", "admin-1", 0, hash_secret("agpat_unused"))
                .await
                .unwrap(),
            RotateOutcome::NotFound
        ));

        let revoked = record(&hash_secret("agpat_revoked"), vec![]);
        let revoked_id = revoked.id.clone();
        store
            .create(revoked)
            .await
            .unwrap();
        store
            .revoke(&revoked_id)
            .await
            .unwrap();
        let replacement = "agpat_revoked_replacement";
        assert!(matches!(
            store
                .rotate(&revoked_id, "admin-1", 0, hash_secret(replacement))
                .await
                .unwrap(),
            RotateOutcome::Inactive
        ));
        assert!(
            !store
                .hash_index
                .contains_key(&hash_secret(replacement))
        );
        assert!(
            store
                .authenticate(replacement)
                .await
                .is_none()
        );

        let mut expired = record(&hash_secret("agpat_expired_rotate"), vec![]);
        expired.expires_at = Some(Utc::now() - Duration::minutes(1));
        let expired_id = expired.id.clone();
        store
            .create(expired)
            .await
            .unwrap();
        assert!(matches!(
            store
                .rotate(&expired_id, "admin-1", 0, hash_secret("agpat_expired_replacement"))
                .await
                .unwrap(),
            RotateOutcome::Inactive
        ));
        assert_eq!(
            store
                .get(&expired_id)
                .unwrap()
                .token_hash,
            hash_secret("agpat_expired_rotate")
        );
    }

    #[tokio::test]
    async fn rotation_rejects_an_active_child_whose_lineage_is_broken() {
        let store = store().await;

        let mut expiring_parent = record(&hash_secret("agpat_expiring_parent"), vec!["secrets.view".into()]);
        expiring_parent.expires_at = Some(Utc::now() + Duration::milliseconds(200));
        let expiring_parent_id = expiring_parent.id.clone();
        store
            .create(expiring_parent)
            .await
            .unwrap();
        let mut orphan = record(&hash_secret("agpat_expired_parent_child"), vec!["secrets.view".into()]);
        orphan.parent_token_id = Some(expiring_parent_id);
        orphan.delegation_depth = 1;
        let orphan_id = orphan.id.clone();
        store
            .create(orphan)
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            store
                .get(&orphan_id)
                .unwrap()
                .is_active(Utc::now()),
            "parent expiry does not cascade to the child record"
        );

        let narrowed_root =
            record(&hash_secret("agpat_narrowed_root"), vec!["access_tokens.edit".into(), "secrets.view".into()]);
        let narrowed_root_id = narrowed_root.id.clone();
        store
            .create(narrowed_root)
            .await
            .unwrap();
        let mut broader_child = record(&hash_secret("agpat_broader_child"), vec!["secrets.view".into()]);
        broader_child.parent_token_id = Some(narrowed_root_id.clone());
        broader_child.delegation_depth = 1;
        let broader_child_id = broader_child.id.clone();
        store
            .create(broader_child)
            .await
            .unwrap();
        store
            .update(
                &narrowed_root_id,
                "narrowed".into(),
                String::new(),
                vec!["access_tokens.edit".into()],
                None,
                Vec::new(),
            )
            .await
            .unwrap();

        for (id, replacement) in
            [(&orphan_id, "agpat_expired_parent_replacement"), (&broader_child_id, "agpat_narrowed_replacement")]
        {
            assert!(matches!(
                store
                    .rotate(id, "admin-1", 0, hash_secret(replacement))
                    .await
                    .unwrap(),
                RotateOutcome::Inactive
            ));
            let record = store.get(id).unwrap();
            assert_eq!(record.rotation_generation, 0);
            assert!(
                !store
                    .hash_index
                    .contains_key(&hash_secret(replacement))
            );
        }
    }

    #[tokio::test]
    async fn rotation_with_a_stale_generation_is_rejected_and_keeps_the_winning_secret() {
        let store = store().await;
        let token = record(&hash_secret("agpat_stale_original"), vec![]);
        let id = token.id.clone();
        store
            .create(token)
            .await
            .unwrap();

        assert!(matches!(
            store
                .rotate(&id, "admin-1", 0, hash_secret("agpat_stale_first"))
                .await
                .unwrap(),
            RotateOutcome::Rotated(_)
        ));
        assert!(matches!(
            store
                .rotate(&id, "admin-2", 0, hash_secret("agpat_stale_second"))
                .await
                .unwrap(),
            RotateOutcome::Stale
        ));
        assert!(
            store
                .authenticate("agpat_stale_first")
                .await
                .is_some()
        );
        assert!(
            store
                .authenticate("agpat_stale_second")
                .await
                .is_none()
        );

        let RotateOutcome::Rotated(again) = store
            .rotate(&id, "admin-2", 1, hash_secret("agpat_stale_third"))
            .await
            .unwrap()
        else {
            panic!("a rotation that read the current generation should succeed");
        };
        assert_eq!(again.rotation_generation, 2);
        assert_eq!(again.rotated_by.as_deref(), Some("admin-2"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_rotations_of_the_same_generation_have_exactly_one_winner() {
        for iteration in 0..32 {
            let store = Arc::new(store().await);
            let token = record(&hash_secret(&format!("agpat_race_{iteration}")), vec![]);
            let id = token.id.clone();
            store
                .create(token)
                .await
                .unwrap();

            let attempts: Vec<_> = ["a", "b"]
                .into_iter()
                .map(|label| {
                    let store = store.clone();
                    let id = id.clone();
                    let secret = format!("agpat_race_{iteration}_{label}");
                    tokio::spawn(async move {
                        let outcome = store
                            .rotate(&id, label, 0, hash_secret(&secret))
                            .await
                            .unwrap();
                        (secret, outcome)
                    })
                })
                .collect();
            let mut winners = Vec::new();
            for attempt in attempts {
                let (secret, outcome) = attempt.await.unwrap();
                match outcome {
                    RotateOutcome::Rotated(_) => winners.push(secret),
                    RotateOutcome::Stale => {}
                    other => panic!("iteration {iteration}: unexpected outcome {other:?}"),
                }
            }

            assert_eq!(winners.len(), 1, "iteration {iteration}: exactly one rotation wins");
            assert_eq!(
                store
                    .get(&id)
                    .unwrap()
                    .rotation_generation,
                1
            );
            assert!(
                store
                    .authenticate(&winners[0])
                    .await
                    .is_some(),
                "iteration {iteration}: the winner's secret is live"
            );
        }
    }

    #[tokio::test]
    async fn narrowing_parent_scopes_invalidates_broader_descendant() {
        let store = store().await;
        let root_secret = "agpat_scope_root";
        let child_secret = "agpat_scope_child";

        let root = record(&hash_secret(root_secret), vec!["access_tokens.edit".into(), "secrets.view".into()]);
        let root_id = root.id.clone();
        store
            .create(root)
            .await
            .unwrap();

        let mut child = record(&hash_secret(child_secret), vec!["secrets.view".into()]);
        child.parent_token_id = Some(root_id.clone());
        child.delegation_depth = 1;
        store
            .create(child)
            .await
            .unwrap();
        assert!(
            store
                .authenticate(child_secret)
                .await
                .is_some()
        );

        store
            .update(
                &root_id,
                "narrowed root".into(),
                String::new(),
                vec!["access_tokens.edit".into()],
                None,
                Vec::new(),
            )
            .await
            .unwrap();

        assert!(
            store
                .authenticate(child_secret)
                .await
                .is_none()
        );
    }
}
