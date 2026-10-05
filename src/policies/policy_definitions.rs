//! Policy Definition storage and types
//!
//! Defines reusable OPA policy definitions that can be referenced by
//! gateways and agent surfaces. Uses RwLockFilesystemStorage for
//! async-friendly cached storage (write-through pattern).

use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tracing::info;

/// The type of entity a policy applies to
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PolicyType {
    /// Gateway-level policy (evaluated before agent-surface policies)
    Gateway,
    /// Agent-surface-level policy. Also accepts the legacy `channel` wire
    /// value so policy definitions written before agent surfaces replaced
    /// channels still deserialize — they re-serialize as `agent_surface`.
    #[serde(alias = "channel")]
    AgentSurface,
}

impl std::fmt::Display for PolicyType {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            PolicyType::Gateway => write!(f, "gateway"),
            PolicyType::AgentSurface => write!(f, "agent_surface"),
        }
    }
}

impl PolicyType {
    /// The canonical Rego `package` a policy of this scope must declare.
    ///
    /// Used to scaffold a new policy and to build the validation error message.
    /// The write API rejects any other package (see [`validate_scope_text`]), and
    /// the dashboard both scaffolds this package and offers a one-click repair.
    pub fn expected_package(&self) -> &'static str {
        match self {
            PolicyType::Gateway => "gateway.policy",
            PolicyType::AgentSurface => "surface.policy",
        }
    }
}

/// Locate the `package` declaration of a Rego module — the first non-blank,
/// non-comment line — returning the byte offset of the package **name** within
/// `policy` together with the name. `None` when that first meaningful line is not
/// a `package` declaration (or the body is empty / comment-only).
///
/// Single source of truth for parsing the declaration: the write-time scope check
/// reads the name through [`declared_package`], and the startup storage migration
/// ([`crate::policies::migrate_legacy_surface_package`]) uses the offset to rewrite
/// the name in place — so both parse the declaration the same way, once.
pub(crate) fn declared_package_span(policy: &str) -> Option<(usize, &str)> {
    let mut offset = 0usize;
    for line in policy.split_inclusive('\n') {
        let trimmed = line.trim_start();
        if trimmed.trim_end().is_empty() || trimmed.starts_with('#') {
            offset += line.len();
            continue;
        }
        // The first meaningful line must be the `package` declaration.
        let rest = trimmed.strip_prefix("package")?;
        if !rest.starts_with(char::is_whitespace) {
            return None;
        }
        let ws_len = rest.len() - rest.trim_start().len();
        let name = rest[ws_len..]
            .split_whitespace()
            .next()?;
        let name_offset = offset + (line.len() - trimmed.len()) + "package".len() + ws_len;
        return Some((name_offset, name));
    }
    None
}

/// Extract the `package` a Rego module declares, skipping leading blank lines and
/// `#` comments. Returns `None` when the body declares no package.
fn declared_package(policy: &str) -> Option<&str> {
    declared_package_span(policy).map(|(_, name)| name)
}

/// The result of classifying a policy body's declared package against the scope
/// it is being saved under.
///
/// This is a **write-time** (create/update) verdict; it says nothing about how an
/// already-stored policy evaluates at runtime (see `opa::eval_surface_decision`
/// for that).
#[derive(Debug, Clone, PartialEq, Eq)]
enum ScopeVerdict {
    /// Declares the scope's canonical package (`gateway.policy` / `surface.policy`),
    /// or is empty. An empty body means "no policy", which the runtime treats as
    /// allow-all.
    Ok,
    /// Declares a package that does not belong to this scope — a cross-scope
    /// package, an unknown package, the legacy `channel.policy`, or no package at
    /// all. Every such body is rejected on create/update.
    ///
    /// A cross-scope or unknown package would also fail closed at runtime, because
    /// the fixed `data.<pkg>.allow` query never resolves. `channel.policy` is the
    /// one exception: it is refused on write, yet definitions saved before the
    /// rename keep working because the policy store's startup migration pass
    /// rewrites the package to `surface.policy` (see
    /// `FileSystemPolicyDefinitionStore::migrate_legacy_packages`).
    Invalid {
        /// The package the policy actually declares, or `None` when it declares none.
        declared: Option<String>,
        /// The canonical package the scope expects.
        expected: &'static str,
    },
}

/// Classify a policy body's declared package against its scope.
///
/// This is the pure classifier behind the write-time guard [`validate_scope_text`];
/// keeping the "is this package in the right scope?" decision separate from error
/// formatting makes it directly unit-testable. An empty or whitespace-only body is
/// [`ScopeVerdict::Ok`] ("no policy" == allow-all at runtime); only the scope's
/// canonical package (see [`PolicyType::expected_package`]) is `Ok`; everything
/// else — including the legacy `channel.policy` and a missing package — is
/// `Invalid`.
fn check_scope(
    policy: &str,
    policy_type: &PolicyType,
) -> ScopeVerdict {
    if policy.trim().is_empty() {
        return ScopeVerdict::Ok;
    }
    let expected = policy_type.expected_package();
    match declared_package(policy) {
        Some(pkg) if pkg == expected => ScopeVerdict::Ok,
        Some(pkg) => ScopeVerdict::Invalid {
            declared: Some(pkg.to_string()),
            expected,
        },
        None => ScopeVerdict::Invalid { declared: None, expected },
    }
}

/// Reject a raw Rego policy body whose `package` does not match `policy_type`.
///
/// Shared by both write paths that persist Rego — the policy-definition CRUD
/// endpoints ([`validate_policy_scope`]) and the gateway inline-policy write path
/// — so they reject a scope mismatch with the same actionable message. The legacy
/// `channel.policy` is rejected here so no new definition can declare it; existing
/// definitions keep working because the policy store's startup migration pass
/// rewrites the package to `surface.policy` (see
/// `FileSystemPolicyDefinitionStore::migrate_legacy_packages`).
pub fn validate_scope_text(
    policy: &str,
    policy_type: &PolicyType,
) -> Result<(), String> {
    match check_scope(policy, policy_type) {
        ScopeVerdict::Ok => Ok(()),
        ScopeVerdict::Invalid { declared: Some(pkg), expected } => Err(format!(
            "Policy package `package {pkg}` does not match {policy_type} policies; use `package {expected}`"
        )),
        ScopeVerdict::Invalid { declared: None, expected } => {
            Err(format!("Policy must declare `package {expected}` for {policy_type} policies"))
        }
    }
}

/// Validate that a policy definition's Rego package matches its scope.
///
/// Delegates to [`validate_scope_text`].
pub fn validate_policy_scope(policy: &PolicyDefinition) -> Result<(), String> {
    validate_scope_text(&policy.policy, &policy.policy_type)
}

/// The name, enforced version and content hash of the policy definition that
/// made a decision, recorded with the decision as attestation. Every field is
/// `None` when no stored definition backs the decision.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PolicyAttestation {
    pub name: Option<String>,
    pub version: Option<u32>,
    pub content_hash: Option<String>,
}

impl PolicyAttestation {
    pub fn of(definition: &PolicyDefinition) -> Self {
        Self {
            name: Some(definition.name.clone()),
            version: definition.version,
            content_hash: definition
                .content_hash
                .clone(),
        }
    }
}

/// A reusable OPA policy definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDefinition {
    /// Unique identifier
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Human-readable name
    pub name: String,
    /// Description of what this policy does
    #[serde(default)]
    pub description: String,
    /// What type of entity this policy can be applied to
    pub policy_type: PolicyType,
    /// The Rego policy content
    pub policy: String,
    /// Whether this policy is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// ISO 8601 creation timestamp
    pub created_at: String,
    /// ISO 8601 last-updated timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Resolved version number of the enforced revision (projection of the
    /// document's `current_version`). Output-only; ignored on write.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// Content hash (`sha256:<hex>`) of the enforced revision. Output-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    /// Saved sample input for the policy dry-run (Test panel), retained with the
    /// policy so an operator's last test fixture persists across edits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_input: Option<String>,
}

fn default_true() -> bool {
    true
}

/// SHA-256 content hash (`sha256:<hex>`) binding a policy's scope to its Rego
/// body — the attestation primitive audit and governance records carry so a
/// verifier can prove which bytes were enforced. The policy type is mixed in
/// (with a unit separator) so identical Rego under a different scope hashes
/// differently.
pub fn content_hash(
    policy_type: &PolicyType,
    rego: &str,
) -> String {
    content_hash_from_parts(&policy_type.to_string(), rego)
}

fn content_hash_from_parts(
    policy_type: &str,
    rego: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(policy_type.as_bytes());
    hasher.update([0x1e]); // ASCII record separator
    hasher.update(rego.as_bytes());
    format!("sha256:{:x}", hasher.finalize())
}

/// One immutable revision of a policy's Rego body. Versions are append-only and
/// never mutated after creation — the sole exception is the one-time legacy
/// package normalization in [`FileSystemPolicyDefinitionStore::migrate_legacy_packages`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyVersion {
    /// Monotonic, 1-based revision number (per appliance; single-instance).
    pub version: u32,
    /// The Rego policy content for this revision — immutable.
    pub policy: String,
    /// `sha256:<hex>` content hash binding scope + body (see [`content_hash`]).
    pub content_hash: String,
    /// ISO 8601 creation timestamp.
    pub created_at: String,
    /// Authoring admin principal, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
    /// Optional operator change note.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Policy name as it stood for this revision. Bindings resolve a policy by
    /// id, so a rename never breaks enforcement — each revision keeps its own
    /// name for the history view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Policy description as it stood for this revision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// A versioned, immutable OPA policy document. Persisted one file per id; the
/// runtime enforces `current_version` and can resolve any historical version
/// for attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyDocument {
    /// Stable identifier — the policy identity referenced by bindings + audits.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Human-readable name.
    pub name: String,
    /// Description of what this policy does.
    #[serde(default)]
    pub description: String,
    /// What type of entity this policy applies to.
    pub policy_type: PolicyType,
    /// Document-level active flag.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Version number currently enforced at runtime.
    pub current_version: u32,
    /// ISO 8601 creation timestamp (of the document).
    pub created_at: String,
    /// ISO 8601 last-updated timestamp (document metadata or new version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    /// Append-only revision history (never mutated post-creation).
    pub versions: Vec<PolicyVersion>,
    /// Saved sample input for the policy dry-run (document-level; not versioned).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_input: Option<String>,
}

impl StorableEntity for PolicyDocument {
    fn id(&self) -> &str {
        &self.id
    }

    /// Convert a legacy flat `PolicyDefinition` file into a single-version
    /// document on load. Idempotent: an already-versioned document (has
    /// `versions`) is left untouched.
    fn migrate_raw_json(value: &mut serde_json::Value) -> Result<bool> {
        let Some(obj) = value.as_object_mut() else {
            return Ok(false);
        };
        if obj.contains_key("versions") {
            return Ok(false);
        }
        let policy = obj
            .get("policy")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        // Normalise the legacy `channel` policy-type alias so the migrated
        // revision hash matches what `content_hash(&AgentSurface, ..)` recomputes.
        let policy_type = match obj
            .get("policy_type")
            .and_then(|v| v.as_str())
            .unwrap_or("agent_surface")
        {
            "channel" => "agent_surface".to_string(),
            other => other.to_string(),
        };
        let created_at = obj
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let hash = content_hash_from_parts(&policy_type, &policy);
        let name = obj
            .get("name")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let description = obj
            .get("description")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let version = serde_json::json!({
            "version": 1,
            "policy": policy,
            "content_hash": hash,
            "created_at": created_at,
            "note": "migrated",
            "name": name,
            "description": description,
        });
        obj.remove("policy");
        obj.insert("current_version".to_string(), serde_json::json!(1));
        obj.insert("versions".to_string(), serde_json::json!([version]));
        Ok(true)
    }
}

impl PolicyDocument {
    /// The currently enforced version entry.
    pub fn current(&self) -> Option<&PolicyVersion> {
        self.versions
            .iter()
            .find(|v| v.version == self.current_version)
    }

    /// Resolve a specific historical version.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn version(
        &self,
        version: u32,
    ) -> Option<&PolicyVersion> {
        self.versions
            .iter()
            .find(|v| v.version == version)
    }

    /// Project to the flat [`PolicyDefinition`] view of the current version —
    /// what existing API consumers and runtime managers read.
    pub fn to_definition(&self) -> PolicyDefinition {
        let current = self.current();
        PolicyDefinition {
            id: self.id.clone(),
            tenant_id: self.tenant_id.clone(),
            name: self.name.clone(),
            description: self.description.clone(),
            policy_type: self.policy_type.clone(),
            policy: current
                .map(|v| v.policy.clone())
                .unwrap_or_default(),
            enabled: self.enabled,
            created_at: self.created_at.clone(),
            updated_at: self.updated_at.clone(),
            version: current.map(|v| v.version),
            content_hash: current.map(|v| v.content_hash.clone()),
            sample_input: self.sample_input.clone(),
        }
    }
}

/// File-based storage for versioned, immutable policy documents.
pub struct FileSystemPolicyDefinitionStore {
    storage: Box<dyn StorageBackend<PolicyDocument>>,
}

impl FileSystemPolicyDefinitionStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage_path = PathBuf::from(storage_dir);
        let storage = rwlock_storage(storage_path, "policy_definition").await?;
        Ok(Self { storage })
    }

    /// Reconcile the in-memory cache with the shared-storage directory, so a
    /// node promoted from standby resolves referencing objects' Rego from the
    /// active writer's latest definitions rather than a stale boot snapshot.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }

    /// Get the flat (current-version) view of a policy by ID.
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<PolicyDefinition> {
        self.get_document(id)
            .await
            .map(|d| d.to_definition())
    }

    /// Get the full versioned document by ID.
    pub async fn get_document(
        &self,
        id: &str,
    ) -> Option<PolicyDocument> {
        self.storage
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// Resolve a specific historical version — the primitive that makes an
    /// attestation referencing `policy_id@version` reproducible.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn get_version(
        &self,
        id: &str,
        version: u32,
    ) -> Option<PolicyVersion> {
        self.get_document(id)
            .await
            .and_then(|d| d.version(version).cloned())
    }

    /// List all policies as flat current-version views.
    pub async fn list(&self) -> Vec<PolicyDefinition> {
        self.list_documents()
            .await
            .iter()
            .map(PolicyDocument::to_definition)
            .collect()
    }

    /// List all versioned documents.
    pub async fn list_documents(&self) -> Vec<PolicyDocument> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    pub async fn set_tenant_id(
        &self,
        id: &str,
        tenant_id: Option<String>,
    ) -> Result<PolicyDefinition> {
        let mut document = self
            .get_document(id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Policy definition not found: {}", id))?;
        document.tenant_id = tenant_id;
        document.updated_at = Some(chrono::Utc::now().to_rfc3339());
        self.storage
            .save(&document)
            .await?;
        Ok(document.to_definition())
    }

    /// List policy definitions filtered by type
    #[cfg_attr(not(test), expect(dead_code))]
    pub async fn list_by_type(
        &self,
        policy_type: &PolicyType,
    ) -> Vec<PolicyDefinition> {
        self.list()
            .await
            .into_iter()
            .filter(|p| &p.policy_type == policy_type)
            .collect()
    }

    /// Save a policy (create or update). A change to the Rego body appends a new
    /// immutable version; metadata-only changes (name/description/enabled) update
    /// the document without a new version. Provenance is unattributed — use
    /// [`save_authored`](Self::save_authored) to record the author.
    #[cfg_attr(not(test), allow(dead_code))]
    pub async fn save(
        &self,
        policy: PolicyDefinition,
    ) -> Result<()> {
        self.save_authored(policy, None, None)
            .await
    }

    /// Save a policy, recording the authoring principal and an optional change
    /// note on any newly appended version.
    pub async fn save_authored(
        &self,
        policy: PolicyDefinition,
        author: Option<String>,
        note: Option<String>,
    ) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let hash = content_hash(&policy.policy_type, &policy.policy);

        let doc = match self
            .get_document(&policy.id)
            .await
        {
            Some(mut existing) => {
                let name = policy.name;
                let description = policy.description;
                existing.name = name.clone();
                existing.description = description.clone();
                existing.policy_type = policy.policy_type;
                existing.enabled = policy.enabled;
                existing.sample_input = policy.sample_input;
                existing.updated_at = Some(now.clone());
                let unchanged = existing
                    .current()
                    .is_some_and(|v| v.content_hash == hash);
                if unchanged {
                    // Metadata-only edit: keep the current revision's name /
                    // description snapshot in sync; older revisions stay frozen.
                    if let Some(cur) = existing
                        .versions
                        .iter_mut()
                        .find(|v| v.version == existing.current_version)
                    {
                        cur.name = Some(name);
                        cur.description = Some(description);
                    }
                } else {
                    let next = existing.current_version + 1;
                    existing
                        .versions
                        .push(PolicyVersion {
                            version: next,
                            policy: policy.policy,
                            content_hash: hash,
                            created_at: now,
                            created_by: author,
                            note,
                            name: Some(name),
                            description: Some(description),
                        });
                    existing.current_version = next;
                }
                existing
            }
            None => {
                let created_at = if policy.created_at.is_empty() {
                    now.clone()
                } else {
                    policy.created_at
                };
                let name = policy.name;
                let description = policy.description;
                PolicyDocument {
                    id: policy.id,
                    tenant_id: policy.tenant_id,
                    name: name.clone(),
                    description: description.clone(),
                    policy_type: policy.policy_type,
                    enabled: policy.enabled,
                    current_version: 1,
                    created_at,
                    updated_at: Some(now.clone()),
                    versions: vec![PolicyVersion {
                        version: 1,
                        policy: policy.policy,
                        content_hash: hash,
                        created_at: now,
                        created_by: author,
                        note,
                        name: Some(name),
                        description: Some(description),
                    }],
                    sample_input: policy.sample_input,
                }
            }
        };

        self.storage.save(&doc).await
    }

    /// One-time, idempotent migration of stored agent-surface definitions from
    /// the legacy `package channel.policy` to the canonical `package
    /// surface.policy`, rewriting the current revision's body in place (the only
    /// permitted mutation of an existing version) and recomputing its content
    /// hash. Gateway definitions are left untouched. Runs at startup and on
    /// config reload, before surfaces are (re)compiled. Returns the number of
    /// definitions rewritten.
    pub async fn migrate_legacy_packages(&self) -> Result<usize> {
        let mut migrated = 0usize;
        for mut doc in self.list_documents().await {
            if doc.policy_type != PolicyType::AgentSurface {
                continue;
            }
            let cv = doc.current_version;
            let current_policy = match doc
                .versions
                .iter()
                .find(|v| v.version == cv)
            {
                Some(v) => v.policy.clone(),
                None => continue,
            };
            if let std::borrow::Cow::Owned(rewritten) = crate::policies::migrate_legacy_surface_package(&current_policy)
            {
                info!(policy_id = %doc.id, "Migrating surface policy definition from `channel.policy` to `surface.policy`");
                let new_hash = content_hash(&doc.policy_type, &rewritten);
                if let Some(entry) = doc
                    .versions
                    .iter_mut()
                    .find(|v| v.version == cv)
                {
                    entry.policy = rewritten;
                    entry.content_hash = new_hash;
                }
                doc.updated_at = Some(chrono::Utc::now().to_rfc3339());
                self.storage
                    .save(&doc)
                    .await?;
                migrated += 1;
            }
        }
        Ok(migrated)
    }

    /// Delete a policy definition
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }

    /// Check if a policy definition exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> bool {
        self.storage
            .exists(id)
            .await
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_attestation_names_the_definition_revision() {
        let definition = PolicyDefinition {
            id: "def-1".into(),
            name: "Deny unknown callers".into(),
            description: String::new(),
            policy_type: PolicyType::AgentSurface,
            policy: "package surface.policy".into(),
            enabled: true,
            created_at: "t".into(),
            updated_at: None,
            version: Some(7),
            content_hash: Some("sha256:abc".into()),
            sample_input: None,
            tenant_id: None,
        };
        assert_eq!(
            PolicyAttestation::of(&definition),
            PolicyAttestation {
                name: Some("Deny unknown callers".into()),
                version: Some(7),
                content_hash: Some("sha256:abc".into()),
            }
        );

        let unversioned = PolicyDefinition {
            version: None,
            content_hash: None,
            ..definition
        };
        let attestation = PolicyAttestation::of(&unversioned);
        assert_eq!(attestation.name.as_deref(), Some("Deny unknown callers"));
        assert_eq!((attestation.version, attestation.content_hash), (None, None));
    }

    fn def(
        policy_type: PolicyType,
        policy: &str,
    ) -> PolicyDefinition {
        PolicyDefinition {
            id: "id".into(),
            tenant_id: None,
            name: "n".into(),
            description: String::new(),
            policy_type,
            policy: policy.into(),
            enabled: true,
            created_at: "t".into(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        }
    }

    #[tokio::test]
    async fn sample_input_round_trips_and_survives_metadata_edit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            tmp.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .expect("store");
        let mut d = def(PolicyType::Gateway, "package gateway.policy\ndefault allow = true");
        d.sample_input = Some("{\"a\":1}".to_string());
        store
            .save(d)
            .await
            .expect("save");
        assert_eq!(
            store
                .get("id")
                .await
                .expect("get")
                .sample_input
                .as_deref(),
            Some("{\"a\":1}")
        );

        // A metadata-only edit (unchanged Rego) still updates the saved input.
        let mut d2 = def(PolicyType::Gateway, "package gateway.policy\ndefault allow = true");
        d2.sample_input = Some("{\"b\":2}".to_string());
        store
            .save(d2)
            .await
            .expect("save2");
        assert_eq!(
            store
                .get("id")
                .await
                .expect("get2")
                .sample_input
                .as_deref(),
            Some("{\"b\":2}")
        );
    }

    #[tokio::test]
    async fn save_appends_version_on_rego_change_and_projects_current() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            tmp.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .expect("store");
        store
            .save(def(PolicyType::Gateway, "package gateway.policy\n\ndefault allow = true\n"))
            .await
            .expect("v1");
        let doc = store
            .get_document("id")
            .await
            .expect("doc");
        assert_eq!(doc.current_version, 1);
        assert_eq!(doc.versions.len(), 1);

        // Editing the Rego appends v2 and repoints current.
        store
            .save(def(PolicyType::Gateway, "package gateway.policy\n\ndefault allow = false\n"))
            .await
            .expect("v2");
        let doc = store
            .get_document("id")
            .await
            .expect("doc");
        assert_eq!(doc.current_version, 2);
        assert_eq!(doc.versions.len(), 2, "prior version must be retained");
        assert_eq!(
            store
                .get_version("id", 1)
                .await
                .unwrap()
                .policy,
            "package gateway.policy\n\ndefault allow = true\n"
        );
        // The flat projection reflects the current version + its content hash.
        let flat = store
            .get("id")
            .await
            .expect("flat");
        assert_eq!(flat.version, Some(2));
        assert_eq!(
            flat.content_hash.as_deref(),
            Some(content_hash(&PolicyType::Gateway, "package gateway.policy\n\ndefault allow = false\n").as_str())
        );
    }

    #[tokio::test]
    async fn metadata_only_edit_does_not_append_version() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            tmp.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .expect("store");
        store
            .save(def(PolicyType::AgentSurface, "package surface.policy\n\ndefault allow = true\n"))
            .await
            .expect("v1");
        let mut edited = def(PolicyType::AgentSurface, "package surface.policy\n\ndefault allow = true\n");
        edited.name = "renamed".into();
        edited.description = "new desc".into();
        store
            .save(edited)
            .await
            .expect("metadata edit");
        let doc = store
            .get_document("id")
            .await
            .expect("doc");
        assert_eq!(doc.current_version, 1, "metadata edit must not bump version");
        assert_eq!(doc.versions.len(), 1);
        assert_eq!(doc.name, "renamed");
        assert_eq!(
            doc.current()
                .unwrap()
                .name
                .as_deref(),
            Some("renamed")
        );
        assert_eq!(
            doc.current()
                .unwrap()
                .description
                .as_deref(),
            Some("new desc")
        );
    }

    #[test]
    fn content_hash_binds_scope_to_body() {
        let rego = "package gateway.policy\ndefault allow = true";
        // Same bytes, different scope → different hash.
        assert_ne!(content_hash(&PolicyType::Gateway, rego), content_hash(&PolicyType::AgentSurface, rego));
        // Stable for identical inputs, and prefixed.
        assert_eq!(content_hash(&PolicyType::Gateway, rego), content_hash(&PolicyType::Gateway, rego));
        assert!(content_hash(&PolicyType::Gateway, rego).starts_with("sha256:"));
    }

    #[test]
    fn migrate_raw_json_wraps_flat_definition_into_v1() {
        let mut value = serde_json::json!({
            "id": "flat-1",
            "name": "Flat",
            "description": "d",
            "policy_type": "gateway",
            "policy": "package gateway.policy\ndefault allow = true",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        });
        assert!(PolicyDocument::migrate_raw_json(&mut value).expect("migrate"), "a flat definition must migrate");
        let doc: PolicyDocument = serde_json::from_value(value).expect("doc deserializes");
        assert_eq!(doc.current_version, 1);
        assert_eq!(doc.versions.len(), 1);
        assert_eq!(doc.versions[0].policy, "package gateway.policy\ndefault allow = true");
        assert_eq!(
            doc.versions[0]
                .note
                .as_deref(),
            Some("migrated")
        );
        assert_eq!(
            doc.versions[0].content_hash,
            content_hash(&PolicyType::Gateway, "package gateway.policy\ndefault allow = true")
        );
        // Idempotent: a document already carrying versions is untouched.
        let mut again = serde_json::to_value(&doc).unwrap();
        assert!(
            !PolicyDocument::migrate_raw_json(&mut again).expect("noop"),
            "an already-versioned document must not re-migrate"
        );
    }

    #[test]
    fn migrate_raw_json_normalises_legacy_channel_type_for_hash() {
        let mut value = serde_json::json!({
            "id": "flat-ch",
            "name": "Ch",
            "policy_type": "channel",
            "policy": "package surface.policy\ndefault allow = false",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        });
        assert!(PolicyDocument::migrate_raw_json(&mut value).expect("migrate"));
        let doc: PolicyDocument = serde_json::from_value(value).expect("doc");
        assert_eq!(doc.policy_type, PolicyType::AgentSurface);
        // Hash computed with the normalised `agent_surface` scope, not `channel`.
        assert_eq!(
            doc.versions[0].content_hash,
            content_hash(&PolicyType::AgentSurface, "package surface.policy\ndefault allow = false")
        );
    }

    #[test]
    fn policy_type_serializes_to_canonical_snake_case() {
        assert_eq!(serde_json::to_string(&PolicyType::Gateway).unwrap(), "\"gateway\"");
        assert_eq!(serde_json::to_string(&PolicyType::AgentSurface).unwrap(), "\"agent_surface\"");
    }

    #[test]
    fn policy_type_never_serializes_legacy_channel() {
        for pt in [PolicyType::Gateway, PolicyType::AgentSurface] {
            assert_ne!(serde_json::to_string(&pt).unwrap(), "\"channel\"");
        }
    }

    #[test]
    fn policy_type_deserializes_canonical_values() {
        assert_eq!(serde_json::from_str::<PolicyType>("\"gateway\"").unwrap(), PolicyType::Gateway);
        assert_eq!(serde_json::from_str::<PolicyType>("\"agent_surface\"").unwrap(), PolicyType::AgentSurface);
    }

    #[test]
    fn legacy_channel_policy_type_deserializes_as_agent_surface() {
        let parsed: PolicyType = serde_json::from_str("\"channel\"").unwrap();
        assert_eq!(parsed, PolicyType::AgentSurface);
        assert_eq!(serde_json::to_string(&parsed).unwrap(), "\"agent_surface\"");
    }

    #[test]
    fn legacy_channel_policy_definition_migrates_to_agent_surface() {
        let legacy = serde_json::json!({
            "id": "deny-all",
            "name": "Deny All",
            "policy_type": "channel",
            "policy": "package surface.policy\n\ndefault allow := false\n",
            "enabled": true,
            "created_at": "2026-01-01T00:00:00Z"
        });
        let def: PolicyDefinition = serde_json::from_value(legacy).expect("legacy channel definition must deserialize");
        assert_eq!(def.policy_type, PolicyType::AgentSurface);
        let reserialized = serde_json::to_value(&def).unwrap();
        // The `policy_type` metadata migrates forward; surface Rego must now use
        // the `surface.policy` package.
        assert_eq!(reserialized["policy_type"], "agent_surface");
        assert_eq!(reserialized["policy"], "package surface.policy\n\ndefault allow := false\n");
    }

    #[test]
    fn unknown_policy_type_is_rejected() {
        assert!(serde_json::from_str::<PolicyType>("\"pipe\"").is_err());
        assert!(serde_json::from_str::<PolicyType>("\"bogus\"").is_err());
    }

    #[tokio::test]
    async fn list_by_type_filters_by_policy_type() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let store = FileSystemPolicyDefinitionStore::new(
            tmp.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .expect("build store");

        let make = |id: &str, policy_type: PolicyType| PolicyDefinition {
            id: id.to_string(),
            tenant_id: None,
            name: id.to_string(),
            description: String::new(),
            policy_type,
            policy: "package gateway.policy\n\ndefault allow := true\n".to_string(),
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
        };

        store
            .save(make("gw", PolicyType::Gateway))
            .await
            .expect("save gw");
        store
            .save(make("surf", PolicyType::AgentSurface))
            .await
            .expect("save surf");

        let gateways = store
            .list_by_type(&PolicyType::Gateway)
            .await;
        assert_eq!(gateways.len(), 1);
        assert_eq!(gateways[0].id, "gw");

        let surfaces = store
            .list_by_type(&PolicyType::AgentSurface)
            .await;
        assert_eq!(surfaces.len(), 1);
        assert_eq!(surfaces[0].id, "surf");
    }

    #[tokio::test]
    async fn migrate_legacy_packages_rewrites_stored_definitions_via_store() {
        // Startup migration rewrites legacy surface definitions through the store's
        // normal `save` path (no direct file access) and leaves gateway
        // definitions untouched; a second run is a no-op.
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp
            .path()
            .to_string_lossy()
            .into_owned();
        let store = FileSystemPolicyDefinitionStore::new(dir.clone())
            .await
            .expect("build store");

        store
            .save(PolicyDefinition {
                id: "legacy-surf".into(),
                tenant_id: None,
                name: "Legacy Surface".into(),
                description: String::new(),
                policy_type: PolicyType::AgentSurface,
                policy: "package channel.policy\n\ndefault allow = false\n".into(),
                enabled: true,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
            })
            .await
            .expect("save legacy surface def");
        store
            .save(PolicyDefinition {
                id: "gw".into(),
                tenant_id: None,
                name: "Gateway".into(),
                description: String::new(),
                policy_type: PolicyType::Gateway,
                policy: "package gateway.policy\n\ndefault allow = true\n".into(),
                enabled: true,
                created_at: "2026-01-01T00:00:00Z".into(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
            })
            .await
            .expect("save gateway def");

        let migrated = store
            .migrate_legacy_packages()
            .await
            .expect("migrate");
        assert_eq!(migrated, 1, "only the legacy surface definition should migrate");

        // A fresh store over the same directory observes the persisted change —
        // proving the rewrite went through the store's save path, not the cache.
        let reopened = FileSystemPolicyDefinitionStore::new(dir)
            .await
            .expect("reopen store");
        let surf = reopened
            .get("legacy-surf")
            .await
            .expect("surface def present");
        assert!(
            surf.policy
                .starts_with("package surface.policy"),
            "surface def must be migrated: {}",
            surf.policy
        );
        let gw = reopened
            .get("gw")
            .await
            .expect("gateway def present");
        assert_eq!(gw.policy, "package gateway.policy\n\ndefault allow = true\n", "gateway def untouched");

        // Idempotent: nothing left to migrate on a second pass.
        assert_eq!(
            reopened
                .migrate_legacy_packages()
                .await
                .expect("rerun"),
            0
        );
    }

    #[test]
    fn expected_package_maps_scope() {
        assert_eq!(PolicyType::Gateway.expected_package(), "gateway.policy");
        assert_eq!(PolicyType::AgentSurface.expected_package(), "surface.policy");
    }

    #[test]
    fn declared_package_reads_first_package_ignoring_comments() {
        assert_eq!(declared_package("package surface.policy\ndefault allow = true"), Some("surface.policy"));
        assert_eq!(declared_package("\n# a comment\n\n  package gateway.policy\n"), Some("gateway.policy"));
        assert_eq!(declared_package("package surface.policy  # note"), Some("surface.policy"));
        // Extra whitespace between the keyword and the name is tolerated.
        assert_eq!(declared_package("package\t  surface.policy"), Some("surface.policy"));
    }

    #[test]
    fn declared_package_none_when_absent_or_not_the_keyword() {
        assert_eq!(declared_package("default allow = true"), None);
        // `package` must be followed by whitespace — a longer identifier is not a match.
        assert_eq!(declared_package("packages.installed"), None);
        assert_eq!(declared_package("package"), None);
        assert_eq!(declared_package(""), None);
    }

    #[test]
    fn declared_package_span_reports_the_name_offset() {
        // The offset must point at the package name so the migration can rewrite
        // it in place, across leading blank lines, comments, and indentation.
        for (policy, name) in [
            ("package surface.policy\ndefault allow = true", "surface.policy"),
            ("\n# a comment\n\n  package channel.policy\n", "channel.policy"),
            ("package\t  gateway.policy  # note", "gateway.policy"),
        ] {
            let (offset, parsed) = declared_package_span(policy).expect("a package is declared");
            assert_eq!(parsed, name);
            assert_eq!(&policy[offset..offset + name.len()], name, "offset must land on the name in {policy:?}");
        }
        assert_eq!(declared_package_span("default allow = true"), None);
    }

    #[test]
    fn scope_ok_for_matching_and_empty() {
        assert_eq!(
            validate_policy_scope(&def(PolicyType::AgentSurface, "package surface.policy\ndefault allow = true")),
            Ok(())
        );
        // Legacy `channel.policy` is rejected on create/update; already-stored
        // legacy definitions are rewritten to `surface.policy` when the store
        // loads them at startup.
        assert_eq!(
            validate_policy_scope(&def(PolicyType::AgentSurface, "package channel.policy\ndefault allow = true"))
                .unwrap_err(),
            "Policy package `package channel.policy` does not match agent_surface policies; use `package surface.policy`"
        );
        assert_eq!(validate_policy_scope(&def(PolicyType::Gateway, "package gateway.policy")), Ok(()));
        // Empty / whitespace-only means "no policy" (allow-all at runtime), so it is accepted.
        assert_eq!(validate_policy_scope(&def(PolicyType::AgentSurface, "")), Ok(()));
        assert_eq!(validate_policy_scope(&def(PolicyType::Gateway, "   \n")), Ok(()));
    }

    #[test]
    fn scope_err_opposite_package_names_both_and_scope() {
        assert_eq!(
            validate_policy_scope(&def(PolicyType::AgentSurface, "package gateway.policy")).unwrap_err(),
            "Policy package `package gateway.policy` does not match agent_surface policies; use `package surface.policy`"
        );
    }

    #[test]
    fn scope_err_custom_package_rejected() {
        assert_eq!(
            validate_policy_scope(&def(PolicyType::Gateway, "package authz\ndefault allow = true")).unwrap_err(),
            "Policy package `package authz` does not match gateway policies; use `package gateway.policy`"
        );
    }

    #[test]
    fn scope_err_missing_package_rejected() {
        assert_eq!(
            validate_policy_scope(&def(PolicyType::AgentSurface, "default allow = true")).unwrap_err(),
            "Policy must declare `package surface.policy` for agent_surface policies"
        );
    }

    #[test]
    fn validate_scope_text_enforces_gateway_scope() {
        // A gateway inline policy declaring a surface package is rejected with the
        // same actionable message the definition write path produces.
        assert_eq!(
            validate_scope_text("package surface.policy\ndefault allow = true", &PolicyType::Gateway).unwrap_err(),
            "Policy package `package surface.policy` does not match gateway policies; use `package gateway.policy`"
        );
        // Canonical gateway package and empty body pass.
        assert!(validate_scope_text("package gateway.policy\ndefault allow = false", &PolicyType::Gateway).is_ok());
        assert!(validate_scope_text("", &PolicyType::Gateway).is_ok());
        // `channel.policy` is not a legacy alias for the gateway scope — rejected.
        assert!(validate_scope_text("package channel.policy", &PolicyType::Gateway).is_err());
    }

    #[test]
    fn check_scope_ok_for_canonical_and_empty() {
        assert_eq!(
            check_scope("package surface.policy\ndefault allow = true", &PolicyType::AgentSurface),
            ScopeVerdict::Ok
        );
        assert_eq!(check_scope("package gateway.policy", &PolicyType::Gateway), ScopeVerdict::Ok);
        assert_eq!(check_scope("", &PolicyType::AgentSurface), ScopeVerdict::Ok);
        assert_eq!(check_scope("   \n", &PolicyType::Gateway), ScopeVerdict::Ok);
    }

    #[test]
    fn check_scope_invalid_for_channel_on_surface() {
        // Legacy `channel.policy` is no longer accepted on create/update. Stored
        // legacy definitions are handled by the startup storage migration instead.
        assert_eq!(
            check_scope("package channel.policy\ndefault allow = true", &PolicyType::AgentSurface),
            ScopeVerdict::Invalid {
                declared: Some("channel.policy".to_string()),
                expected: "surface.policy"
            }
        );
    }

    #[test]
    fn check_scope_invalid_cross_scope_both_directions() {
        assert_eq!(
            check_scope("package gateway.policy", &PolicyType::AgentSurface),
            ScopeVerdict::Invalid {
                declared: Some("gateway.policy".to_string()),
                expected: "surface.policy"
            }
        );
        assert_eq!(
            check_scope("package surface.policy", &PolicyType::Gateway),
            ScopeVerdict::Invalid {
                declared: Some("surface.policy".to_string()),
                expected: "gateway.policy"
            }
        );
        // `channel.policy` is not accepted on any scope on the write path; on the
        // gateway scope it is Invalid.
        assert_eq!(
            check_scope("package channel.policy", &PolicyType::Gateway),
            ScopeVerdict::Invalid {
                declared: Some("channel.policy".to_string()),
                expected: "gateway.policy"
            }
        );
    }

    #[test]
    fn check_scope_invalid_unknown_and_missing() {
        assert_eq!(
            check_scope("package authz\ndefault allow = true", &PolicyType::Gateway),
            ScopeVerdict::Invalid {
                declared: Some("authz".to_string()),
                expected: "gateway.policy"
            }
        );
        assert_eq!(
            check_scope("default allow = true", &PolicyType::AgentSurface),
            ScopeVerdict::Invalid {
                declared: None,
                expected: "surface.policy"
            }
        );
    }
}
