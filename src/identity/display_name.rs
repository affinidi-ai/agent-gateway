//! Human-readable display names for managed agent identities.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::Serialize;
use tracing::warn;
use unicode_general_category::{GeneralCategory, get_general_category};

use super::IdentityStore;
use super::filesystem::{AgentIdentityRecord, IdentityOrigin};
use crate::config::agent_surface::AgentSurface;
use crate::surfaces::AgentSurfaceStore;

pub const DISPLAY_NAME_MAX_CHARS: usize = 128;
pub const DISPLAY_NAME_MAX_BYTES: usize = 256;
pub const DESCRIPTION_MAX_BYTES: usize = 2048;
pub const SURFACES_BY_DID_TTL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DisplayNameError {
    #[error("display name is empty")]
    Empty,
    #[error("display name contains a control character")]
    ControlCharacter,
    #[error("display name contains an invisible format character")]
    FormatCharacter,
    #[error("display name has {0} characters; maximum is {DISPLAY_NAME_MAX_CHARS}")]
    TooManyChars(usize),
    #[error("display name has {0} bytes; maximum is {DISPLAY_NAME_MAX_BYTES}")]
    TooManyBytes(usize),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct DisplayName(String);

impl DisplayName {
    pub fn parse(raw: &str) -> Result<Self, DisplayNameError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(DisplayNameError::Empty);
        }
        if trimmed
            .chars()
            .any(char::is_control)
        {
            return Err(DisplayNameError::ControlCharacter);
        }
        if trimmed.chars().any(is_format) {
            return Err(DisplayNameError::FormatCharacter);
        }
        let chars = trimmed.chars().count();
        if chars > DISPLAY_NAME_MAX_CHARS {
            return Err(DisplayNameError::TooManyChars(chars));
        }
        if trimmed.len() > DISPLAY_NAME_MAX_BYTES {
            return Err(DisplayNameError::TooManyBytes(trimmed.len()));
        }
        Ok(Self(trimmed.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Unicode `Cf` characters, such as zero-width spaces and bidirectional overrides, which
/// render invisibly or reorder text and so let a name visually impersonate another.
fn is_format(c: char) -> bool {
    get_general_category(c) == GeneralCategory::Format
}

pub fn sanitize_description(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed
        .chars()
        .any(|c| c.is_control() || is_format(c))
    {
        warn!("Dropping description containing control or format characters");
        return None;
    }
    if trimmed.len() > DESCRIPTION_MAX_BYTES {
        warn!(bytes = trimmed.len(), max = DESCRIPTION_MAX_BYTES, "Dropping description over the byte limit");
        return None;
    }
    Some(trimmed.to_string())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagedDisplayName {
    Named(DisplayName),
    Conflict { surface_ids: Vec<String> },
    Unnamed,
}

impl ManagedDisplayName {
    /// Name to publish for `did`; a DID shared by several surfaces publishes nothing.
    pub fn publishable(
        &self,
        did: &str,
    ) -> Option<&DisplayName> {
        match self {
            Self::Named(name) => Some(name),
            Self::Conflict { surface_ids } => {
                warn!(did, ?surface_ids, "DID is shared by several surfaces; no name published");
                None
            }
            Self::Unnamed => None,
        }
    }
}

fn is_managed(record: &AgentIdentityRecord) -> bool {
    record.effective_origin() == Some(IdentityOrigin::Managed)
}

pub fn surfaces_by_did(records: &[AgentIdentityRecord]) -> HashMap<String, BTreeSet<String>> {
    let mut by_did: HashMap<String, BTreeSet<String>> = HashMap::new();
    for record in records
        .iter()
        .filter(|r| is_managed(r))
    {
        let surfaces = by_did
            .entry(record.did.clone())
            .or_default();
        let usage_ids = record
            .channel_usage
            .iter()
            .map(|u| u.channel_config_id.as_str());
        for id in record
            .channel_config_id
            .as_deref()
            .into_iter()
            .chain(usage_ids)
            .filter(|id| !id.is_empty())
        {
            surfaces.insert(id.to_string());
        }
    }
    by_did
}

/// A managed agent is named by its target's Agent Card name when that is valid, else by its
/// surface name. A DID managed on several surfaces has no name. Pass `card_name` only for
/// dashboard display: signed and published names come from the surface alone.
pub fn resolve_managed_display_name(
    surface: &AgentSurface,
    surfaces_for_did: &BTreeSet<String>,
    card_name: Option<&str>,
) -> ManagedDisplayName {
    if surfaces_for_did
        .iter()
        .any(|id| id != &surface.surface_id)
    {
        let mut ids = surfaces_for_did.clone();
        ids.insert(surface.surface_id.clone());
        return ManagedDisplayName::Conflict {
            surface_ids: ids.into_iter().collect(),
        };
    }
    card_name
        .and_then(|name| DisplayName::parse(name).ok())
        .or_else(|| DisplayName::parse(&surface.name).ok())
        .map_or(ManagedDisplayName::Unnamed, ManagedDisplayName::Named)
}

type SurfacesByDid = HashMap<String, BTreeSet<String>>;

/// Snapshot of [`surfaces_by_did`], reloaded once older than its TTL or when asked
/// about a DID it does not contain, so a newly issued identity is seen at once.
pub struct SurfacesByDidCache {
    ttl: Duration,
    snapshot: Mutex<Option<(Instant, SurfacesByDid)>>,
}

impl Default for SurfacesByDidCache {
    fn default() -> Self {
        Self::new(SURFACES_BY_DID_TTL)
    }
}

impl SurfacesByDidCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            snapshot: Mutex::new(None),
        }
    }

    fn cached(
        &self,
        did: &str,
    ) -> Option<BTreeSet<String>> {
        let snapshot = self
            .snapshot
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let (loaded_at, by_did) = snapshot.as_ref()?;
        if loaded_at.elapsed() >= self.ttl {
            return None;
        }
        by_did.get(did).cloned()
    }

    /// Managed surfaces using `did`; `None` when the identity store cannot be listed.
    pub async fn surfaces_for(
        &self,
        did: &str,
        identity_store: &dyn IdentityStore,
    ) -> Option<BTreeSet<String>> {
        if let Some(surfaces) = self.cached(did) {
            return Some(surfaces);
        }
        let records = match identity_store
            .list_all()
            .await
        {
            Ok(records) => records,
            Err(e) => {
                warn!(did, error = %e, "Failed to list identities for display name");
                return None;
            }
        };
        let by_did = surfaces_by_did(&records);
        let surfaces = by_did
            .get(did)
            .cloned()
            .unwrap_or_default();
        *self
            .snapshot
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some((Instant::now(), by_did));
        Some(surfaces)
    }
}

/// Name signed into the managed agent's VC and published for it: the surface name, never the
/// target-controlled Agent Card name.
pub async fn resolve_managed_display_name_in(
    surface_store: &dyn AgentSurfaceStore,
    did: &str,
    surface_id: &str,
    identity_store: &dyn IdentityStore,
    cache: &SurfacesByDidCache,
) -> Option<ManagedDisplayName> {
    let surface = match surface_store
        .get(surface_id)
        .await
    {
        Ok(Some(surface)) => surface,
        Ok(None) => return None,
        Err(e) => {
            warn!(surface_id, error = %e, "Failed to load surface for display name");
            return None;
        }
    };
    let surfaces = cache
        .surfaces_for(did, identity_store)
        .await?;
    Some(resolve_managed_display_name(&surface, &surfaces, None))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_helpers::{MockIdentityStore, test_surface_identity_record};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingStore {
        inner: MockIdentityStore,
        list_calls: AtomicUsize,
        fail: bool,
    }

    impl CountingStore {
        async fn with(
            records: Vec<AgentIdentityRecord>,
            fail: bool,
        ) -> Self {
            let inner = MockIdentityStore::new();
            for record in records {
                inner
                    .create(record)
                    .await
                    .unwrap();
            }
            Self {
                inner,
                list_calls: AtomicUsize::new(0),
                fail,
            }
        }

        fn list_calls(&self) -> usize {
            self.list_calls
                .load(Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl IdentityStore for CountingStore {
        async fn find_by_hash(
            &self,
            identity_hash: &str,
        ) -> anyhow::Result<Option<AgentIdentityRecord>> {
            self.inner
                .find_by_hash(identity_hash)
                .await
        }

        async fn create(
            &self,
            record: AgentIdentityRecord,
        ) -> anyhow::Result<()> {
            self.inner
                .create(record)
                .await
        }

        async fn list_all(&self) -> anyhow::Result<Vec<AgentIdentityRecord>> {
            self.list_calls
                .fetch_add(1, Ordering::SeqCst);
            if self.fail {
                anyhow::bail!("store unavailable");
            }
            self.inner.list_all().await
        }

        async fn update_usage(
            &self,
            identity_hash: &str,
            channel_config_id: Option<String>,
        ) -> anyhow::Result<()> {
            self.inner
                .update_usage(identity_hash, channel_config_id)
                .await
        }

        async fn find_by_did(
            &self,
            did: &str,
        ) -> anyhow::Result<Option<AgentIdentityRecord>> {
            self.inner
                .find_by_did(did)
                .await
        }

        async fn store_external_did(
            &self,
            did: &str,
            identity_fields: HashMap<String, serde_json::Value>,
            channel_config_id: Option<String>,
            verified: bool,
        ) -> anyhow::Result<()> {
            self.inner
                .store_external_did(did, identity_fields, channel_config_id, verified)
                .await
        }
    }

    fn managed(
        did: &str,
        surface_id: &str,
    ) -> AgentIdentityRecord {
        let mut record = test_surface_identity_record(did, surface_id);
        record.origin = Some(IdentityOrigin::Managed);
        record
    }

    fn surface(
        id: &str,
        name: &str,
    ) -> AgentSurface {
        AgentSurface {
            surface_id: id.to_string(),
            name: name.to_string(),
            ..Default::default()
        }
    }

    fn set(ids: &[&str]) -> BTreeSet<String> {
        ids.iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn parse_trims_and_keeps_case() {
        let name = DisplayName::parse("  OXYGEN agent \t").unwrap();
        assert_eq!(name.as_str(), "OXYGEN agent");
    }

    #[test]
    fn parse_accepts_128_chars_and_rejects_129() {
        let ok = "a".repeat(128);
        assert_eq!(
            DisplayName::parse(&ok)
                .unwrap()
                .as_str(),
            ok
        );
        assert_eq!(DisplayName::parse(&"a".repeat(129)), Err(DisplayNameError::TooManyChars(129)));
    }

    #[test]
    fn parse_accepts_64_four_byte_chars_and_rejects_65_on_bytes() {
        let ok = "\u{1F600}".repeat(64);
        assert_eq!(
            DisplayName::parse(&ok)
                .unwrap()
                .as_str(),
            ok
        );
        assert_eq!(DisplayName::parse(&"\u{1F600}".repeat(65)), Err(DisplayNameError::TooManyBytes(260)));
    }

    #[test]
    fn parse_rejects_control_characters() {
        for raw in ["bell\u{7}", "new\nline", "c1\u{9f}char"] {
            assert_eq!(DisplayName::parse(raw), Err(DisplayNameError::ControlCharacter), "{raw:?}");
        }
    }

    #[test]
    fn parse_rejects_format_characters() {
        for raw in [
            "zero\u{200B}width",
            "joiner\u{200D}",
            "rtl\u{202E}override",
            "isolate\u{2066}x\u{2069}",
            "\u{FEFF}bom",
            "soft\u{AD}hyphen",
            "tag\u{E0041}",
        ] {
            assert_eq!(DisplayName::parse(raw), Err(DisplayNameError::FormatCharacter), "{raw:?}");
        }
    }

    #[test]
    fn parse_accepts_non_format_unicode() {
        for raw in ["Café Agent", "代理 Agent", "Agent \u{1F600}", "Агент"] {
            assert_eq!(
                DisplayName::parse(raw)
                    .unwrap()
                    .as_str(),
                raw
            );
        }
    }

    #[test]
    fn parse_rejects_empty_and_whitespace() {
        assert_eq!(DisplayName::parse(""), Err(DisplayNameError::Empty));
        assert_eq!(DisplayName::parse("   \t "), Err(DisplayNameError::Empty));
    }

    #[test]
    fn display_name_serializes_as_plain_string() {
        let name = DisplayName::parse("OXYGEN").unwrap();
        assert_eq!(serde_json::to_value(&name).unwrap(), serde_json::json!("OXYGEN"));
    }

    #[test]
    fn sanitize_description_trims_and_filters() {
        assert_eq!(sanitize_description(Some("  billing bot  ")), Some("billing bot".to_string()));
        assert_eq!(sanitize_description(None), None);
        assert_eq!(sanitize_description(Some("   ")), None);
        assert_eq!(sanitize_description(Some("bad\u{0}")), None);
        assert_eq!(sanitize_description(Some("pay \u{202E}evil")), None);
        assert_eq!(sanitize_description(Some("zero\u{200B}width")), None);
        assert_eq!(
            sanitize_description(Some(&"d".repeat(DESCRIPTION_MAX_BYTES))),
            Some("d".repeat(DESCRIPTION_MAX_BYTES))
        );
        assert_eq!(sanitize_description(Some(&"d".repeat(DESCRIPTION_MAX_BYTES + 1))), None);
    }

    #[test]
    fn resolve_uses_surface_name_not_principal() {
        let mut record = test_surface_identity_record("did:web:a", "s1");
        record.origin = Some(IdentityOrigin::Managed);
        record
            .identity_fields
            .insert("certificate_id".to_string(), serde_json::json!("NITROGEN"));
        let surfaces = surfaces_by_did(&[record]);
        let result = resolve_managed_display_name(&surface("s1", "OXYGEN"), &surfaces["did:web:a"], None);
        assert_eq!(result, ManagedDisplayName::Named(DisplayName::parse("OXYGEN").unwrap()));
    }

    #[test]
    fn resolve_reports_conflict_with_sorted_ids() {
        let result = resolve_managed_display_name(&surface("s2", "OXYGEN"), &set(&["s3", "s2", "s1"]), None);
        assert_eq!(
            result,
            ManagedDisplayName::Conflict {
                surface_ids: vec!["s1".to_string(), "s2".to_string(), "s3".to_string()]
            }
        );
    }

    #[test]
    fn resolve_conflict_includes_current_surface_when_absent() {
        let result = resolve_managed_display_name(&surface("s2", "OXYGEN"), &set(&["s1"]), None);
        assert_eq!(
            result,
            ManagedDisplayName::Conflict {
                surface_ids: vec!["s1".to_string(), "s2".to_string()]
            }
        );
    }

    #[test]
    fn resolve_prefers_valid_agent_card_name_over_surface_name() {
        let result = resolve_managed_display_name(&surface("s1", "DEF"), &set(&["s1"]), Some("DateTime Agent"));
        assert_eq!(result, ManagedDisplayName::Named(DisplayName::parse("DateTime Agent").unwrap()));
    }

    #[test]
    fn resolve_invalid_agent_card_name_falls_back_to_surface_name() {
        let result = resolve_managed_display_name(&surface("s1", "DEF"), &set(&["s1"]), Some("bad\nname"));
        assert_eq!(result, ManagedDisplayName::Named(DisplayName::parse("DEF").unwrap()));
    }

    #[test]
    fn resolve_agent_card_name_does_not_override_conflict() {
        let result = resolve_managed_display_name(&surface("s2", "DEF"), &set(&["s1"]), Some("DateTime Agent"));
        assert!(matches!(result, ManagedDisplayName::Conflict { .. }));
    }

    #[test]
    fn resolve_agent_card_name_names_unnamed_surface() {
        let result = resolve_managed_display_name(&surface("s1", "  "), &set(&["s1"]), Some("DateTime Agent"));
        assert_eq!(result, ManagedDisplayName::Named(DisplayName::parse("DateTime Agent").unwrap()));
    }

    #[test]
    fn resolve_invalid_name_is_unnamed() {
        assert_eq!(
            resolve_managed_display_name(&surface("s1", "  "), &set(&["s1"]), None),
            ManagedDisplayName::Unnamed
        );
        assert_eq!(
            resolve_managed_display_name(&surface("s1", "bad\nname"), &set(&[]), None),
            ManagedDisplayName::Unnamed
        );
    }

    #[test]
    fn surfaces_by_did_unions_usage_and_ignores_callers_and_legacy_records() {
        let mut managed = test_surface_identity_record("did:web:a", "s1");
        managed.origin = Some(IdentityOrigin::Managed);
        managed
            .channel_usage
            .push(crate::identity::filesystem::ChannelUsage {
                channel_config_id: "s2".to_string(),
                usage_count: 1,
                last_used_at: chrono::Utc::now(),
            });
        let mut legacy = test_surface_identity_record("did:web:a", "s3");
        legacy.identity_hash = "legacy".to_string();
        let mut caller = test_surface_identity_record("did:web:a", "s9");
        caller.identity_hash = "caller".to_string();
        caller.origin = Some(IdentityOrigin::ExternalCaller);
        let mut legacy_remote = test_surface_identity_record("did:web:b", "s8");
        legacy_remote.is_local = false;

        let by_did = surfaces_by_did(&[managed, legacy, caller, legacy_remote]);

        assert_eq!(by_did.get("did:web:a"), Some(&set(&["s1", "s2"])));
        assert_eq!(by_did.get("did:web:b"), None);
    }

    #[test]
    fn surfaces_by_did_excludes_legacy_local_record_without_origin() {
        let mut legacy = test_surface_identity_record("did:web:legacy", "s1");
        legacy.origin = None;
        legacy.is_local = true;

        assert_eq!(surfaces_by_did(&[legacy]).get("did:web:legacy"), None);
    }

    #[test]
    fn publishable_returns_only_named() {
        let oxygen = DisplayName::parse("OXYGEN").unwrap();
        assert_eq!(ManagedDisplayName::Named(oxygen.clone()).publishable("did:a"), Some(&oxygen));
        assert_eq!(
            ManagedDisplayName::Conflict {
                surface_ids: vec!["s1".into(), "s2".into()]
            }
            .publishable("did:a"),
            None
        );
        assert_eq!(ManagedDisplayName::Unnamed.publishable("did:a"), None);
    }

    #[tokio::test]
    async fn cache_serves_known_did_without_relisting() {
        let store = CountingStore::with(vec![managed("did:web:a", "s1")], false).await;
        let cache = SurfacesByDidCache::default();

        let first = cache
            .surfaces_for("did:web:a", &store)
            .await;
        store
            .create(managed("did:web:x", "s2"))
            .await
            .unwrap();
        let second = cache
            .surfaces_for("did:web:a", &store)
            .await;

        assert_eq!(first, Some(set(&["s1"])));
        assert_eq!(second, Some(set(&["s1"])));
        assert_eq!(store.list_calls(), 1);
    }

    #[tokio::test]
    async fn cache_reloads_for_unknown_did() {
        let store = CountingStore::with(vec![managed("did:web:a", "s1")], false).await;
        let cache = SurfacesByDidCache::default();
        cache
            .surfaces_for("did:web:a", &store)
            .await;

        let missing = cache
            .surfaces_for("did:web:new", &store)
            .await;
        store
            .create(managed("did:web:new", "s2"))
            .await
            .unwrap();
        let found = cache
            .surfaces_for("did:web:new", &store)
            .await;

        assert_eq!(missing, Some(BTreeSet::new()));
        assert_eq!(found, Some(set(&["s2"])));
        assert_eq!(store.list_calls(), 3);
    }

    #[tokio::test]
    async fn cache_reloads_after_ttl() {
        let store = CountingStore::with(vec![managed("did:web:a", "s1")], false).await;
        let cache = SurfacesByDidCache::new(Duration::ZERO);
        cache
            .surfaces_for("did:web:a", &store)
            .await;
        let mut sibling = managed("did:web:a", "s2");
        sibling.identity_hash = "sibling".to_string();
        store
            .create(sibling)
            .await
            .unwrap();

        let reloaded = cache
            .surfaces_for("did:web:a", &store)
            .await;

        assert_eq!(reloaded, Some(set(&["s1", "s2"])));
        assert_eq!(store.list_calls(), 2);
    }

    #[tokio::test]
    async fn cache_returns_none_when_store_fails() {
        let store = CountingStore::with(vec![], true).await;
        let cache = SurfacesByDidCache::default();

        assert_eq!(
            cache
                .surfaces_for("did:web:a", &store)
                .await,
            None
        );
        assert_eq!(store.list_calls(), 1);
    }
}
