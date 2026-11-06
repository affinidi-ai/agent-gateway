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
    Shared { surface_ids: Vec<String> },
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
            Self::Shared { surface_ids } => {
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

/// Whether a usage entry in `role` makes `surface` a managed surface of the DID: a managed
/// use, or one recorded before roles, counts only while the surface still issues a managed
/// identity.
fn counts_as_managed(
    role: Option<IdentityOrigin>,
    surface: &AgentSurface,
) -> bool {
    role != Some(IdentityOrigin::ExternalCaller) && surface.has_managed_identity()
}

/// The live surfaces where each managed DID is the managed agent: surfaces where it was only
/// a caller, and surfaces `live_surface` no longer finds, are left out. The dashboard, the
/// name signed into the VC and Trust Registry publishing all read managed surfaces from here.
pub fn managed_surfaces_by_did<'a>(
    records: &[AgentIdentityRecord],
    live_surface: impl Fn(&str) -> Option<&'a AgentSurface>,
) -> HashMap<String, BTreeSet<String>> {
    let mut by_did: HashMap<String, BTreeSet<String>> = HashMap::new();
    for record in records
        .iter()
        .filter(|r| is_managed(r))
    {
        let surfaces = by_did
            .entry(record.did.clone())
            .or_default();
        let unrecorded_last_used = record
            .channel_config_id
            .as_deref()
            .filter(|id| {
                !record
                    .channel_usage
                    .iter()
                    .any(|u| u.channel_config_id == *id)
            })
            .map(|id| (id, None));
        let usages = record
            .channel_usage
            .iter()
            .map(|u| (u.channel_config_id.as_str(), u.role))
            .chain(unrecorded_last_used);
        for (id, role) in usages.filter(|(id, _)| !id.is_empty()) {
            if live_surface(id).is_some_and(|surface| counts_as_managed(role, surface)) {
                surfaces.insert(id.to_string());
            }
        }
    }
    by_did
}

/// A managed agent is named by its target's Agent Card name when that is valid, else by its
/// surface name. A DID managed on several surfaces is shared and has no name. Pass
/// `card_name` only for dashboard display: signed and published names come from the surface
/// alone.
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
        return ManagedDisplayName::Shared {
            surface_ids: ids.into_iter().collect(),
        };
    }
    card_name
        .and_then(|name| DisplayName::parse(name).ok())
        .or_else(|| DisplayName::parse(&surface.name).ok())
        .map_or(ManagedDisplayName::Unnamed, ManagedDisplayName::Named)
}

type SurfacesByDid = HashMap<String, BTreeSet<String>>;

/// Snapshot of [`managed_surfaces_by_did`], reloaded once older than its TTL or when asked
/// about a DID it does not contain, so a newly issued identity is seen at once. The snapshot
/// also holds the live surface list, so a surface deleted or reconfigured since it was taken
/// is seen only after the next reload.
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

    /// Managed surfaces of `did`; `None` when the identity or surface store cannot be listed.
    pub async fn surfaces_for(
        &self,
        did: &str,
        identity_store: &dyn IdentityStore,
        surface_store: &dyn AgentSurfaceStore,
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
        let live_surfaces = match surface_store.list_all().await {
            Ok(surfaces) => surfaces,
            Err(e) => {
                warn!(did, error = %e, "Failed to list surfaces for display name");
                return None;
            }
        };
        let live_by_id: HashMap<&str, &AgentSurface> = live_surfaces
            .iter()
            .map(|s| (s.surface_id.as_str(), s))
            .collect();
        let by_did = managed_surfaces_by_did(&records, |id| live_by_id.get(id).copied());
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

/// Name signed into the managed agent's VC and published for it: the name of its one managed
/// surface, never the target-controlled Agent Card name. `managed_on` is a surface where
/// `did` is the managed agent in the current request, counted even before its usage is stored.
/// `None` when the DID has no managed surface or a store is unavailable.
pub async fn resolve_managed_display_name_in(
    surface_store: &dyn AgentSurfaceStore,
    did: &str,
    managed_on: Option<&str>,
    identity_store: &dyn IdentityStore,
    cache: &SurfacesByDidCache,
) -> Option<ManagedDisplayName> {
    let mut surfaces = cache
        .surfaces_for(did, identity_store, surface_store)
        .await?;
    surfaces.extend(managed_on.map(str::to_string));
    let mut ids = surfaces.iter();
    let surface_id = match (ids.next(), ids.next()) {
        (Some(only), None) => only,
        (Some(_), Some(_)) => {
            return Some(ManagedDisplayName::Shared {
                surface_ids: surfaces.into_iter().collect(),
            });
        }
        (None, _) => return None,
    };
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
            role: Option<IdentityOrigin>,
        ) -> anyhow::Result<()> {
            self.inner
                .update_usage(identity_hash, channel_config_id, role)
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

    struct Surfaces(Vec<AgentSurface>);

    #[async_trait::async_trait]
    impl AgentSurfaceStore for Surfaces {
        async fn get_checked(
            &self,
            surface_id: &str,
        ) -> anyhow::Result<Option<AgentSurface>> {
            self.get(surface_id).await
        }

        async fn save(
            &self,
            _surface: &AgentSurface,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        async fn get(
            &self,
            surface_id: &str,
        ) -> anyhow::Result<Option<AgentSurface>> {
            Ok(self
                .0
                .iter()
                .find(|s| s.surface_id == surface_id)
                .cloned())
        }

        async fn list_all(&self) -> anyhow::Result<Vec<AgentSurface>> {
            Ok(self.0.clone())
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    fn live(ids: &[&str]) -> Surfaces {
        Surfaces(
            ids.iter()
                .map(|id| with_managed_identity(surface(id, &id.to_uppercase())))
                .collect(),
        )
    }

    fn managed(
        did: &str,
        surface_id: &str,
    ) -> AgentIdentityRecord {
        let mut record = test_surface_identity_record(did, surface_id);
        record.origin = Some(IdentityOrigin::Managed);
        record.channel_usage[0].role = Some(IdentityOrigin::Managed);
        record
    }

    use crate::identity::test_helpers::test_channel_usage as usage;

    fn with_managed_identity(mut surface: AgentSurface) -> AgentSurface {
        surface
            .target
            .identity_injection
            .identity_type = Some("from_jwt_claim".to_string());
        assert!(surface.has_managed_identity());
        surface
    }

    fn by_did_over(
        records: &[AgentIdentityRecord],
        surfaces: &[AgentSurface],
    ) -> HashMap<String, BTreeSet<String>> {
        managed_surfaces_by_did(records, |id| {
            surfaces
                .iter()
                .find(|s| s.surface_id == id)
        })
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
        record.channel_usage[0].role = Some(IdentityOrigin::Managed);
        let surfaces = by_did_over(&[record], &[surface("s1", "OXYGEN")]);
        let result = resolve_managed_display_name(&surface("s1", "OXYGEN"), &surfaces["did:web:a"], None);
        assert_eq!(result, ManagedDisplayName::Named(DisplayName::parse("OXYGEN").unwrap()));
    }

    #[test]
    fn resolve_reports_shared_did_with_sorted_ids() {
        let result = resolve_managed_display_name(&surface("s2", "OXYGEN"), &set(&["s3", "s2", "s1"]), None);
        assert_eq!(
            result,
            ManagedDisplayName::Shared {
                surface_ids: vec!["s1".to_string(), "s2".to_string(), "s3".to_string()]
            }
        );
    }

    #[test]
    fn resolve_shared_did_includes_current_surface_when_absent() {
        let result = resolve_managed_display_name(&surface("s2", "OXYGEN"), &set(&["s1"]), None);
        assert_eq!(
            result,
            ManagedDisplayName::Shared {
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
    fn resolve_agent_card_name_does_not_name_shared_did() {
        let result = resolve_managed_display_name(&surface("s2", "DEF"), &set(&["s1"]), Some("DateTime Agent"));
        assert!(matches!(result, ManagedDisplayName::Shared { .. }));
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
    fn managed_surfaces_union_managed_usage_and_ignore_caller_records() {
        let mut managed = managed("did:web:a", "s1");
        managed
            .channel_usage
            .push(usage("s2", Some(IdentityOrigin::Managed)));
        let mut legacy = test_surface_identity_record("did:web:a", "s3");
        legacy.identity_hash = "legacy".to_string();
        let mut caller = test_surface_identity_record("did:web:a", "s9");
        caller.identity_hash = "caller".to_string();
        caller.origin = Some(IdentityOrigin::ExternalCaller);
        let mut legacy_remote = test_surface_identity_record("did:web:b", "s8");
        legacy_remote.is_local = false;
        let surfaces: Vec<_> = ["s1", "s2", "s3", "s8", "s9"]
            .into_iter()
            .map(|id| with_managed_identity(surface(id, id)))
            .collect();

        let by_did = by_did_over(&[managed, legacy, caller, legacy_remote], &surfaces);

        assert_eq!(by_did.get("did:web:a"), Some(&set(&["s1", "s2"])));
        assert_eq!(by_did.get("did:web:b"), None);
    }

    #[test]
    fn managed_surfaces_exclude_legacy_local_record_without_origin() {
        let mut legacy = test_surface_identity_record("did:web:legacy", "s1");
        legacy.origin = None;
        legacy.is_local = true;

        assert_eq!(by_did_over(&[legacy], &[with_managed_identity(surface("s1", "A"))]).get("did:web:legacy"), None);
    }

    #[test]
    fn managed_surfaces_leave_out_caller_only_surfaces() {
        let mut record = managed("did:web:a", "alpha");
        record
            .channel_usage
            .push(usage("delta", Some(IdentityOrigin::ExternalCaller)));
        record.channel_config_id = Some("delta".to_string());
        let surfaces =
            [with_managed_identity(surface("alpha", "ALPHA")), with_managed_identity(surface("delta", "DELTA"))];

        assert_eq!(by_did_over(&[record], &surfaces)["did:web:a"], set(&["alpha"]));
    }

    #[test]
    fn managed_surfaces_leave_out_deleted_surfaces() {
        let mut record = managed("did:web:a", "alpha");
        record
            .channel_usage
            .push(usage("bravo", Some(IdentityOrigin::Managed)));

        assert_eq!(
            by_did_over(&[record], &[with_managed_identity(surface("alpha", "ALPHA"))])["did:web:a"],
            set(&["alpha"])
        );
    }

    #[test]
    fn managed_surfaces_leave_out_surfaces_that_no_longer_issue_a_managed_identity() {
        let mut record = managed("did:web:a", "alpha");
        record
            .channel_usage
            .push(usage("bravo", Some(IdentityOrigin::Managed)));
        let surfaces = [with_managed_identity(surface("alpha", "ALPHA")), surface("bravo", "BRAVO")];

        assert_eq!(by_did_over(&[record], &surfaces)["did:web:a"], set(&["alpha"]));
    }

    #[test]
    fn managed_surfaces_count_entries_without_role_only_on_surfaces_with_managed_identity() {
        let mut record = managed("did:web:a", "alpha");
        record.channel_usage = vec![usage("alpha", None), usage("bravo", None)];
        record.channel_config_id = Some("charlie".to_string());
        let surfaces = [
            with_managed_identity(surface("alpha", "ALPHA")),
            surface("bravo", "BRAVO"),
            with_managed_identity(surface("charlie", "CHARLIE")),
        ];

        assert_eq!(by_did_over(&[record], &surfaces)["did:web:a"], set(&["alpha", "charlie"]));
    }

    #[test]
    fn managed_surfaces_count_entries_without_role_on_a2a_proxy_surfaces() {
        let mut record = managed("did:web:a", "proxy");
        record.channel_usage = vec![usage("proxy", None)];
        let mut proxy = surface("proxy", "PROXY");
        proxy.target.endpoint = "a2a-proxy://worker".to_string();

        assert_eq!(by_did_over(&[record], &[proxy])["did:web:a"], set(&["proxy"]));
    }

    #[test]
    fn managed_surfaces_count_shared_did_once_per_surface() {
        let mut record = managed("did:web:a", "alpha");
        record.channel_usage = vec![
            usage("alpha", Some(IdentityOrigin::Managed)),
            usage("bravo", Some(IdentityOrigin::Managed)),
            usage("charlie", Some(IdentityOrigin::Managed)),
            usage("delta", Some(IdentityOrigin::ExternalCaller)),
        ];
        let surfaces = ["alpha", "bravo", "charlie", "delta"].map(|id| with_managed_identity(surface(id, id)));

        assert_eq!(by_did_over(&[record], &surfaces)["did:web:a"], set(&["alpha", "bravo", "charlie"]));
    }

    #[test]
    fn publishable_returns_only_named() {
        let oxygen = DisplayName::parse("OXYGEN").unwrap();
        assert_eq!(ManagedDisplayName::Named(oxygen.clone()).publishable("did:a"), Some(&oxygen));
        assert_eq!(
            ManagedDisplayName::Shared {
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
        let surfaces = live(&["s1", "s2"]);

        let first = cache
            .surfaces_for("did:web:a", &store, &surfaces)
            .await;
        store
            .create(managed("did:web:x", "s2"))
            .await
            .unwrap();
        let second = cache
            .surfaces_for("did:web:a", &store, &surfaces)
            .await;

        assert_eq!(first, Some(set(&["s1"])));
        assert_eq!(second, Some(set(&["s1"])));
        assert_eq!(store.list_calls(), 1);
    }

    #[tokio::test]
    async fn cache_reloads_for_unknown_did() {
        let store = CountingStore::with(vec![managed("did:web:a", "s1")], false).await;
        let cache = SurfacesByDidCache::default();
        let surfaces = live(&["s1", "s2"]);
        cache
            .surfaces_for("did:web:a", &store, &surfaces)
            .await;

        let missing = cache
            .surfaces_for("did:web:new", &store, &surfaces)
            .await;
        store
            .create(managed("did:web:new", "s2"))
            .await
            .unwrap();
        let found = cache
            .surfaces_for("did:web:new", &store, &surfaces)
            .await;

        assert_eq!(missing, Some(BTreeSet::new()));
        assert_eq!(found, Some(set(&["s2"])));
        assert_eq!(store.list_calls(), 3);
    }

    #[tokio::test]
    async fn cache_reloads_after_ttl() {
        let store = CountingStore::with(vec![managed("did:web:a", "s1")], false).await;
        let cache = SurfacesByDidCache::new(Duration::ZERO);
        let surfaces = live(&["s1", "s2"]);
        cache
            .surfaces_for("did:web:a", &store, &surfaces)
            .await;
        let mut sibling = managed("did:web:a", "s2");
        sibling.identity_hash = "sibling".to_string();
        store
            .create(sibling)
            .await
            .unwrap();

        let reloaded = cache
            .surfaces_for("did:web:a", &store, &surfaces)
            .await;

        assert_eq!(reloaded, Some(set(&["s1", "s2"])));
        assert_eq!(store.list_calls(), 2);
    }

    #[tokio::test]
    async fn resolve_in_names_did_after_its_one_managed_surface() {
        let mut record = managed("did:web:a", "s1");
        record
            .channel_usage
            .push(usage("s2", Some(IdentityOrigin::ExternalCaller)));
        record.channel_config_id = Some("s2".to_string());
        let store = CountingStore::with(vec![record], false).await;

        let name = resolve_managed_display_name_in(
            &live(&["s1", "s2"]),
            "did:web:a",
            None,
            &store,
            &SurfacesByDidCache::default(),
        )
        .await;

        assert_eq!(name, Some(ManagedDisplayName::Named(DisplayName::parse("S1").unwrap())));
    }

    #[tokio::test]
    async fn resolve_in_counts_the_request_surface_before_its_usage_is_stored() {
        let store = CountingStore::with(vec![], false).await;

        let name = resolve_managed_display_name_in(
            &live(&["s1"]),
            "did:web:new",
            Some("s1"),
            &store,
            &SurfacesByDidCache::default(),
        )
        .await;

        assert_eq!(name, Some(ManagedDisplayName::Named(DisplayName::parse("S1").unwrap())));
    }

    #[tokio::test]
    async fn resolve_in_reports_shared_did_and_none_without_managed_surface() {
        let mut record = managed("did:web:a", "s1");
        record
            .channel_usage
            .push(usage("s2", Some(IdentityOrigin::Managed)));
        let store = CountingStore::with(vec![record], false).await;
        let surfaces = live(&["s1", "s2"]);
        let cache = SurfacesByDidCache::default();

        let shared = resolve_managed_display_name_in(&surfaces, "did:web:a", Some("s1"), &store, &cache).await;
        let unknown = resolve_managed_display_name_in(&surfaces, "did:web:none", None, &store, &cache).await;

        assert_eq!(
            shared,
            Some(ManagedDisplayName::Shared {
                surface_ids: vec!["s1".to_string(), "s2".to_string()]
            })
        );
        assert_eq!(unknown, None);
    }

    #[tokio::test]
    async fn cache_returns_none_when_store_fails() {
        let store = CountingStore::with(vec![], true).await;
        let cache = SurfacesByDidCache::default();
        let surfaces = live(&["s1", "s2"]);

        assert_eq!(
            cache
                .surfaces_for("did:web:a", &store, &surfaces)
                .await,
            None
        );
        assert_eq!(store.list_calls(), 1);
    }
}
