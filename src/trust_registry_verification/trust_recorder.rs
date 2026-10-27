//! Trust Recorder runtime stage.
//!
//! Writes `TrAdminRecordRequest`s to one or more configured trust registries
//! on the MA→AP response leg. Fire-and-forget: any per-record failure is
//! logged, the response continues, and the per-entry outcome is kept as the
//! agent's recorder status (see [`super::recorder_status`]).
//!
//! Wire path: `AgentSurface::access_point::trust_recorder`.
//! Frontend element: `www/default/src/components/surface-builder/elements/trust-recorder/`.
//!
//! Since removing the legacy `VCIssuer::register_agent_in_trust_registry`
//! writer, Trust Recorder is the **only** stage that writes agent-in-TR
//! records. Both the direct and `fabric://` request pipelines fire it on
//! discovery + response.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use tracing::{debug, info, warn};

use super::recorder_status::{EntryStatus, RecorderReason, global_store};

use crate::config::agent_surface::AgentSurface;
use crate::config::types::{EntityTarget, TrustRecorderConfig, TrustRecorderEntry};
use crate::identity::display_name::DisplayName;
use crate::trust_registries::TrustRegistryListenerManager;
use crate::trust_registries::communication::TrustRegistryError;
use crate::trust_registries::reference_fields::{
    ReferenceFieldPublisher, ReferenceFieldValue, authority_value_for_did, issuer_entity_value_for_did,
};
use crate::trust_registries::store::TrustRegistryStore;
use crate::trust_registries::types::TrAdminRecordRequest;

/// Template token operators can put in a `TrustRecorderEntry.authority_did`
/// slot to have the recorder resolve the surface's Issuer DID at write
/// time (instead of a static literal DID). Resolves to `Issuer.did` for
/// the surface's `issuer_id`; when that isn't configured or the issuer
/// can't be looked up, the entry is skipped with a WARN.
///
/// Kept in sync with the frontend constant of the same name in
/// `www/default/src/components/surface-builder/elements/trust-recorder/definition.ts`.
pub const SURFACE_ISSUER_DID_TEMPLATE: &str = "{{ surface.issuer_did }}";

/// Result of writing one record to a trust registry.
///
/// `detail` is the registry error text for the operator log only; it is never
/// stored or sent to the dashboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    Created,
    AlreadyExisted,
    Failed { reason: RecorderReason, detail: String },
}

/// Seam over the registry write protocol so the recorder's outcome handling
/// does not depend on which protocol the registry speaks.
#[async_trait]
pub trait RecordWriter: Send + Sync {
    async fn write_record(
        &self,
        tr_did: &str,
        record: &TrAdminRecordRequest,
    ) -> RecordOutcome;
}

#[async_trait]
impl RecordWriter for TrustRegistryListenerManager {
    async fn write_record(
        &self,
        tr_did: &str,
        record: &TrAdminRecordRequest,
    ) -> RecordOutcome {
        match self
            .create_record(tr_did, record)
            .await
        {
            Ok(_) => RecordOutcome::Created,
            Err(e) => classify_write_error(&e),
        }
    }
}

/// Duplicate records are expected on every response from the same managed
/// agent: the recorder is idempotent by design, so a duplicate is not a failure.
fn classify_write_error(error: &TrustRegistryError) -> RecordOutcome {
    if error.is_conflict()
        || error
            .to_string()
            .contains("already exists")
    {
        return RecordOutcome::AlreadyExisted;
    }
    let reason = match error {
        TrustRegistryError::Timeout(_) => RecorderReason::NoResponse,
        TrustRegistryError::ProblemReport(..) => RecorderReason::Rejected,
        _ => RecorderReason::Error,
    };
    RecordOutcome::Failed {
        reason,
        detail: error.to_string(),
    }
}

struct ReadyEntry<'a> {
    entry: &'a TrustRecorderEntry,
    authority_did: String,
    tr_did: String,
}

enum Resolution<'a> {
    Ready(ReadyEntry<'a>),
    Skipped(EntryStatus),
}

async fn resolve_entries<'a>(
    cfg: &'a TrustRecorderConfig,
    resolved_issuer_did: Option<&str>,
    tr_store: &dyn TrustRegistryStore,
) -> Vec<Resolution<'a>> {
    let mut resolutions = Vec::with_capacity(cfg.entries.len());
    for entry in &cfg.entries {
        let Some(authority_did) = resolve_authority_did(entry, resolved_issuer_did) else {
            resolutions.push(Resolution::Skipped(EntryStatus::skipped(
                &entry.trust_registry_id,
                RecorderReason::NoSurfaceIssuer,
            )));
            continue;
        };
        match lookup_entry_tr_did(tr_store, &entry.trust_registry_id).await {
            Ok(tr_did) => resolutions.push(Resolution::Ready(ReadyEntry { entry, authority_did, tr_did })),
            Err(reason) => {
                resolutions.push(Resolution::Skipped(EntryStatus::skipped(&entry.trust_registry_id, reason)))
            }
        }
    }
    resolutions
}

/// Writes every record of every ready entry, sequentially, and returns one
/// status per entry in configuration order. Skipped entries pass through;
/// entries that declare no records are left out.
async fn write_entries<W: RecordWriter + ?Sized>(
    writer: &W,
    resolutions: &[Resolution<'_>],
    agent_did: &str,
    context: Option<&serde_json::Value>,
) -> Vec<EntryStatus> {
    let mut statuses = Vec::with_capacity(resolutions.len());
    for resolution in resolutions {
        let ready = match resolution {
            Resolution::Skipped(status) => {
                statuses.push(status.clone());
                continue;
            }
            Resolution::Ready(ready) => ready,
        };
        let records = build_records(ready.entry, agent_did, &ready.authority_did, context);
        if records.is_empty() {
            continue;
        }
        let (mut created, mut already_existed, mut failed) = (0, 0, 0);
        let mut first_failure = None;
        for record in &records {
            match writer
                .write_record(&ready.tr_did, record)
                .await
            {
                RecordOutcome::Created => {
                    created += 1;
                    info!(
                        trust_registry_did = %ready.tr_did,
                        authority = %record.authority_id,
                        entity = %record.entity_id,
                        action = %record.action,
                        resource = %record.resource,
                        "Trust Recorder: record created"
                    );
                }
                RecordOutcome::AlreadyExisted => {
                    already_existed += 1;
                    debug!(
                        trust_registry_did = %ready.tr_did,
                        action = %record.action,
                        resource = %record.resource,
                        "Trust Recorder: record already exists (idempotent)"
                    );
                }
                RecordOutcome::Failed { reason, detail } => {
                    failed += 1;
                    first_failure.get_or_insert(reason);
                    warn!(
                        trust_registry_did = %ready.tr_did,
                        error = %detail,
                        action = %record.action,
                        resource = %record.resource,
                        "Trust Recorder: create_record failed (non-fatal)"
                    );
                }
            }
        }
        statuses.push(EntryStatus::from_counts(
            &ready.entry.trust_registry_id,
            created,
            already_existed,
            failed,
            first_failure,
        ));
    }
    statuses
}

/// Write all triples declared by `cfg` for `agent_did` to their target
/// trust registries. Runs sequentially per entry × per triple; errors are
/// logged and the loop continues (never fails the response leg). Returns one
/// [`EntryStatus`] per entry that was skipped or wrote at least one record.
///
/// Resolves each entry's `trust_registry_id` → TR DID via `tr_store`.
/// The TR DID is required by `TrustRegistryListenerManager::create_record`.
///
/// `resolved_issuer_did` is the pre-computed value for the
/// `{{ surface.issuer_did }}` template — usually the surface's `Issuer.did`
/// resolved by [`spawn_trust_recorder`] before firing the task. Pass
/// `None` when no surface Issuer is configured; entries whose
/// `authority_did` uses the template are then skipped with a WARN.
pub async fn apply_trust_recorder(
    cfg: &TrustRecorderConfig,
    agent_did: &str,
    resolved_issuer_did: Option<&str>,
    tenant_id: Option<&str>,
    display_name: Option<&DisplayName>,
    tr_manager: Arc<TrustRegistryListenerManager>,
    tr_store: Arc<dyn TrustRegistryStore>,
) -> Vec<EntryStatus> {
    if cfg.entries.is_empty() {
        return Vec::new();
    }
    info!(
        entry_count = cfg.entries.len(),
        agent_did = agent_did,
        "Trust Recorder: writing records for {} entry(ies)",
        cfg.entries.len()
    );

    let resolutions = resolve_entries(cfg, resolved_issuer_did, tr_store.as_ref()).await;
    let context = display_name.map(record_context);
    let statuses = write_entries(tr_manager.as_ref(), &resolutions, agent_did, context.as_ref()).await;

    let targets: Vec<(&TrustRecorderEntry, String, String)> = resolutions
        .iter()
        .filter_map(|resolution| match resolution {
            Resolution::Ready(ready) => Some((ready.entry, ready.authority_did.clone(), ready.tr_did.clone())),
            Resolution::Skipped(_) => None,
        })
        .collect();
    let authorities = crate::gateways::connection_points::get_authority_store();
    let issuers = crate::gateways::connection_points::get_issuer_store();
    let fields = recorder_reference_fields(
        &targets,
        agent_did,
        display_name,
        tenant_id,
        authorities.as_deref(),
        issuers.as_deref(),
    )
    .await;
    let publisher = ReferenceFieldPublisher::global();
    for (tr_did, value) in &fields {
        publisher
            .publish(tr_manager.as_ref(), tr_did, value)
            .await;
    }
    statuses
}

/// Names for the DIDs the recorder wrote, per trust registry: the agent entity (when
/// named), each authority, and each Issuer used as a record entity. Authorities and
/// Issuers are named only when global or owned by the surface's `tenant_id`.
async fn recorder_reference_fields(
    targets: &[(&TrustRecorderEntry, String, String)],
    agent_did: &str,
    display_name: Option<&DisplayName>,
    tenant_id: Option<&str>,
    authorities: Option<&dyn crate::authorities::AuthorityStore>,
    issuers: Option<&dyn crate::issuers::IssuerStore>,
) -> Vec<(String, ReferenceFieldValue)> {
    let mut fields: Vec<(String, ReferenceFieldValue)> = Vec::new();
    let mut push = |tr_did: &str, value: ReferenceFieldValue| {
        if !fields
            .iter()
            .any(|(t, v)| t == tr_did && v.field_type == value.field_type && v.id == value.id)
        {
            fields.push((tr_did.to_string(), value));
        }
    };
    for (entry, authority_did, tr_did) in targets {
        if let Some(name) = display_name {
            push(tr_did, ReferenceFieldValue::entity(agent_did, name.clone()));
        }
        if let Some(value) = authority_value_for_did(authority_did, tenant_id, authorities, issuers).await {
            push(tr_did, value);
        }
        let issuer_is_entity = entry
            .custom_resources
            .iter()
            .any(|r| r.entity_target == EntityTarget::Issuer);
        if issuer_is_entity
            && let Some(value) = issuer_entity_value_for_did(&entry.issuer_did, tenant_id, issuers).await
        {
            push(tr_did, value);
        }
    }
    fields
}

/// Resolve a Trust Recorder entry's `trust_registry_id` to the TR DID that
/// `TrustRegistryListenerManager` addresses. Fails (with a WARN) with the
/// reason the entry is skipped when the TR is unknown or not connected yet.
async fn lookup_entry_tr_did(
    tr_store: &dyn TrustRegistryStore,
    trust_registry_id: &str,
) -> Result<String, RecorderReason> {
    let tr = match tr_store
        .get(trust_registry_id)
        .await
    {
        Ok(Some(tr)) => tr,
        Ok(None) => {
            warn!(
                trust_registry_id = %trust_registry_id,
                "Trust Recorder: TR not found, skipping entry"
            );
            return Err(RecorderReason::RegistryNotFound);
        }
        Err(e) => {
            warn!(
                trust_registry_id = %trust_registry_id,
                error = %e,
                "Trust Recorder: TR lookup failed, skipping entry"
            );
            return Err(RecorderReason::Error);
        }
    };

    let tr_did = tr
        .main_did
        .as_deref()
        .or(tr.registry_did.as_deref())
        .or(tr.did.as_deref())
        .map(str::to_string);
    tr_did.ok_or_else(|| {
        warn!(
            trust_registry_id = %trust_registry_id,
            "Trust Recorder: TR has no resolved DID (not connected yet), skipping entry"
        );
        RecorderReason::RegistryNotConnected
    })
}

/// Distinct TR DIDs a Trust Recorder configuration writes to.
pub async fn recorder_registry_dids(
    cfg: &TrustRecorderConfig,
    tr_store: &dyn TrustRegistryStore,
) -> BTreeSet<String> {
    let mut dids = BTreeSet::new();
    for entry in &cfg.entries {
        if let Ok(did) = lookup_entry_tr_did(tr_store, &entry.trust_registry_id).await {
            dids.insert(did);
        }
    }
    dids
}

/// Trust-record context snapshot naming a managed agent.
pub fn record_context(name: &DisplayName) -> serde_json::Value {
    serde_json::json!({ "displayName": name, "origin": "managed" })
}

async fn resolve_recorder_display_name(
    agent_did: &str,
    surface_id: &str,
) -> Option<DisplayName> {
    crate::gateways::connection_points::get_vc_issuer()?
        .surface_display_name(agent_did, surface_id)
        .await?
        .publishable(agent_did)
        .cloned()
}

/// Resolve `entry.authority_did` for the current write, expanding the
/// `{{ surface.issuer_did }}` template against the surface-resolved issuer
/// DID. Returns `None` (with a WARN) when the template is used but no
/// resolved issuer is available — that entry is skipped fail-safe rather
/// than falling back to a literal template string, which would produce a
/// registry record with a `{{ … }}` `authority_id` (garbage).
fn resolve_authority_did(
    entry: &TrustRecorderEntry,
    resolved_issuer_did: Option<&str>,
) -> Option<String> {
    if entry.authority_did.trim() == SURFACE_ISSUER_DID_TEMPLATE {
        match resolved_issuer_did {
            Some(did) if !did.is_empty() => Some(did.to_string()),
            _ => {
                warn!(
                    trust_registry_id = %entry.trust_registry_id,
                    template = SURFACE_ISSUER_DID_TEMPLATE,
                    "Trust Recorder: `surface.issuer_did` template unresolved (surface has no issuer configured), skipping entry"
                );
                None
            }
        }
    } else {
        Some(entry.authority_did.clone())
    }
}

/// Fire-and-forget wrapper that spawns a `tokio` task to run
/// `apply_trust_recorder`. Centralises the gate every call site would
/// otherwise duplicate: `agent_did` must be `did:`-prefixed,
/// `surface.trust_recorder()` must have at least one entry, and a
/// `TrustRegistryListenerManager` must be available. The async
/// `tr_manager.store()` lookup runs inside the spawned task, so callers do
/// not need to `.await` before firing.
///
/// The spawned task also resolves `surface.issuer_id → Issuer.did` (via
/// the global `IssuerStore`) so entries authored with
/// `authority_did = "{{ surface.issuer_did }}"` write records whose
/// `authority_id` matches the surface's Issuer at record time.
///
/// Idempotent (`apply_trust_recorder` logs duplicates at `DEBUG`), so it is
/// safe to fire on every eligible request. Never blocks the response.
pub fn spawn_trust_recorder(
    surface: &AgentSurface,
    agent_did: &str,
    tr_manager: Option<Arc<TrustRegistryListenerManager>>,
) {
    if !agent_did.starts_with("did:") {
        return;
    }
    let Some(recorder_cfg) = surface.trust_recorder() else {
        return;
    };
    if recorder_cfg
        .entries
        .is_empty()
    {
        return;
    }
    let Some(tr_manager) = tr_manager else {
        return;
    };
    let cfg = recorder_cfg.clone();
    let did = agent_did.to_string();
    let issuer_id = surface.issuer_id.clone();
    let surface_id = surface.surface_id.clone();
    let tenant_id = surface.tenant_id.clone();
    let started_at = chrono::Utc::now();
    tokio::spawn(async move {
        let Some(store) = tr_manager.store().await else {
            return;
        };
        let resolved_issuer_did = resolve_surface_issuer_did(issuer_id.as_deref()).await;
        let display_name = resolve_recorder_display_name(&did, &surface_id).await;
        let entries = apply_trust_recorder(
            &cfg,
            &did,
            resolved_issuer_did.as_deref(),
            tenant_id.as_deref(),
            display_name.as_ref(),
            tr_manager,
            store,
        )
        .await;
        if let Some(status_store) = global_store()
            && let Err(e) = status_store
                .record(&surface_id, &did, entries, started_at, chrono::Utc::now())
                .await
        {
            warn!(surface_id = %surface_id, error = %e, "Trust Recorder: failed to store status");
        }
    });
}

/// Look up `surface.issuer_id → Issuer.did` via the process-global
/// `IssuerStore`. Returns `None` when the issuer_id is unset, the store
/// isn't initialised, or the lookup fails — the caller decides how to
/// treat the missing value (per-entry, whether to skip or use a literal).
async fn resolve_surface_issuer_did(issuer_id: Option<&str>) -> Option<String> {
    let issuer_id = issuer_id?;
    let store = crate::gateways::connection_points::get_issuer_store()?;
    match store.get(issuer_id).await {
        Ok(Some(issuer)) => Some(issuer.did),
        Ok(None) => {
            warn!(
                issuer_id = %issuer_id,
                "Trust Recorder: surface issuer_id not found in issuer store"
            );
            None
        }
        Err(e) => {
            warn!(
                issuer_id = %issuer_id,
                error = %e,
                "Trust Recorder: issuer store lookup failed"
            );
            None
        }
    }
}

/// Expand one `TrustRecorderEntry` into the concrete TrAdmin records it
/// declares: the optional `ownedAgent` triple plus a `custom_resources`
/// fan-out (each with its own action/resource/entity_target).
///
/// `authority_did` is the value passed to every emitted record — usually
/// `entry.authority_did` verbatim, but the `{{ surface.issuer_did }}`
/// template gets expanded upstream in [`resolve_authority_did`].
///
/// `context` is attached only to records whose entity is the agent itself.
fn build_records(
    entry: &TrustRecorderEntry,
    agent_did: &str,
    authority_did: &str,
    context: Option<&serde_json::Value>,
) -> Vec<TrAdminRecordRequest> {
    let mut out = Vec::new();

    if entry.include_owned_agent {
        out.push(TrAdminRecordRequest {
            authority_id: authority_did.to_string(),
            entity_id: agent_did.to_string(),
            action: "is".to_string(),
            resource: "ownedAgent".to_string(),
            record_type: "recognition".to_string(),
            authorized: true,
            recognized: true,
            context: context.cloned(),
        });
    }
    for resource in &entry.custom_resources {
        let action = resource.action.trim();
        let res = resource.resource.trim();
        let record_type = resource.record_type.trim();
        if action.is_empty() || res.is_empty() || record_type.is_empty() {
            continue;
        }
        let (entity_id, record_context) = match resource.entity_target {
            EntityTarget::Issuer => (entry.issuer_did.clone(), None),
            EntityTarget::Agent => (agent_did.to_string(), context.cloned()),
        };
        out.push(TrAdminRecordRequest {
            authority_id: authority_did.to_string(),
            entity_id,
            action: action.to_string(),
            resource: res.to_string(),
            record_type: record_type.to_string(),
            authorized: true,
            recognized: true,
            context: record_context,
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::CustomResource;
    use crate::identity::display_name::ManagedDisplayName;
    use crate::trust_registry_verification::recorder_status::RecorderState;

    fn base_entry() -> TrustRecorderEntry {
        TrustRecorderEntry {
            trust_registry_id: "tr-1".into(),
            issuer_did: "did:example:issuer".into(),
            authority_did: "did:example:authority".into(),
            include_owned_agent: false,
            custom_resources: vec![],
        }
    }

    async fn issuer_store_with(
        issuers: &[crate::issuers::types::Issuer]
    ) -> (crate::issuers::FileSystemIssuerStore, tempfile::TempDir) {
        use crate::issuers::IssuerStore;
        let dir = tempfile::tempdir().unwrap();
        let store = crate::issuers::FileSystemIssuerStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        for issuer in issuers {
            store
                .create(issuer)
                .await
                .unwrap();
        }
        (store, dir)
    }

    fn named_issuer(
        did: &str,
        name: &str,
    ) -> crate::issuers::types::Issuer {
        crate::issuers::types::Issuer::new(
            format!("id-{did}"),
            name.to_string(),
            did.to_string(),
            serde_json::Value::Null,
            serde_json::Value::Null,
        )
    }

    fn summary(fields: &[(String, ReferenceFieldValue)]) -> Vec<(String, String, String, String)> {
        fields
            .iter()
            .map(|(tr, v)| (tr.clone(), format!("{:?}", v.field_type), v.id.clone(), v.name.as_str().to_string()))
            .collect()
    }

    #[tokio::test]
    async fn recorder_reference_fields_name_the_agent_authority_and_issuer_entity() {
        let issuer_did = "did:web:gw:issuers:abc";
        let (issuers, _dir) = issuer_store_with(&[named_issuer(issuer_did, "ABC Issuer")]).await;
        let mut entry = base_entry();
        entry.issuer_did = issuer_did.into();
        entry.custom_resources = vec![CustomResource {
            action: "issue".into(),
            resource: "credential".into(),
            entity_target: EntityTarget::Issuer,
            record_type: "authorization".into(),
        }];
        let targets = vec![(&entry, issuer_did.to_string(), "did:example:tr".to_string())];
        let name = DisplayName::parse("OXYGEN").unwrap();

        let fields =
            recorder_reference_fields(&targets, "did:example:agent", Some(&name), None, None, Some(&issuers)).await;

        assert_eq!(
            summary(&fields),
            vec![
                ("did:example:tr".into(), "Entity".into(), "did:example:agent".into(), "OXYGEN".into()),
                ("did:example:tr".into(), "Authority".into(), issuer_did.into(), "ABC Issuer".into()),
                ("did:example:tr".into(), "Entity".into(), issuer_did.into(), "ABC Issuer".into()),
            ]
        );
    }

    #[tokio::test]
    async fn recorder_reference_fields_skip_unknown_dids_and_unnamed_agents() {
        let (issuers, _dir) = issuer_store_with(&[]).await;
        let mut entry = base_entry();
        entry.custom_resources = vec![CustomResource {
            action: "issue".into(),
            resource: "credential".into(),
            entity_target: EntityTarget::Issuer,
            record_type: "authorization".into(),
        }];
        let targets = vec![(&entry, "did:example:authority".to_string(), "did:example:tr".to_string())];

        let fields = recorder_reference_fields(&targets, "did:example:agent", None, None, None, Some(&issuers)).await;

        assert!(fields.is_empty());
    }

    #[tokio::test]
    async fn recorder_reference_fields_skip_another_tenants_issuer() {
        let issuer_did = "did:web:gw:issuers:abc";
        let mut owned = named_issuer(issuer_did, "Tenant A Issuer");
        owned.tenant_id = Some("tenant-a".to_string());
        let (issuers, _dir) = issuer_store_with(&[owned]).await;
        let mut entry = base_entry();
        entry.issuer_did = issuer_did.into();
        entry.custom_resources = vec![CustomResource {
            action: "issue".into(),
            resource: "credential".into(),
            entity_target: EntityTarget::Issuer,
            record_type: "authorization".into(),
        }];
        let targets = vec![(&entry, issuer_did.to_string(), "did:example:tr".to_string())];
        let name = DisplayName::parse("OXYGEN").unwrap();

        let other_tenant = recorder_reference_fields(
            &targets,
            "did:example:agent",
            Some(&name),
            Some("tenant-b"),
            None,
            Some(&issuers),
        )
        .await;
        let same_tenant = recorder_reference_fields(
            &targets,
            "did:example:agent",
            Some(&name),
            Some("tenant-a"),
            None,
            Some(&issuers),
        )
        .await;

        assert_eq!(
            summary(&other_tenant),
            vec![("did:example:tr".into(), "Entity".into(), "did:example:agent".into(), "OXYGEN".into())]
        );
        assert_eq!(
            summary(&same_tenant),
            vec![
                ("did:example:tr".into(), "Entity".into(), "did:example:agent".into(), "OXYGEN".into()),
                ("did:example:tr".into(), "Authority".into(), issuer_did.into(), "Tenant A Issuer".into()),
                ("did:example:tr".into(), "Entity".into(), issuer_did.into(), "Tenant A Issuer".into()),
            ]
        );
    }

    #[tokio::test]
    async fn recorder_reference_fields_publish_once_per_registry() {
        let issuer_did = "did:web:gw:issuers:abc";
        let (issuers, _dir) = issuer_store_with(&[named_issuer(issuer_did, "ABC Issuer")]).await;
        let entry = base_entry();
        let targets = vec![
            (&entry, issuer_did.to_string(), "did:example:tr-1".to_string()),
            (&entry, issuer_did.to_string(), "did:example:tr-1".to_string()),
            (&entry, issuer_did.to_string(), "did:example:tr-2".to_string()),
        ];

        let fields = recorder_reference_fields(&targets, "did:example:agent", None, None, None, Some(&issuers)).await;

        assert_eq!(
            summary(&fields),
            vec![
                ("did:example:tr-1".into(), "Authority".into(), issuer_did.into(), "ABC Issuer".into()),
                ("did:example:tr-2".into(), "Authority".into(), issuer_did.into(), "ABC Issuer".into()),
            ]
        );
    }

    #[test]
    fn empty_entry_yields_no_records() {
        let e = base_entry();
        assert!(build_records(&e, "did:example:agent", &e.authority_did, None).is_empty());
    }

    #[test]
    fn owned_agent_uses_authority_did_and_agent_entity() {
        let mut e = base_entry();
        e.include_owned_agent = true;
        let recs = build_records(&e, "did:example:agent", &e.authority_did, None);
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.resource, "ownedAgent");
        assert_eq!(r.action, "is");
        assert_eq!(r.entity_id, "did:example:agent");
        assert_eq!(r.authority_id, "did:example:authority");
        assert_ne!(r.authority_id, r.entity_id);
    }

    #[test]
    fn custom_resources_respect_entity_target_and_skip_blanks() {
        let mut e = base_entry();
        e.custom_resources = vec![
            CustomResource {
                action: "is".into(),
                resource: "paymentAgent".into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            },
            CustomResource {
                action: "register".into(),
                resource: "agents".into(),
                entity_target: EntityTarget::Issuer,
                record_type: "authorization".into(),
            },
            CustomResource {
                action: "  ".into(),
                resource: "blank".into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            },
            CustomResource {
                action: "is".into(),
                resource: "  ".into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            },
            CustomResource {
                action: "is".into(),
                resource: "logs".into(),
                entity_target: EntityTarget::Agent,
                record_type: "  ".into(),
            },
        ];
        let recs = build_records(&e, "did:example:agent", &e.authority_did, None);
        assert_eq!(recs.len(), 2);

        assert_eq!(recs[0].action, "is");
        assert_eq!(recs[0].resource, "paymentAgent");
        assert_eq!(recs[0].entity_id, "did:example:agent");
        assert_eq!(recs[0].authority_id, "did:example:authority");
        assert_eq!(recs[0].record_type, "recognition");

        assert_eq!(recs[1].action, "register");
        assert_eq!(recs[1].resource, "agents");
        assert_eq!(recs[1].entity_id, "did:example:issuer");
        assert_eq!(recs[1].authority_id, "did:example:authority");
        assert_eq!(recs[1].record_type, "authorization");
    }

    #[test]
    fn resolve_authority_did_returns_literal_verbatim() {
        let e = base_entry();
        let resolved = resolve_authority_did(&e, Some("did:example:issuer-runtime"));
        assert_eq!(resolved.as_deref(), Some("did:example:authority"));
    }

    #[test]
    fn resolve_authority_did_expands_surface_issuer_template() {
        let mut e = base_entry();
        e.authority_did = SURFACE_ISSUER_DID_TEMPLATE.to_string();
        let resolved = resolve_authority_did(&e, Some("did:example:issuer-runtime"));
        assert_eq!(resolved.as_deref(), Some("did:example:issuer-runtime"));
    }

    #[test]
    fn resolve_authority_did_skips_entry_when_template_unresolved() {
        let mut e = base_entry();
        e.authority_did = SURFACE_ISSUER_DID_TEMPLATE.to_string();
        // No resolved issuer available (surface has no issuer_id or lookup failed).
        assert!(resolve_authority_did(&e, None).is_none());
        // Empty string is treated the same as None — never emit a record
        // with an empty `authority_id`.
        assert!(resolve_authority_did(&e, Some("")).is_none());
    }

    #[test]
    fn build_records_uses_template_expanded_authority_end_to_end() {
        let mut e = base_entry();
        e.authority_did = SURFACE_ISSUER_DID_TEMPLATE.to_string();
        e.include_owned_agent = true;
        e.custom_resources = vec![CustomResource {
            action: "sign".into(),
            resource: "invoice".into(),
            entity_target: EntityTarget::Agent,
            record_type: "authorization".into(),
        }];
        let resolved = resolve_authority_did(&e, Some("did:example:issuer-runtime")).unwrap();
        let recs = build_records(&e, "did:example:agent", &resolved, None);
        assert_eq!(recs.len(), 2);
        // Both emitted records now carry the resolved DID as authority_id,
        // matching what a downstream Trust Check `authority = verified issuer`
        // query will look for.
        assert_eq!(recs[0].authority_id, "did:example:issuer-runtime");
        assert_eq!(recs[1].authority_id, "did:example:issuer-runtime");
    }

    fn oxygen() -> DisplayName {
        DisplayName::parse("OXYGEN").unwrap()
    }

    #[test]
    fn record_context_has_exact_shape() {
        assert_eq!(record_context(&oxygen()), serde_json::json!({"displayName": "OXYGEN", "origin": "managed"}));
        assert_eq!(
            serde_json::to_string(&record_context(&oxygen())).unwrap(),
            r#"{"displayName":"OXYGEN","origin":"managed"}"#
        );
    }

    #[test]
    fn context_is_attached_only_to_agent_entity_records() {
        let mut e = base_entry();
        e.include_owned_agent = true;
        e.custom_resources = vec![
            CustomResource {
                action: "is".into(),
                resource: "paymentAgent".into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            },
            CustomResource {
                action: "register".into(),
                resource: "agents".into(),
                entity_target: EntityTarget::Issuer,
                record_type: "authorization".into(),
            },
        ];
        let context = record_context(&oxygen());

        let recs = build_records(&e, "did:example:agent", &e.authority_did, Some(&context));

        assert_eq!(recs.len(), 3);
        assert_eq!(recs[0].context.as_ref(), Some(&context));
        assert_eq!(recs[1].context.as_ref(), Some(&context));
        assert_eq!(recs[2].entity_id, "did:example:issuer");
        assert_eq!(recs[2].context, None);
    }

    #[test]
    fn conflict_yields_records_without_context() {
        let mut e = base_entry();
        e.include_owned_agent = true;
        let conflict = ManagedDisplayName::Conflict {
            surface_ids: vec!["s1".into(), "s2".into()],
        };
        let context = conflict
            .publishable("did:example:agent")
            .map(record_context);

        let recs = build_records(&e, "did:example:agent", &e.authority_did, context.as_ref());

        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].context, None);
    }

    struct ScriptedWriter {
        outcomes: std::sync::Mutex<std::collections::VecDeque<RecordOutcome>>,
        calls: std::sync::Mutex<Vec<(String, String, String)>>,
    }

    impl ScriptedWriter {
        fn new(outcomes: Vec<RecordOutcome>) -> Self {
            Self {
                outcomes: std::sync::Mutex::new(outcomes.into()),
                calls: std::sync::Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<(String, String, String)> {
            self.calls
                .lock()
                .unwrap()
                .clone()
        }
    }

    #[async_trait]
    impl RecordWriter for ScriptedWriter {
        async fn write_record(
            &self,
            tr_did: &str,
            record: &TrAdminRecordRequest,
        ) -> RecordOutcome {
            self.calls
                .lock()
                .unwrap()
                .push((tr_did.to_string(), record.action.clone(), record.resource.clone()));
            self.outcomes
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(RecordOutcome::Created)
        }
    }

    fn entry_writing(
        registry: &str,
        resources: &[&str],
    ) -> TrustRecorderEntry {
        let mut entry = base_entry();
        entry.trust_registry_id = registry.into();
        entry.custom_resources = resources
            .iter()
            .map(|resource| CustomResource {
                action: "is".into(),
                resource: (*resource).into(),
                entity_target: EntityTarget::Agent,
                record_type: "recognition".into(),
            })
            .collect();
        entry
    }

    fn ready(entry: &TrustRecorderEntry) -> Resolution<'_> {
        Resolution::Ready(ReadyEntry {
            entry,
            authority_did: "did:example:authority".into(),
            tr_did: format!("did:example:{}", entry.trust_registry_id),
        })
    }

    fn failure(
        reason: RecorderReason,
        detail: &str,
    ) -> RecordOutcome {
        RecordOutcome::Failed { reason, detail: detail.into() }
    }

    #[tokio::test]
    async fn created_records_make_a_recorded_entry_and_go_to_the_entrys_registry() {
        let entry = entry_writing("tr-1", &["a", "b"]);
        let writer = ScriptedWriter::new(vec![RecordOutcome::Created, RecordOutcome::Created]);

        let statuses = write_entries(&writer, &[ready(&entry)], "did:example:agent", None).await;

        assert_eq!(statuses, vec![EntryStatus::from_counts("tr-1", 2, 0, 0, None)]);
        assert_eq!(
            writer.calls(),
            vec![
                ("did:example:tr-1".into(), "is".into(), "a".into()),
                ("did:example:tr-1".into(), "is".into(), "b".into()),
            ]
        );
    }

    #[tokio::test]
    async fn duplicate_records_still_count_as_recorded() {
        let entry = entry_writing("tr-1", &["a"]);
        let writer = ScriptedWriter::new(vec![RecordOutcome::AlreadyExisted]);

        let statuses = write_entries(&writer, &[ready(&entry)], "did:example:agent", None).await;

        assert_eq!(statuses, vec![EntryStatus::from_counts("tr-1", 0, 1, 0, None)]);
        assert_eq!(statuses[0].state, RecorderState::Recorded);
    }

    #[tokio::test]
    async fn one_failed_record_among_written_ones_makes_the_entry_partial() {
        let entry = entry_writing("tr-1", &["a", "b", "c"]);
        let writer = ScriptedWriter::new(vec![
            RecordOutcome::Created,
            failure(RecorderReason::NoResponse, "Timeout: no reply"),
            RecordOutcome::AlreadyExisted,
        ]);

        let statuses = write_entries(&writer, &[ready(&entry)], "did:example:agent", None).await;

        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, RecorderState::Partial);
        assert_eq!(statuses[0].reason, Some(RecorderReason::NoResponse));
        assert_eq!((statuses[0].created, statuses[0].already_existed, statuses[0].failed), (1, 1, 1));
        assert_eq!(writer.calls().len(), 3, "a failure must not stop the remaining records");
    }

    #[tokio::test]
    async fn every_record_failing_makes_a_failed_entry_with_the_first_failure_reason() {
        let entry = entry_writing("tr-1", &["a", "b"]);
        let writer = ScriptedWriter::new(vec![
            failure(RecorderReason::Rejected, "Problem report [e.p.x]: no"),
            failure(RecorderReason::NoResponse, "Timeout"),
        ]);

        let statuses = write_entries(&writer, &[ready(&entry)], "did:example:agent", None).await;

        assert_eq!(statuses[0].state, RecorderState::Failed);
        assert_eq!(statuses[0].reason, Some(RecorderReason::Rejected));
        assert_eq!(statuses[0].failed, 2);
    }

    #[tokio::test]
    async fn registry_error_text_never_reaches_the_status() {
        let entry = entry_writing("tr-1", &["a"]);
        let writer = ScriptedWriter::new(vec![failure(RecorderReason::Error, "internal host db.corp:5432 refused")]);

        let statuses = write_entries(&writer, &[ready(&entry)], "did:example:agent", None).await;

        let json = serde_json::to_string(&statuses).unwrap();
        assert!(!json.contains("db.corp"), "status leaked registry error text: {json}");
    }

    #[tokio::test]
    async fn skipped_entries_keep_their_place_and_entries_without_records_are_left_out() {
        let writes = entry_writing("tr-b", &["a"]);
        let declares_nothing = entry_writing("tr-d", &[]);
        let resolutions = vec![
            Resolution::Skipped(EntryStatus::skipped("tr-a", RecorderReason::NoSurfaceIssuer)),
            ready(&writes),
            Resolution::Skipped(EntryStatus::skipped("tr-c", RecorderReason::RegistryNotConnected)),
            ready(&declares_nothing),
        ];
        let writer = ScriptedWriter::new(vec![]);

        let statuses = write_entries(&writer, &resolutions, "did:example:agent", None).await;

        let order: Vec<(&str, RecorderState)> = statuses
            .iter()
            .map(|s| (s.trust_registry_id.as_str(), s.state))
            .collect();
        assert_eq!(
            order,
            vec![("tr-a", RecorderState::Skipped), ("tr-b", RecorderState::Recorded), ("tr-c", RecorderState::Skipped),]
        );
        assert_eq!(writer.calls().len(), 1);
    }

    #[test]
    fn write_errors_are_classified_into_outcomes() {
        use crate::trust_registries::communication::TR_CONFLICT_CODE;
        let failed_with = |error: TrustRegistryError| match classify_write_error(&error) {
            RecordOutcome::Failed { reason, .. } => reason,
            other => panic!("expected a failure, got {other:?}"),
        };

        assert_eq!(
            classify_write_error(&TrustRegistryError::ProblemReport(TR_CONFLICT_CODE.into(), "x".into())),
            RecordOutcome::AlreadyExisted
        );
        assert_eq!(
            classify_write_error(&TrustRegistryError::ProblemReport(
                "e.p.msg.other".into(),
                "Record already exists: k".into()
            )),
            RecordOutcome::AlreadyExisted
        );
        assert_eq!(failed_with(TrustRegistryError::Timeout("t".into())), RecorderReason::NoResponse);
        assert_eq!(
            failed_with(TrustRegistryError::ProblemReport("e.p.me.unauthorized".into(), "no".into())),
            RecorderReason::Rejected
        );
        for error in [
            TrustRegistryError::SendError("s".into()),
            TrustRegistryError::NoConnection("n".into()),
            TrustRegistryError::ConnectionError("c".into()),
            TrustRegistryError::StaleConnection("s".into()),
            TrustRegistryError::ParseError("p".into()),
            TrustRegistryError::NotFound("f".into()),
        ] {
            assert_eq!(failed_with(error), RecorderReason::Error);
        }
    }

    #[test]
    fn a_failure_outcome_keeps_the_registry_text_for_the_operator_log() {
        match classify_write_error(&TrustRegistryError::Timeout("No response within 10s".into())) {
            RecordOutcome::Failed { detail, .. } => assert!(detail.contains("No response within 10s")),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    async fn store_with(
        registries: &[(&str, Option<&str>)]
    ) -> (crate::trust_registries::FileSystemTrustRegistryStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = crate::trust_registries::FileSystemTrustRegistryStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        for (id, main_did) in registries {
            let mut registry = crate::trust_registries::types::TrustRegistry::new(
                format!("registry {id}"),
                String::new(),
                "https://example.com/oob".into(),
                crate::trust_registries::did_manager::DidMethod::default(),
            );
            registry.id = (*id).into();
            registry.main_did = main_did.map(str::to_string);
            store
                .create(&registry)
                .await
                .unwrap();
        }
        (store, dir)
    }

    #[tokio::test]
    async fn entries_are_resolved_or_skipped_with_the_reason_in_configuration_order() {
        let (store, _dir) = store_with(&[("tr-connected", Some("did:example:tr")), ("tr-pending", None)]).await;
        let mut cfg = TrustRecorderConfig::default();
        let mut templated = entry_writing("tr-connected", &["a"]);
        templated.authority_did = SURFACE_ISSUER_DID_TEMPLATE.into();
        cfg.entries = vec![
            entry_writing("tr-connected", &["a"]),
            entry_writing("tr-pending", &["a"]),
            entry_writing("tr-missing", &["a"]),
            templated,
        ];

        let resolutions = resolve_entries(&cfg, None, &store).await;

        let summary: Vec<String> = resolutions
            .iter()
            .map(|r| match r {
                Resolution::Ready(ready) => format!("ready {} -> {}", ready.entry.trust_registry_id, ready.tr_did),
                Resolution::Skipped(status) => format!("skipped {} {:?}", status.trust_registry_id, status.reason),
            })
            .collect();
        assert_eq!(
            summary,
            vec![
                "ready tr-connected -> did:example:tr".to_string(),
                "skipped tr-pending Some(RegistryNotConnected)".to_string(),
                "skipped tr-missing Some(RegistryNotFound)".to_string(),
                "skipped tr-connected Some(NoSurfaceIssuer)".to_string(),
            ]
        );
    }

    #[tokio::test]
    async fn the_template_authority_resolves_when_the_surface_has_an_issuer() {
        let (store, _dir) = store_with(&[("tr-1", Some("did:example:tr"))]).await;
        let mut entry = entry_writing("tr-1", &["a"]);
        entry.authority_did = SURFACE_ISSUER_DID_TEMPLATE.into();
        let cfg = TrustRecorderConfig { entries: vec![entry] };

        let resolutions = resolve_entries(&cfg, Some("did:example:issuer-runtime"), &store).await;

        match &resolutions[0] {
            Resolution::Ready(ready) => assert_eq!(ready.authority_did, "did:example:issuer-runtime"),
            Resolution::Skipped(status) => panic!("unexpected skip: {status:?}"),
        }
    }

    #[tokio::test]
    async fn repeated_runs_store_the_status_only_when_the_outcome_changes() {
        use crate::trust_registry_verification::recorder_status::TrustRecorderStatusStore;
        let entry = entry_writing("tr-1", &["a"]);
        let status_store = TrustRecorderStatusStore::in_memory();
        let now = chrono::Utc::now();
        let run = |outcome: RecordOutcome, at: chrono::DateTime<chrono::Utc>| {
            let entry = &entry;
            let status_store = &status_store;
            async move {
                let writer = ScriptedWriter::new(vec![outcome]);
                let statuses = write_entries(&writer, &[ready(entry)], "did:example:agent", None).await;
                status_store
                    .record("surface-1", "did:example:agent", statuses, at, at)
                    .await
                    .unwrap()
            }
        };

        assert!(run(RecordOutcome::Created, now).await);
        assert!(run(RecordOutcome::AlreadyExisted, now + chrono::Duration::seconds(1)).await);
        assert!(!run(RecordOutcome::AlreadyExisted, now + chrono::Duration::seconds(2)).await);
        assert!(run(failure(RecorderReason::NoResponse, "Timeout"), now + chrono::Duration::seconds(3)).await);

        let status = status_store
            .status_for("surface-1", "did:example:agent")
            .await
            .unwrap();
        assert_eq!(status.state, RecorderState::Failed);
        assert_eq!(status.reason, Some(RecorderReason::NoResponse));
    }
}
